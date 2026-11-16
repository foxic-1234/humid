import { secp256k1 } from "@noble/curves/secp256k1.js";
import { bech32m } from "@scure/base";

import { computeLabelTweak, deriveLabeledSpendPublicKey } from "./crypto";
import type {
	SilentPaymentAddressInfo,
	SilentPaymentNetwork,
	SilentPaymentRecipientKeys,
} from "./types";

// Blech32m alphabet; bech32m itself comes from @scure/base.
const CHARSET = "qpzry9x8gf2tvdw0s3jn54khce6mua7l";

// BIP-352 raises bech32m's 90-character limit to 1023: an SP address is 117 characters.
const BECH32M_MAX_LENGTH = 1023;

// ELIP-352 HRPs for Silent Payments
export const HRP_LIQUID_MAINNET = "lqsp";
export const HRP_LIQUID_TESTNET = "tlqsp";

function hrpExpand(hrp: string): number[] {
	const ret: number[] = [];
	for (let i = 0; i < hrp.length; i++) {
		ret.push(hrp.charCodeAt(i) >> 5);
	}
	ret.push(0);
	for (let i = 0; i < hrp.length; i++) {
		ret.push(hrp.charCodeAt(i) & 31);
	}
	return ret;
}

function validateCompressedPubKey(bytes: Uint8Array, label: string): void {
	if (bytes.length !== 33) {
		throw new Error(`${label} must be 33 bytes compressed, got ${bytes.length} bytes`);
	}
	if (bytes[0] !== 0x02 && bytes[0] !== 0x03) {
		throw new Error(`${label} prefix must be 0x02 or 0x03`);
	}
	try {
		const pt = secp256k1.Point.fromHex(bytes);
		pt.assertValidity();
	} catch (e) {
		throw new Error(`Invalid curve point for ${label}: ${String(e)}`, { cause: e });
	}
}

/**
 * Encode a static Liquid Silent Payment address (B_scan, B_spend) to standard Bech32m:
 * Version 0 (1 byte) || B_scan (33 bytes) || B_spend (33 bytes) = 67 bytes.
 *
 * ELIP-352 HRP: "lqsp" (mainnet) or "tlqsp" (testnet and regtest).
 */
export function encodeSilentPaymentAddress(
	scanPublicKey: Uint8Array,
	spendPublicKey: Uint8Array,
	network: SilentPaymentNetwork = "mainnet",
): string {
	validateCompressedPubKey(scanPublicKey, "Scan public key B_scan");
	validateCompressedPubKey(spendPublicKey, "Spend public key B_spend");

	const hrp = network === "mainnet" ? HRP_LIQUID_MAINNET : HRP_LIQUID_TESTNET;

	// BIP-352: payload is B_scan(33) || B_spend(33) = 66 bytes
	const payload = new Uint8Array(66);
	payload.set(scanPublicKey, 0);
	payload.set(spendPublicKey, 33);

	// BIP-352: version 0 is prepended as a separate 5-bit word (symbol 'q')
	return bech32m.encode(hrp, [0, ...bech32m.toWords(payload)], BECH32M_MAX_LENGTH);
}

/**
 * Derive a labeled Silent Payment address for a given label index m.
 * Uses b_scan to compute label tweak ℓ = H_label(b_scan || m),
 * tweaks B_spend -> B_spend_m = B_spend + [ℓ]G,
 * and encodes the resulting pair (B_scan, B_spend_m).
 */
export function deriveLabeledSilentPaymentAddress(
	recipientKeys: SilentPaymentRecipientKeys,
	labelIndex: number,
	network: SilentPaymentNetwork = "mainnet",
): {
	address: string;
	labelTweak: bigint;
	spendPublicKey: Uint8Array;
} {
	const labelTweak = computeLabelTweak(recipientKeys.scanKey.privateKey, labelIndex);
	const spendPublicKey = deriveLabeledSpendPublicKey(recipientKeys.spendKey.publicKey, labelTweak);
	const address = encodeSilentPaymentAddress(
		recipientKeys.scanKey.publicKey,
		spendPublicKey,
		network,
	);
	return { address, labelTweak, spendPublicKey };
}

// Segwit address HRPs of each network (Elements `AddressParams`). Unlike the SP address, which is
// `tlqsp` on both testnet and regtest, an output address belongs to one network only.
const BECH32_HRPS: Record<SilentPaymentNetwork, string> = {
	mainnet: "ex",
	testnet: "tex",
	regtest: "ert",
};
const BLECH32_HRPS: Record<SilentPaymentNetwork, string> = {
	mainnet: "lq",
	testnet: "tlq",
	regtest: "el",
};

/**
 * Encode a 32-byte Taproot x-only public key to standard Elements/Liquid Taproot address:
 * Witness version 1 (1 byte) || xOnly (32 bytes)
 * HRP: 'ex' for Liquid mainnet, 'tex' for Liquid testnet, 'ert' for Elements regtest.
 */
export function encodeTaprootAddress(
	xOnlyPublicKey: Uint8Array,
	network: SilentPaymentNetwork = "mainnet",
): string {
	if (xOnlyPublicKey.length !== 32) {
		throw new Error(`Taproot x-only public key must be 32 bytes, got ${xOnlyPublicKey.length}`);
	}
	const hrp = BECH32_HRPS[network];
	return bech32m.encode(hrp, [1, ...bech32m.toWords(xOnlyPublicKey)]);
}

const BLECH32M_GENERATORS = [
	0x7d52fba40bd886n,
	0x5e8dbf1a03950cn,
	0x1c3a3c74072a18n,
	0x385d72fa0e5139n,
	0x7093e5a608865bn,
];
const BLECH32M_CONST = 0x455972a3350f7a1n;

function blech32mPolymod(values: number[]): bigint {
	let chk = 1n;
	for (let p = 0; p < values.length; ++p) {
		const top = chk >> 55n;
		chk = ((chk & 0x7fffffffffffffn) << 5n) ^ BigInt(values[p]);
		for (let i = 0; i < 5; i++) {
			if ((top >> BigInt(i)) & 1n) {
				chk ^= BLECH32M_GENERATORS[i];
			}
		}
	}
	return chk;
}

function blech32mCreateChecksum(hrp: string, data: number[]): number[] {
	const values = hrpExpand(hrp)
		.concat(data)
		.concat(Array.from({ length: 12 }, () => 0));
	const mod = blech32mPolymod(values) ^ BLECH32M_CONST;
	const ret: number[] = [];
	for (let p = 0; p < 12; ++p) {
		ret.push(Number((mod >> (5n * BigInt(11 - p))) & 31n));
	}
	return ret;
}

export function blech32mEncode(hrp: string, data: number[]): string {
	const checksum = blech32mCreateChecksum(hrp, data);
	const combined = data.concat(checksum);
	return `${hrp}1${combined.map((d) => CHARSET[d]).join("")}`;
}

export function blech32mDecode(blechString: string): {
	hrp: string;
	witnessVersion: number;
	blindingPublicKey: Uint8Array;
	witness: Uint8Array;
} | null {
	const trimmed = blechString.trim();
	// Like bech32, all-lowercase or all-uppercase only.
	if (trimmed !== trimmed.toLowerCase() && trimmed !== trimmed.toUpperCase()) return null;
	const str = trimmed.toLowerCase();
	const pos = str.lastIndexOf("1");
	if (pos < 1 || pos + 13 > str.length) return null;
	const hrp = str.substring(0, pos);
	const data: number[] = [];
	for (let i = pos + 1; i < str.length; i++) {
		const idx = CHARSET.indexOf(str[i]);
		if (idx === -1) return null;
		data.push(idx);
	}
	const hrpAndData = hrpExpand(hrp).concat(data);
	if (blech32mPolymod(hrpAndData) !== BLECH32M_CONST) return null;
	const payloadWords = data.slice(0, -12);
	const witnessVersion = payloadWords[0];
	const programBytes = bech32m.fromWordsUnsafe(payloadWords.slice(1));
	if (!programBytes || programBytes.length !== 65) return null;
	return {
		blindingPublicKey: programBytes.slice(0, 33),
		hrp,
		witness: programBytes.slice(33, 65),
		witnessVersion,
	};
}

/**
 * Encode a Taproot output with a one-time blinding public key BK_k
 * into a standard Liquid Blech32 confidential address (lq1p... for mainnet, tlq1p... for testnet,
 * el1p... for Elements regtest).
 */
export function encodeConfidentialTaprootAddress(
	xOnlyPublicKey: Uint8Array,
	blindingPublicKey: Uint8Array,
	network: SilentPaymentNetwork = "mainnet",
): string {
	validateCompressedPubKey(blindingPublicKey, "Blinding public key BK_k");
	if (xOnlyPublicKey.length !== 32) {
		throw new Error(`Taproot x-only public key must be 32 bytes, got ${xOnlyPublicKey.length}`);
	}
	const hrp = BLECH32_HRPS[network];
	const witnessProgram = new Uint8Array(blindingPublicKey.length + xOnlyPublicKey.length);
	witnessProgram.set(blindingPublicKey, 0);
	witnessProgram.set(xOnlyPublicKey, blindingPublicKey.length);
	return blech32mEncode(hrp, [1, ...bech32m.toWords(witnessProgram)]);
}

/**
 * Parse a Silent Payment address string, as a sender reads it (ELIP-352 / BIP-352):
 * - "lqsp1..." for Liquid mainnet, "tlqsp1..." for Liquid testnet and regtest
 * - version 0 ('q'): exactly 66 bytes, 33-byte B_scan || 33-byte B_spend
 * - versions 1..30: the first 66 bytes are B_scan || B_spend, the rest is ignored
 * - version 31: rejected
 * This wallet only ever encodes version 0.
 */
export function parseSilentPaymentAddress(addressStr: string): SilentPaymentAddressInfo {
	const trimmed = addressStr.trim();

	// Rejects bad checksums and mixed case; the prefix comes back lowercase.
	const decoded = bech32m.decodeUnsafe(trimmed, BECH32M_MAX_LENGTH);
	if (decoded) {
		const hrp = decoded.prefix;

		let network: SilentPaymentNetwork;
		if (hrp === HRP_LIQUID_MAINNET) {
			network = "mainnet";
		} else if (hrp === HRP_LIQUID_TESTNET) {
			network = "testnet";
		} else {
			throw new Error(
				`Invalid Silent Payment address: unrecognized HRP "${hrp}". ELIP-352 requires "${HRP_LIQUID_MAINNET}" for mainnet or "${HRP_LIQUID_TESTNET}" for testnet/regtest.`,
			);
		}

		if (decoded.words.length > 0) {
			// BIP-352 "Versions", inherited by ELIP-352: v0 carries exactly 66 bytes; v1..v30 are
			// forward compatible, so a sender reads their first 66 bytes and discards the rest;
			// v31 marks a backwards-incompatible change and fails.
			const version = decoded.words[0];
			if (version === 31) {
				throw new Error(
					"Unsupported Silent Payment address version: 31 (reserved for a backwards-incompatible change).",
				);
			}
			const payloadBytes = bech32m.fromWordsUnsafe(decoded.words.slice(1));
			const validLength =
				payloadBytes !== undefined &&
				(version === 0 ? payloadBytes.length === 66 : payloadBytes.length >= 66);
			if (payloadBytes && validLength) {
				const scanKey = payloadBytes.slice(0, 33);
				const spendKey = payloadBytes.slice(33, 66);

				validateCompressedPubKey(scanKey, "Scan public key B_scan");
				validateCompressedPubKey(spendKey, "Spend public key B_spend");

				return {
					address: trimmed.toLowerCase(),
					hrp,
					network,
					scanPublicKey: scanKey,
					spendPublicKey: spendKey,
					version,
				};
			}
		}
	}

	throw new Error(`Invalid Silent Payment address: "${addressStr}"`);
}

/**
 * Check if an address string is a valid Silent Payment address.
 */
export function isSilentPaymentAddress(addressStr: string): boolean {
	try {
		parseSilentPaymentAddress(addressStr);
		return true;
	} catch {
		return false;
	}
}
