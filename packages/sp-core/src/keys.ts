import { secp256k1 } from "@noble/curves/secp256k1.js";
import { HDKey } from "@scure/bip32";

import { encodeSilentPaymentAddress } from "./address";
import type {
	AggregateSenderInputsResult,
	SilentPaymentKeyPair,
	SilentPaymentNetwork,
	SilentPaymentRecipientKeys,
} from "./types";

/** A key pair owning a copy of `privateKey`, so the caller can zeroize its own buffer. */
function keyPairOf(privateKey: Uint8Array): SilentPaymentKeyPair {
	const copy = Uint8Array.from(privateKey);
	return { privateKey: copy, publicKey: secp256k1.getPublicKey(copy, true) };
}

/**
 * Explicitly zeroize a sensitive memory buffer.
 */
export function zeroizeBuffer(buf: Uint8Array): void {
	buf.fill(0);
}

/**
 * Zeroize private key material contained in SilentPaymentRecipientKeys.
 */
export function zeroizeRecipientKeys(keys?: SilentPaymentRecipientKeys): void {
	if (!keys) return;
	if (keys.scanKey?.privateKey) {
		keys.scanKey.privateKey.fill(0);
	}
	if (keys.spendKey?.privateKey) {
		keys.spendKey.privateKey.fill(0);
	}
}

/**
 * Zeroize private key material contained in an AggregateSenderInputsResult.
 */
export function zeroizeAggregateSenderInputs(agg?: AggregateSenderInputsResult): void {
	if (!agg) return;
	zeroizeBuffer(agg.aBytes);
	for (const input of agg.normalizedInputs) {
		zeroizeBuffer(input.privateKey);
	}
}

const HARDENED = 0x80000000;

/**
 * Derives the private key at `path` (child indices) from a BIP-32 master node via @scure/bip32,
 * wiping every intermediate node's private data as soon as its child exists.
 */
function derivePrivateKeyAtPath(master: HDKey, path: number[]): Uint8Array {
	let node = master;
	try {
		for (const index of path) {
			const child = node.deriveChild(index);
			if (node !== master) node.wipePrivateData();
			node = child;
		}
		if (!node.privateKey) {
			throw new Error("BIP-32: derived node has no private key");
		}
		return new Uint8Array(node.privateKey);
	} finally {
		if (node !== master) node.wipePrivateData();
	}
}

/**
 * ELIP-352 key derivation paths:
 *
 * Mainnet (coin type 1776):
 *   scan_key:  m/352'/1776'/account'/1'/0
 *   spend_key: m/352'/1776'/account'/0'/0
 *
 * Testnet/Regtest (coin type 1):
 *   scan_key:  m/352'/1'/account'/1'/0
 *   spend_key: m/352'/1'/account'/0'/0
 *
 * This keeps Liquid SP keys disjoint from Bitcoin SP keys (m/352'/0'/...).
 */
export function deriveSilentPaymentKeysFromSeed(
	seed: Uint8Array,
	network: SilentPaymentNetwork = "mainnet",
	account = 0,
): SilentPaymentRecipientKeys & { address: string } {
	const coinType = network === "mainnet" ? 1776 : 1;
	const accountPath = [352 + HARDENED, coinType + HARDENED, account + HARDENED];

	const master = HDKey.fromMasterSeed(seed);
	let scanKeyBytes: Uint8Array | undefined;
	let spendKeyBytes: Uint8Array | undefined;
	try {
		// scan_key: m/352'/coinType'/account'/1'/0
		scanKeyBytes = derivePrivateKeyAtPath(master, [...accountPath, 1 + HARDENED, 0]);
		// spend_key: m/352'/coinType'/account'/0'/0
		spendKeyBytes = derivePrivateKeyAtPath(master, [...accountPath, 0 + HARDENED, 0]);

		const scanKey = keyPairOf(scanKeyBytes);
		const spendKey = keyPairOf(spendKeyBytes);
		const address = encodeSilentPaymentAddress(scanKey.publicKey, spendKey.publicKey, network);

		return { address, scanKey, spendKey };
	} finally {
		scanKeyBytes?.fill(0);
		spendKeyBytes?.fill(0);
		master.wipePrivateData();
	}
}
