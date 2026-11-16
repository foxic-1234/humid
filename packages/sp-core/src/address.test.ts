import { describe, expect, it } from "bun:test";

import { secp256k1 } from "@noble/curves/secp256k1.js";
import { bytesToHex } from "@noble/hashes/utils.js";
import { bech32m } from "@scure/base";

import {
	encodeConfidentialTaprootAddress,
	encodeSilentPaymentAddress,
	encodeTaprootAddress,
	HRP_LIQUID_MAINNET,
	HRP_LIQUID_TESTNET,
	isSilentPaymentAddress,
	parseSilentPaymentAddress,
} from "./address";

describe("@humid/sp-core: ELIP-352 Address Parsing and Validation", () => {
	// Canonical ELIP-352 test vector keys (from mainnetAddress)
	const B_scan_hex = "034f355bdcb7cc0af728ef3cceb9615d90684bb5b2ca5f859ab0f0b704075871aa";
	const B_spend_hex = "02466d7fcae563e5cb09a0d1870bb580344804617879a14949cf22285f1bae3f27";
	const mainnetAddress =
		"lqsp1qqd8n2k7uklxq4aegau7vawtptkgxsja4kt99lpv6krctwpq8tpc65qjxd4lu4etruh9sngx3su9mtqp5fqzxz7re59y5nnez9p03ht3lyudcfhfe";

	const testnetAddress =
		"tlqsp1qqvc5jg0y3w4sxdy7yedqmecfcgdplyx7acattladk6g3853k3cn0wqazpyrr39wz9k40jwgha0yqfuwv25hcr20hxyv0alkmk2d7yfgsmcvxauwz";

	// Derive bech32m decoded words to create test addresses
	const decodedMainnet = { data: bech32m.decode(mainnetAddress, 1023).words };
	const bech32mEncode = (hrp: string, words: number[]) => bech32m.encode(hrp, words, 1023);
	const btcMainnetSp = bech32mEncode("sp", decodedMainnet.data);
	const btcTestnetSp = bech32mEncode("tsp", decodedMainnet.data);
	const legacyLsp = bech32mEncode("lsp", decodedMainnet.data);
	const legacyTlsp = bech32mEncode("tlsp", decodedMainnet.data);
	const legacyElsp = bech32mEncode("elsp", decodedMainnet.data);
	const rawHex = B_scan_hex + B_spend_hex;

	describe("Standard ELIP-352 mode (strict ELIP-352)", () => {
		it("parses valid ELIP-352 mainnet address (lqsp1q...)", () => {
			const parsed = parseSilentPaymentAddress(mainnetAddress);
			expect(parsed.network).toBe("mainnet");
			expect(parsed.hrp).toBe(HRP_LIQUID_MAINNET);
			expect(parsed.version).toBe(0);
			expect(bytesToHex(parsed.scanPublicKey)).toBe(B_scan_hex);
			expect(bytesToHex(parsed.spendPublicKey)).toBe(B_spend_hex);
			expect(isSilentPaymentAddress(mainnetAddress)).toBe(true);
		});

		it("parses valid ELIP-352 testnet address (tlqsp1q...)", () => {
			const parsed = parseSilentPaymentAddress(testnetAddress);
			expect(parsed.network).toBe("testnet");
			expect(parsed.hrp).toBe(HRP_LIQUID_TESTNET);
			expect(parsed.version).toBe(0);
			expect(isSilentPaymentAddress(testnetAddress)).toBe(true);
		});

		it("roundtrips encode and parse for mainnet and testnet", () => {
			const parsed = parseSilentPaymentAddress(mainnetAddress);
			const encodedMain = encodeSilentPaymentAddress(
				parsed.scanPublicKey,
				parsed.spendPublicKey,
				"mainnet",
			);
			expect(encodedMain).toBe(mainnetAddress);

			const encodedTest = encodeSilentPaymentAddress(
				parsed.scanPublicKey,
				parsed.spendPublicKey,
				"testnet",
			);
			const parsedTest = parseSilentPaymentAddress(encodedTest);
			expect(parsedTest.network).toBe("testnet");
			expect(parsedTest.hrp).toBe(HRP_LIQUID_TESTNET);
			expect(parsedTest.version).toBe(0);
		});

		it("rejects Bitcoin mainnet SP address (sp1...)", () => {
			expect(() => parseSilentPaymentAddress(btcMainnetSp)).toThrow(/unrecognized HRP "sp"/);
			expect(isSilentPaymentAddress(btcMainnetSp)).toBe(false);
		});

		it("rejects Bitcoin testnet SP address (tsp1...)", () => {
			expect(() => parseSilentPaymentAddress(btcTestnetSp)).toThrow(/unrecognized HRP "tsp"/);
			expect(isSilentPaymentAddress(btcTestnetSp)).toBe(false);
		});

		it("rejects legacy lsp address format", () => {
			expect(() => parseSilentPaymentAddress(legacyLsp)).toThrow(/unrecognized HRP "lsp"/);
			expect(isSilentPaymentAddress(legacyLsp)).toBe(false);
		});

		it("rejects legacy tlsp address format", () => {
			expect(() => parseSilentPaymentAddress(legacyTlsp)).toThrow(/unrecognized HRP "tlsp"/);
			expect(isSilentPaymentAddress(legacyTlsp)).toBe(false);
		});

		it("rejects legacy elsp address format", () => {
			expect(() => parseSilentPaymentAddress(legacyElsp)).toThrow(/unrecognized HRP "elsp"/);
			expect(isSilentPaymentAddress(legacyElsp)).toBe(false);
		});

		it("rejects raw 132-char hex string", () => {
			expect(() => parseSilentPaymentAddress(rawHex)).toThrow(/Invalid Silent Payment address/);
			expect(isSilentPaymentAddress(rawHex)).toBe(false);
		});

		it("rejects JSON representation", () => {
			const json = JSON.stringify({
				scanPublicKey: B_scan_hex,
				spendPublicKey: B_spend_hex,
			});
			expect(() => parseSilentPaymentAddress(json)).toThrow(/Invalid Silent Payment address/);
			expect(isSilentPaymentAddress(json)).toBe(false);
		});

		it("accepts an all-uppercase address but rejects mixed case (BIP-173)", () => {
			expect(parseSilentPaymentAddress(mainnetAddress.toUpperCase()).address).toBe(mainnetAddress);
			const mixed = mainnetAddress.slice(0, 10) + mainnetAddress.slice(10).toUpperCase();
			expect(isSilentPaymentAddress(mixed)).toBe(false);
		});

		describe("address versions (BIP-352)", () => {
			const payload = bech32m.fromWords(decodedMainnet.data.slice(1));
			const withVersion = (version: number, bytes: Uint8Array) =>
				bech32mEncode(HRP_LIQUID_MAINNET, [version, ...bech32m.toWords(bytes)]);
			const extended = new Uint8Array([...payload, ...new Uint8Array(30).fill(0xab)]);

			it("v1..v30: reads the first 66 bytes and ignores the rest", () => {
				for (const version of [1, 2, 30]) {
					for (const bytes of [payload, extended]) {
						const parsed = parseSilentPaymentAddress(withVersion(version, bytes));
						expect(parsed.version).toBe(version);
						expect(bytesToHex(parsed.scanPublicKey)).toBe(B_scan_hex);
						expect(bytesToHex(parsed.spendPublicKey)).toBe(B_spend_hex);
					}
				}
			});

			it("v0: requires exactly 66 bytes", () => {
				expect(isSilentPaymentAddress(withVersion(0, extended))).toBe(false);
			});

			it("rejects fewer than 66 bytes in any version", () => {
				expect(isSilentPaymentAddress(withVersion(1, payload.slice(0, 65)))).toBe(false);
			});

			it("v31: fails", () => {
				expect(() => parseSilentPaymentAddress(withVersion(31, payload))).toThrow(
					/Unsupported Silent Payment address version: 31/,
				);
				expect(isSilentPaymentAddress(withVersion(31, extended))).toBe(false);
			});
		});

		it("rejects invalid Bech32m checksum", () => {
			const corrupted = mainnetAddress.slice(0, -1) + "x";
			expect(() => parseSilentPaymentAddress(corrupted)).toThrow(/Invalid Silent Payment address/);
			expect(isSilentPaymentAddress(corrupted)).toBe(false);
		});
	});
});

describe("@humid/sp-core: Taproot output addresses per network", () => {
	const xOnly = new Uint8Array(32).fill(1);
	const blindingKey = secp256k1.Point.BASE.toRawBytes(true);

	it("uses each network's own HRPs: an SP address is tlqsp on testnet and regtest alike", () => {
		expect(encodeTaprootAddress(xOnly, "mainnet").startsWith("ex1p")).toBe(true);
		expect(encodeTaprootAddress(xOnly, "testnet").startsWith("tex1p")).toBe(true);
		expect(encodeTaprootAddress(xOnly, "regtest").startsWith("ert1p")).toBe(true);

		expect(encodeConfidentialTaprootAddress(xOnly, blindingKey, "mainnet").startsWith("lq1p")).toBe(
			true,
		);
		expect(
			encodeConfidentialTaprootAddress(xOnly, blindingKey, "testnet").startsWith("tlq1p"),
		).toBe(true);
		expect(encodeConfidentialTaprootAddress(xOnly, blindingKey, "regtest").startsWith("el1p")).toBe(
			true,
		);
	});

	it("keeps the witness program whatever the network", () => {
		const decoded = bech32m.decode(encodeTaprootAddress(xOnly, "regtest") as `${string}1${string}`);
		expect(decoded.words[0]).toBe(1);
		expect(bytesToHex(bech32m.fromWords(decoded.words.slice(1)))).toBe(bytesToHex(xOnly));
	});
});
