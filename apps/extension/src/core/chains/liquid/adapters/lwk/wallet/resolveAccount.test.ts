import { beforeAll, describe, expect, mock, test } from "bun:test";

import { deriveSilentPaymentKeysFromSeed } from "@humid/sp-core";
import { ripemd160 } from "@noble/hashes/ripemd160";
import { sha256 } from "@noble/hashes/sha256";
import { bytesToHex } from "@noble/hashes/utils";
import { mnemonicToSeedSync } from "@scure/bip39";

import type { KeyManagerState } from "@/core/key-manager/types";

import type { LiquidChainRecord } from "../../../chains/LiquidChainRecord";
import { LIQUID_MAINNET_CHAIN_ID, LIQUID_TESTNET_CHAIN_ID } from "../../../domain/LiquidChain";
import { loadLwkWasm } from "../loadLwkWasm";
import { lwk } from "../lwkWasmForTests";
import { createLwkLiquidAccount, descriptorKeyOrigin } from "./resolveAccount";

// The extension loads LWK by fetching a wasm URL, which Bun cannot; tests use the bytes on disk.
mock.module("../loadLwkWasm", () => ({ loadLwkWasm: async () => lwk }));

const TEST_MNEMONIC =
	"abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about";

function mockKeyManagerState(mnemonic: string): KeyManagerState {
	const keySourceId = "local-root-id" as any;
	return {
		accountModel: {
			keySources: {
				[keySourceId]: {
					id: keySourceId,
					kind: "local-root",
					material: { kind: "seed" },
				},
			},
		} as any,
		secretMaterials: {
			[keySourceId]: {
				id: keySourceId,
				kind: "seed",
				value: mnemonic,
			},
		} as any,
	} as unknown as KeyManagerState;
}

function mockChainRecord(chainId: string, network: "mainnet" | "testnet"): LiquidChainRecord {
	return {
		id: chainId,
		settings: {
			backend: {
				url: "https://blockstream.info/liquid/api",
			},
			network,
			policyAsset:
				network === "mainnet"
					? "6f0279e9ed041c3d710a9f57d0c02928416460c4b722ae3457a11eec381c526d"
					: "144c654344aa716d6f3abcc1ca90e5641e4e2a7f633bc09fe3baf430095e8223",
		},
	} as unknown as LiquidChainRecord;
}

function toP2wpkhScriptPubKeyHex(publicKey: Uint8Array): string {
	const hash = ripemd160(sha256(publicKey));
	return "0014" + bytesToHex(hash);
}

describe("resolveAccount key derivation", () => {
	beforeAll(async () => {
		await loadLwkWasm();
	}, 30000);

	test("deriveInputKey matches Wollet scriptPubKey on Liquid Mainnet (coin type 1776)", async () => {
		const lwk = await loadLwkWasm();
		const state = mockKeyManagerState(TEST_MNEMONIC);
		const chain = mockChainRecord(LIQUID_MAINNET_CHAIN_ID, "mainnet");

		const account = await createLwkLiquidAccount({
			accountGroupIndex: 0,
			chain,
			keyManagerState: state,
		});

		const { wollet, deriveInputKey } = account.implementation as {
			wollet: any;
			deriveInputKey: (
				isInternal: boolean,
				wildcardIndex: number,
			) => {
				privateKey: Uint8Array;
				publicKey: Uint8Array;
			};
		};

		// Test both external addresses (receive, branch 0) and internal (change, branch 1)
		for (let index = 0; index < 3; index++) {
			const addrResult = wollet.address(index);
			const addressStr = addrResult.address().toString();
			const parsedAddr = new lwk.Address(addressStr);
			const expectedScriptPubKey = parsedAddr.scriptPubkey().toString().toLowerCase();

			// External key (isInternal = false)
			const derived = deriveInputKey(false, index);
			const computedScriptPubKey = toP2wpkhScriptPubKeyHex(derived.publicKey).toLowerCase();

			expect(computedScriptPubKey).toBe(expectedScriptPubKey);
		}
	});

	test("deriveInputKey matches Wollet scriptPubKey on Liquid Testnet (coin type 1)", async () => {
		const lwk = await loadLwkWasm();
		const state = mockKeyManagerState(TEST_MNEMONIC);
		const chain = mockChainRecord(LIQUID_TESTNET_CHAIN_ID, "testnet");

		const account = await createLwkLiquidAccount({
			accountGroupIndex: 0,
			chain,
			keyManagerState: state,
		});

		const { wollet, deriveInputKey } = account.implementation as {
			wollet: any;
			deriveInputKey: (
				isInternal: boolean,
				wildcardIndex: number,
			) => {
				privateKey: Uint8Array;
				publicKey: Uint8Array;
			};
		};

		for (let index = 0; index < 3; index++) {
			const addrResult = wollet.address(index);
			const addressStr = addrResult.address().toString();
			const parsedAddr = new lwk.Address(addressStr);
			const expectedScriptPubKey = parsedAddr.scriptPubkey().toString().toLowerCase();

			const derived = deriveInputKey(false, index);
			const computedScriptPubKey = toP2wpkhScriptPubKeyHex(derived.publicKey).toLowerCase();

			expect(computedScriptPubKey).toBe(expectedScriptPubKey);
		}
	});

	test("silent payment keys derive at account 0 on child mnemonic seed (no double derivation)", async () => {
		const lwk = await loadLwkWasm();
		const state = mockKeyManagerState(TEST_MNEMONIC);
		const chainMainnet = mockChainRecord(LIQUID_MAINNET_CHAIN_ID, "mainnet");
		const chainTestnet = mockChainRecord(LIQUID_TESTNET_CHAIN_ID, "testnet");

		// Account 0 (master seed)
		const account0 = await createLwkLiquidAccount({
			accountGroupIndex: 0,
			chain: chainMainnet,
			keyManagerState: state,
		});

		const masterSeed = mnemonicToSeedSync(TEST_MNEMONIC);
		const expectedSp0 = deriveSilentPaymentKeysFromSeed(masterSeed, "mainnet", 0);
		expect(account0.silentPaymentAddress).toBe(expectedSp0.address);
		expect(bytesToHex(account0.silentPaymentKeys?.scanKey.publicKey!)).toBe(
			bytesToHex(expectedSp0.scanKey.publicKey),
		);
		expect(bytesToHex(account0.silentPaymentKeys?.spendKey.publicKey!)).toBe(
			bytesToHex(expectedSp0.spendKey.publicKey),
		);

		// Account 1 (BIP-85 child mnemonic at index 1)
		const account1 = await createLwkLiquidAccount({
			accountGroupIndex: 1,
			chain: chainMainnet,
			keyManagerState: state,
		});

		// Compute BIP-85 child mnemonic independently to simulate third-party recovery
		const masterSigner = new lwk.Signer(new lwk.Mnemonic(TEST_MNEMONIC), lwk.Network.mainnet());
		const childMnemonic1 = masterSigner.derive_bip85_mnemonic(1, 12);
		const childSeed1 = mnemonicToSeedSync(childMnemonic1.toString());

		// Standard third-party ELIP-352 wallet importing child mnemonic derives account 0:
		const expectedSp1FromChildMnemonic = deriveSilentPaymentKeysFromSeed(childSeed1, "mainnet", 0);

		// Humid account 1 MUST match the standard third-party derivation at account 0 of child mnemonic
		expect(account1.silentPaymentAddress).toBe(expectedSp1FromChildMnemonic.address);
		expect(bytesToHex(account1.silentPaymentKeys?.scanKey.publicKey!)).toBe(
			bytesToHex(expectedSp1FromChildMnemonic.scanKey.publicKey),
		);
		expect(bytesToHex(account1.silentPaymentKeys?.spendKey.publicKey!)).toBe(
			bytesToHex(expectedSp1FromChildMnemonic.spendKey.publicKey),
		);

		// Account isolation: account 0 and account 1 have distinct addresses and keys
		expect(account1.silentPaymentAddress).not.toBe(account0.silentPaymentAddress);
		expect(bytesToHex(account1.silentPaymentKeys?.scanKey.publicKey!)).not.toBe(
			bytesToHex(account0.silentPaymentKeys?.scanKey.publicKey!),
		);

		// Ensure we did NOT do double derivation (which would have derived account 1 on child seed)
		const doubleDerivedSp1 = deriveSilentPaymentKeysFromSeed(childSeed1, "mainnet", 1);
		expect(account1.silentPaymentAddress).not.toBe(doubleDerivedSp1.address);

		// Testnet test: account 1 on testnet derives at account 0 with testnet HRP
		const account1Testnet = await createLwkLiquidAccount({
			accountGroupIndex: 1,
			chain: chainTestnet,
			keyManagerState: state,
		});
		const expectedSp1Testnet = deriveSilentPaymentKeysFromSeed(childSeed1, "testnet", 0);
		expect(account1Testnet.silentPaymentAddress).toBe(expectedSp1Testnet.address);
		expect(account1Testnet.silentPaymentAddress?.startsWith("tlqsp1")).toBe(true);
	});

	test("a chain the user added for mainnet gets mainnet Silent Payment keys, whatever its id", async () => {
		const state = mockKeyManagerState(TEST_MNEMONIC);
		const expected = deriveSilentPaymentKeysFromSeed(
			mnemonicToSeedSync(TEST_MNEMONIC),
			"mainnet",
			0,
		);

		const account = await createLwkLiquidAccount({
			accountGroupIndex: 0,
			chain: mockChainRecord("bip122:0123456789abcdef0123456789abcdef", "mainnet"),
			keyManagerState: state,
		});

		// ELIP-352: m/352'/1776'/... and the `lqsp` prefix on mainnet.
		expect(account.silentPaymentAddress).toBe(expected.address);
		expect(account.silentPaymentAddress?.startsWith("lqsp1")).toBe(true);
		account.wipePrivateData?.();
	});

	test("account exposes wipePrivateData and zeroizes in-memory private keys on demand", async () => {
		await loadLwkWasm();
		const state = mockKeyManagerState(TEST_MNEMONIC);
		const chainMainnet = mockChainRecord(LIQUID_MAINNET_CHAIN_ID, "mainnet");

		const account = await createLwkLiquidAccount({
			accountGroupIndex: 0,
			chain: chainMainnet,
			keyManagerState: state,
		});

		expect(typeof account.wipePrivateData).toBe("function");
		expect(account.silentPaymentKeys).toBeDefined();

		const scanPriv = account.silentPaymentKeys!.scanKey.privateKey;
		const spendPriv = account.silentPaymentKeys!.spendKey.privateKey;

		// Prior to wipe, keys have non-zero entropy
		expect(scanPriv.some((b) => b !== 0)).toBe(true);
		expect(spendPriv.some((b) => b !== 0)).toBe(true);

		// Execute memory zeroization
		account.wipePrivateData!();

		// Memory buffers must now be completely zeroized
		expect(scanPriv.every((b) => b === 0)).toBe(true);
		expect(spendPriv.every((b) => b === 0)).toBe(true);

		// Public keys and metadata remain valid
		expect(account.silentPaymentAddress?.startsWith("lqsp1q")).toBe(true);
		expect(account.silentPaymentKeys!.scanKey.publicKey.some((b) => b !== 0)).toBe(true);
		expect(account.silentPaymentKeys!.spendKey.publicKey.some((b) => b !== 0)).toBe(true);
	});
});

describe("descriptorKeyOrigin", () => {
	test("reads the fingerprint and account path of an LWK descriptor", () => {
		const descriptor =
			"ct(slip77(b1ec7bea2eb2bb601a30988faaf573b6c6ff1675230448a368410260f0d164c4),elwpkh([5abf90c6/84'/1'/0']tpubDCizYVR8XSRjeBEhzmb1jY66pZrrR5y1jXtibzLv57y4HdqBPDzfEsDKA7cfaKJLqrU4g9Ps1ayWhTekCnde9bYENsFFugYHR7Ded9GEfEh/<0;1>/*))#0eyzu7yr";
		expect(descriptorKeyOrigin(descriptor)).toEqual({
			fingerprint: 0x5abf90c6,
			path: "m/84'/1'/0'",
		});
		expect(descriptorKeyOrigin("elwpkh([0000000a/84h/1776h/0h]xpub/<0;1>/*)").path).toBe(
			"m/84'/1776'/0'",
		);
	});

	test("rejects a descriptor without a key origin", () => {
		expect(() => descriptorKeyOrigin("elwpkh(xpub/<0;1>/*)")).toThrow("no key origin");
	});
});
