import { describe, expect, mock, test } from "bun:test";

import { deriveSilentPaymentKeysFromSeed } from "@humid/sp-core";
import { secp256k1 } from "@noble/curves/secp256k1.js";
import { bytesToHex } from "@noble/hashes/utils.js";

import { loadLwkWasm } from "../adapters/lwk/loadLwkWasm";
import { lwk } from "../adapters/lwk/lwkWasmForTests";
import { createSilentPaymentOutput, type CreateSilentPaymentOutputParams } from "./sender";

// The extension loads LWK by fetching a wasm URL, which Bun cannot; tests use the bytes on disk.
mock.module("../adapters/lwk/loadLwkWasm", () => ({ loadLwkWasm: async () => lwk }));

// LWK builds the transaction, and its `addRecipient` refuses an address of another network.
describe("createSilentPaymentOutput with real LWK", () => {
	const recipientAddress = deriveSilentPaymentKeysFromSeed(
		new Uint8Array(32).fill(7),
		"testnet",
	).address;
	const privateKey = new Uint8Array(32).fill(3);
	const outputOn = (network: CreateSilentPaymentOutputParams["network"]) =>
		createSilentPaymentOutput({
			inputPrivkeys: [privateKey],
			inputPubkeys: [secp256k1.getPublicKey(privateKey, true)],
			inputScripts: ["0014" + bytesToHex(new Uint8Array(20))],
			k: 0,
			network,
			outpoints: [{ txid: "ab".repeat(32), vout: 0 }],
			recipientAddress,
		});

	test("pays a tlqsp address on a regtest chain", async () => {
		const lwk = await loadLwkWasm();
		const network = lwk.Network.regtestDefault();
		const asset = network.policyAsset();
		const { confidentialAddress } = outputOn("regtest");

		const address = new lwk.Address(confidentialAddress);
		expect(address.isBlinded()).toBe(true);
		expect(() => new lwk.TxBuilder(network).addRecipient(address, 1000n, asset)).not.toThrow();
		// A testnet output address is what the regtest chain used to get.
		expect(() =>
			new lwk.TxBuilder(network).addRecipient(
				new lwk.Address(outputOn("testnet").confidentialAddress),
				1000n,
				asset,
			),
		).toThrow();
	});

	test("pays a tlqsp address on Liquid Testnet", async () => {
		const lwk = await loadLwkWasm();
		const network = lwk.Network.testnet();
		const address = new lwk.Address(outputOn("testnet").confidentialAddress);
		expect(() =>
			new lwk.TxBuilder(network).addRecipient(address, 1000n, network.policyAsset()),
		).not.toThrow();
	});
});
