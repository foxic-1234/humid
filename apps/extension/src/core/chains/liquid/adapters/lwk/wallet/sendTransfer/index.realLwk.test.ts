import { describe, expect, mock, test } from "bun:test";
import fs from "fs";

import { HDKey } from "@scure/bip32";
import { mnemonicToSeedSync } from "@scure/bip39";

import { lwk } from "../../lwkWasmForTests";

// The extension loads LWK by fetching a wasm URL, which Bun cannot; tests use the bytes on disk.
mock.module("../../loadLwkWasm", () => ({ loadLwkWasm: async () => lwk }));

(globalThis as any).chrome = { runtime: { id: "test-runtime" } };
(globalThis as any).browser = (globalThis as any).chrome;

mock.module("webextension-polyfill", () => ({
	default: { runtime: { id: "test-runtime" } },
}));

// "Broadcast" extracts the real transaction so later sends can fetch it back as a funding tx.
let lastBroadcastedPsetBase64: string | null = null;
let lastBroadcastedTxid: string | null = null;
const broadcastedTxHex = new Map<string, string>();
mock.module("../../sync-worker/createSyncWorkerClient", () => ({
	getSyncWorkerClient: () => ({
		broadcast: async ({ psetBase64 }: { psetBase64: string }) => {
			const { loadLwkWasm } = await import("../../loadLwkWasm");
			const lwk = await loadLwkWasm();
			const tx = new lwk.Pset(psetBase64).extractTx();
			const txid = tx.txid().toString();
			broadcastedTxHex.set(txid, tx.toString());
			lastBroadcastedPsetBase64 = psetBase64;
			lastBroadcastedTxid = txid;
			return { txid };
		},
	}),
}));

// Mocked Esplora: serves previously "broadcast" transactions as funding transactions.
const realFetch = globalThis.fetch;
globalThis.fetch = (async (input: RequestInfo | URL, init?: RequestInit) => {
	const url = typeof input === "string" ? input : input instanceof URL ? input.href : input.url;
	const match = /\/tx\/([0-9a-f]{64})\/hex$/.exec(url);
	if (match) {
		const hex = broadcastedTxHex.get(match[1]);
		return hex ? new Response(hex) : new Response("not found", { status: 404 });
	}
	return realFetch(input, init);
}) as typeof fetch;

describe("Real LWK integration: TxBuilder dynamic change sizing and anti-fingerprinting", () => {
	async function setupRealLwkWallet() {
		const { loadLwkWasm } = await import("../../loadLwkWasm");
		const { deriveSilentPaymentKeysFromSeed } = await import("@humid/sp-core");

		const lwk = await loadLwkWasm();
		const descriptorString = fs
			.readFileSync("./lwk/lwk_wasm/test_data/update_with_mnemonic/descriptor.txt", "utf8")
			.trim();
		const mnemonicString = fs
			.readFileSync("./lwk/lwk_wasm/test_data/update_with_mnemonic/mnemonic.txt", "utf8")
			.trim();
		const encryptedUpdate = fs
			.readFileSync(
				"./lwk/lwk_wasm/test_data/update_with_mnemonic/update_serialized_encrypted.txt",
				"utf8",
			)
			.trim();

		const network = lwk.Network.testnet();
		const descriptor = new lwk.WolletDescriptor(descriptorString);
		const update = lwk.Update.deserializeDecryptedBase64(encryptedUpdate, descriptor);
		const wollet = new lwk.Wollet(network, descriptor);
		wollet.applyUpdate(update);

		const mnemonic = new lwk.Mnemonic(mnemonicString);
		const signer = new lwk.Signer(mnemonic, network);

		const seed = mnemonicToSeedSync(mnemonicString);
		const masterHD = HDKey.fromMasterSeed(seed);
		const accountHD = masterHD.derive("m/84'/1'/0'");

		function deriveInputKey(isInternal: boolean, wildcardIndex: number) {
			const branch = isInternal ? 1 : 0;
			const child = accountHD.deriveChild(branch).deriveChild(wildcardIndex);
			return { privateKey: child.privateKey!, publicKey: child.publicKey! };
		}

		const spKeys = deriveSilentPaymentKeysFromSeed(seed, "testnet", 0);
		const POLICY = network.policyAsset().toString();

		const account: any = {
			accountIdentifier: "testnet_real_lwk_acct",
			chain: {
				id: "bip122:liquid-testnet",
				settings: { explorerUrl: "https://explorer.mock", network: "testnet" },
			},
			chainId: "bip122:liquid-testnet",
			policyAssetId: `bip122:liquid-testnet/asset:${POLICY}`,
			rawPolicyAssetId: POLICY,
			silentPaymentAddress: spKeys.address,
			silentPaymentKeys: spKeys,
			implementation: {
				deriveInputKey,
				network,
				signer,
				wollet,
			},
		};

		return { account, lwk, network, POLICY, spKeys };
	}

	test("partial send to Silent Payment address dynamically sizes P2TR change output and avoids Wollet P2WPKH change", async () => {
		const { sendTransfer } = await import("./index");
		const { getUnspentSilentPaymentUtxos } = await import("../../../../silent-payments");
		const { account, lwk, POLICY } = await setupRealLwkWallet();
		(await import("../../../../silent-payments/storeTestStorage")).useMemorySpStore();
		lastBroadcastedPsetBase64 = null;

		// Distinct test recipient SP address
		const recipientSpAddress =
			"tlqsp1qqvc5jg0y3w4sxdy7yedqmecfcgdplyx7acattladk6g3853k3cn0wqazpyrr39wz9k40jwgha0yqfuwv25hcr20hxyv0alkmk2d7yfgsmcvxauwz";

		const result = await sendTransfer(
			account,
			{
				amount: "50000",
				recipientAddress: recipientSpAddress,
			},
			POLICY,
		);

		expect(result.txid).toBe(lastBroadcastedTxid!);
		expect(lastBroadcastedPsetBase64).toBeTruthy();

		const pset = new lwk.Pset(lastBroadcastedPsetBase64!);
		const outputs = pset.outputs();

		// Exactly 3 outputs: recipient (P2TR), change (P2TR), fee
		expect(outputs.length).toBe(3);

		const out0Spk = outputs[0].scriptPubkey().toString();
		const out1Spk = outputs[1].scriptPubkey().toString();
		const out2Spk = outputs[2].scriptPubkey().toString();

		// Output 0: Recipient Taproot output (5120...)
		expect(out0Spk.startsWith("5120")).toBe(true);
		expect(outputs[0].amount?.()).toBe(50000n);

		// Output 1: Change Taproot output (5120...) - NO P2WPKH (anti-fingerprinting verified)
		expect(out1Spk.startsWith("5120")).toBe(true);
		expect(out1Spk.startsWith("0014")).toBe(false);

		// Output 2: Fee output (empty scriptPubkey)
		expect(out2Spk).toBe("");
		const feeAmount = outputs[2].amount?.();
		expect(feeAmount).toBeGreaterThan(0n);

		// Dynamic change sizing check: 100,000 sats input = 50,000 recipient + change + fee
		const changeAmount = outputs[1].amount?.();
		expect(changeAmount).toBe(100000n - 50000n - feeAmount!);

		// Verify change UTXO was saved to tracker with authoritative output index and amount
		const tracked = await getUnspentSilentPaymentUtxos(
			"bip122:liquid-testnet",
			account.silentPaymentAddress!,
		);
		expect(tracked.length).toBe(1);
		expect(tracked[0].txid).toBe(result.txid);
		expect(tracked[0].outputIndex).toBe(1);
		expect(tracked[0].amountSats).toBe(changeAmount!.toString());
		expect(tracked[0].scriptPubKeyHex).toBe(out1Spk);
	}, 25000);

	test("sendAll (drain) to Silent Payment address constructs exact 2 outputs (P2TR drain + fee)", async () => {
		const { sendTransfer } = await import("./index");
		const { account, lwk, POLICY } = await setupRealLwkWallet();
		(await import("../../../../silent-payments/storeTestStorage")).useMemorySpStore();
		lastBroadcastedPsetBase64 = null;

		const recipientSpAddress =
			"tlqsp1qqvc5jg0y3w4sxdy7yedqmecfcgdplyx7acattladk6g3853k3cn0wqazpyrr39wz9k40jwgha0yqfuwv25hcr20hxyv0alkmk2d7yfgsmcvxauwz";

		const result = await sendTransfer(
			account,
			{
				amount: "0",
				recipientAddress: recipientSpAddress,
				sendAll: true,
			},
			POLICY,
		);

		expect(result.txid).toBe(lastBroadcastedTxid!);
		expect(lastBroadcastedPsetBase64).toBeTruthy();

		const pset = new lwk.Pset(lastBroadcastedPsetBase64!);
		const outputs = pset.outputs();

		// Exactly 2 outputs: recipient drain + fee
		expect(outputs.length).toBe(2);

		const out0Spk = outputs[0].scriptPubkey().toString();
		const out1Spk = outputs[1].scriptPubkey().toString();

		expect(out0Spk.startsWith("5120")).toBe(true);
		expect(out1Spk).toBe(""); // fee output

		const feeAmount = outputs[1].amount?.();
		expect(feeAmount).toBeGreaterThan(0n);
		expect(outputs[0].amount?.()).toBe(100000n - feeAmount!);
	}, 25000);

	test("rejects transaction producing a change output below dust limit (600 sats)", async () => {
		const { sendTransfer } = await import("./index");
		const { account, POLICY } = await setupRealLwkWallet();
		lastBroadcastedPsetBase64 = null;

		const recipientSpAddress =
			"tlqsp1qqvc5jg0y3w4sxdy7yedqmecfcgdplyx7acattladk6g3853k3cn0wqazpyrr39wz9k40jwgha0yqfuwv25hcr20hxyv0alkmk2d7yfgsmcvxauwz";

		// 100,000 sats UTXO. If sending 99,500 sats with ~30 sats fee, change is ~470 sats (< 600 dust limit)
		await expect(
			sendTransfer(
				account,
				{
					amount: "99500",
					recipientAddress: recipientSpAddress,
				},
				POLICY,
			),
		).rejects.toThrow("Liquid dust limit");

		// Broadcast was not triggered
		expect(lastBroadcastedPsetBase64).toBeNull();
	}, 25000);

	test("spends the SP change output of a previous send: real ExternalUtxo + verified Taproot key-path signature", async () => {
		const { sendTransfer } = await import("./index");
		const { getTrackedSilentPaymentUtxos } = await import("../../../../silent-payments");
		const { parseRawElementsTransaction } = await import("@humid/sp-core");
		const { account, POLICY } = await setupRealLwkWallet();
		(await import("../../../../silent-payments/storeTestStorage")).useMemorySpStore();
		broadcastedTxHex.clear();

		const recipientSpAddress =
			"tlqsp1qqvc5jg0y3w4sxdy7yedqmecfcgdplyx7acattladk6g3853k3cn0wqazpyrr39wz9k40jwgha0yqfuwv25hcr20hxyv0alkmk2d7yfgsmcvxauwz";

		// 1. A partial send to an SP address leaves confidential P2TR change on our label m = 0.
		const first = await sendTransfer(
			account,
			{ amount: "50000", recipientAddress: recipientSpAddress },
			POLICY,
		);
		const [change] = await getTrackedSilentPaymentUtxos();
		expect(change.txid).toBe(first.txid);
		expect(change.labelIndex).toBe(0);
		expect(change.labelTweakHex).toBeDefined();
		expect(change.blindingKeyHex).toBeDefined();

		// 2. Spend more than the wallet UTXO holds (the in-memory Wollet still lists its 100,000 sat
		// UTXO), forcing a mixed spend of the P2WPKH wallet input and the SP change input.
		const ownAddress = account.implementation.wollet.address(0).address().toString();
		const second = await sendTransfer(
			account,
			{ amount: "120000", recipientAddress: ownAddress },
			POLICY,
		);
		expect(second.txid).not.toBe(first.txid);

		// 3. The change input carries a single 64-byte BIP-340 signature. signTaprootKeypath only
		// writes it after verifying it against the output key over the sighash of the real prevout.
		const spentTx = parseRawElementsTransaction(broadcastedTxHex.get(second.txid)!);
		const changeInput = spentTx.vin.find(
			(vin) => vin.txid === change.txid && vin.vout === change.outputIndex,
		);
		expect(changeInput).toBeDefined();
		expect(changeInput!.witness?.length).toBe(1);
		const witnessItem = changeInput!.witness![0];
		const sigHex =
			typeof witnessItem === "string" ? witnessItem : Buffer.from(witnessItem).toString("hex");
		expect(sigHex.length).toBe(128);
		expect(spentTx.vin.length).toBe(2);

		const tracked = await getTrackedSilentPaymentUtxos();
		expect(tracked.find((u) => u.txid === change.txid)?.spent).toBe(true);
	}, 45000);

	test("spends SP UTXOs alone when the wallet has no UTXO of its own", async () => {
		const { sendTransfer } = await import("./index");
		const { getTrackedSilentPaymentUtxos } = await import("../../../../silent-payments");
		const { parseRawElementsTransaction } = await import("@humid/sp-core");
		const { account, lwk, network, POLICY } = await setupRealLwkWallet();
		(await import("../../../../silent-payments/storeTestStorage")).useMemorySpStore();
		broadcastedTxHex.clear();

		const recipientSpAddress =
			"tlqsp1qqvc5jg0y3w4sxdy7yedqmecfcgdplyx7acattladk6g3853k3cn0wqazpyrr39wz9k40jwgha0yqfuwv25hcr20hxyv0alkmk2d7yfgsmcvxauwz";
		await sendTransfer(account, { amount: "50000", recipientAddress: recipientSpAddress }, POLICY);
		const [change] = await getTrackedSilentPaymentUtxos();

		// The same keys with a Wollet that has seen no transaction: the SP change is all it owns.
		const emptyWallet = {
			...account,
			implementation: {
				...account.implementation,
				wollet: new lwk.Wollet(network, account.implementation.wollet.descriptor()),
			},
		};
		const ownAddress = emptyWallet.implementation.wollet.address(0).address().toString();
		const second = await sendTransfer(
			emptyWallet,
			{ amount: "10000", recipientAddress: ownAddress },
			POLICY,
		);

		const spentTx = parseRawElementsTransaction(broadcastedTxHex.get(second.txid)!);
		expect(spentTx.vin).toHaveLength(1);
		expect(spentTx.vin[0].txid).toBe(change.txid);
		expect(spentTx.vin[0].witness).toHaveLength(1);
		const tracked = await getTrackedSilentPaymentUtxos();
		expect(tracked.find((u) => u.txid === change.txid)?.spent).toBe(true);
	}, 45000);

	test("leaves SP UTXOs unspent when the wallet can pay alone", async () => {
		const { sendTransfer } = await import("./index");
		const { getTrackedSilentPaymentUtxos } = await import("../../../../silent-payments");
		const { parseRawElementsTransaction } = await import("@humid/sp-core");
		const { account, POLICY } = await setupRealLwkWallet();
		(await import("../../../../silent-payments/storeTestStorage")).useMemorySpStore();
		broadcastedTxHex.clear();

		const recipientSpAddress =
			"tlqsp1qqvc5jg0y3w4sxdy7yedqmecfcgdplyx7acattladk6g3853k3cn0wqazpyrr39wz9k40jwgha0yqfuwv25hcr20hxyv0alkmk2d7yfgsmcvxauwz";
		await sendTransfer(account, { amount: "50000", recipientAddress: recipientSpAddress }, POLICY);
		const [change] = await getTrackedSilentPaymentUtxos();

		// The in-memory Wollet still lists its 100,000 sat UTXO, which covers 10,000 on its own.
		const ownAddress = account.implementation.wollet.address(0).address().toString();
		const second = await sendTransfer(
			account,
			{ amount: "10000", recipientAddress: ownAddress },
			POLICY,
		);

		const spentTx = parseRawElementsTransaction(broadcastedTxHex.get(second.txid)!);
		expect(spentTx.vin).toHaveLength(1);
		expect(spentTx.vin[0].txid).not.toBe(change.txid);
		const tracked = await getTrackedSilentPaymentUtxos();
		expect(tracked.find((u) => u.txid === change.txid)?.spent).toBe(false);
	}, 45000);

	test("refuses to spend an SP UTXO whose tracked amount disagrees with the unblinded funding output", async () => {
		const { sendTransfer } = await import("./index");
		const { getTrackedSilentPaymentUtxos, saveTrackedSilentPaymentUtxo } =
			await import("../../../../silent-payments");
		const { account, POLICY } = await setupRealLwkWallet();
		(await import("../../../../silent-payments/storeTestStorage")).useMemorySpStore();
		broadcastedTxHex.clear();

		const recipientSpAddress =
			"tlqsp1qqvc5jg0y3w4sxdy7yedqmecfcgdplyx7acattladk6g3853k3cn0wqazpyrr39wz9k40jwgha0yqfuwv25hcr20hxyv0alkmk2d7yfgsmcvxauwz";
		await sendTransfer(account, { amount: "50000", recipientAddress: recipientSpAddress }, POLICY);
		const [change] = await getTrackedSilentPaymentUtxos();
		await saveTrackedSilentPaymentUtxo({
			...change,
			amountSats: (BigInt(change.amountSats) + 1n).toString(),
		});

		const ownAddress = account.implementation.wollet.address(0).address().toString();
		await expect(
			sendTransfer(account, { amount: "120000", recipientAddress: ownAddress }, POLICY),
		).rejects.toThrow("does not match the tracked record");
	}, 45000);
});
