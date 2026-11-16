import { afterAll, afterEach, beforeEach, describe, expect, it } from "bun:test";

import { deriveLabeledSilentPaymentAddress } from "@humid/sp-core";
import { secp256k1 } from "@noble/curves/secp256k1.js";

import { createLiquidChainRecord } from "../chains/createBuiltInLiquidChains";
import { LIQUID_TESTNET_CHAIN_ID } from "../domain/LiquidChain";
import {
	createSilentPaymentLabel,
	getSilentPaymentLabels,
	MAX_SILENT_PAYMENT_LABELS,
	renameSilentPaymentLabel,
	setSpStoreVaultForTesting,
	updateSilentPaymentLabels,
} from "./index";
import { useMemorySpStore } from "./storeTestStorage";
import type { SilentPaymentRecipientKeys } from "./types";

function keyPair(last: number) {
	const privateKey = new Uint8Array(32);
	privateKey[31] = last;
	return { privateKey, publicKey: secp256k1.getPublicKey(privateKey, true) };
}

const keys: SilentPaymentRecipientKeys = { scanKey: keyPair(0x11), spendKey: keyPair(0x22) };
const address = "tlqsp1mockaddress";
const chain = createLiquidChainRecord({ id: LIQUID_TESTNET_CHAIN_ID, name: "Liquid Testnet" });

const create = (name: string) =>
	createSilentPaymentLabel({ chain, name, recipientKeys: keys, silentPaymentAddress: address });

const storedLabels = () => getSilentPaymentLabels(chain.id, address);

describe("Silent Payment labels", () => {
	const realFetch = globalThis.fetch;
	let requests = 0;

	beforeEach(() => {
		useMemorySpStore();
		requests = 0;
		globalThis.fetch = (async () => {
			requests++;
			return new Response("unexpected", { status: 500 });
		}) as unknown as typeof fetch;
	});

	afterEach(() => {
		globalThis.fetch = realFetch;
	});

	afterAll(() => {
		setSpStoreVaultForTesting(null);
	});

	it("stores the next label after the highest one, without any request", async () => {
		await updateSilentPaymentLabels(chain.id, address, () => [
			{ address: "tlqsp1three", createdAt: 1, index: 3, name: "Shop" },
		]);

		const label = await create("  Donations  ");

		expect(label.index).toBe(4);
		expect(label.name).toBe("Donations");
		expect(label.address).toBe(deriveLabeledSilentPaymentAddress(keys, 4, "testnet").address);
		expect((await storedLabels()).map((l) => [l.index, l.name])).toEqual([
			[3, "Shop"],
			[4, "Donations"],
		]);
		expect(requests).toBe(0);
	});

	it("starts at label 1: label 0 is change", async () => {
		expect((await create("Donations")).index).toBe(1);
	});

	it("refuses an empty or overlong name", async () => {
		await expect(create("   ")).rejects.toThrow("cannot be empty");
		await expect(create("x".repeat(41))).rejects.toThrow("longer than 40");
		expect(await storedLabels()).toEqual([]);
	});

	it(`refuses a label past the limit of ${MAX_SILENT_PAYMENT_LABELS}`, async () => {
		await updateSilentPaymentLabels(chain.id, address, () =>
			Array.from({ length: MAX_SILENT_PAYMENT_LABELS }, (_, i) => ({
				address: `tlqsp1label${i + 1}`,
				createdAt: 1,
				index: i + 1,
				name: `Label ${i + 1}`,
			})),
		);

		await expect(create("One too many")).rejects.toThrow(
			`at most ${MAX_SILENT_PAYMENT_LABELS} labels`,
		);
		expect(await storedLabels()).toHaveLength(MAX_SILENT_PAYMENT_LABELS);
	});

	it("renames a label", async () => {
		await create("Donations");

		const renamed = await renameSilentPaymentLabel({
			chainId: chain.id,
			index: 1,
			name: "Tips",
			silentPaymentAddress: address,
		});

		expect(renamed.name).toBe("Tips");
		expect((await storedLabels())[0]!.name).toBe("Tips");
		await expect(
			renameSilentPaymentLabel({
				chainId: chain.id,
				index: 9,
				name: "Nope",
				silentPaymentAddress: address,
			}),
		).rejects.toThrow("Unknown label 9");
	});

	it("keeps each account's labels apart", async () => {
		await create("Donations");

		expect(await getSilentPaymentLabels(chain.id, "tlqsp1otheraccount")).toEqual([]);
		expect(await getSilentPaymentLabels("bip122:otherchain", address)).toEqual([]);
	});
});
