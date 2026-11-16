import { afterAll, beforeEach, describe, expect, it } from "bun:test";

import type { LiquidWalletAccount } from "../application/backends/LiquidWalletBackend";
import type { LiquidChainRecord } from "../chains/LiquidChainRecord";
import type { LiquidPortfolio } from "../contract";
import {
	augmentPortfolioWithSilentPayments,
	countHeldSilentPaymentUtxos,
	expireUnconfirmedSilentPaymentSpend,
	getSilentPaymentBirthday,
	getTrackedSilentPaymentUtxos,
	getUnspentSilentPaymentUtxos,
	isSpendableSilentPaymentUtxo,
	markSilentPaymentUtxoSpent,
	mergeActivityWithSilentPayments,
	rollBackSilentPaymentBlocks,
	saveSilentPaymentBirthday,
	saveTrackedSilentPaymentUtxo,
	setSpStoreVaultForTesting,
	SP_STORAGE_KEY,
	type TrackedSilentPaymentUtxo,
	updateSilentPaymentLabels,
} from "./index";
import { useMemorySpStore } from "./storeTestStorage";

const POLICY_ASSET = "b6f2d543a3f4ce8aa28607b1222515fa3781186079b6a5ca617801f3754aa30d";
const CHAIN_ID = "liquid-testnet";
const SP_ADDRESS = "tlqsp1testowner";

const chain = {
	id: CHAIN_ID,
	settings: { explorerUrl: "https://explorer.mock", policyAsset: POLICY_ASSET },
} as unknown as LiquidChainRecord;

const account = {
	rawPolicyAssetId: POLICY_ASSET,
	silentPaymentAddress: SP_ADDRESS,
} as unknown as LiquidWalletAccount;

function spUtxo(overrides: Partial<TrackedSilentPaymentUtxo> = {}): TrackedSilentPaymentUtxo {
	return {
		address: "tex1ptest",
		amountSats: "50000",
		blindingKeyHex: "bb".repeat(32),
		chainId: CHAIN_ID,
		confirmed: true,
		createdAt: Date.now(),
		outputIndex: 0,
		rawAssetId: POLICY_ASSET,
		recipientAddress: SP_ADDRESS,
		scriptPubKeyHex: "5120" + "11".repeat(32),
		spent: false,
		tweakHex: "22".repeat(32),
		txid: "a".repeat(64),
		...overrides,
	};
}

async function findTracked(txid: string): Promise<TrackedSilentPaymentUtxo | undefined> {
	return (await getTrackedSilentPaymentUtxos()).find((u) => u.txid === txid);
}

describe("silent-payments store & persistence", () => {
	let vaultMemory: Map<string, string>;

	beforeEach(() => {
		vaultMemory = useMemorySpStore();
	});

	afterAll(() => {
		setSpStoreVaultForTesting(null);
	});

	describe("storage", () => {
		it("persists tracked UTXOs in the secure vault", async () => {
			await saveTrackedSilentPaymentUtxo(spUtxo({ txid: "txid_vault_1" }));

			expect(vaultMemory.get(SP_STORAGE_KEY)).toContain("txid_vault_1");
			expect(await findTracked("txid_vault_1")).toBeDefined();
		});

		it("has no SP data and fails writes while the vault is unavailable", async () => {
			setSpStoreVaultForTesting(null);

			// A failed write must surface, so a scan does not advance its cursor past it.
			await expect(saveTrackedSilentPaymentUtxo(spUtxo({ txid: "txid_no_vault" }))).rejects.toThrow(
				"Secure vault is locked",
			);

			expect(await getTrackedSilentPaymentUtxos()).toEqual([]);
			expect(vaultMemory.size).toBe(0);
		});

		it("serializes concurrent writes without losing updates in read-modify-write", async () => {
			const COUNT = 10;
			await Promise.all(
				Array.from({ length: COUNT }, (_, i) =>
					saveTrackedSilentPaymentUtxo(
						spUtxo({ amountSats: `${(i + 1) * 1000}`, txid: `txid_concurrent_${i}` }),
					),
				),
			);

			for (let i = 0; i < COUNT; i++) {
				expect((await findTracked(`txid_concurrent_${i}`))?.amountSats).toBe(`${(i + 1) * 1000}`);
			}
		});
	});

	describe("updates", () => {
		it("keeps labelIndex, bk_k and createdAt when a later event omits them", async () => {
			const first = spUtxo({ confirmed: false, createdAt: 1000, labelIndex: 0 });
			await saveTrackedSilentPaymentUtxo(first);
			await saveTrackedSilentPaymentUtxo(
				spUtxo({ blindingKeyHex: undefined, confirmed: true, createdAt: 2000 }),
			);

			const updated = await findTracked(first.txid);
			expect(updated?.confirmed).toBe(true);
			expect(updated?.labelIndex).toBe(0);
			expect(updated?.blindingKeyHex).toBe("bb".repeat(32));
			expect(updated?.createdAt).toBe(1000);
		});

		it("a replayed event neither un-spends nor un-confirms a record", async () => {
			await saveTrackedSilentPaymentUtxo(spUtxo({ blockTime: 1_700_000_000 }));
			await markSilentPaymentUtxoSpent("a".repeat(64), 0, "c".repeat(64));

			await saveTrackedSilentPaymentUtxo(spUtxo({ blockTime: undefined, confirmed: false }));

			const tracked = await findTracked("a".repeat(64));
			expect(tracked?.spent).toBe(true);
			expect(tracked?.spentInTxid).toBe("c".repeat(64));
			expect(tracked?.confirmed).toBe(true);
			expect(tracked?.blockTime).toBe(1_700_000_000);
		});

		it("a rescan's successful re-verification replaces a failed unblind", async () => {
			await saveTrackedSilentPaymentUtxo(
				spUtxo({ amountSats: "0", rawAssetId: "", unblindFailed: true }),
			);
			await saveTrackedSilentPaymentUtxo(spUtxo({ amountSats: "99000", unblindFailed: false }));

			const tracked = await findTracked("a".repeat(64));
			expect(tracked?.unblindFailed).toBe(false);
			expect(tracked?.amountSats).toBe("99000");
			expect(tracked?.rawAssetId).toBe(POLICY_ASSET);
		});

		it("a rescan's failed unblind does not erase an output unblinded before", async () => {
			await saveTrackedSilentPaymentUtxo(
				spUtxo({ amountSats: "99000", valueBlindingFactorHex: "cc".repeat(32) }),
			);
			await saveTrackedSilentPaymentUtxo(
				spUtxo({
					amountSats: "0",
					rawAssetId: "",
					unblindFailed: true,
					valueBlindingFactorHex: undefined,
				}),
			);

			const tracked = await findTracked("a".repeat(64));
			expect(tracked?.unblindFailed).toBeFalsy();
			expect(tracked?.amountSats).toBe("99000");
			expect(tracked?.rawAssetId).toBe(POLICY_ASSET);
			expect(tracked?.valueBlindingFactorHex).toBe("cc".repeat(32));
		});

		it("does not write labels over a list it could not read", async () => {
			const label = { address: "tlqsp1label", createdAt: 1, index: 1, name: "Shop" };
			await updateSilentPaymentLabels(CHAIN_ID, SP_ADDRESS, () => [label]);
			const key = [...vaultMemory.keys()].find((k) => k.startsWith("sp_labels_"))!;
			const stored = vaultMemory.get(key)!;

			vaultMemory.set(key, "{not json");
			await expect(
				updateSilentPaymentLabels(CHAIN_ID, SP_ADDRESS, (labels) => [...labels, label]),
			).rejects.toThrow();
			vaultMemory.set(key, JSON.stringify({ not: "a list" }));
			await expect(
				updateSilentPaymentLabels(CHAIN_ID, SP_ADDRESS, (labels) => [...labels, label]),
			).rejects.toThrow("malformed");

			// Nothing was written in place of what could not be read.
			expect(vaultMemory.get(key)).toBe(JSON.stringify({ not: "a list" }));
			vaultMemory.set(key, stored);
		});
	});

	describe("spend and reorg bookkeeping", () => {
		it("marking one UTXO spent keeps bk_k on every other UTXO", async () => {
			await saveTrackedSilentPaymentUtxo(spUtxo({ blindingKeyHex: "33".repeat(32) }));
			await saveTrackedSilentPaymentUtxo(
				spUtxo({ blindingKeyHex: "44".repeat(32), txid: "b".repeat(64) }),
			);

			await markSilentPaymentUtxoSpent("a".repeat(64), 0, "c".repeat(64));

			const spent = await findTracked("a".repeat(64));
			const other = await findTracked("b".repeat(64));
			expect(spent?.spent).toBe(true);
			expect(spent?.spentInTxid).toBe("c".repeat(64));
			expect(spent?.blindingKeyHex).toBe("33".repeat(32));
			expect(other?.spent).toBe(false);
			expect(other?.blindingKeyHex).toBe("44".repeat(32));
		});

		it("undoes what replaced blocks recorded, without un-spending anything", async () => {
			const t = (c: string) => c.repeat(64);
			await saveTrackedSilentPaymentUtxo(
				spUtxo({ blockHeight: 100, blockTime: 1_700_000_100, createdAt: 1, txid: t("a") }),
			);
			await saveTrackedSilentPaymentUtxo(
				spUtxo({ blockHeight: 90, blockTime: 1_700_000_090, txid: t("b") }),
			);
			await markSilentPaymentUtxoSpent(t("b"), 0, t("c"), {
				blockHeight: 101,
				blockTime: 1_700_000_101,
				confirmed: true,
			});
			// Below the replaced blocks.
			await saveTrackedSilentPaymentUtxo(spUtxo({ blockHeight: 80, txid: t("d") }));
			await saveTrackedSilentPaymentUtxo(spUtxo({ blockHeight: 100, txid: t("f") }));

			const changed = await rollBackSilentPaymentBlocks(CHAIN_ID, SP_ADDRESS, 95);

			expect(changed).toBe(3);
			const funding = await findTracked(t("a"));
			expect(funding).toMatchObject({ blockTime: null, confirmed: false });
			expect(funding?.blockHeight).toBeUndefined();
			// Its expiry counts from the rollback, not from when it was first found.
			expect(funding!.createdAt).toBeGreaterThan(1);
			const spend = await findTracked(t("b"));
			expect(spend).toMatchObject({ confirmed: true, spent: true, spentBlockTime: null });
			expect(spend?.spentBlockHeight).toBeUndefined();
			expect(spend?.spentSeenAt).toBeNumber();
			expect(await findTracked(t("d"))).toMatchObject({ blockHeight: 80, confirmed: true });
			expect(await getUnspentSilentPaymentUtxos(CHAIN_ID, SP_ADDRESS)).not.toContainEqual(
				expect.objectContaining({ txid: t("b") }),
			);

			// Scanning the new block that holds the same spend confirms it again.
			await markSilentPaymentUtxoSpent(t("b"), 0, t("c"), {
				blockHeight: 102,
				blockTime: 1_700_000_102,
				confirmed: true,
			});
			expect(await findTracked(t("b"))).toMatchObject({
				spentBlockHeight: 102,
				spentBlockTime: 1_700_000_102,
			});
			expect((await findTracked(t("b")))?.spentSeenAt).toBeUndefined();
		});

		it("rolls back only the given range, and only the account's records", async () => {
			const t = (c: string) => c.repeat(64);
			await saveTrackedSilentPaymentUtxo(spUtxo({ blockHeight: 100, txid: t("a") }));
			await saveTrackedSilentPaymentUtxo(spUtxo({ blockHeight: 110, txid: t("b") }));
			await saveTrackedSilentPaymentUtxo(
				spUtxo({ blockHeight: 100, recipientAddress: "tlqsp1other", txid: t("c") }),
			);

			expect(await rollBackSilentPaymentBlocks(CHAIN_ID, SP_ADDRESS, 95, 105)).toBe(1);
			expect((await findTracked(t("a")))?.confirmed).toBe(false);
			expect((await findTracked(t("b")))?.confirmed).toBe(true);
			expect((await findTracked(t("c")))?.confirmed).toBe(true);
		});

		describe("unconfirmed spends", () => {
			const HOUR = 60 * 60 * 1000;

			it("an unconfirmed spend not confirmed in time makes the output unspent again", async () => {
				await saveTrackedSilentPaymentUtxo(spUtxo());
				await markSilentPaymentUtxoSpent("a".repeat(64), 0, "c".repeat(64), {
					blockTime: null,
					confirmed: false,
					feeSats: "20",
				});

				expect(
					await expireUnconfirmedSilentPaymentSpend("a".repeat(64), 0, Date.now() - HOUR),
				).toBe(false);
				expect(await expireUnconfirmedSilentPaymentSpend("a".repeat(64), 0, Date.now() + 1)).toBe(
					true,
				);

				const tracked = await findTracked("a".repeat(64));
				expect(tracked?.spent).toBe(false);
				expect(tracked?.spentInTxid).toBeUndefined();
				expect(tracked?.spentFeeSats).toBeUndefined();
				expect(tracked?.spentSeenAt).toBeUndefined();
				expect(await getUnspentSilentPaymentUtxos(CHAIN_ID, SP_ADDRESS)).toHaveLength(1);
			});

			it("a spend a block confirmed never expires, with or without its block time", async () => {
				await saveTrackedSilentPaymentUtxo(spUtxo());
				await saveTrackedSilentPaymentUtxo(spUtxo({ txid: "b".repeat(64) }));
				for (const txid of ["a".repeat(64), "b".repeat(64)]) {
					await markSilentPaymentUtxoSpent(txid, 0, "c".repeat(64), {
						blockTime: null,
						confirmed: false,
					});
				}

				await markSilentPaymentUtxoSpent("a".repeat(64), 0, "c".repeat(64), {
					blockTime: 1_700_000_000,
					confirmed: true,
				});
				await markSilentPaymentUtxoSpent("b".repeat(64), 0, "c".repeat(64), {
					blockTime: null,
					confirmed: true,
				});

				for (const txid of ["a".repeat(64), "b".repeat(64)]) {
					expect(await expireUnconfirmedSilentPaymentSpend(txid, 0, Date.now() + HOUR)).toBe(false);
					expect((await findTracked(txid))?.spent).toBe(true);
				}
			});

			it("a spend recorded without a confirmation state never expires", async () => {
				await saveTrackedSilentPaymentUtxo(spUtxo());
				await markSilentPaymentUtxoSpent("a".repeat(64), 0, "c".repeat(64));
				// Seen again in the mempool: it does not get a deadline it never had.
				await markSilentPaymentUtxoSpent("a".repeat(64), 0, "c".repeat(64), {
					blockTime: null,
					confirmed: false,
				});

				expect(
					await expireUnconfirmedSilentPaymentSpend("a".repeat(64), 0, Date.now() + HOUR),
				).toBe(false);
				expect((await findTracked("a".repeat(64)))?.spent).toBe(true);
			});

			it("seeing the same unconfirmed spend again keeps its first deadline", async () => {
				await saveTrackedSilentPaymentUtxo(spUtxo());
				const mark = () =>
					markSilentPaymentUtxoSpent("a".repeat(64), 0, "c".repeat(64), {
						blockTime: null,
						confirmed: false,
					});
				await mark();
				const firstSeen = (await findTracked("a".repeat(64)))?.spentSeenAt;
				await new Promise((resolve) => setTimeout(resolve, 5));
				await mark();

				expect(firstSeen).toBeNumber();
				expect((await findTracked("a".repeat(64)))?.spentSeenAt).toBe(firstSeen!);
			});
		});
	});

	describe("spendability and account scoping", () => {
		it("isSpendableSilentPaymentUtxo requires unspent, unblinded and a spending tweak", () => {
			const valid = spUtxo();
			expect(isSpendableSilentPaymentUtxo(valid)).toBe(true);
			expect(isSpendableSilentPaymentUtxo({ ...valid, spent: true })).toBe(false);
			expect(isSpendableSilentPaymentUtxo({ ...valid, unblindFailed: true })).toBe(false);
			expect(isSpendableSilentPaymentUtxo({ ...valid, tweakHex: undefined })).toBe(false);
		});

		it("isSpendableSilentPaymentUtxo filters by asset", () => {
			const valid = spUtxo();
			expect(isSpendableSilentPaymentUtxo(valid, { rawAssetId: "other" })).toBe(false);
			expect(isSpendableSilentPaymentUtxo(valid, { rawAssetId: POLICY_ASSET })).toBe(true);
			expect(
				isSpendableSilentPaymentUtxo(valid, { isNative: true, policyAssetIds: [POLICY_ASSET] }),
			).toBe(true);
			expect(
				isSpendableSilentPaymentUtxo(valid, { isNative: true, policyAssetIds: ["other"] }),
			).toBe(false);
		});

		it("getUnspentSilentPaymentUtxos skips spent and failed-unblind records", async () => {
			await saveTrackedSilentPaymentUtxo(spUtxo({ txid: "txid_ok" }));
			await saveTrackedSilentPaymentUtxo(spUtxo({ txid: "txid_failed", unblindFailed: true }));
			await saveTrackedSilentPaymentUtxo(spUtxo({ spent: true, txid: "txid_spent" }));

			const unspent = await getUnspentSilentPaymentUtxos(CHAIN_ID, SP_ADDRESS);
			expect(unspent.map((u) => u.txid)).toEqual(["txid_ok"]);
		});

		it("unspent UTXOs are scoped to the owning account's SP address", async () => {
			await saveTrackedSilentPaymentUtxo(spUtxo({ recipientAddress: "tlqsp1ownera", txid: "d" }));
			await saveTrackedSilentPaymentUtxo(spUtxo({ recipientAddress: "tlqsp1ownerb", txid: "e" }));

			const forA = await getUnspentSilentPaymentUtxos(CHAIN_ID, "TLQSP1OWNERA");
			const forB = await getUnspentSilentPaymentUtxos(CHAIN_ID, "tlqsp1ownerb");
			expect(forA.map((u) => u.txid)).toEqual(["d"]);
			expect(forB.map((u) => u.txid)).toEqual(["e"]);
		});

		it("counts the account's payments held out of the balance until their spend is checked", async () => {
			await saveTrackedSilentPaymentUtxo(spUtxo({ spendUnverified: true, txid: "held" }));
			await saveTrackedSilentPaymentUtxo(spUtxo({ txid: "checked" }));
			await saveTrackedSilentPaymentUtxo(
				spUtxo({ spendUnverified: true, txid: "failed", unblindFailed: true }),
			);
			await saveTrackedSilentPaymentUtxo(
				spUtxo({ recipientAddress: "tlqsp1other", spendUnverified: true, txid: "other" }),
			);

			expect(await countHeldSilentPaymentUtxos(CHAIN_ID, SP_ADDRESS.toUpperCase())).toBe(1);
			expect(await getUnspentSilentPaymentUtxos(CHAIN_ID, SP_ADDRESS)).not.toContainEqual(
				expect.objectContaining({ txid: "held" }),
			);
		});
	});

	describe("birthday", () => {
		it("is kept per network and per account", async () => {
			await saveSilentPaymentBirthday(CHAIN_ID, SP_ADDRESS, 1_000);

			expect(await getSilentPaymentBirthday(CHAIN_ID, SP_ADDRESS.toUpperCase())).toBe(1_000);
			expect(await getSilentPaymentBirthday("liquid-mainnet", SP_ADDRESS)).toBeNull();
			expect(await getSilentPaymentBirthday(CHAIN_ID, "tlqsp1otheraccount")).toBeNull();
		});
	});

	it("refuses to write over a stored list it cannot read", async () => {
		vaultMemory.set(SP_STORAGE_KEY, "{not json");

		await expect(saveTrackedSilentPaymentUtxo(spUtxo({ txid: "txid_new" }))).rejects.toThrow();
		await expect(markSilentPaymentUtxoSpent("txid_new", 0)).rejects.toThrow();
		expect(vaultMemory.get(SP_STORAGE_KEY)).toBe("{not json");

		vaultMemory.set(SP_STORAGE_KEY, JSON.stringify({ not: "a list" }));
		await expect(saveTrackedSilentPaymentUtxo(spUtxo({ txid: "txid_new" }))).rejects.toThrow(
			"malformed",
		);
	});

	describe("portfolio", () => {
		const emptyPortfolio: LiquidPortfolio = {
			assets: [
				{
					amountSats: "1000",
					decimals: 8,
					isNative: true,
					metadata: { isNative: true, issuerDomain: null, verified: true },
					name: "Liquid Bitcoin",
					rawAssetId: POLICY_ASSET,
					symbol: "L-BTC",
				},
			],
			utxos: [],
		};

		it("shows an issued asset received only via SP as unverified", async () => {
			// Anyone can send any asset to a public SP address.
			const unknownAsset = "ab".repeat(32);
			await saveTrackedSilentPaymentUtxo(
				spUtxo({ amountSats: "7", rawAssetId: unknownAsset, txid: "txid_token" }),
			);

			const augmented = await augmentPortfolioWithSilentPayments(emptyPortfolio, chain, SP_ADDRESS);

			const token = augmented.assets.find((a) => a.rawAssetId === unknownAsset);
			expect(token?.amountSats).toBe("7");
			expect(token?.metadata.verified).toBe(false);
		});

		it("adds unspent unblinded SP UTXOs to the balance without querying the explorer", async () => {
			const originalFetch = globalThis.fetch;
			let fetchCalls = 0;
			globalThis.fetch = (async () => {
				fetchCalls++;
				return new Response("unexpected", { status: 500 });
			}) as unknown as typeof fetch;

			try {
				await saveTrackedSilentPaymentUtxo(spUtxo({ amountSats: "50000", txid: "txid_ok" }));
				await saveTrackedSilentPaymentUtxo(spUtxo({ txid: "txid_failed", unblindFailed: true }));
				await saveTrackedSilentPaymentUtxo(spUtxo({ spent: true, txid: "txid_spent" }));

				const augmented = await augmentPortfolioWithSilentPayments(
					emptyPortfolio,
					chain,
					SP_ADDRESS,
				);

				expect(fetchCalls).toBe(0);
				expect(augmented.utxos.map((u) => u.txid)).toEqual(["txid_ok"]);
				expect(augmented.assets[0].amountSats).toBe("51000");
				// The input snapshot is not mutated.
				expect(emptyPortfolio.assets[0].amountSats).toBe("1000");
			} finally {
				globalThis.fetch = originalFetch;
			}
		});

		it("marks SP UTXOs and keeps them from the previous portfolio while the vault is locked", async () => {
			await saveTrackedSilentPaymentUtxo(spUtxo({ amountSats: "50000", txid: "txid_ok" }));
			const unlocked = await augmentPortfolioWithSilentPayments(emptyPortfolio, chain, SP_ADDRESS);
			expect(unlocked.utxos.map((u) => u.silentPayment)).toEqual([true]);

			const lwkUtxo = {
				address: "tex1qlwk",
				amountSats: "1000",
				confidential: true,
				rawAssetId: POLICY_ASSET,
				scriptPubKey: "0014" + "00".repeat(20),
				spendable: true,
				txid: "txid_lwk",
				txOut: "txid_lwk:0",
				vout: 0,
			};
			const previous = { ...unlocked, utxos: [lwkUtxo, ...unlocked.utxos] };

			setSpStoreVaultForTesting(null);
			const locked = await augmentPortfolioWithSilentPayments(
				emptyPortfolio,
				chain,
				SP_ADDRESS,
				undefined,
				previous,
			);

			// Only the SP outputs come from `previous`: LWK's own UTXOs are always rescanned.
			expect(locked.utxos.map((u) => u.txid)).toEqual(["txid_ok"]);
			expect(locked.assets[0].amountSats).toBe("51000");
		});

		it("adds no SP UTXOs while the vault is locked and there is no previous portfolio", async () => {
			await saveTrackedSilentPaymentUtxo(spUtxo({ amountSats: "50000", txid: "txid_ok" }));
			setSpStoreVaultForTesting(null);

			const locked = await augmentPortfolioWithSilentPayments(emptyPortfolio, chain, SP_ADDRESS);

			expect(locked).toBe(emptyPortfolio);
		});
	});

	describe("activity", () => {
		it("shows incoming SP payments, but not change or failed unblinds", async () => {
			await saveTrackedSilentPaymentUtxo(spUtxo({ txid: "txid_incoming" }));
			await saveTrackedSilentPaymentUtxo(spUtxo({ labelIndex: 0, txid: "txid_change" }));
			await saveTrackedSilentPaymentUtxo(spUtxo({ txid: "txid_failed", unblindFailed: true }));

			const items = await mergeActivityWithSilentPayments([], chain, account, POLICY_ASSET);

			expect(items.map((i) => i.txid)).toEqual(["txid_incoming"]);
			expect(items[0].direction).toBe("received");
			expect(items[0].isSilentPayment).toBe(true);
		});

		it("names the label a payment arrived on", async () => {
			await updateSilentPaymentLabels(CHAIN_ID, SP_ADDRESS, () => [
				{ address: "tlqsp1label", createdAt: 1, index: 2, name: "Donations" },
			]);
			await saveTrackedSilentPaymentUtxo(spUtxo({ labelIndex: 2, txid: "b".repeat(64) }));
			await saveTrackedSilentPaymentUtxo(spUtxo({ txid: "c".repeat(64) }));
			await saveTrackedSilentPaymentUtxo(spUtxo({ labelIndex: 7, txid: "d".repeat(64) }));

			const items = await mergeActivityWithSilentPayments([], chain, account, POLICY_ASSET);

			const labelOf = (txid: string) => items.find((i) => i.txid === txid)?.silentPaymentLabel;
			expect(labelOf("b".repeat(64))).toBe("Donations");
			// Unlabeled, and a label the wallet does not know (yet): no name.
			expect(labelOf("c".repeat(64))).toBeUndefined();
			expect(labelOf("d".repeat(64))).toBeUndefined();
		});

		const lwkSent = (txid: string, amountSats: string) => ({
			amountSats,
			direction: "sent" as const,
			feeSats: "29",
			timestamp: 1_700_000_000,
			txid,
		});

		it("does not count SP change returned to the wallet as sent", async () => {
			// LWK sees its 143601-sat input spent, but not the 142802-sat SP change of the same tx.
			await saveTrackedSilentPaymentUtxo(
				spUtxo({ amountSats: "142802", labelIndex: 0, txid: "a1".repeat(32) }),
			);

			const items = await mergeActivityWithSilentPayments(
				[lwkSent("a1".repeat(32), "143601")],
				chain,
				account,
				POLICY_ASSET,
			);

			expect(items).toHaveLength(1);
			expect(items[0]).toMatchObject({
				amountSats: "799",
				direction: "sent",
				txid: "a1".repeat(32),
			});
		});

		it("counts SP outputs a send spent alongside wallet inputs", async () => {
			// LWK sees its own 123713 sats spent, but not the 770-sat SP input of the same tx.
			await saveTrackedSilentPaymentUtxo(spUtxo({ amountSats: "770", txid: "b1".repeat(32) }));
			await markSilentPaymentUtxoSpent("b1".repeat(32), 0, "b2".repeat(32));

			const items = await mergeActivityWithSilentPayments(
				[lwkSent("b2".repeat(32), "123713")],
				chain,
				account,
				POLICY_ASSET,
			);

			const byTxid = Object.fromEntries(items.map((i) => [i.txid, i]));
			expect(byTxid["b2".repeat(32)]).toMatchObject({ amountSats: "124483", direction: "sent" });
			expect(byTxid["b1".repeat(32)]).toMatchObject({
				amountSats: "770",
				direction: "received",
				isSilentPayment: true,
			});
		});

		it("shows a send paid only from SP outputs, which the LWK wallet does not see", async () => {
			await saveTrackedSilentPaymentUtxo(spUtxo({ amountSats: "1000", txid: "c1".repeat(32) }));
			await markSilentPaymentUtxoSpent("c1".repeat(32), 0, "c2".repeat(32), {
				blockTime: 1_700_000_600,
				feeSats: "30",
			});
			await saveTrackedSilentPaymentUtxo(
				spUtxo({ amountSats: "400", labelIndex: 0, txid: "c2".repeat(32) }),
			);

			const items = await mergeActivityWithSilentPayments([], chain, account, POLICY_ASSET);

			expect(items.find((i) => i.txid === "c2".repeat(32))).toEqual({
				amountSats: "600",
				direction: "sent",
				feeSats: "30",
				timestamp: 1_700_000_600,
				txid: "c2".repeat(32),
			});
		});
	});
});
