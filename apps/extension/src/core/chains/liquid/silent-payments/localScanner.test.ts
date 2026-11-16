import {
	afterAll,
	afterEach,
	beforeAll,
	beforeEach,
	describe,
	expect,
	it,
	mock,
	setSystemTime,
} from "bun:test";

import { computeLabelTweak, zeroizeRecipientKeys } from "@humid/sp-core";
import { encodeRawElementsTransaction } from "@humid/sp-core/testing";
import { sha256 } from "@noble/hashes/sha2.js";
import { bytesToHex, hexToBytes } from "@noble/hashes/utils.js";

import { loadLwkWasm } from "../adapters/lwk/loadLwkWasm";
import { lwk } from "../adapters/lwk/lwkWasmForTests";
import { createLiquidChainRecord } from "../chains/createBuiltInLiquidChains";
import { LIQUID_TESTNET_CHAIN_ID } from "../domain/LiquidChain";
import { resetExplorerLimiterForTesting } from "./explorer";
import {
	augmentPortfolioWithSilentPayments,
	buildExplorerApis,
	explorerBudgetSpent,
	fetchFromExplorer,
	getSilentPaymentBirthday,
	getSilentPaymentBackfill,
	getSilentPaymentBlockCursor,
	getSilentPaymentLabels,
	getSilentPaymentLocalScanProgress,
	getSilentPaymentScanRate,
	getSilentPaymentSpentIndex,
	getTrackedSilentPaymentUtxos,
	getUnspentSilentPaymentUtxos,
	markSilentPaymentUtxoSpent,
	saveSilentPaymentBackfill,
	saveSilentPaymentBirthday,
	saveSilentPaymentBlockCursor,
	saveSilentPaymentSpentIndex,
	saveTrackedSilentPaymentUtxo,
	DEFAULT_LOOKBACK_BLOCKS,
	RESTORED_LOOKBACK_BLOCKS,
	RESTORED_MARGIN_BLOCKS,
	rescanFromExplorer,
	resetLocalScannerForTesting,
	setExplorerScanWaitForTesting,
	setSpStoreVaultForTesting,
	setUnblindForTesting,
	SP_STORAGE_KEY,
	startExplorerCatchUp,
	syncFromExplorer,
	updateSilentPaymentLabels,
	usableExplorerApis,
} from "./index";
import {
	fetchAllBlockTransactions,
	heightAtOrBefore,
	spentOutpointFingerprint,
} from "./localScanner";
import {
	buildPaymentTx,
	blockHash,
	type BlockTx,
	createTestRecipientKeys,
	fakeChain,
	fakeExplorer,
	keyPair,
	PAYMENT_SATS,
	spendOf,
} from "./localScannerTestChain";
import type { SilentPaymentSpentIndex } from "./store";
import { useMemorySpStore } from "./storeTestStorage";
import type { SilentPaymentRecipientKeys } from "./types";

// The extension loads LWK by fetching a wasm URL, which Bun cannot; tests use the bytes on disk.
mock.module("../adapters/lwk/loadLwkWasm", () => ({ loadLwkWasm: async () => lwk }));

describe("Autonomous Wallet Scanner (localScanner)", () => {
	const keys = createTestRecipientKeys();
	const address = "tlqsp1localwalletaddress";
	const chain = createLiquidChainRecord({
		id: LIQUID_TESTNET_CHAIN_ID,
		name: "Liquid Testnet",
	});
	const realFetch = globalThis.fetch;

	beforeAll(async () => {
		await loadLwkWasm();
	});

	beforeEach(() => {
		useMemorySpStore();
		resetLocalScannerForTesting();
		// The fake explorer is local: no rate cap.
		resetExplorerLimiterForTesting({ requestsPerSecond: Infinity });
	});

	afterEach(() => {
		globalThis.fetch = realFetch;
	});

	afterAll(() => {
		setSpStoreVaultForTesting(null);
	});

	it("scans blocks directly via Esplora", async () => {
		const { blockTx, validTx } = buildPaymentTx(keys, 0x31);

		const requests: string[] = [];
		globalThis.fetch = fakeExplorer(100, { 100: [blockTx] }, () => undefined, requests);

		const snapshot = { assets: [], utxos: [] };
		const augmented = await augmentPortfolioWithSilentPayments(snapshot, chain, address, keys);

		expect(augmented.utxos).toHaveLength(1);
		expect(augmented.utxos[0]!.txid).toBe(validTx.txid);
		expect(augmented.utxos[0]!.amountSats).toBe(PAYMENT_SATS.toString());
		// The payment was found and unblinded from the whole block: no request names it.
		expect(requests.filter((p) => p.includes("/tx/"))).toEqual([]);

		const cursor = await getSilentPaymentBlockCursor(chain.id, address);
		expect(cursor).toEqual({ blockHash: blockHash(100), height: 100 });

		const progress = getSilentPaymentLocalScanProgress(chain.id, address);
		expect(progress?.state).toBe("synced");
		expect(progress?.currentHeight).toBe(100);
	});

	it("probes a fallback explorer that failed when a run starts, and uses it again once it answers", async () => {
		const apis = buildExplorerApis(chain);
		const fallback = apis.find((api) => api.startsWith("https://liquid.network"))!;
		globalThis.fetch = (async () => {
			throw new TypeError("fetch failed");
		}) as unknown as typeof fetch;
		await expect(fetchFromExplorer(`${fallback}/blocks/tip/height`)).rejects.toThrow();
		expect(usableExplorerApis(apis)).not.toContain(fallback);

		try {
			setSystemTime(new Date(Date.now() + 61_000));
			globalThis.fetch = fakeExplorer(110, {}, () => undefined);
			await syncFromExplorer({
				chain,
				forceFromHeight: 109,
				recipientKeys: keys,
				silentPaymentAddress: address,
			});
		} finally {
			setSystemTime();
		}

		expect(usableExplorerApis(apis)).toContain(fallback);
	});

	it("after a reorg, records payments and spends from the blocks that replaced theirs, without asking", async () => {
		// `kept` is paid below the replaced blocks and spent in one of them; `moved` is paid in one.
		const kept = buildPaymentTx(keys, 0x3a);
		const moved = buildPaymentTx(keys, 0x3b);
		const spend = spendOf(kept.validTx.txid, kept.esploraTx.vout[0]!.scriptpubkey);
		const spendTxid = (spend.json as { txid: string }).txid;
		const find = async (txid: string) =>
			(await getTrackedSilentPaymentUtxos()).find((u) => u.txid === txid);
		globalThis.fetch = fakeExplorer(
			110,
			{ 95: [kept.blockTx], 105: [moved.blockTx], 107: [spend] },
			() => undefined,
		);
		await syncFromExplorer({
			chain,
			forceFromHeight: 90,
			recipientKeys: keys,
			silentPaymentAddress: address,
		});
		expect(await find(kept.validTx.txid)).toMatchObject({ blockHeight: 95, spentBlockHeight: 107 });
		expect(await find(moved.validTx.txid)).toMatchObject({ blockHeight: 105 });

		// The chain from block 105 up was replaced: the payment is now in 108, the spend in 111.
		const requests: string[] = [];
		globalThis.fetch = fakeExplorer(
			111,
			{ 95: [kept.blockTx], 108: [moved.blockTx], 111: [spend] },
			() => undefined,
			requests,
		);
		await syncFromExplorer({ chain, recipientKeys: keys, silentPaymentAddress: address });

		const keptAfter = await find(kept.validTx.txid);
		expect(keptAfter).toMatchObject({
			blockHeight: 95,
			confirmed: true,
			spent: true,
			spentBlockHeight: 111,
			spentBlockTime: 1_700_000_000 + 111 * 60,
			spentInTxid: spendTxid,
		});
		expect(keptAfter!.spentSeenAt).toBeUndefined();
		expect(await find(moved.validTx.txid)).toMatchObject({
			blockHeight: 108,
			blockTime: 1_700_000_000 + 108 * 60,
			confirmed: true,
		});
		expect(requests.filter((p) => p.includes("/outspend/") || p.includes("/tx/"))).toEqual([]);
	});

	it("reports a catch-up from the cursor, not from the wallet's birthday", async () => {
		globalThis.fetch = fakeExplorer(110, {}, () => undefined);
		await saveSilentPaymentBirthday(chain.id, address, 1);
		await syncFromExplorer({
			chain,
			forceFromHeight: 101,
			maxBlocks: 4,
			recipientKeys: keys,
			silentPaymentAddress: address,
		});

		// Blocks 105-107 of the six since the cursor at 104.
		await syncFromExplorer({
			chain,
			maxBlocks: 3,
			recipientKeys: keys,
			silentPaymentAddress: address,
		});

		expect(getSilentPaymentLocalScanProgress(chain.id, address)).toMatchObject({
			currentHeight: 107,
			newBlocksLeft: 3,
			percentage: 50,
			state: "backfilling",
			totalBlocksToScan: 6,
		});
		expect(getSilentPaymentLocalScanProgress(chain.id, address)?.history).toBeUndefined();
	});

	it("keeps the scan rate across a service worker restart, for a while", async () => {
		const session: Record<string, unknown> = {};
		const scope = globalThis as { chrome?: unknown };
		scope.chrome = {
			storage: {
				session: {
					get: async (key: string) => ({ [key]: structuredClone(session[key]) }),
					set: async (items: Record<string, unknown>) =>
						Object.assign(session, structuredClone(items)),
				},
			},
		};
		// Each explorer answer takes a fake second, so the run measures a rate.
		const explorer = fakeExplorer(130, {}, () => undefined);
		globalThis.fetch = (async (input: string) => {
			setSystemTime(new Date(Date.now() + 1000));
			return explorer(input);
		}) as unknown as typeof fetch;

		try {
			await syncFromExplorer({
				chain,
				forceFromHeight: 101,
				maxBlocks: 30,
				recipientKeys: keys,
				silentPaymentAddress: address,
			});
			expect(await getSilentPaymentScanRate(chain.id, address)).toBeGreaterThan(0);

			// A new service worker: memory is gone, the session storage is not.
			resetLocalScannerForTesting();
			expect(await getSilentPaymentScanRate(chain.id, address)).toBeGreaterThan(0);

			setSystemTime(new Date(Date.now() + 31 * 60_000));
			resetLocalScannerForTesting();
			expect(await getSilentPaymentScanRate(chain.id, address)).toBeUndefined();
		} finally {
			delete scope.chrome;
			setSystemTime();
		}
	});

	it("leaves an explorer whose hour of requests is spent, and goes on with the other one", async () => {
		resetExplorerLimiterForTesting({ hourlyBudget: 8, requestsPerSecond: Infinity });
		const { blockTx, validTx } = buildPaymentTx(keys, 0x71);
		const explorer = fakeExplorer(400, { 380: [blockTx] }, () => undefined);
		const hosts: string[] = [];
		globalThis.fetch = (async (input: string) => {
			hosts.push(new URL(input).host);
			return explorer(input);
		}) as unknown as typeof fetch;

		// The tip and two windows of empty blocks (five header pages each) outrun the budget.
		const first = await syncFromExplorer({
			chain,
			forceFromHeight: 101,
			recipientKeys: keys,
			silentPaymentAddress: address,
		});

		expect(first.status).toBe("partial");
		expect(new Set(hosts)).toEqual(new Set(["blockstream.info"]));
		expect(hosts.length).toBeLessThanOrEqual(11);
		const cursor = await getSilentPaymentBlockCursor(chain.id, address);
		expect(cursor?.height).toBe(200);

		hosts.length = 0;
		const second = await syncFromExplorer({
			chain,
			recipientKeys: keys,
			silentPaymentAddress: address,
		});

		expect(second.status).toBe("synced");
		expect(new Set(hosts)).toEqual(new Set(["liquid.network"]));
		expect((await getTrackedSilentPaymentUtxos()).map((u) => u.txid)).toEqual([validTx.txid]);
	});

	it("does not start a run on an explorer whose hour is spent when there is no other", async () => {
		resetExplorerLimiterForTesting({ hourlyBudget: 300, requestsPerSecond: Infinity });
		// Not one of the public explorers, so it has no fallback; on a server with an hourly cap.
		const alone = {
			...chain,
			settings: { ...chain.settings, explorerUrl: "https://blockstream.info/other/" },
		};
		let requests = 0;
		globalThis.fetch = (async () => {
			requests++;
			return new Response("{}", { status: 429 });
		}) as unknown as typeof fetch;
		const run = () =>
			syncFromExplorer({
				chain: alone,
				forceFromHeight: 101,
				recipientKeys: keys,
				silentPaymentAddress: address,
			});

		await expect(run()).rejects.toThrow();
		const asked = requests;
		await expect(run()).rejects.toThrow("hourly request limit");

		// The second run asked nobody: every request to a spent server adds to its count.
		expect(requests).toBe(asked);
		expect(getSilentPaymentLocalScanProgress(alone.id, address)?.state).toBe("error");
	});

	it("does not hold a portfolio refresh for a slow scan, whose finds come with the next one", async () => {
		const { blockTx, validTx } = buildPaymentTx(keys, 0x32);
		const honest = fakeExplorer(100, { 100: [blockTx] }, () => undefined);
		let release = () => {};
		const explorerAnswers = new Promise<void>((resolve) => {
			release = resolve;
		});
		globalThis.fetch = (async (input: string) => {
			await explorerAnswers;
			return honest(input);
		}) as unknown as typeof fetch;
		setExplorerScanWaitForTesting(20);

		try {
			const first = await augmentPortfolioWithSilentPayments(
				{ assets: [], utxos: [] },
				chain,
				address,
				keys,
			);
			expect(first.utxos).toEqual([]);

			release();
			// The run keeps going in the background catch-up.
			await startExplorerCatchUp({ chain, recipientKeys: keys, silentPaymentAddress: address });
			const next = await augmentPortfolioWithSilentPayments(
				{ assets: [], utxos: [] },
				chain,
				address,
				keys,
			);
			expect(next.utxos.map((u) => u.txid)).toEqual([validTx.txid]);
		} finally {
			setExplorerScanWaitForTesting();
		}
	});

	it("matches labeled payments in local wallet scanning mode and supports rescanFromExplorer", async () => {
		const labelTweak = computeLabelTweak(keys.scanKey.privateKey, 2);
		const { blockTx, validTx } = buildPaymentTx(keys, 0x42, labelTweak);

		await updateSilentPaymentLabels(chain.id, address, () => [
			{ address: "tlqsp1label2", createdAt: 1, index: 2, name: "Invoice" },
		]);

		await rescanFromExplorer({
			birthdayHeight: 100,
			chain,
			silentPaymentAddress: address,
		});
		expect(await getSilentPaymentBirthday(chain.id, address)).toBe(100);
		expect(await getSilentPaymentBlockCursor(chain.id, address)).toBeNull();

		globalThis.fetch = fakeExplorer(100, { 100: [blockTx] }, (path) =>
			path.endsWith(`/tx/${validTx.txid}/hex`)
				? new Response(validTx.rawHex, { status: 200 })
				: undefined,
		);

		const res = await syncFromExplorer({
			chain,
			recipientKeys: keys,
			silentPaymentAddress: address,
		});

		expect(res.scannedUtxos).toHaveLength(1);
		expect(res.scannedUtxos[0]!.labelIndex).toBe(2);
		const tracked = await getTrackedSilentPaymentUtxos();
		expect(tracked[0]!.labelIndex).toBe(2);
	});

	it("fetches headers ten per request and skips transactions of coinbase-only blocks", async () => {
		const { blockTx, validTx } = buildPaymentTx(keys, 0x51);
		const requests: string[] = [];
		globalThis.fetch = fakeExplorer(
			130,
			{ 125: [blockTx] },
			(path) =>
				path.endsWith(`/tx/${validTx.txid}/hex`)
					? new Response(validTx.rawHex, { status: 200 })
					: undefined,
			requests,
		);

		const res = await syncFromExplorer({
			chain,
			forceFromHeight: 101,
			recipientKeys: keys,
			silentPaymentAddress: address,
		});

		expect(res.scannedUtxos.map((u) => u.txid)).toEqual([validTx.txid]);
		expect(requests.filter((p) => /\/blocks\/\d+$/.test(p))).toHaveLength(3);
		const txsRequests = requests.filter((p) => p.endsWith("/txs"));
		expect(txsRequests).toHaveLength(1);
		expect(txsRequests[0]).toEndWith(`/api/block/${blockHash(125)}/txs`);
		expect(await getSilentPaymentBlockCursor(chain.id, address)).toEqual({
			blockHash: blockHash(130),
			height: 130,
		});
	});

	it("fetches the raw block of every block that could pay an SP output, matched or not", async () => {
		const payment = buildPaymentTx(keys, 0x52);
		const stranger = buildPaymentTx({ scanKey: keyPair(0x33), spendKey: keyPair(0x44) }, 0x53);
		const plainSpk = "0014" + "55".repeat(20);
		const plain = encodeRawElementsTransaction({
			vin: [{ txid: "ab".repeat(32), vout: 0, witness: ["", "02" + "11".repeat(32)] }],
			vout: [{ scriptPubKeyHex: plainSpk, valueSats: 1 }],
		});
		const plainTx: BlockTx = {
			json: {
				txid: plain.txid,
				vin: [
					{
						prevout: { scriptpubkey: plainSpk, scriptpubkey_type: "v0_p2wpkh" },
						txid: "ab".repeat(32),
						vout: 0,
						witness: ["", "02" + "11".repeat(32)],
					},
				],
				vout: [{ scriptpubkey: plainSpk }],
			},
			rawHex: plain.rawHex,
		};
		const requests: string[] = [];
		globalThis.fetch = fakeExplorer(
			130,
			{ 115: [plainTx], 120: [stranger.blockTx], 125: [payment.blockTx] },
			() => undefined,
			requests,
		);

		const res = await syncFromExplorer({
			chain,
			forceFromHeight: 101,
			recipientKeys: keys,
			silentPaymentAddress: address,
		});

		expect(res.scannedUtxos.map((u) => u.txid)).toEqual([payment.validTx.txid]);
		expect(requests.filter((p) => p.endsWith("/txs"))).toHaveLength(3);
		// The stranger's block too: the explorer cannot tell which candidate paid the wallet.
		expect(requests.filter((p) => p.endsWith("/raw"))).toEqual([
			expect.stringMatching(new RegExp(`/block/${blockHash(120)}/raw$`)),
			expect.stringMatching(new RegExp(`/block/${blockHash(125)}/raw$`)),
		]);
	});

	it("fetches a window's raw blocks together and the next window while it scans", async () => {
		const first = buildPaymentTx(keys, 0x54);
		const stranger = buildPaymentTx({ scanKey: keyPair(0x33), spendKey: keyPair(0x44) }, 0x56);
		const second = buildPaymentTx(keys, 0x55);
		const events: string[] = [];
		// Windows of 50 blocks from 101: 101-150 and 151-200.
		globalThis.fetch = fakeExplorer(
			200,
			{ 105: [first.blockTx], 140: [stranger.blockTx], 160: [second.blockTx] },
			() => undefined,
			events,
		);
		// The scan's first find, among the requests.
		const memory = useMemorySpStore();
		setSpStoreVaultForTesting({
			deleteItem: async (key) => {
				memory.delete(key);
			},
			getItem: async (key) => memory.get(key) ?? null,
			setItem: async (key, value) => {
				if (key === SP_STORAGE_KEY) events.push("found");
				memory.set(key, value);
			},
			updateItem: async () => {
				throw new Error("unused");
			},
		});

		const res = await syncFromExplorer({
			chain,
			forceFromHeight: 101,
			recipientKeys: keys,
			silentPaymentAddress: address,
		});

		expect(res.scannedUtxos.map((u) => u.txid)).toEqual([first.validTx.txid, second.validTx.txid]);
		const firstFind = events.indexOf("found");
		const rawOf = (height: number) =>
			events.findIndex((p) => p.endsWith(`/block/${blockHash(height)}/raw`));
		// Block 140's raw block is not waited for until the scan reaches it.
		expect(rawOf(105)).toBeGreaterThan(-1);
		expect(rawOf(140)).toBeLessThan(firstFind);
		expect(events.findIndex((p) => p.endsWith("/blocks/160"))).toBeLessThan(firstFind);
		expect(await getSilentPaymentBlockCursor(chain.id, address)).toEqual({
			blockHash: blockHash(200),
			height: 200,
		});
	});

	it("lists blocks on the primary explorer and on the fallback only when it fails", async () => {
		const strangers = [0x61, 0x62, 0x63, 0x64].map((n) =>
			buildPaymentTx({ scanKey: keyPair(0x33), spendKey: keyPair(0x44) }, n),
		);
		const explorer = fakeExplorer(
			130,
			{
				121: [strangers[0]!.blockTx],
				122: [strangers[1]!.blockTx],
				123: [strangers[2]!.blockTx],
				124: [strangers[3]!.blockTx],
			},
			() => undefined,
		);
		const listedOn: string[] = [];
		let primaryDown = false;
		globalThis.fetch = (async (input: string) => {
			const { host } = new URL(input);
			if (input.endsWith("/txs")) {
				listedOn.push(host);
				if (primaryDown && host === "blockstream.info") {
					return new Response("unavailable", { status: 503 });
				}
			}
			return explorer(input);
		}) as unknown as typeof fetch;
		const scan = (from: number) =>
			syncFromExplorer({
				chain,
				forceFromHeight: from,
				recipientKeys: keys,
				silentPaymentAddress: address,
			});

		await scan(101);
		expect(new Set(listedOn)).toEqual(new Set(["blockstream.info"]));

		listedOn.length = 0;
		primaryDown = true;
		await scan(101);
		expect(listedOn.filter((h) => h === "liquid.network")).toHaveLength(4);
	});

	describe("long gap, newest first", () => {
		const recent = buildPaymentTx(keys, 0x71);
		const old = buildPaymentTx(keys, 0x72);
		const spender = "ee".repeat(32);
		const baseChain = { 200: [old.blockTx], 1995: [recent.blockTx] };
		const withChain = (
			extra: (path: string) => Response | undefined,
			txsByHeight: Record<number, BlockTx[]> = baseChain,
			requests?: string[],
		) => fakeExplorer(2000, txsByHeight, extra, requests);
		const run = (maxBlocks = 20) =>
			syncFromExplorer({
				chain,
				maxBlocks,
				recipientKeys: keys,
				silentPaymentAddress: address,
			});
		const namesAnOutput = (p: string) => p.includes("/outspend/") || p.includes("/tx/");

		it("finds a recent payment in the first run and settles it unspent without asking", async () => {
			const requests: string[] = [];
			globalThis.fetch = withChain(() => undefined, baseChain, requests);
			await rescanFromExplorer({ birthdayHeight: 100, chain, silentPaymentAddress: address });

			const res = await run();

			expect(res.status).toBe("partial");
			expect(res.scannedUtxos.map((u) => u.txid)).toEqual([recent.validTx.txid]);
			expect((await getSilentPaymentBlockCursor(chain.id, address))?.height).toBe(2000);
			expect((await getUnspentSilentPaymentUtxos(chain.id, address)).map((u) => u.txid)).toEqual([
				recent.validTx.txid,
			]);
			expect(requests.filter(namesAnOutput)).toEqual([]);
			// The newest blocks are done; the history is reported on its own.
			expect(getSilentPaymentLocalScanProgress(chain.id, address)).toMatchObject({
				currentHeight: 1980,
				history: { done: 20, total: 1901 },
				newBlocksLeft: 0,
				percentage: 1,
				totalBlocksToScan: 1901,
			});
		});

		it("marks a found output spent by a block the backfill passed, without asking", async () => {
			const spend = spendOf(recent.validTx.txid, recent.esploraTx.vout[0]!.scriptpubkey);
			const requests: string[] = [];
			globalThis.fetch = withChain(() => undefined, { ...baseChain, 1998: [spend] }, requests);
			await rescanFromExplorer({ birthdayHeight: 100, chain, silentPaymentAddress: address });

			await run();

			const [tracked] = await getTrackedSilentPaymentUtxos();
			expect(tracked).toMatchObject({
				spent: true,
				spentBlockHeight: 1998,
				spentBlockTime: 1_700_000_000 + 1998 * 60,
				spentFeeSats: "30",
				spentInTxid: (spend.json as { txid: string }).txid,
			});
			expect(tracked!.spendUnverified).toBeUndefined();
			expect(await getUnspentSilentPaymentUtxos(chain.id, address)).toEqual([]);
			expect(requests.filter(namesAnOutput)).toEqual([]);
		});

		it("marks a found output spent by a passed block whose listing gives no prevout", async () => {
			const spend = spendOf(recent.validTx.txid, recent.esploraTx.vout[0]!.scriptpubkey);
			const json = spend.json as { vin: Array<{ prevout?: unknown }> };
			delete json.vin[0]!.prevout;
			globalThis.fetch = withChain(() => undefined, { ...baseChain, 1998: [spend] });
			await rescanFromExplorer({ birthdayHeight: 100, chain, silentPaymentAddress: address });

			await run();

			const [tracked] = await getTrackedSilentPaymentUtxos();
			expect(tracked).toMatchObject({ spent: true, spentBlockHeight: 1998 });
			expect(await getUnspentSilentPaymentUtxos(chain.id, address)).toEqual([]);
		});

		it("settles outputs tracked before the gap once the backfill ends", async () => {
			const spentTxid = "96".repeat(32);
			const keptTxid = "95".repeat(32);
			const tracked = (txid: string) => ({
				address: "tex1pbefore",
				amountSats: "1000",
				chainId: chain.id,
				confirmed: true,
				createdAt: Date.now(),
				outputIndex: 0,
				rawAssetId: "",
				recipientAddress: address,
				scriptPubKeyHex: "5120" + "66".repeat(32),
				spent: false,
				tweakHex: "22".repeat(32),
				txid,
			});
			await saveTrackedSilentPaymentUtxo(tracked(spentTxid));
			await saveTrackedSilentPaymentUtxo(tracked(keptTxid));
			const spend = spendOf(spentTxid, "5120" + "66".repeat(32));
			const requests: string[] = [];
			globalThis.fetch = withChain(() => undefined, { ...baseChain, 1500: [spend] }, requests);
			await rescanFromExplorer({ birthdayHeight: 100, chain, silentPaymentAddress: address });

			// The spend may lie anywhere in the gap: neither output counts until the backfill ends.
			expect((await run(1000)).status).toBe("partial");
			expect((await getUnspentSilentPaymentUtxos(chain.id, address)).map((u) => u.txid)).toEqual([
				recent.validTx.txid,
			]);

			expect((await run(1000)).status).toBe("synced");
			const byTxid = new Map((await getTrackedSilentPaymentUtxos()).map((u) => [u.txid, u]));
			expect(byTxid.get(spentTxid)).toMatchObject({
				spent: true,
				spentBlockHeight: 1500,
				spentBlockTime: 1_700_000_000 + 1500 * 60,
				spentInTxid: (spend.json as { txid: string }).txid,
			});
			expect(byTxid.get(keptTxid)).toMatchObject({ spent: false });
			expect(byTxid.get(keptTxid)!.spendUnverified).toBeUndefined();
			expect(await getSilentPaymentSpentIndex(chain.id, address)).toBeNull();
			expect(requests.filter(namesAnOutput)).toEqual([]);
		});

		it("leaves an output awaiting its spend check to a new backfill's index", async () => {
			await saveTrackedSilentPaymentUtxo({
				address: "tex1pwaiting",
				amountSats: "1000",
				chainId: chain.id,
				confirmed: true,
				createdAt: Date.now(),
				outputIndex: 0,
				rawAssetId: "",
				recipientAddress: address,
				scriptPubKeyHex: "5120" + "66".repeat(32),
				spendUnverified: true,
				spent: false,
				tweakHex: "22".repeat(32),
				txid: "94".repeat(32),
			});
			const requests: string[] = [];
			globalThis.fetch = withChain(() => undefined, baseChain, requests);
			await rescanFromExplorer({ birthdayHeight: 100, chain, silentPaymentAddress: address });

			await run(1000);
			await run(1000);

			const waiting = (await getTrackedSilentPaymentUtxos()).find(
				(u) => u.txid === "94".repeat(32),
			);
			expect(waiting?.spendUnverified).toBeUndefined();
			expect(waiting?.spent).toBe(false);
			expect(requests.filter(namesAnOutput)).toEqual([]);
		});

		it("steps back up and goes on when a block does not link to the one above it", async () => {
			globalThis.fetch = withChain(() => undefined);
			await rescanFromExplorer({ birthdayHeight: 100, chain, silentPaymentAddress: address });
			await run();
			const stalled = await getSilentPaymentBackfill(chain.id, address);
			// The block above named another block (say, a reorg the explorer has since resolved).
			await saveSilentPaymentBackfill(chain.id, address, {
				...stalled!,
				nextHash: "ff".repeat(32),
			});

			const statuses = [(await run()).status];
			const rewound = await getSilentPaymentBackfill(chain.id, address);
			while (statuses.at(-1) !== "synced" && statuses.length < 5) {
				statuses.push((await run(1000)).status);
			}

			expect(statuses[0]).toBe("partial");
			// Ten blocks back up, then twenty blocks down.
			expect(rewound?.nextHeight).toBe(stalled!.nextHeight + 10 - 20);
			expect(statuses).not.toContain("halted");
			expect(statuses.at(-1)).toBe("synced");
			expect((await getTrackedSilentPaymentUtxos()).map((u) => u.txid).sort()).toEqual(
				[old.validTx.txid, recent.validTx.txid].sort(),
			);
		});

		it("forgets the indexed spends of the blocks it steps back over", async () => {
			globalThis.fetch = withChain(() => undefined);
			await rescanFromExplorer({ birthdayHeight: 100, chain, silentPaymentAddress: address });
			await run();
			const stalled = (await getSilentPaymentBackfill(chain.id, address))!;
			const top = stalled.nextHeight;
			const output = (txid: string) => ({
				address: "tex1pbefore",
				amountSats: "1000",
				chainId: chain.id,
				confirmed: true,
				createdAt: Date.now(),
				outputIndex: 0,
				rawAssetId: "",
				recipientAddress: address,
				scriptPubKeyHex: "5120" + "66".repeat(32),
				spendUnverified: true as const,
				spent: false,
				tweakHex: "22".repeat(32),
				txid,
			});
			const replaced = "93".repeat(32);
			const kept = "92".repeat(32);
			await saveTrackedSilentPaymentUtxo(output(replaced));
			await saveTrackedSilentPaymentUtxo(output(kept));
			// Spent in a block the rewind rescans (which the chain as it is now does not hold), and in
			// one above its reach.
			const index = (await getSilentPaymentSpentIndex(chain.id, address))!;
			const fingerprint = (txid: string) => spentOutpointFingerprint(index, txid, 0);
			index.entries[fingerprint(replaced)] = ["91".repeat(32), 1_700_000_000, "30", top + 5];
			index.entries[fingerprint(kept)] = ["90".repeat(32), 1_700_000_000, "30", top + 15];
			await saveSilentPaymentSpentIndex(chain.id, address, index);
			await saveSilentPaymentBackfill(chain.id, address, { ...stalled, nextHash: "ff".repeat(32) });

			for (let i = 0; i < 5; i++) {
				if ((await run(1000)).status === "synced") break;
			}

			const byTxid = new Map((await getTrackedSilentPaymentUtxos()).map((u) => [u.txid, u]));
			expect(byTxid.get(replaced)).toMatchObject({ spent: false });
			expect(byTxid.get(kept)).toMatchObject({ spent: true, spentBlockHeight: top + 15 });
		});

		it("forgets the indexed spends of the blocks a reorg above the backfill replaced", async () => {
			globalThis.fetch = withChain(() => undefined);
			await rescanFromExplorer({ birthdayHeight: 100, chain, silentPaymentAddress: address });
			await run();
			const output = (txid: string) => ({
				address: "tex1pbefore",
				amountSats: "1000",
				chainId: chain.id,
				confirmed: true,
				createdAt: Date.now(),
				outputIndex: 0,
				rawAssetId: "",
				recipientAddress: address,
				scriptPubKeyHex: "5120" + "66".repeat(32),
				spendUnverified: true as const,
				spent: false,
				tweakHex: "22".repeat(32),
				txid,
			});
			const replaced = "89".repeat(32);
			const kept = "88".repeat(32);
			await saveTrackedSilentPaymentUtxo(output(replaced));
			await saveTrackedSilentPaymentUtxo(output(kept));
			// Spent in a block the reorg replaces, and in one below its reach.
			const index = (await getSilentPaymentSpentIndex(chain.id, address))!;
			const fingerprint = (txid: string) => spentOutpointFingerprint(index, txid, 0);
			index.entries[fingerprint(replaced)] = ["87".repeat(32), 1_700_000_000, "30", 1995];
			index.entries[fingerprint(kept)] = ["86".repeat(32), 1_700_000_000, "30", 1985];
			await saveSilentPaymentSpentIndex(chain.id, address, index);
			// The cursor's block is no longer the one at its height.
			await saveSilentPaymentBlockCursor(chain.id, address, {
				blockHash: "ab".repeat(32),
				height: 2000,
			});

			for (let i = 0; i < 5; i++) {
				if ((await run(1000)).status === "synced") break;
			}

			const byTxid = new Map((await getTrackedSilentPaymentUtxos()).map((u) => [u.txid, u]));
			expect(byTxid.get(replaced)).toMatchObject({ spent: false });
			expect(byTxid.get(replaced)!.spendUnverified).toBeUndefined();
			expect(byTxid.get(kept)).toMatchObject({ spent: true, spentBlockHeight: 1985 });
		});

		describe("on an explorer with an hourly budget", () => {
			const [primary, fallback] = buildExplorerApis(chain) as [string, string];
			let fallbackUp: boolean;
			let fallbackRequests: number;

			beforeEach(async () => {
				resetExplorerLimiterForTesting({ hourlyBudget: 60, requestsPerSecond: Infinity });
				fallbackUp = false;
				fallbackRequests = 0;
				const explorer = withChain(() => undefined);
				globalThis.fetch = (async (input: string) => {
					if (input.startsWith(fallback)) {
						fallbackRequests++;
						if (!fallbackUp) throw new TypeError("fetch failed");
					}
					return explorer(input);
				}) as unknown as typeof fetch;
				await rescanFromExplorer({ birthdayHeight: 100, chain, silentPaymentAddress: address });
			});

			it("keeps part of the hour for new blocks when no other explorer answers", async () => {
				let status = "";
				for (let i = 0; i < 4; i++) ({ status } = await run(2000));

				// The search stopped at its share: the new blocks can still be checked this hour.
				expect(status).toBe("waiting");
				expect(explorerBudgetSpent(primary)).toBe(false);
				const backfill = await getSilentPaymentBackfill(chain.id, address);
				expect(backfill!.nextHeight).toBeLessThan(2000);
				expect(backfill!.nextHeight).toBeGreaterThan(100);
				expect(getSilentPaymentLocalScanProgress(chain.id, address)?.state).not.toBe("error");
			});

			it("does not run again and again while the search waits for the next hour", async () => {
				// Each idle run would cost the requests that find the tip, until the hour is gone.
				await startExplorerCatchUp({
					chain,
					recipientKeys: keys,
					retryDelayMs: 0,
					silentPaymentAddress: address,
				});

				expect(explorerBudgetSpent(primary)).toBe(false);
				expect(await getSilentPaymentBackfill(chain.id, address)).not.toBeNull();
			});

			it("reads older blocks from an explorer without a cap while one answers", async () => {
				fallbackUp = true;

				let status = "";
				for (let i = 0; i < 4 && status !== "synced"; i++) ({ status } = await run(2000));

				expect(status).toBe("synced");
				expect(fallbackRequests).toBeGreaterThan(0);
				expect(explorerBudgetSpent(primary)).toBe(false);
				expect(await getSilentPaymentBackfill(chain.id, address)).toBeNull();
			});
		});

		it("asks the explorer for a backfill without a spent index", async () => {
			let answer = false;
			globalThis.fetch = withChain((path) =>
				path.includes("/outspend/") && !answer ? new Response("busy", { status: 503 }) : undefined,
			);
			await saveSilentPaymentBlockCursor(chain.id, address, {
				blockHash: blockHash(2000),
				height: 2000,
			});
			await saveSilentPaymentBackfill(chain.id, address, {
				nextHash: blockHash(2000),
				nextHeight: 2000,
				stopHeight: 100,
				topHeight: 2000,
			});

			await run();
			expect((await getTrackedSilentPaymentUtxos())[0]?.spendUnverified).toBe(true);
			expect(await getUnspentSilentPaymentUtxos(chain.id, address)).toEqual([]);

			answer = true;
			await run();
			expect((await getUnspentSilentPaymentUtxos(chain.id, address)).map((u) => u.txid)).toEqual([
				recent.validTx.txid,
			]);
		});

		it("asks the explorer when the stored spent index has no salt", async () => {
			const spend = spendOf(recent.validTx.txid, recent.esploraTx.vout[0]!.scriptpubkey);
			const spendTxid = (spend.json as { txid: string }).txid;
			const requests: string[] = [];
			globalThis.fetch = withChain(() => undefined, baseChain, requests);
			await saveSilentPaymentBlockCursor(chain.id, address, {
				blockHash: blockHash(2000),
				height: 2000,
			});
			await saveSilentPaymentBackfill(chain.id, address, {
				nextHash: blockHash(2000),
				nextHeight: 2000,
				stopHeight: 100,
				topHeight: 2000,
			});
			// Keyed by a plain hash, which a payer of the output could grind a spend to match.
			const plainKey = bytesToHex(
				sha256(new TextEncoder().encode(`${recent.validTx.txid}:0`)).subarray(0, 8),
			);
			await saveSilentPaymentSpentIndex(chain.id, address, {
				entries: { [plainKey]: [spendTxid, 1_700_000_000, null, 1998] },
			} as unknown as SilentPaymentSpentIndex);

			await run();

			expect(await getTrackedSilentPaymentUtxos()).toMatchObject([
				{ spent: false, txid: recent.validTx.txid },
			]);
			expect(requests.some((p) => p.endsWith(`/tx/${recent.validTx.txid}/outspend/0`))).toBe(true);
		});

		it("keeps a spend unsettled while the explorer gives its block no height", async () => {
			const spendTxid = "e1".repeat(32);
			let withHeight = false;
			globalThis.fetch = withChain((path) => {
				if (path.includes("/outspend/")) {
					return new Response(JSON.stringify({ spent: true, txid: spendTxid, vin: 0 }), {
						status: 200,
					});
				}
				if (path.endsWith(`/tx/${spendTxid}`)) {
					const status = withHeight
						? { block_height: 1999, block_time: 1_700_000_000 + 1999 * 60, confirmed: true }
						: { block_time: 1_700_000_000 + 1999 * 60, confirmed: true };
					return new Response(JSON.stringify({ fee: 30, status, txid: spendTxid }), {
						status: 200,
					});
				}
				return undefined;
			});
			await saveSilentPaymentBlockCursor(chain.id, address, {
				blockHash: blockHash(2000),
				height: 2000,
			});
			await saveSilentPaymentBackfill(chain.id, address, {
				nextHash: blockHash(2000),
				nextHeight: 2000,
				stopHeight: 100,
				topHeight: 2000,
			});

			await run();
			const [unsettled] = await getTrackedSilentPaymentUtxos();
			expect(unsettled).toMatchObject({ spendUnverified: true, spent: false });
			expect(await getUnspentSilentPaymentUtxos(chain.id, address)).toEqual([]);

			withHeight = true;
			await run();
			const [settled] = await getTrackedSilentPaymentUtxos();
			expect(settled).toMatchObject({
				spent: true,
				spentBlockHeight: 1999,
				spentInTxid: spendTxid,
			});
			expect(settled!.spendUnverified).toBeUndefined();
		});

		it("keeps an old unconfirmed spend while older blocks are left to scan", async () => {
			globalThis.fetch = withChain(() => undefined);
			await rescanFromExplorer({ birthdayHeight: 100, chain, silentPaymentAddress: address });
			await saveTrackedSilentPaymentUtxo({
				address: "tex1pspent",
				amountSats: "1000",
				chainId: chain.id,
				confirmed: true,
				createdAt: Date.now(),
				outputIndex: 0,
				rawAssetId: "",
				recipientAddress: address,
				scriptPubKeyHex: "5120" + "66".repeat(32),
				spent: true,
				spentInTxid: spender,
				spentSeenAt: Date.now() - 3 * 60 * 60 * 1000,
				txid: "97".repeat(32),
			});

			// The cursor reaches the tip at once, but the spend may be mined in the backfill's range.
			expect((await run()).status).toBe("partial");

			const tracked = (await getTrackedSilentPaymentUtxos()).find(
				(u) => u.txid === "97".repeat(32),
			);
			expect(tracked?.spent).toBe(true);
		});
	});

	it("continues from the cursor and stops at a block that does not link to it", async () => {
		globalThis.fetch = fakeExplorer(105, {}, () => undefined);
		await syncFromExplorer({
			chain,
			forceFromHeight: 100,
			recipientKeys: keys,
			silentPaymentAddress: address,
		});
		expect((await getSilentPaymentBlockCursor(chain.id, address))?.height).toBe(105);

		// The chain grew by five blocks, but block 106 claims a parent other than the scanned 105.
		const requests: string[] = [];
		globalThis.fetch = fakeExplorer(
			110,
			{},
			() => undefined,
			requests,
			(h) => (h.height === 106 ? { ...h, previousblockhash: "ab".repeat(32) } : h),
		);
		await syncFromExplorer({ chain, recipientKeys: keys, silentPaymentAddress: address });

		expect(requests.some((p) => p.endsWith("/blocks/110"))).toBe(true);
		expect((await getSilentPaymentBlockCursor(chain.id, address))?.height).toBe(105);
		const progress = getSilentPaymentLocalScanProgress(chain.id, address);
		expect(progress?.state).toBe("error");
		expect(progress?.currentHeight).toBe(105);
	});

	it("catches up a backlog over several runs with its own copy of the scan key", async () => {
		const { blockTx, validTx } = buildPaymentTx(keys, 0x61);
		const requests: string[] = [];
		globalThis.fetch = fakeExplorer(
			130,
			{ 125: [blockTx] },
			(path) =>
				path.endsWith(`/tx/${validTx.txid}/hex`)
					? new Response(validTx.rawHex, { status: 200 })
					: undefined,
			requests,
		);
		await rescanFromExplorer({ birthdayHeight: 101, chain, silentPaymentAddress: address });

		const callerKeys: SilentPaymentRecipientKeys = {
			scanKey: { ...keys.scanKey, privateKey: new Uint8Array(keys.scanKey.privateKey) },
			spendKey: keys.spendKey,
		};
		const catchUp = startExplorerCatchUp({
			chain,
			maxBlocksPerRun: 10,
			recipientKeys: callerKeys,
			silentPaymentAddress: address,
		});
		// The caller wipes its copy as soon as the call returns, as resolveScanTarget's callers do.
		zeroizeRecipientKeys(callerKeys);
		await catchUp;

		expect(requests.filter((p) => p.endsWith("/blocks/tip/height")).length).toBeGreaterThanOrEqual(
			3,
		);
		expect((await getSilentPaymentBlockCursor(chain.id, address))?.height).toBe(130);
		expect((await getTrackedSilentPaymentUtxos()).map((u) => u.txid)).toEqual([validTx.txid]);
		expect(getSilentPaymentLocalScanProgress(chain.id, address)?.state).toBe("synced");
	});

	it("does not move the cursor a rescan reset while the run was in flight", async () => {
		const { blockTx, validTx } = buildPaymentTx(keys, 0x71);
		const explorer = fakeExplorer(110, { 105: [blockTx] }, (path) =>
			path.endsWith(`/tx/${validTx.txid}/hex`)
				? new Response(validTx.rawHex, { status: 200 })
				: undefined,
		);
		let release!: () => void;
		const gate = new Promise<void>((resolve) => (release = resolve));
		let reachedGate!: () => void;
		const atGate = new Promise<void>((resolve) => (reachedGate = resolve));
		globalThis.fetch = (async (input: string) => {
			if (input.endsWith(`/block/${blockHash(105)}/txs`)) {
				reachedGate();
				await gate;
			}
			return explorer(input);
		}) as unknown as typeof fetch;
		await rescanFromExplorer({ birthdayHeight: 100, chain, silentPaymentAddress: address });

		const run = syncFromExplorer({ chain, recipientKeys: keys, silentPaymentAddress: address });
		await atGate;
		await rescanFromExplorer({ birthdayHeight: 50, chain, silentPaymentAddress: address });
		release();

		expect((await run).status).toBe("superseded");
		expect(await getSilentPaymentBlockCursor(chain.id, address)).toBeNull();
		expect(await getSilentPaymentBirthday(chain.id, address)).toBe(50);
	});

	it("puts a rescan back that came while the run was starting a backfill", async () => {
		const memory = useMemorySpStore();
		let rescan: Promise<void> | undefined;
		// A rescan comes as the run writes the first of the backfill's records, after its check: the
		// rescan's reset is queued among the rest of them.
		setSpStoreVaultForTesting({
			deleteItem: async (key) => {
				memory.delete(key);
			},
			getItem: async (key) => memory.get(key) ?? null,
			setItem: async (key, value) => {
				if (!rescan && key.startsWith("sp_spent_index_")) {
					rescan = rescanFromExplorer({ birthdayHeight: 50, chain, silentPaymentAddress: address });
				}
				memory.set(key, value);
			},
			updateItem: async () => {
				throw new Error("unused");
			},
		});
		globalThis.fetch = fakeExplorer(2000, {}, () => undefined);
		await saveSilentPaymentBirthday(chain.id, address, 100);

		const res = await syncFromExplorer({
			chain,
			maxBlocks: 20,
			recipientKeys: keys,
			silentPaymentAddress: address,
		});
		await rescan;

		expect(res.status).toBe("superseded");
		expect(await getSilentPaymentBlockCursor(chain.id, address)).toBeNull();
		expect(await getSilentPaymentBackfill(chain.id, address)).toBeNull();
		expect(await getSilentPaymentSpentIndex(chain.id, address)).toBeNull();
		expect(await getSilentPaymentBirthday(chain.id, address)).toBe(50);
	});

	it("keeps catching up after a run the explorer failed", async () => {
		const explorer = fakeExplorer(130, {}, () => undefined);
		let tipFailures = 1;
		globalThis.fetch = (async (input: string) => {
			if (input.endsWith("/blocks/tip/height") && tipFailures > 0) {
				tipFailures--;
				return new Response("unavailable", { status: 503 });
			}
			return explorer(input);
		}) as unknown as typeof fetch;
		await rescanFromExplorer({ birthdayHeight: 101, chain, silentPaymentAddress: address });

		await startExplorerCatchUp({
			chain,
			maxBlocksPerRun: 10,
			recipientKeys: keys,
			retryDelayMs: 5,
			silentPaymentAddress: address,
		});

		expect((await getSilentPaymentBlockCursor(chain.id, address))?.height).toBe(130);
	});

	it("finds a payment to a label the restored wallet's list lost, and lists the label again", async () => {
		const { blockTx, validTx } = buildPaymentTx(
			keys,
			0xd1,
			computeLabelTweak(keys.scanKey.privateKey, 7),
		);
		globalThis.fetch = fakeExplorer(100, { 100: [blockTx] }, () => undefined);

		await syncFromExplorer({
			chain,
			forceFromHeight: 100,
			recipientKeys: keys,
			silentPaymentAddress: address,
		});

		const [tracked] = await getTrackedSilentPaymentUtxos();
		expect(tracked).toMatchObject({ labelIndex: 7, txid: validTx.txid });
		expect((await getSilentPaymentLabels(chain.id, address)).map((l) => [l.index, l.name])).toEqual(
			[[7, "Label 7"]],
		);
	});

	it("does not scan while the vault is locked", async () => {
		const requests: string[] = [];
		globalThis.fetch = fakeExplorer(110, {}, () => undefined, requests);
		setSpStoreVaultForTesting(null);

		await startExplorerCatchUp({ chain, recipientKeys: keys, silentPaymentAddress: address });

		expect(requests).toEqual([]);
	});

	it("marks an output spent when a later scanned block spends it, without asking the explorer", async () => {
		const { blockTx, validTx } = buildPaymentTx(keys, 0x81);
		const spend = encodeRawElementsTransaction({
			vin: [{ txid: validTx.txid, vout: 0, witness: ["aa".repeat(64)] }],
			vout: [
				{ scriptPubKeyHex: "0014" + "55".repeat(20), valueSats: 1 },
				{ scriptPubKeyHex: "", valueSats: 25 },
			],
		});
		const spendTx: BlockTx = {
			json: {
				txid: spend.txid,
				vin: [{ txid: validTx.txid, vout: 0, witness: ["aa".repeat(64)] }],
				vout: [{ scriptpubkey: "0014" + "55".repeat(20) }, { scriptpubkey: "" }],
			},
			rawHex: spend.rawHex,
		};
		const requests: string[] = [];
		globalThis.fetch = fakeExplorer(
			110,
			{ 105: [blockTx], 107: [spendTx] },
			() => undefined,
			requests,
		);

		await syncFromExplorer({
			chain,
			forceFromHeight: 101,
			recipientKeys: keys,
			silentPaymentAddress: address,
		});

		const [tracked] = await getTrackedSilentPaymentUtxos();
		expect(tracked).toMatchObject({
			spent: true,
			// The spend's block time and fee let the activity feed show a send LWK does not see.
			spentBlockTime: 1_700_000_000 + 107 * 60,
			spentFeeSats: "25",
			spentInTxid: spend.txid,
			txid: validTx.txid,
		});
		expect(requests.filter((p) => p.includes("/outspend/") || p.includes("/status"))).toEqual([]);
	});

	it("writes the cursor once a window, not once a block", async () => {
		const memory = useMemorySpStore();
		const cursorWrites: number[] = [];
		setSpStoreVaultForTesting({
			deleteItem: async (key) => {
				memory.delete(key);
			},
			getItem: async (key) => memory.get(key) ?? null,
			setItem: async (key, value) => {
				if (key.startsWith("sp_block_cursor_")) {
					cursorWrites.push((JSON.parse(value) as { height: number }).height);
				}
				memory.set(key, value);
			},
			updateItem: async () => {
				throw new Error("not used");
			},
		});
		globalThis.fetch = fakeExplorer(200, {}, () => undefined);

		await syncFromExplorer({
			chain,
			forceFromHeight: 101,
			recipientKeys: keys,
			silentPaymentAddress: address,
		});

		expect(cursorWrites).toEqual([150, 200]);
	});

	it("stops at a raw block that is not the block the header names", async () => {
		const { blockTx } = buildPaymentTx(keys, 0x91);
		const honest = fakeExplorer(110, { 105: [blockTx] }, () => undefined);
		const other = fakeChain({}).at(105);
		globalThis.fetch = (async (input: string) =>
			input.endsWith(`/block/${blockHash(105)}/raw`)
				? new Response(new Uint8Array(hexToBytes(other.rawHex)), { status: 200 })
				: honest(input)) as unknown as typeof fetch;

		const res = await syncFromExplorer({
			chain,
			forceFromHeight: 101,
			recipientKeys: keys,
			silentPaymentAddress: address,
		});

		expect(res.status).toBe("halted");
		expect((await getSilentPaymentBlockCursor(chain.id, address))?.height).toBe(104);
		expect(await getTrackedSilentPaymentUtxos()).toEqual([]);
	});

	describe("an output that does not unblind", () => {
		const payment = buildPaymentTx(keys, 0x92);
		// The same transaction with another signature: same txid and block hash, other witness.
		const resigned = encodeRawElementsTransaction({
			vin: [
				{
					txid: payment.parentTx.txid,
					vout: 0,
					witness: ["01", payment.esploraTx.vin[0]!.witness[1]!],
				},
			],
			vout: [{ scriptPubKeyHex: payment.esploraTx.vout[0]!.scriptpubkey, valueSats: PAYMENT_SATS }],
		});
		const unblindsOnlyResigned = async (hex: string) =>
			hex === resigned.rawHex ? { amountSats: "777", rawAssetId: "aa".repeat(32) } : null;

		/** The primary explorer serves `payment`; liquid.network the re-signed copy, if `copy`. */
		const explorers = (copy: boolean, requests: string[]) => {
			const primary = fakeExplorer(110, { 105: [payment.blockTx] }, () => undefined);
			const fallbackBlock = fakeChain({
				105: [{ json: payment.esploraTx, rawHex: resigned.rawHex }],
			}).at(105);
			return (async (input: string) => {
				requests.push(input);
				if (input.startsWith("https://liquid.network/") && input.endsWith("/raw")) {
					return copy
						? new Response(new Uint8Array(hexToBytes(fallbackBlock.rawHex)), { status: 200 })
						: new Response("Not found", { status: 404 });
				}
				return primary(input);
			}) as unknown as typeof fetch;
		};

		it("unblinds it from another explorer's copy of the block", async () => {
			const requests: string[] = [];
			globalThis.fetch = explorers(true, requests);
			setUnblindForTesting(unblindsOnlyResigned);

			const res = await syncFromExplorer({
				chain,
				forceFromHeight: 101,
				recipientKeys: keys,
				silentPaymentAddress: address,
			});

			expect(res.scannedUtxos.map((u) => [u.txid, u.amountSats])).toEqual([
				[payment.validTx.txid, "777"],
			]);
			expect((await getTrackedSilentPaymentUtxos())[0]?.unblindFailed).toBe(false);
			const rawFetches = requests.filter((u) => u.endsWith(`/block/${blockHash(105)}/raw`));
			expect(rawFetches).toHaveLength(2);
			expect(requests.filter((u) => u.includes("/tx/"))).toEqual([]);
		});

		it("is recorded as failed when no other copy unblinds", async () => {
			globalThis.fetch = explorers(false, []);
			setUnblindForTesting(unblindsOnlyResigned);

			const res = await syncFromExplorer({
				chain,
				forceFromHeight: 101,
				recipientKeys: keys,
				silentPaymentAddress: address,
			});

			expect(res.status).toBe("synced");
			expect(res.scannedUtxos).toEqual([]);
			expect(await getTrackedSilentPaymentUtxos()).toMatchObject([
				{ txid: payment.validTx.txid, unblindFailed: true },
			]);
		});
	});

	/** Fake explorer at tip 100 whose mempool lists `mempool()` and serves `payment` as unconfirmed. */
	function mempoolExplorer(
		payment: ReturnType<typeof buildPaymentTx>,
		mempool: () => string[],
		requests: string[],
		txStatus: () => number = () => 200,
	) {
		const blocks = fakeExplorer(100, {}, () => undefined);
		return (async (input: string) => {
			const path = new URL(input).pathname;
			requests.push(path);
			if (path.endsWith("/mempool/txids")) {
				return new Response(JSON.stringify(mempool()), { status: 200 });
			}
			if (path.endsWith(`/tx/${payment.validTx.txid}`)) {
				const status = txStatus();
				return status === 200
					? new Response(JSON.stringify({ ...payment.esploraTx, status: { confirmed: false } }))
					: new Response("busy", { status });
			}
			if (path.endsWith(`/tx/${payment.validTx.txid}/hex`)) {
				return new Response(payment.validTx.rawHex, { status: 200 });
			}
			return blocks(input);
		}) as unknown as typeof fetch;
	}

	const decoys = Array.from({ length: 14 }, (_, i) => (i + 1).toString(16).padStart(64, "0"));

	it("finds an unconfirmed payment anywhere in the mempool, not only among the latest ten", async () => {
		const payment = buildPaymentTx(keys, 0xb1);
		const requests: string[] = [];
		globalThis.fetch = mempoolExplorer(payment, () => [...decoys, payment.validTx.txid], requests);

		const res = await syncFromExplorer({
			chain,
			forceFromHeight: 100,
			recipientKeys: keys,
			silentPaymentAddress: address,
		});

		expect(res.scannedUtxos.map((u) => [u.txid, u.confirmed])).toEqual([
			[payment.validTx.txid, false],
		]);
		expect(requests.filter((p) => p.endsWith("/mempool/recent"))).toEqual([]);
	});

	it("checks each mempool transaction once and retries one whose fetch failed", async () => {
		const payment = buildPaymentTx(keys, 0xc1);
		const requests: string[] = [];
		let paymentStatus = 503;
		let mempool = decoys.slice(0, 3);
		globalThis.fetch = mempoolExplorer(
			payment,
			() => mempool,
			requests,
			() => paymentStatus,
		);
		const run = async () => {
			// Past the mempool throttle of the previous run.
			setSystemTime(new Date(Date.now() + 61_000));
			return syncFromExplorer({ chain, recipientKeys: keys, silentPaymentAddress: address });
		};

		try {
			await syncFromExplorer({
				chain,
				forceFromHeight: 100,
				recipientKeys: keys,
				silentPaymentAddress: address,
			});
			mempool = [...decoys.slice(0, 3), payment.validTx.txid];
			expect((await run()).scannedUtxos).toEqual([]);
			paymentStatus = 200;
			expect((await run()).scannedUtxos.map((u) => u.txid)).toEqual([payment.validTx.txid]);
			await run();
		} finally {
			setSystemTime();
		}

		const fetchesOf = (txid: string) => requests.filter((p) => p.endsWith(`/tx/${txid}`)).length;
		expect(decoys.slice(0, 3).map(fetchesOf)).toEqual([1, 1, 1]);
		expect(fetchesOf(payment.validTx.txid)).toBe(2);
	});

	it("forgets an unconfirmed output that was not mined for two hours", async () => {
		const { validTx } = buildPaymentTx(keys, 0xa1);
		const stale = {
			address: "tex1pstale",
			amountSats: "1",
			chainId: chain.id,
			confirmed: false,
			createdAt: Date.now() - 3 * 60 * 60 * 1000,
			outputIndex: 0,
			rawAssetId: "",
			recipientAddress: address,
			scriptPubKeyHex: "5120" + "66".repeat(32),
			spent: false,
			txid: validTx.txid,
		};
		await saveTrackedSilentPaymentUtxo(stale);
		await saveTrackedSilentPaymentUtxo({ ...stale, createdAt: Date.now(), txid: "77".repeat(32) });
		globalThis.fetch = fakeExplorer(110, {}, () => undefined);

		await syncFromExplorer({
			chain,
			forceFromHeight: 105,
			recipientKeys: keys,
			silentPaymentAddress: address,
		});

		expect((await getTrackedSilentPaymentUtxos()).map((u) => u.txid)).toEqual(["77".repeat(32)]);
	});

	it("keeps an old unconfirmed output while the scan is behind the tip", async () => {
		await saveTrackedSilentPaymentUtxo({
			address: "tex1pstale",
			amountSats: "1",
			chainId: chain.id,
			confirmed: false,
			createdAt: Date.now() - 3 * 60 * 60 * 1000,
			outputIndex: 0,
			rawAssetId: "",
			recipientAddress: address,
			scriptPubKeyHex: "5120" + "66".repeat(32),
			spent: false,
			txid: "88".repeat(32),
		});
		globalThis.fetch = fakeExplorer(110, {}, () => undefined);

		// The block that mined it may lie in the 90 blocks not scanned yet.
		const res = await syncFromExplorer({
			chain,
			forceFromHeight: 10,
			maxBlocks: 10,
			recipientKeys: keys,
			silentPaymentAddress: address,
		});

		expect(res.status).toBe("partial");
		expect((await getTrackedSilentPaymentUtxos()).map((u) => u.txid)).toEqual(["88".repeat(32)]);
	});

	/** A confirmed, unspent SP output of the account, as a scan stored it. */
	const trackedOutput = (txid: string) => ({
		address: "tex1ptracked",
		amountSats: "1000",
		chainId: chain.id,
		confirmed: true,
		createdAt: Date.now(),
		outputIndex: 0,
		rawAssetId: "",
		recipientAddress: address,
		scriptPubKeyHex: "5120" + "66".repeat(32),
		spent: false,
		tweakHex: "22".repeat(32),
		txid,
	});

	it("counts an output again when the mempool spend the explorer listed is never mined", async () => {
		const funding = "99".repeat(32);
		const fakeSpend = "98".repeat(32);
		await saveTrackedSilentPaymentUtxo(trackedOutput(funding));
		let mempool = [fakeSpend];
		globalThis.fetch = fakeExplorer(110, {}, (path) => {
			if (path.endsWith("/mempool/txids")) return new Response(JSON.stringify(mempool));
			if (path.endsWith(`/tx/${fakeSpend}`)) {
				return new Response(
					JSON.stringify({
						txid: fakeSpend,
						vin: [{ txid: funding, vout: 0 }],
						vout: [{ scriptpubkey: "0014" + "55".repeat(20) }],
					}),
				);
			}
			return undefined;
		});

		try {
			await syncFromExplorer({
				chain,
				forceFromHeight: 110,
				recipientKeys: keys,
				silentPaymentAddress: address,
			});
			expect(await getUnspentSilentPaymentUtxos(chain.id, address)).toEqual([]);

			mempool = [];
			setSystemTime(new Date(Date.now() + 3 * 60 * 60 * 1000));
			await syncFromExplorer({ chain, recipientKeys: keys, silentPaymentAddress: address });
		} finally {
			setSystemTime();
		}

		expect((await getUnspentSilentPaymentUtxos(chain.id, address)).map((u) => u.txid)).toEqual([
			funding,
		]);
	});

	it("keeps a spend made at broadcast once a scanned block confirms it", async () => {
		const { blockTx, validTx } = buildPaymentTx(keys, 0x82);
		const spend = encodeRawElementsTransaction({
			vin: [{ txid: validTx.txid, vout: 0, witness: ["aa".repeat(64)] }],
			vout: [{ scriptPubKeyHex: "0014" + "55".repeat(20), valueSats: 1 }],
		});
		const spendTx: BlockTx = {
			json: {
				txid: spend.txid,
				vin: [{ txid: validTx.txid, vout: 0, witness: ["aa".repeat(64)] }],
				vout: [{ scriptpubkey: "0014" + "55".repeat(20) }],
			},
			rawHex: spend.rawHex,
		};
		globalThis.fetch = fakeExplorer(110, { 105: [blockTx], 107: [spendTx] }, () => undefined);
		await syncFromExplorer({
			chain,
			forceFromHeight: 101,
			maxBlocks: 5,
			recipientKeys: keys,
			silentPaymentAddress: address,
		});
		// The wallet spent it before the scan reached the spending block, three hours ago.
		const threeHoursAgo = Date.now() - 3 * 60 * 60 * 1000;
		setSystemTime(new Date(threeHoursAgo));
		await markSilentPaymentUtxoSpent(validTx.txid, 0, spend.txid, {
			blockTime: null,
			confirmed: false,
		});
		setSystemTime();

		await syncFromExplorer({ chain, recipientKeys: keys, silentPaymentAddress: address });

		const [tracked] = await getTrackedSilentPaymentUtxos();
		expect(tracked).toMatchObject({
			spent: true,
			spentBlockTime: 1_700_000_000 + 107 * 60,
			spentInTxid: spend.txid,
		});
		expect(tracked!.spentSeenAt).toBeUndefined();
	});

	describe("first scan of a restored wallet", () => {
		const restoredScan = (
			earliest: number | undefined,
			calls: { count: number },
			walletCreatedAt?: number,
		) =>
			syncFromExplorer({
				chain,
				maxBlocks: 10,
				recipientKeys: keys,
				restoredWallet: {
					earliestTxHeight: async () => {
						calls.count += 1;
						return earliest;
					},
					walletCreatedAt,
				},
				silentPaymentAddress: address,
			});
		/** The fake explorer's block time at `height`, in ms. */
		const timeOfBlock = (height: number) => (1_700_000_000 + height * 60) * 1000;

		it("starts a day before the date the user gave", async () => {
			globalThis.fetch = fakeExplorer(5000, {}, () => undefined);

			await restoredScan(undefined, { count: 0 }, timeOfBlock(4000));

			expect(await getSilentPaymentBirthday(chain.id, address)).toBe(4000 - RESTORED_MARGIN_BLOCKS);
		});

		it("starts before the earliest transaction when it is older than the date given", async () => {
			globalThis.fetch = fakeExplorer(5000, {}, () => undefined);

			await restoredScan(3000, { count: 0 }, timeOfBlock(4000));

			expect(await getSilentPaymentBirthday(chain.id, address)).toBe(3000 - RESTORED_MARGIN_BLOCKS);
		});

		it("starts before the date given when it is older than the earliest transaction", async () => {
			globalThis.fetch = fakeExplorer(5000, {}, () => undefined);

			await restoredScan(4500, { count: 0 }, timeOfBlock(3000));

			expect(await getSilentPaymentBirthday(chain.id, address)).toBe(3000 - RESTORED_MARGIN_BLOCKS);
		});

		it("starts a day before its earliest transaction", async () => {
			globalThis.fetch = fakeExplorer(2000, {}, () => undefined);

			await restoredScan(1800, { count: 0 });

			expect(await getSilentPaymentBirthday(chain.id, address)).toBe(1800 - RESTORED_MARGIN_BLOCKS);
			// More than a day behind: scanned newest first, down to the birthday.
			expect((await getSilentPaymentBlockCursor(chain.id, address))?.height).toBe(2000);
			expect(await getSilentPaymentBackfill(chain.id, address)).toMatchObject({
				nextHeight: 1990,
				stopHeight: 1800 - RESTORED_MARGIN_BLOCKS,
				topHeight: 2000,
			});
		});

		it("goes 30 days back without any transaction", async () => {
			globalThis.fetch = fakeExplorer(2000, {}, () => undefined);

			await restoredScan(undefined, { count: 0 });

			expect(await getSilentPaymentBirthday(chain.id, address)).toBe(
				Math.max(0, 2000 - RESTORED_LOOKBACK_BLOCKS),
			);
		});

		it("keeps an existing birthday and does not read the history", async () => {
			globalThis.fetch = fakeExplorer(2000, {}, () => undefined);
			await rescanFromExplorer({ birthdayHeight: 1990, chain, silentPaymentAddress: address });
			const calls = { count: 0 };

			await restoredScan(100, calls);

			expect(calls.count).toBe(0);
			expect(await getSilentPaymentBirthday(chain.id, address)).toBe(1990);
		});

		it("still starts at the date given when a catch-up retries a first run that failed", async () => {
			let headerFailures = 1;
			globalThis.fetch = fakeExplorer(5000, {}, (path) => {
				// The first header request, while it looks for the block of the date, fails.
				if (/\/blocks\/\d+$/.test(path) && headerFailures > 0) {
					headerFailures -= 1;
					return new Response("gone", { status: 404 });
				}
				return undefined;
			});

			await startExplorerCatchUp({
				chain,
				recipientKeys: keys,
				restoredWallet: {
					earliestTxHeight: async () => undefined,
					walletCreatedAt: timeOfBlock(4000),
				},
				retryDelayMs: 0,
				silentPaymentAddress: address,
			});

			expect(headerFailures).toBe(0);
			expect(await getSilentPaymentBirthday(chain.id, address)).toBe(4000 - RESTORED_MARGIN_BLOCKS);
		});

		it("scans a new wallet from the tip", async () => {
			globalThis.fetch = fakeExplorer(2000, {}, () => undefined);

			await syncFromExplorer({ chain, recipientKeys: keys, silentPaymentAddress: address });

			expect(await getSilentPaymentBirthday(chain.id, address)).toBe(
				2000 - DEFAULT_LOOKBACK_BLOCKS + 1,
			);
		});
	});
});

describe("heightAtOrBefore", () => {
	const realFetch = globalThis.fetch;
	const api = "https://esplora.test/api";
	const base = 1_700_000_000;
	/** Headers whose time is `timeOf(height)`. */
	const explorerWithTimes = (tip: number, timeOf: (height: number) => number | undefined) => {
		const requests: string[] = [];
		globalThis.fetch = fakeExplorer(
			tip,
			{},
			() => undefined,
			requests,
			(header) => ({
				...header,
				timestamp: timeOf(header.height as number),
			}),
		);
		return requests;
	};

	beforeEach(() => {
		resetExplorerLimiterForTesting({ requestsPerSecond: Infinity });
	});

	afterEach(() => {
		globalThis.fetch = realFetch;
	});

	it("finds the block of a time at a block a minute", async () => {
		const requests = explorerWithTimes(5000, (h) => base + h * 60);

		expect(await heightAtOrBefore(api, 5000, base + 4000 * 60)).toBe(4000);
		expect(requests.length).toBe(2);
	});

	it("finds it in a few steps when blocks come faster than a minute", async () => {
		const requests = explorerWithTimes(5000, (h) => base + h * 30);

		expect(await heightAtOrBefore(api, 5000, base + 4000 * 30)).toBe(4000);
		expect(requests.length).toBe(3);
	});

	it("lands before the time across a gap in blocks", async () => {
		// No blocks for a day after block 2999.
		explorerWithTimes(5000, (h) => base + h * 60 + (h >= 3000 ? 86_400 : 0));

		const height = await heightAtOrBefore(api, 5000, base + 2500 * 60);

		expect(height).toBeLessThanOrEqual(2500);
		expect(height).toBeGreaterThanOrEqual(2500 - RESTORED_MARGIN_BLOCKS);
	});

	it("reaches the time when block times keep understating the rate", async () => {
		// Blocks come ever slower towards the tip, so the rate between the last two blocks seen
		// always says fewer blocks lie behind than do.
		const requests = explorerWithTimes(50_000, (h) => base + Math.floor((h * h) / 1000));
		const target = base + Math.floor((1000 * 1000) / 1000);

		const height = await heightAtOrBefore(api, 50_000, target);

		expect(height).toBeGreaterThan(0);
		expect(height).toBeLessThanOrEqual(1000);
		expect(requests.length).toBeLessThanOrEqual(24);
	});

	it("is the tip for a time after it, the genesis block for one before the chain", async () => {
		explorerWithTimes(5000, (h) => base + h * 60);

		expect(await heightAtOrBefore(api, 5000, base + 6000 * 60)).toBe(5000);
		expect(await heightAtOrBefore(api, 5000, base - 1000)).toBe(0);
	});

	it("fails when the explorer gives no block time", async () => {
		explorerWithTimes(5000, () => undefined);

		await expect(heightAtOrBefore(api, 5000, base)).rejects.toThrow("no time for block 5000");
	});
});

describe("fetchAllBlockTransactions", () => {
	const realFetch = globalThis.fetch;
	const api = "https://esplora.test/api";
	const hash = "ab".repeat(32);
	const txs = (from: number, count: number) =>
		Array.from({ length: count }, (_, i) => ({ txid: `tx${from + i}`, vin: [], vout: [] }));

	/** Pages of a block with `total` transactions, until `release` is called; `pageOverride` replaces one. */
	function pagedExplorer(total: number, pageOverride?: (start: number) => unknown[] | undefined) {
		const requested: number[] = [];
		let release = () => {};
		const released = new Promise<void>((resolve) => {
			release = resolve;
		});
		globalThis.fetch = (async (input: string) => {
			const match = /\/block\/[0-9a-f]{64}\/txs(?:\/(\d+))?$/.exec(new URL(input).pathname);
			const start = Number(match?.[1] ?? 0);
			requested.push(start);
			await released;
			const page = pageOverride?.(start) ?? txs(start, Math.max(0, Math.min(25, total - start)));
			return new Response(JSON.stringify(page), { status: 200 });
		}) as unknown as typeof fetch;
		return { release, requested };
	}

	beforeEach(() => {
		resetExplorerLimiterForTesting({ requestsPerSecond: Infinity });
	});

	afterEach(() => {
		globalThis.fetch = realFetch;
		resetExplorerLimiterForTesting();
	});

	it("asks for every page of a block at once when its header gives the count", async () => {
		const explorer = pagedExplorer(60);

		const listing = fetchAllBlockTransactions(api, hash, undefined, 60);
		await new Promise((resolve) => setTimeout(resolve, 20));
		// All three pages are out before the first one answers.
		expect(explorer.requested.toSorted((a, b) => a - b)).toEqual([0, 25, 50]);
		explorer.release();

		expect((await listing).map((tx) => tx.txid)).toEqual(txs(0, 60).map((tx) => tx.txid));
	});

	it("refuses a page that does not hold its share of the block", async () => {
		const explorer = pagedExplorer(60, (start) => (start === 25 ? txs(25, 24) : undefined));
		explorer.release();

		await expect(fetchAllBlockTransactions(api, hash, 0, 60)).rejects.toThrow(
			"holds 24 transactions, not 25",
		);
	});

	it("pages one after another until a short page without a count", async () => {
		const explorer = pagedExplorer(60);
		explorer.release();

		expect(await fetchAllBlockTransactions(api, hash)).toHaveLength(60);
		expect(explorer.requested).toEqual([0, 25, 50]);
	});
});

describe("spentOutpointFingerprint", () => {
	const txid = "ab".repeat(32);
	const salted = (salt: string) => spentOutpointFingerprint({ salt }, txid, 1);

	it("depends on the index's salt, so it cannot be predicted without it", () => {
		expect(salted("01".repeat(32))).not.toBe(salted("02".repeat(32)));
		expect(salted("01".repeat(32))).not.toBe(
			bytesToHex(sha256(new TextEncoder().encode(`${txid}:1`)).subarray(0, 8)),
		);
		expect(salted("01".repeat(32))).toMatch(/^[0-9a-f]{16}$/);
	});

	it("is the same for an outpoint however its txid is cased", () => {
		expect(spentOutpointFingerprint({ salt: "01" }, txid.toUpperCase(), 1)).toBe(
			spentOutpointFingerprint({ salt: "01" }, txid, 1),
		);
	});
});
