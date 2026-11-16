import {
	deriveBlindingKey,
	encodeTaprootAddress,
	hasTaprootOutput,
	parseRawElementsBlock,
	parseRawElementsTransaction,
	precomputeLabelPoints,
	scanTxForRecipient,
	type SpTransaction,
	zeroizeBuffer,
} from "@humid/sp-core";
import { numberToBytesBE } from "@noble/curves/utils.js";
import { hmac } from "@noble/hashes/hmac.js";
import { sha256 } from "@noble/hashes/sha2.js";
import { bytesToHex, hexToBytes, randomBytes, utf8ToBytes } from "@noble/hashes/utils.js";

import type { LiquidChainRecord } from "../chains/LiquidChainRecord";
import {
	buildExplorerApis,
	describeExplorerError,
	fallbackExplorerUnreachable,
	ExplorerBudgetError,
	explorerBudgetLeftForHistory,
	explorerBudgetSpent,
	explorerRequestsStarted,
	fetchOutspend,
	fetchTxHex,
	fetchFromExplorer,
	fetchWithRetryAndBackoff,
	pickExplorerApi,
	probeUnreachableExplorers,
	restoreExplorerLimiters,
	sessionArea,
	sustainedExplorerRequestRate,
	usableExplorerApis,
	resolveMissingPrevouts,
} from "./explorer";
import { MAX_SILENT_PAYMENT_LABELS, SP_CHANGE_LABEL_INDICES } from "./labelLimits";
import { adoptSilentPaymentLabels } from "./labels";
import {
	clearSilentPaymentSpendCheck,
	expireUnconfirmedSilentPaymentSpend,
	forgetSilentPaymentUtxo,
	getSilentPaymentBackfill,
	getSilentPaymentBirthday,
	getSilentPaymentBlockCursor,
	getSilentPaymentLabels,
	getSilentPaymentSpentIndex,
	getTrackedSilentPaymentUtxos,
	isSilentPaymentStoreUnlocked,
	markSilentPaymentSpendsUnverified,
	markSilentPaymentUtxoSpent,
	rollBackSilentPaymentBlocks,
	saveSilentPaymentBackfill,
	saveSilentPaymentBirthday,
	saveSilentPaymentBlockCursor,
	saveSilentPaymentSpentIndex,
	saveTrackedSilentPaymentUtxo,
	setSilentPaymentLocalScanProgress,
	type SilentPaymentBackfill,
	type SilentPaymentSpentIndex,
	type TrackedSilentPaymentUtxo,
} from "./store";
import type { SilentPaymentRecipientKeys } from "./types";
import { type UnblindedOutput, unblindConfidentialOutput } from "./unblind";

export const DEFAULT_LOOKBACK_BLOCKS = 10;
/**
 * A restored wallet may have received Silent Payments long before this install: its first scan
 * starts a day (Liquid: 1 block a minute) before its earliest LWK transaction, or 30 days back
 * when it has none.
 */
export const RESTORED_MARGIN_BLOCKS = 24 * 60;
export const RESTORED_LOOKBACK_BLOCKS = 30 * 24 * 60;
/** Hard cap on blocks per run; the time budget below usually ends a run first. */
export const MAX_SCAN_BLOCKS_PER_RUN = 1000;
/** A run stops taking new block windows after this long, so it fits between 1-minute refreshes. */
export const SCAN_TIME_BUDGET_MS = 20_000;
/**
 * A background catch-up runs longer: each run starts with a few requests of its own (tip, reorg
 * check, mempool), which a long backlog should not pay every 20 seconds.
 */
export const CATCH_UP_TIME_BUDGET_MS = 120_000;
export const CATCH_UP_MAX_BLOCKS_PER_RUN = 5000;
/**
 * A gap behind the tip longer than this (a day of Liquid blocks) is scanned newest first, so
 * recent payments show without waiting for the whole history.
 */
export const BACKFILL_THRESHOLD_BLOCKS = 24 * 60;
/**
 * How far a backfill steps back up when a block does not link to the one above it: Liquid blocks
 * are final after two confirmations, so a reorg never goes deeper.
 */
const BACKFILL_REWIND_BLOCKS = 10;
/** Rewinds a run allows before it halts: an explorer that keeps switching chains is not followed. */
const MAX_BACKFILL_REWINDS_PER_RUN = 3;
/** Esplora's `/blocks/:height` returns this many headers, newest first. */
const BLOCK_HEADERS_PER_REQUEST = 10;
/**
 * Blocks one step of a scan lists in parallel: wide enough to keep the explorer's rate busy across
 * request latency, then scanned in order.
 */
const SCAN_WINDOW_BLOCKS = 50;
/** Block downloads (headers, JSON, raw) can take several seconds on a busy public Esplora. */
const BLOCK_FETCH_TIMEOUT_MS = 15_000;
/** Liquid mines a block a minute: checking the mempool more often adds requests, not payments. */
const MEMPOOL_SCAN_THROTTLE_MS = 60_000;
/** New mempool transactions checked per run; Liquid's mempool usually holds a handful. */
const MAX_MEMPOOL_TXS_PER_RUN = 50;
/**
 * A transaction not mined for this long is considered dropped: an output it pays is forgotten, an
 * output it spends counts as unspent again.
 */
const UNCONFIRMED_EXPIRY_MS = 2 * 60 * 60 * 1000;
/**
 * Cap on the spent index of a backfill. About 0.5% of Liquid inputs spend a Taproot output, some
 * 4,000 a month of blocks; past the cap the index is dropped and checks ask the explorer.
 */
const MAX_SPENT_INDEX_ENTRIES = 20_000;

export type EsploraBlockHeader = {
	height: number;
	id: string;
	previousblockhash?: string;
	timestamp?: number;
	tx_count?: number;
};

export type EsploraTxInput = {
	is_coinbase?: boolean;
	is_pegin?: boolean;
	prevout?: {
		scriptpubkey?: string;
		scriptpubkey_type?: string;
		value?: number;
	};
	scriptsig?: string;
	sequence?: number;
	txid: string;
	vout: number;
	witness?: string[];
};

export type EsploraTxOutput = {
	asset?: string;
	assetcommitment?: string;
	output_index?: number;
	scriptpubkey: string;
	scriptpubkey_address?: string;
	scriptpubkey_type?: string;
	value?: number;
	valuecommitment?: string;
};

export type EsploraTransaction = {
	fee?: number;
	status?: {
		block_height?: number;
		block_time?: number;
		confirmed?: boolean;
	};
	txid: string;
	vin: EsploraTxInput[];
	vout: EsploraTxOutput[];
};

export type ExplorerScanResult = {
	scannedUtxos: TrackedSilentPaymentUtxo[];
	/**
	 * `synced`: the cursor reached the tip. `partial`: the run's budget ended first. `halted`: a
	 * block failed to scan. `superseded`: a rescan reset the cursor during the run.
	 */
	status: "synced" | "partial" | "halted" | "superseded";
	tipHeight: number;
};

const activeScanPromises = new Map<string, Promise<ExplorerScanResult>>();
const activeCatchUps = new Map<string, Promise<void>>();
const lastMempoolScanAt = new Map<string, number>();
/** Mempool txids already checked, per account; pruned to what is still in the mempool. */
const seenMempoolTxids = new Map<string, Set<string>>();
/** Bumped by every rescan: a run started under an older generation must not move the cursor. */
const scanGenerations = new Map<string, number>();
/**
 * The birthday of each account's latest rescan. A run the rescan superseded in the middle of a
 * write puts the rescan's state back, as its write may have landed after the rescan's.
 */
const rescanResets = new Map<string, number>();
/** Blocks a second each account's last run scanned, for the time left the wallet shows. */
const scanRates = new Map<string, number>();
/**
 * The rates kept in `chrome.storage.session`, so a service worker woken for the next run shows the
 * time left at once instead of after its first blocks.
 */
const SCAN_RATES_SESSION_KEY = "humid_sp_scan_rates";
/** A rate older than this says little: the explorer's load may have changed since. */
const PERSISTED_SCAN_RATE_TTL_MS = 30 * 60_000;
/** Progress updates come every few blocks; the stored rate needs far fewer writes. */
const SCAN_RATE_PERSIST_INTERVAL_MS = 10_000;
let scanRatesRestored: Promise<void> | undefined;
let persistedScanRates: Record<string, { rate: number; savedAt: number }> = {};
let scanRatesPersistedAt = 0;

/** Read the stored rates once per service worker; best effort. */
function restoreScanRates(): Promise<void> {
	scanRatesRestored ??= (async () => {
		try {
			const stored = (await sessionArea()?.get(SCAN_RATES_SESSION_KEY))?.[SCAN_RATES_SESSION_KEY];
			if (!stored || typeof stored !== "object") return;
			persistedScanRates = stored as typeof persistedScanRates;
			for (const [key, { rate, savedAt }] of Object.entries(persistedScanRates)) {
				const fresh = Date.now() - Number(savedAt) < PERSISTED_SCAN_RATE_TTL_MS;
				if (fresh && Number(rate) > 0 && !scanRates.has(key)) scanRates.set(key, Number(rate));
			}
		} catch {
			// Nothing stored: the time left shows once a run has scanned a few blocks.
		}
	})();
	return scanRatesRestored;
}

/** Note an account's scan rate, and store it now and then for the next service worker. */
function rememberScanRate(scanKey: string, rate: number): void {
	scanRates.set(scanKey, rate);
	const area = sessionArea();
	if (!area || Date.now() - scanRatesPersistedAt < SCAN_RATE_PERSIST_INTERVAL_MS) return;
	scanRatesPersistedAt = Date.now();
	persistedScanRates[scanKey] = { rate, savedAt: Date.now() };
	area.set({ [SCAN_RATES_SESSION_KEY]: persistedScanRates }).catch(() => {});
}

/**
 * Blocks a second the account's scan last ran at, kept across service worker restarts for a while;
 * undefined before any run has a rate.
 */
export async function getSilentPaymentScanRate(
	chainId: string,
	silentPaymentAddress: string,
): Promise<number | undefined> {
	await restoreScanRates();
	return scanRates.get(buildScanKey(chainId, silentPaymentAddress));
}

/** Unblinds a matched output; replaced only by tests, which cannot build confidential outputs. */
let unblindOutput = unblindConfidentialOutput;

/** Test-only: forget mempool throttles, checked mempool txids and rescan generations. */
export function resetLocalScannerForTesting(): void {
	lastMempoolScanAt.clear();
	seenMempoolTxids.clear();
	scanGenerations.clear();
	rescanResets.clear();
	scanRates.clear();
	scanRatesRestored = undefined;
	persistedScanRates = {};
	scanRatesPersistedAt = 0;
	unblindOutput = unblindConfidentialOutput;
}

/** Test-only: unblind matched outputs with `unblind` until the next reset. */
export function setUnblindForTesting(unblind: typeof unblindConfidentialOutput): void {
	unblindOutput = unblind;
}

function buildScanKey(chainId: string, silentPaymentAddress: string): string {
	return `${chainId}_${silentPaymentAddress.toLowerCase()}`;
}

function esploraTxToSpTx(tx: EsploraTransaction): SpTransaction {
	return {
		txid: tx.txid,
		vin: (tx.vin ?? []).map((v) => ({
			isCoinbase: v.is_coinbase,
			isPegin: v.is_pegin,
			prevoutScriptPubKey: v.prevout?.scriptpubkey,
			prevoutScriptPubKeyType: v.prevout?.scriptpubkey_type,
			scriptsig: v.scriptsig,
			txid: v.txid,
			vout: v.vout,
			witness: v.witness,
		})),
		vout: (tx.vout ?? []).map((out, i) => ({
			asset: out.asset,
			outputIndex: out.output_index ?? i,
			scriptPubKey: out.scriptpubkey,
			value: out.value,
		})),
	};
}

/** Esplora lists a block's transactions 25 to a page. */
const BLOCK_TXS_PAGE_SIZE = 25;
const MAX_BLOCK_TXS_PAGES = 200;

/**
 * Fetch all transactions in a block from Esplora, handling 25-tx pagination. With the block's
 * `txCount` from its header every page is requested at once (the explorer limiter still paces
 * them); without it the pages follow one another until a short one.
 */
export async function fetchAllBlockTransactions(
	explorerApi: string,
	blockHash: string,
	maxRetries?: number,
	txCount?: number,
): Promise<EsploraTransaction[]> {
	const fetchPage = async (startIndex: number): Promise<EsploraTransaction[]> => {
		const url =
			startIndex === 0
				? `${explorerApi}/block/${blockHash}/txs`
				: `${explorerApi}/block/${blockHash}/txs/${startIndex}`;
		const res = await fetchWithRetryAndBackoff(url, undefined, BLOCK_FETCH_TIMEOUT_MS, maxRetries);
		if (!res.ok) {
			throw new Error(`Failed to fetch block transactions from ${url}: status ${res.status}`);
		}
		const page = (await res.json()) as EsploraTransaction[];
		if (!Array.isArray(page)) {
			throw new Error(`Expected array of transactions from ${url}`);
		}
		return page;
	};
	const tooManyPages = () =>
		new Error(
			`Block transaction pagination exceeded safety limit of ${MAX_BLOCK_TXS_PAGES} pages for block ${blockHash}`,
		);

	if (txCount !== undefined && Number.isInteger(txCount) && txCount > 0) {
		const pageCount = Math.ceil(txCount / BLOCK_TXS_PAGE_SIZE);
		if (pageCount > MAX_BLOCK_TXS_PAGES) throw tooManyPages();
		const pages = await Promise.all(
			Array.from({ length: pageCount }, (_, i) => fetchPage(i * BLOCK_TXS_PAGE_SIZE)),
		);
		// Each page must hold exactly its share: a page of other size means another paging scheme
		// or a block that changed under us, and a gap would hide transactions.
		pages.forEach((page, i) => {
			const expected = Math.min(BLOCK_TXS_PAGE_SIZE, txCount - i * BLOCK_TXS_PAGE_SIZE);
			if (page.length !== expected) {
				throw new Error(
					`Explorer page ${i} of block ${blockHash} holds ${page.length} transactions, not ${expected}`,
				);
			}
		});
		return pages.flat();
	}

	const allTxs: EsploraTransaction[] = [];
	for (let pageIndex = 0; ; pageIndex++) {
		if (pageIndex >= MAX_BLOCK_TXS_PAGES) throw tooManyPages();
		const page = await fetchPage(allTxs.length);
		allTxs.push(...page);
		if (page.length < BLOCK_TXS_PAGE_SIZE) break;
	}
	return allTxs;
}

/**
 * Fetch the headers of blocks `fromHeight..toHeight` (at most one `/blocks/:height` page) in
 * ascending order. Throws unless they are contiguous and each links to the previous one.
 */
export async function fetchBlockHeaders(
	explorerApi: string,
	fromHeight: number,
	toHeight: number,
): Promise<EsploraBlockHeader[]> {
	const url = `${explorerApi}/blocks/${toHeight}`;
	const res = await fetchWithRetryAndBackoff(url, undefined, BLOCK_FETCH_TIMEOUT_MS);
	if (!res.ok) {
		throw new Error(`Failed to fetch block headers from ${url}: status ${res.status}`);
	}
	const page = (await res.json()) as EsploraBlockHeader[];
	if (!Array.isArray(page)) {
		throw new Error(`Expected array of blocks from ${url}`);
	}

	const headers = page
		.filter(
			(b) => b && typeof b.height === "number" && b.height >= fromHeight && b.height <= toHeight,
		)
		.sort((a, b) => a.height - b.height);
	if (headers.length !== toHeight - fromHeight + 1) {
		throw new Error(
			`Explorer returned ${headers.length} headers for heights ${fromHeight}-${toHeight}`,
		);
	}
	headers.forEach((b, i) => {
		if (typeof b.id !== "string" || !/^[0-9a-f]{64}$/i.test(b.id) || b.height !== fromHeight + i) {
			throw new Error(`Explorer returned a malformed header at height ${fromHeight + i}`);
		}
		if (i > 0 && b.previousblockhash !== headers[i - 1]!.id) {
			throw new Error(`Block ${b.height} does not link to block ${b.height - 1}`);
		}
	});

	return headers;
}

/**
 * The raw transaction with the prevouts the explorer's JSON lists for it. The raw bytes are
 * authoritative (their hash is the txid, and a block's are committed to by its header); the JSON
 * only supplies each input's previous scriptPubKey, which ELIP-352 input selection needs.
 */
function withEsploraPrevouts(raw: SpTransaction, json: EsploraTransaction): SpTransaction {
	if (json.txid?.toLowerCase() !== raw.txid || json.vin?.length !== raw.vin.length) {
		throw new Error(`[sp-local-scanner] Explorer JSON does not describe transaction ${raw.txid}`);
	}
	return {
		...raw,
		vin: raw.vin.map((input, i) => {
			const listed = json.vin[i]!;
			if (
				!input.isCoinbase &&
				(listed.txid.toLowerCase() !== input.txid || listed.vout !== input.vout)
			) {
				throw new Error(
					`[sp-local-scanner] Explorer JSON lists another input ${i} for ${raw.txid}`,
				);
			}
			return {
				...input,
				prevoutScriptPubKey: listed.prevout?.scriptpubkey,
				prevoutScriptPubKeyType: listed.prevout?.scriptpubkey_type,
			};
		}),
	};
}

/**
 * Tracked SP outputs by outpoint that a scanned input may spend: unspent ones, and spent ones whose
 * spend has not been seen in a block yet (e.g. marked spent at broadcast).
 */
type WatchedOutpoints = Map<string, TrackedSilentPaymentUtxo>;

const outpointKey = (txid: string, vout: number) => `${txid.toLowerCase()}:${vout}`;

async function loadWatchedOutpoints(
	chainId: string,
	silentPaymentAddress: string,
): Promise<WatchedOutpoints> {
	const owner = silentPaymentAddress.toLowerCase();
	const watched: WatchedOutpoints = new Map();
	for (const u of await getTrackedSilentPaymentUtxos()) {
		if (
			u.chainId === chainId &&
			u.recipientAddress.toLowerCase() === owner &&
			(!u.spent || u.spentBlockTime == null)
		) {
			watched.set(outpointKey(u.txid, u.outputIndex), u);
		}
	}
	return watched;
}

/**
 * The transaction's explicit fee output (an empty scriptPubKey). Liquid relays fees in L-BTC only,
 * so without a configured policy asset the first fee output is it.
 */
function explicitFeeSats(tx: SpTransaction, policyAsset: string | undefined): string | undefined {
	const fee = tx.vout.find(
		(o) =>
			o.scriptPubKey === "" &&
			o.value !== undefined &&
			(policyAsset === undefined || o.asset === policyAsset),
	);
	return fee?.value?.toString();
}

/**
 * Mark tracked outputs `tx` spends as spent, with the spend's block time and fee, so a send the LWK
 * wallet does not see still shows in the activity feed. A mempool spend (`confirmed: false`) stays
 * watched until a scanned block confirms it, and expires if none does.
 */
async function markSpentOutpoints(
	tx: SpTransaction,
	watched: WatchedOutpoints,
	{
		blockHeight,
		blockTime,
		confirmed,
	}: { blockHeight?: number; blockTime: number | null; confirmed: boolean },
	policyAsset: string | undefined,
): Promise<void> {
	for (const input of tx.vin) {
		const key = outpointKey(input.txid, input.vout);
		const tracked = watched.get(key);
		if (!tracked) continue;
		await markSilentPaymentUtxoSpent(tracked.txid, tracked.outputIndex, tx.txid, {
			blockHeight,
			blockTime,
			confirmed,
			feeSats: explicitFeeSats(tx, policyAsset),
		});
		if (confirmed) watched.delete(key);
	}
}

/**
 * Headers of `fromHeight..toHeight`, any length: pages of ten fetched in parallel, then checked to
 * form one chain.
 */
async function fetchHeaderRange(
	explorerApi: string,
	fromHeight: number,
	toHeight: number,
): Promise<EsploraBlockHeader[]> {
	const pages: Array<Promise<EsploraBlockHeader[]>> = [];
	for (let from = fromHeight; from <= toHeight; from += BLOCK_HEADERS_PER_REQUEST) {
		pages.push(
			fetchBlockHeaders(
				explorerApi,
				from,
				Math.min(toHeight, from + BLOCK_HEADERS_PER_REQUEST - 1),
			),
		);
	}
	const headers = (await Promise.all(pages)).flat();
	headers.forEach((b, i) => {
		if (i > 0 && b.previousblockhash !== headers[i - 1]!.id) {
			throw new Error(`Block ${b.height} does not link to block ${b.height - 1}`);
		}
	});
	return headers;
}

/**
 * Check one transaction for ELIP-352 Silent Payment outputs paying `recipientKeys`, unblind and
 * store any matched output, and mark tracked outputs it spends as spent. `rawHex` is the
 * transaction's own serialization, fetched for every candidate before matching, so no request
 * reveals which transaction matched.
 */
async function scanTransaction({
	blockHeight,
	blockTime,
	chain,
	confirmed,
	explorerApi,
	knownLabels,
	labelMap,
	otherCopy,
	rawHex,
	recipientKeys,
	silentPaymentAddress,
	spendUnverified = false,
	tx,
	unspent,
}: {
	/** The block's height; absent for a mempool transaction. */
	blockHeight?: number;
	blockTime: number | null;
	chain: LiquidChainRecord;
	confirmed: boolean;
	explorerApi: string;
	/** Label indices the account's label list holds; a payment to another one adds it. */
	knownLabels: Set<number>;
	labelMap: Map<string, { labelIndex: number; labelTweak: bigint }>;
	/** A transaction's raw hex from another explorer's copy of its block; null without one. */
	otherCopy?: (txid: string) => Promise<string | null>;
	rawHex: string;
	recipientKeys: SilentPaymentRecipientKeys;
	silentPaymentAddress: string;
	/** Found newest first: whether a later block spent it is checked afterwards. */
	spendUnverified?: boolean;
	tx: SpTransaction;
	unspent: WatchedOutpoints;
}): Promise<TrackedSilentPaymentUtxo[]> {
	const { txid } = tx;
	if (!txid) {
		throw new Error("[sp-local-scanner] Cannot scan a transaction without its txid");
	}
	await markSpentOutpoints(
		tx,
		unspent,
		{ blockHeight, blockTime, confirmed },
		chain.settings.policyAsset,
	);
	if (!hasTaprootOutput(tx)) {
		return [];
	}

	await resolveMissingPrevouts(tx.vin, explorerApi);

	const matches = scanTxForRecipient(
		tx,
		recipientKeys.scanKey.privateKey,
		recipientKeys.spendKey.publicKey,
		labelMap,
	);
	const discovered: TrackedSilentPaymentUtxo[] = [];

	for (const match of matches) {
		const stealthAddress = encodeTaprootAddress(match.targetXOnly, chain.settings.network);
		const { bk } = deriveBlindingKey(match.S, match.k);
		const blindingKeyHex = bytesToHex(numberToBytesBE(bk, 32));
		const unblindIn = async (hex: string) => {
			const bkBytes = numberToBytesBE(bk, 32);
			try {
				return await unblindOutput(hex, match.outputIndex, bkBytes);
			} finally {
				zeroizeBuffer(bkBytes);
			}
		};

		let unblinded: UnblindedOutput | null = await unblindIn(rawHex);
		if (!unblinded && otherCopy) {
			// The block's merkle root commits to txids, not to witnesses, where the rangeproofs lie:
			// another explorer's copy of the block may unblind where this one did not.
			const other = await otherCopy(txid);
			if (other && other !== rawHex) unblinded = await unblindIn(other);
		}

		const utxo: TrackedSilentPaymentUtxo = {
			address: stealthAddress,
			amountSats: unblinded?.amountSats ?? "0",
			assetBlindingFactorHex: unblinded?.assetBlindingFactorHex,
			blindingKeyHex,
			...(blockHeight !== undefined ? { blockHeight } : {}),
			blockTime,
			chainId: chain.id,
			confirmed,
			createdAt: Date.now(),
			labelIndex: match.labelIndex,
			labelTweakHex:
				match.labelTweak !== undefined
					? bytesToHex(numberToBytesBE(match.labelTweak, 32))
					: undefined,
			outputIndex: match.outputIndex,
			rawAssetId: unblinded?.rawAssetId ?? "",
			recipientAddress: silentPaymentAddress,
			scriptPubKeyHex: match.scriptPubKeyHex,
			scriptType: "p2tr",
			spent: false,
			tweakHex: bytesToHex(numberToBytesBE(match.tk, 32)),
			txid: txid,
			unblindFailed: !unblinded,
			...(spendUnverified ? { spendUnverified: true as const } : {}),
			valueBlindingFactorHex: unblinded?.valueBlindingFactorHex,
		};
		await saveTrackedSilentPaymentUtxo(utxo);
		unspent.set(outpointKey(utxo.txid, utxo.outputIndex), utxo);
		const { labelIndex } = match;
		if (labelIndex !== undefined && labelIndex > 0 && !knownLabels.has(labelIndex)) {
			// A payment to a label the list lost (a restored wallet): show the label again.
			await adoptSilentPaymentLabels({
				chain,
				labelIndices: [labelIndex],
				recipientKeys,
				silentPaymentAddress,
			});
			knownLabels.add(labelIndex);
		}
		discovered.push(utxo);
	}

	return discovered;
}

/** What one run of the scanner works with, shared by its block and spend checks. */
type ScanContext = {
	chain: LiquidChainRecord;
	explorerApis: string[];
	knownLabels: Set<number>;
	labelMap: Map<string, { labelIndex: number; labelTweak: bigint }>;
	recipientKeys: SilentPaymentRecipientKeys;
	silentPaymentAddress: string;
	/** Spends in the blocks scanned since the backfill began; null without one. */
	spentIndex: SilentPaymentSpentIndex | null;
	unspent: WatchedOutpoints;
};

const TAPROOT_SCRIPT_PUBKEY = /^5120[0-9a-f]{64}$/i;

/**
 * Key of a spent outpoint in the spent index: 64 bits of its HMAC under the index's salt. A plain
 * hash would let a sender who knows an output of the wallet (they paid it) grind a spend of their
 * own whose 64 bits match, and the index would show the wallet's output as spent.
 */
export function spentOutpointFingerprint(
	index: Pick<SilentPaymentSpentIndex, "salt">,
	txid: string,
	vout: number,
): string {
	const message = utf8ToBytes(outpointKey(txid, vout));
	return bytesToHex(hmac(sha256, hexToBytes(index.salt), message).subarray(0, 8));
}

/**
 * Add the spends of Taproot outputs in listed blocks to the index. Returns whether it changed; an
 * index that outgrows `MAX_SPENT_INDEX_ENTRIES` is emptied and marked `overflow`.
 */
function indexSpends(
	index: SilentPaymentSpentIndex,
	headers: EsploraBlockHeader[],
	listings: Array<PromiseSettledResult<BlockListing>>,
): boolean {
	if (index.overflow) return false;
	let changed = false;
	headers.forEach((header, i) => {
		const listing = listings[i];
		if (listing?.status !== "fulfilled") return;
		for (const tx of listing.value.listed) {
			for (const input of tx.vin ?? []) {
				// An input the listing gives no prevout for may spend an SP output: indexed, as
				// `needsRawBlock` takes it for a candidate. A peg-in spends a Bitcoin output.
				const spk = input.prevout?.scriptpubkey;
				if (
					input.is_coinbase ||
					input.is_pegin ||
					(spk ? !TAPROOT_SCRIPT_PUBKEY.test(spk) : false)
				) {
					continue;
				}
				index.entries[spentOutpointFingerprint(index, input.txid, input.vout)] = [
					tx.txid.toLowerCase(),
					header.timestamp ?? null,
					typeof tx.fee === "number" ? String(tx.fee) : null,
					header.height,
				];
				changed = true;
			}
		}
	});
	if (Object.keys(index.entries).length > MAX_SPENT_INDEX_ENTRIES) {
		index.entries = {};
		index.overflow = true;
	}
	return changed;
}

/**
 * Drop the spends the index holds from blocks `fromHeight..toHeight`, which a rewind is about to
 * rescan: a spend in a replaced block must not outlive it. Returns whether the index changed.
 */
function dropIndexedSpends(
	index: SilentPaymentSpentIndex,
	fromHeight: number,
	toHeight: number,
): boolean {
	let changed = false;
	for (const [key, [, , , height]] of Object.entries(index.entries)) {
		if (height >= fromHeight && height <= toHeight) {
			delete index.entries[key];
			changed = true;
		}
	}
	return changed;
}

/**
 * Settle whether outputs waiting on a spend check were spent, from the spent index: every block
 * after them has been scanned into it, so no request names an output. Without a usable index (it
 * overflowed, or there is none) the explorer is asked, as `verifySpends` does.
 */
async function checkSpends(ctx: ScanContext, outputs: TrackedSilentPaymentUtxo[]): Promise<void> {
	const index = ctx.spentIndex;
	if (!index || index.overflow) {
		await verifySpends(ctx, outputs);
		return;
	}
	for (const u of outputs) {
		const key = outpointKey(u.txid, u.outputIndex);
		// A spend in a scanned block already marked it (and stopped watching it).
		if (!ctx.unspent.has(key)) continue;
		const spend = index.entries[spentOutpointFingerprint(index, u.txid, u.outputIndex)];
		if (!spend) {
			await clearSilentPaymentSpendCheck(u.txid, u.outputIndex);
			continue;
		}
		const [spentInTxid, blockTime, feeSats, blockHeight] = spend;
		// With its height, a reorg of that block undoes the spend locally, as it does a scanned one.
		await markSilentPaymentUtxoSpent(u.txid, u.outputIndex, spentInTxid, {
			blockHeight,
			blockTime,
			confirmed: true,
			feeSats: feeSats ?? undefined,
		});
		ctx.unspent.delete(key);
	}
}

/** The account's outputs waiting on a spend check. */
async function getUnverifiedOutputs(
	chainId: string,
	silentPaymentAddress: string,
): Promise<TrackedSilentPaymentUtxo[]> {
	const owner = silentPaymentAddress.toLowerCase();
	return (await getTrackedSilentPaymentUtxos()).filter(
		(u) =>
			u.chainId === chainId &&
			u.recipientAddress.toLowerCase() === owner &&
			u.spendUnverified &&
			!u.spent,
	);
}

/**
 * Whether a listed block transaction needs the raw block: it could pay or spend an SP output, as
 * it has a Taproot output, or an input spending a Taproot output, a watched one, or one its listing
 * gives no prevout for. Such a block is fetched whole whether or not it pays the account (about a
 * fifth of Liquid blocks qualify), so the explorer cannot tell the blocks that pay or spend the
 * wallet's outputs from the other candidates; the match runs on the raw transactions its header
 * commits to. Other blocks cost one JSON request.
 */
function needsRawBlock(listed: EsploraTransaction, ctx: ScanContext): boolean {
	if ((listed.vout ?? []).some((o) => TAPROOT_SCRIPT_PUBKEY.test(o.scriptpubkey ?? ""))) {
		return true;
	}
	return (listed.vin ?? []).some(
		(v) =>
			!v.is_coinbase &&
			(ctx.unspent.has(outpointKey(v.txid, v.vout)) ||
				TAPROOT_SCRIPT_PUBKEY.test(v.prevout?.scriptpubkey ?? "") ||
				(!v.is_pegin && !v.prevout?.scriptpubkey)),
	);
}

type BlockListing = { api: string; listed: EsploraTransaction[] };

/**
 * A block's JSON listing, from the first usable explorer with retries (a dropped connection there
 * is usually a passing one); a block it keeps failing on is asked of each fallback once, which are
 * never loaded on purpose and may be down themselves.
 */
async function fetchListing(header: EsploraBlockHeader, ctx: ScanContext): Promise<BlockListing> {
	const order = usableExplorerApis(ctx.explorerApis);
	let lastError: unknown;
	for (const [i, api] of order.entries()) {
		try {
			const listed = await fetchAllBlockTransactions(
				api,
				header.id,
				i === 0 ? undefined : 0,
				header.tx_count,
			);
			if (header.tx_count !== undefined && listed.length !== header.tx_count) {
				throw new Error(
					`Explorer lists ${listed.length} of ${header.tx_count} transactions in block ${header.id}`,
				);
			}
			return { api, listed };
		} catch (error) {
			lastError = error;
		}
	}
	throw lastError;
}

/** Scan one listed block; the raw block is fetched only if a transaction needs it. */
async function scanListedBlock(
	header: EsploraBlockHeader,
	{ api, listed }: BlockListing,
	ctx: ScanContext,
	spendUnverified: boolean,
	/** The raw block, if its window already fetched it. */
	prefetched?: Promise<Array<{ rawHex: string; tx: SpTransaction }>>,
): Promise<TrackedSilentPaymentUtxo[]> {
	// Esplora lists the coinbase first; it has no inputs to aggregate or spend.
	if (!listed.some((tx, i) => i > 0 && needsRawBlock(tx, ctx))) return [];

	// Fetched once, and only if an output fails to unblind; a block-level request names no transaction.
	let otherBlock: Promise<Map<string, string> | null> | undefined;
	const otherCopy = async (txid: string) => {
		otherBlock ??= (async () => {
			const other = usableExplorerApis(ctx.explorerApis).find((candidate) => candidate !== api);
			if (!other) return null;
			try {
				const txs = await fetchRawBlock(other, header);
				return new Map(txs.map(({ rawHex, tx }) => [tx.txid ?? "", rawHex]));
			} catch {
				return null;
			}
		})();
		return (await otherBlock)?.get(txid) ?? null;
	};

	const found: TrackedSilentPaymentUtxo[] = [];
	for (const { rawHex, tx } of await (prefetched ?? fetchRawBlockForScan(api, header, listed))) {
		if (tx.vin[0]?.isCoinbase) continue;
		found.push(
			...(await scanTransaction({
				blockHeight: header.height,
				blockTime: header.timestamp ?? null,
				chain: ctx.chain,
				confirmed: true,
				explorerApi: api,
				knownLabels: ctx.knownLabels,
				labelMap: ctx.labelMap,
				otherCopy,
				rawHex,
				recipientKeys: ctx.recipientKeys,
				silentPaymentAddress: ctx.silentPaymentAddress,
				spendUnverified,
				tx,
				unspent: ctx.unspent,
			})),
		);
	}
	return found;
}

/** Block time and fee of a spending transaction, for the activity feed; best effort. */
async function fetchSpendDetails(
	explorerApi: string,
	txid: string,
): Promise<
	| { blockHeight?: number; blockTime: number | null; confirmed: boolean; feeSats?: string }
	| undefined
> {
	try {
		const res = await fetchFromExplorer(`${explorerApi}/tx/${txid}`);
		if (!res.ok) return undefined;
		const tx = (await res.json()) as {
			fee?: number;
			status?: { block_height?: number; block_time?: number; confirmed?: boolean };
		};
		if (typeof tx.status?.confirmed !== "boolean") return undefined;
		// A mined spend without its height could not be rolled back by a reorg of its block.
		if (tx.status.confirmed && typeof tx.status.block_height !== "number") return undefined;
		return {
			blockHeight: tx.status.confirmed ? tx.status.block_height : undefined,
			blockTime: tx.status.confirmed ? (tx.status.block_time ?? null) : null,
			confirmed: tx.status.confirmed,
			feeSats: typeof tx.fee === "number" ? String(tx.fee) : undefined,
		};
	} catch {
		return undefined;
	}
}

/**
 * Ask the explorer whether outputs a newest-first scan found were spent: the blocks after them were
 * scanned before the wallet knew them. An output without an answer stays out of the balance and is
 * asked about again on the next run. Each request names an output of the wallet: only for a
 * backfill without a usable spent index (see `checkSpends`).
 */
async function verifySpends(ctx: ScanContext, outputs: TrackedSilentPaymentUtxo[]): Promise<void> {
	for (const u of outputs) {
		const api = pickExplorerApi(ctx.explorerApis);
		const outspend = await fetchOutspend(api, u.txid, u.outputIndex);
		if (!outspend) continue;
		if (!outspend.spent) {
			await clearSilentPaymentSpendCheck(u.txid, u.outputIndex);
			continue;
		}
		const spend = outspend.txid ? await fetchSpendDetails(api, outspend.txid) : undefined;
		if (!spend) continue;
		await markSilentPaymentUtxoSpent(u.txid, u.outputIndex, outspend.txid, spend);
		// An unconfirmed spend stays watched: the block that confirms it may come in this run.
		if (spend.confirmed) ctx.unspent.delete(outpointKey(u.txid, u.outputIndex));
	}
}

/** The raw block `header` names, whose transactions its header commits to; throws otherwise. */
async function fetchRawBlock(
	explorerApi: string,
	header: EsploraBlockHeader,
): Promise<Array<{ rawHex: string; tx: SpTransaction }>> {
	const rawRes = await fetchWithRetryAndBackoff(
		`${explorerApi}/block/${header.id}/raw`,
		undefined,
		BLOCK_FETCH_TIMEOUT_MS,
	);
	if (!rawRes.ok) {
		throw new Error(`Failed to fetch raw block ${header.id}: status ${rawRes.status}`);
	}
	const block = parseRawElementsBlock(new Uint8Array(await rawRes.arrayBuffer()));
	if (block.blockHash !== header.id || block.height !== header.height) {
		throw new Error(`Explorer returned another raw block for ${header.height} (${header.id})`);
	}
	return block.txs;
}

/**
 * The raw block, whose transactions its header commits to, with the prevouts of its JSON listing.
 * Throws unless both describe `header`.
 */
async function fetchRawBlockForScan(
	explorerApi: string,
	header: EsploraBlockHeader,
	listed: EsploraTransaction[],
): Promise<Array<{ rawHex: string; tx: SpTransaction }>> {
	const txs = await fetchRawBlock(explorerApi, header);
	if (listed.length !== txs.length) {
		throw new Error(
			`Explorer lists ${listed.length} of ${txs.length} transactions in block ${header.id}`,
		);
	}

	return txs.map(({ rawHex, tx }, i) => ({
		rawHex,
		tx: withEsploraPrevouts(tx, listed[i]!),
	}));
}

/**
 * Scan the explorer's whole mempool for unconfirmed Silent Payments. Each run lists every mempool
 * txid and checks only the ones not seen before, at most `MAX_MEMPOOL_TXS_PER_RUN`; the rest wait
 * for the next run. A transaction whose fetch fails is not marked seen, so it is retried.
 */
async function scanMempoolFromExplorer({
	chain,
	explorerApi,
	knownLabels,
	labelMap,
	recipientKeys,
	silentPaymentAddress,
	unspent,
}: {
	chain: LiquidChainRecord;
	explorerApi: string;
	knownLabels: Set<number>;
	labelMap: Map<string, { labelIndex: number; labelTweak: bigint }>;
	recipientKeys: SilentPaymentRecipientKeys;
	silentPaymentAddress: string;
	unspent: WatchedOutpoints;
}): Promise<TrackedSilentPaymentUtxo[]> {
	const throttleKey = buildScanKey(chain.id, silentPaymentAddress);
	const lastScan = lastMempoolScanAt.get(throttleKey) ?? 0;
	if (Date.now() - lastScan < MEMPOOL_SCAN_THROTTLE_MS) {
		return [];
	}

	const detected: TrackedSilentPaymentUtxo[] = [];
	const seen = seenMempoolTxids.get(throttleKey) ?? new Set<string>();
	seenMempoolTxids.set(throttleKey, seen);

	try {
		const txidsRes = await fetchFromExplorer(`${explorerApi}/mempool/txids`);
		if (!txidsRes.ok) return [];
		const listedTxids = (await txidsRes.json()) as unknown;
		if (!Array.isArray(listedTxids)) return [];
		const inMempool = new Set(
			listedTxids
				.filter((id): id is string => typeof id === "string")
				.map((id) => id.toLowerCase()),
		);
		// Drop txids that left the mempool, so the set never outgrows it.
		for (const txid of seen) {
			if (!inMempool.has(txid)) seen.delete(txid);
		}

		const fresh = [...inMempool]
			.filter((txid) => !seen.has(txid))
			.slice(0, MAX_MEMPOOL_TXS_PER_RUN);
		for (const txid of fresh) {
			try {
				const txRes = await fetchWithRetryAndBackoff(`${explorerApi}/tx/${txid}`);
				if (txRes.status === 404) {
					seen.add(txid); // Left the mempool since the listing.
					continue;
				}
				if (!txRes.ok) continue;
				const listed = (await txRes.json()) as EsploraTransaction;
				const listedTx = esploraTxToSpTx(listed);
				// Every candidate with a Taproot output gets its raw hex fetched, matched or not.
				if (!hasTaprootOutput(listedTx)) {
					await markSpentOutpoints(
						listedTx,
						unspent,
						{ blockTime: null, confirmed: false },
						chain.settings.policyAsset,
					);
					seen.add(txid);
					continue;
				}
				const fetched = await fetchTxHex(explorerApi, txid);
				if (!fetched) continue;
				if ("notFound" in fetched) {
					seen.add(txid);
					continue;
				}
				const raw = parseRawElementsTransaction(fetched.hex);
				if (raw.txid !== txid) continue;

				const matches = await scanTransaction({
					blockTime: null,
					chain,
					confirmed: false,
					explorerApi,
					knownLabels,
					labelMap,
					rawHex: fetched.hex,
					recipientKeys,
					silentPaymentAddress,
					tx: withEsploraPrevouts(raw, listed),
					unspent,
				});
				seen.add(txid);
				detected.push(...matches.filter((m) => !m.unblindFailed));
			} catch {
				// Transient: not marked seen, so the next run retries it.
			}
		}
	} catch {
		// Mempool endpoints are best-effort
	} finally {
		lastMempoolScanAt.set(throttleKey, Date.now());
	}

	return detected;
}

/**
 * Spends and confirmations are found by scanning blocks, so tracked outputs are not looked up one
 * by one, which would tell the explorer which outputs are the wallet's. Two cases remain:
 * - forget an unconfirmed output not mined for `UNCONFIRMED_EXPIRY_MS`: its transaction left the
 *   mempool, and if it is mined after all, scanning its block finds the output again;
 * - make an output unspent again when its unconfirmed spend was not mined for as long: the spend
 *   left the mempool (or the explorer listed one that never existed), and if it is mined after
 *   all, scanning its block marks the output spent again.
 * A reorg needs no request either: what the replaced blocks recorded was rolled back before the
 * scan, which confirmed again what the new blocks hold.
 */
async function reconcileTrackedUtxos({
	caughtUp,
	chainId,
	fullyScanned,
	silentPaymentAddress,
}: {
	/** The cursor reached the tip, so any mined transaction's block has been scanned. */
	caughtUp: boolean;
	chainId: string;
	/** Caught up and no backfill left: every block since any recorded spend has been scanned. */
	fullyScanned: boolean;
	silentPaymentAddress: string;
}): Promise<void> {
	const owner = silentPaymentAddress.toLowerCase();
	const tracked = (await getTrackedSilentPaymentUtxos()).filter(
		(u) => u.chainId === chainId && u.recipientAddress.toLowerCase() === owner,
	);

	const expiredBefore = Date.now() - UNCONFIRMED_EXPIRY_MS;
	for (const u of tracked) {
		// Behind the tip, the block that mined it may simply not be scanned yet.
		if (caughtUp && !u.confirmed && u.createdAt < expiredBefore) {
			await forgetSilentPaymentUtxo(u.txid, u.outputIndex);
			continue;
		}
		if (fullyScanned && u.spent && u.spentBlockTime == null && u.spentSeenAt !== undefined) {
			await expireUnconfirmedSilentPaymentSpend(u.txid, u.outputIndex, expiredBefore);
		}
	}
}

/** A wallet restored from its recovery phrase, as its first scan sees it. */
export type RestoredWallet = {
	/** Height of the wallet's earliest LWK transaction, if it has any. */
	earliestTxHeight: () => Promise<number | undefined>;
	/** When the user says the wallet was created (ms since epoch): it received nothing before. */
	walletCreatedAt?: number;
};

/** Steps of `heightAtOrBefore` before it settles for the genesis block. */
const MAX_HEIGHT_AT_TIME_STEPS = 24;
/** Steps it takes the rate it sees at its word; after them each step at least doubles. */
const HEIGHT_AT_TIME_TRUSTED_STEPS = 4;

/**
 * The height of a block mined no later than `time` (unix seconds). The first step assumes
 * Liquid's block a minute; later ones the rate between the last two blocks seen, so a gap in
 * blocks or blocks faster than a minute (regtest) cost a step or two. Past a few steps each one
 * goes back at least twice as far as the one before, so block times that keep understating the
 * rate cannot stall it short of the time. Without an answer in its steps: the genesis block.
 */
export async function heightAtOrBefore(
	explorerApi: string,
	tipHeight: number,
	time: number,
): Promise<number> {
	let height = tipHeight;
	let later: { height: number; time: number } | undefined;
	let lastStep = 0;
	for (let step = 0; step < MAX_HEIGHT_AT_TIME_STEPS && height > 0; step++) {
		const [header] = await fetchBlockHeaders(explorerApi, height, height);
		const blockTime = header?.timestamp;
		if (typeof blockTime !== "number" || !Number.isFinite(blockTime)) {
			throw new Error(`Explorer returned no time for block ${height}`);
		}
		if (blockTime <= time) return height;
		const blocksPerSecond =
			later && later.time > blockTime ? (later.height - height) / (later.time - blockTime) : 1 / 60;
		later = { height, time: blockTime };
		const floor = step >= HEIGHT_AT_TIME_TRUSTED_STEPS ? 2 * lastStep : 1;
		lastStep = Math.max(floor, Math.ceil((blockTime - time) * blocksPerSecond));
		height = Math.max(0, height - lastStep);
	}
	return 0;
}

/**
 * Where an account's first scan starts. A new wallet cannot have received anything before it
 * existed: the lookback window ends at the tip, so the first run fits in one batch. A restored
 * wallet may have, so it starts a day before the earlier of its earliest LWK transaction and the
 * date the user gave for it. With neither: 30 days back.
 */
async function defaultBirthdayHeight(
	explorerApi: string,
	tipHeight: number,
	restoredWallet: RestoredWallet | undefined,
): Promise<number> {
	if (!restoredWallet) {
		return Math.max(0, tipHeight - DEFAULT_LOOKBACK_BLOCKS + 1);
	}
	const starts: number[] = [];
	const earliest = await restoredWallet.earliestTxHeight();
	if (earliest !== undefined) starts.push(Math.min(earliest, tipHeight));
	const { walletCreatedAt } = restoredWallet;
	if (walletCreatedAt !== undefined && Number.isFinite(walletCreatedAt)) {
		const time = Math.floor(walletCreatedAt / 1000);
		starts.push(await heightAtOrBefore(explorerApi, tipHeight, time));
	}
	return Math.max(
		0,
		starts.length > 0
			? Math.min(...starts) - RESTORED_MARGIN_BLOCKS
			: tipHeight - RESTORED_LOOKBACK_BLOCKS,
	);
}

/**
 * The wallet's own Silent Payments scanner over Esplora.
 */
export async function syncFromExplorer(options: {
	birthdayHeight?: number;
	chain: LiquidChainRecord;
	/** Scan forward from this height, never newest first (tests and benchmarks). */
	forceFromHeight?: number;
	maxBlocks?: number;
	recipientKeys: SilentPaymentRecipientKeys;
	/** How long the run takes new block windows; `SCAN_TIME_BUDGET_MS` by default. */
	timeBudgetMs?: number;
	/**
	 * Set for a wallet restored from its recovery phrase: without a birthday it is not scanned
	 * from the tip. `earliestTxHeight` is read only then.
	 */
	restoredWallet?: RestoredWallet;
	silentPaymentAddress: string;
}): Promise<ExplorerScanResult> {
	const {
		birthdayHeight,
		chain,
		forceFromHeight,
		maxBlocks,
		recipientKeys,
		restoredWallet,
		silentPaymentAddress,
		timeBudgetMs = SCAN_TIME_BUDGET_MS,
	} = options;

	const scanKey = buildScanKey(chain.id, silentPaymentAddress);
	const existing = activeScanPromises.get(scanKey);
	if (existing) {
		return existing;
	}
	const generation = scanGenerations.get(scanKey) ?? 0;
	const isSuperseded = () => (scanGenerations.get(scanKey) ?? 0) !== generation;
	/**
	 * Write scan state unless a rescan superseded this run. A rescan that comes during the write may
	 * have reset the state before it lands: its reset is then put back. Runs of one account never
	 * overlap, so no later run has written in between. Returns whether the write stands.
	 */
	const unlessSuperseded = async (write: () => Promise<void>): Promise<boolean> => {
		if (isSuperseded()) return false;
		await write();
		if (!isSuperseded()) return true;
		const birthday = rescanResets.get(scanKey);
		if (birthday !== undefined) {
			await applyRescanReset(chain.id, silentPaymentAddress, birthday);
		}
		return false;
	};

	// Copy scan key bytes so async work after resolveScanTarget's caller wipes its copy remains safe.
	const scanPrivCopy = new Uint8Array(recipientKeys.scanKey.privateKey);
	const spendPubCopy = new Uint8Array(recipientKeys.spendKey.publicKey);
	const localKeys: SilentPaymentRecipientKeys = {
		scanKey: {
			privateKey: scanPrivCopy,
			publicKey: new Uint8Array(recipientKeys.scanKey.publicKey),
		},
		spendKey: {
			privateKey: new Uint8Array(0),
			publicKey: spendPubCopy,
		},
	};

	const scanPromise = (async (): Promise<ExplorerScanResult> => {
		try {
			// Headers come from one explorer per run (a server that answered 429 hands the run to
			// another); a block listing asks a fallback only when the first usable one keeps failing.
			const explorerApis = buildExplorerApis(chain);
			await Promise.all([restoreExplorerLimiters(), restoreScanRates()]);
			await probeUnreachableExplorers(explorerApis);
			let explorerApi = pickExplorerApi(explorerApis);
			const newlyDetectedUtxos: TrackedSilentPaymentUtxo[] = [];

			// Every label index the wallet can hand out (they are sequential, at most
			// MAX_SILENT_PAYMENT_LABELS), not only the stored ones: a wallet restored from its seed has
			// lost its label list, not the payments to it. A label costs one point here, not per output.
			const userLabels = await getSilentPaymentLabels(chain.id, silentPaymentAddress);
			const labelIndices = [
				...new Set([
					...SP_CHANGE_LABEL_INDICES,
					...Array.from({ length: MAX_SILENT_PAYMENT_LABELS }, (_, i) => i + 1),
					...userLabels.map((l) => l.index),
				]),
			];
			const ctx: ScanContext = {
				chain,
				explorerApis,
				knownLabels: new Set(userLabels.map((l) => l.index)),
				labelMap: precomputeLabelPoints(localKeys.scanKey.privateKey, labelIndices),
				recipientKeys: localKeys,
				silentPaymentAddress,
				spentIndex: null,
				unspent: await loadWatchedOutpoints(chain.id, silentPaymentAddress),
			};

			// 1. Fetch current chain tip height
			let tipHeight = 0;
			try {
				// Picked although its hour of requests is spent: no other explorer is usable either.
				if (explorerBudgetSpent(explorerApi)) throw new ExplorerBudgetError();
				let tipRes = await fetchFromExplorer(`${explorerApi}/blocks/tip/height`).catch(
					() => undefined,
				);
				if (!tipRes || tipRes.status === 429 || tipRes.status >= 500) {
					// The run's first request: another explorer can take the whole run.
					explorerApi = pickExplorerApi(explorerApis);
					tipRes = await fetchWithRetryAndBackoff(`${explorerApi}/blocks/tip/height`);
				}
				if (!tipRes.ok) {
					throw new Error(
						tipRes.status === 429
							? "The block explorer is limiting requests; scanning resumes shortly."
							: `Explorer returned status ${tipRes.status} for /blocks/tip/height`,
					);
				}
				tipHeight = Number.parseInt((await tipRes.text()).trim(), 10);
				if (!Number.isFinite(tipHeight) || tipHeight < 0) {
					throw new Error("Invalid tip height returned by explorer");
				}
			} catch (err) {
				setSilentPaymentLocalScanProgress(chain.id, silentPaymentAddress, {
					chainId: chain.id,
					currentHeight: 0,
					errorMessage: describeExplorerError(
						err,
						"Block explorer is unreachable or offline",
						explorerApis,
					),
					isScanning: false,
					percentage: 100,
					state: "error",
					tipHeight: 0,
					totalBlocksToScan: 0,
				});
				throw err;
			}

			const storedBirthday = await getSilentPaymentBirthday(chain.id, silentPaymentAddress);
			const savedCursor = await getSilentPaymentBlockCursor(chain.id, silentPaymentAddress);
			let backfill = await getSilentPaymentBackfill(chain.id, silentPaymentAddress);
			const storedSpentIndex = await getSilentPaymentSpentIndex(chain.id, silentPaymentAddress);
			if (backfill) {
				// Outputs waiting on a spend check are settled from the index when the backfill ends.
				ctx.spentIndex = storedSpentIndex;
			} else if (storedSpentIndex) {
				// Left over from a backfill that ended (its checks ran first) or a rescan.
				await saveSilentPaymentSpentIndex(chain.id, silentPaymentAddress, null);
			}

			// 2. Resolve start height and check for reorgs
			let startHeight: number;
			let reorgDetected = false;
			let effectiveBirthday = storedBirthday ?? undefined;

			if (forceFromHeight !== undefined && Number.isFinite(forceFromHeight)) {
				startHeight = Math.max(0, Math.trunc(forceFromHeight));
				effectiveBirthday = startHeight;
			} else if (!savedCursor) {
				const bHeight = birthdayHeight ?? storedBirthday;
				if (bHeight !== null && bHeight !== undefined && Number.isFinite(bHeight)) {
					startHeight = Math.max(0, Math.trunc(bHeight));
					effectiveBirthday = startHeight;
				} else {
					try {
						startHeight = await defaultBirthdayHeight(explorerApi, tipHeight, restoredWallet);
					} catch (err) {
						// Nothing is saved: the next run looks for the start again.
						setSilentPaymentLocalScanProgress(chain.id, silentPaymentAddress, {
							chainId: chain.id,
							currentHeight: 0,
							errorMessage: describeExplorerError(err, "Could not find where to start scanning"),
							isScanning: false,
							percentage: 0,
							state: "error",
							tipHeight,
							totalBlocksToScan: 0,
						});
						throw err;
					}
					effectiveBirthday = startHeight;
					const height = startHeight;
					if (
						!(await unlessSuperseded(() =>
							saveSilentPaymentBirthday(chain.id, silentPaymentAddress, height),
						))
					) {
						return { scannedUtxos: newlyDetectedUtxos, status: "superseded", tipHeight };
					}
				}
			} else {
				if (savedCursor.blockHash && savedCursor.height > 0 && savedCursor.height <= tipHeight) {
					try {
						const checkRes = await fetchWithRetryAndBackoff(
							`${explorerApi}/block-height/${savedCursor.height}`,
						);
						if (checkRes.ok) {
							const currentHashAtHeight = (await checkRes.text()).trim();
							if (currentHashAtHeight && currentHashAtHeight !== savedCursor.blockHash) {
								reorgDetected = true;
							}
						}
					} catch {
						// Ignore transient reorg check failure; block loop will catch network errors
					}
				}

				if (reorgDetected) {
					const fromHeight = Math.max(0, savedCursor.height - 10);
					startHeight = fromHeight;
					// What the replaced blocks recorded is undone and found again by scanning the blocks
					// that replace them, without a request naming an output of the wallet. A running
					// backfill's index forgets their spends too, or it would settle an output spent by a
					// transaction the chain no longer holds.
					if (
						!(await unlessSuperseded(async () => {
							await rollBackSilentPaymentBlocks(chain.id, silentPaymentAddress, fromHeight);
							const index = ctx.spentIndex;
							if (index && dropIndexedSpends(index, fromHeight, Infinity)) {
								await saveSilentPaymentSpentIndex(chain.id, silentPaymentAddress, index);
							}
						}))
					) {
						return { scannedUtxos: newlyDetectedUtxos, status: "superseded", tipHeight };
					}
					ctx.unspent = await loadWatchedOutpoints(chain.id, silentPaymentAddress);
				} else {
					startHeight = savedCursor.height + 1;
				}
			}

			// 3. A long gap is scanned newest first, so recent payments show in minutes rather than
			// after the whole history: the forward cursor jumps to the tip, and a backfill walks down
			// to the start. Spends in the blocks scanned meanwhile go to a spent index: an output the
			// backfill finds is checked against it at once, and outputs tracked before the gap, which
			// may have been spent in it, once the backfill ends. No request names an output.
			if (
				forceFromHeight === undefined &&
				!backfill &&
				tipHeight - startHeight + 1 > BACKFILL_THRESHOLD_BLOCKS
			) {
				const [tipHeader] = await fetchBlockHeaders(explorerApi, tipHeight, tipHeight);
				const spentIndex: SilentPaymentSpentIndex = {
					entries: {},
					salt: bytesToHex(randomBytes(32)),
				};
				const started: SilentPaymentBackfill = {
					nextHash: tipHeader!.id,
					nextHeight: tipHeight,
					stopHeight: startHeight,
					topHeight: tipHeight,
				};
				const begun = await unlessSuperseded(async () => {
					// Saved before the backfill: a backfill without an index falls back to the explorer.
					await saveSilentPaymentSpentIndex(chain.id, silentPaymentAddress, spentIndex);
					await markSilentPaymentSpendsUnverified(
						[...ctx.unspent.values()].filter((u) => !u.spent),
					);
					await saveSilentPaymentBackfill(chain.id, silentPaymentAddress, started);
					await saveSilentPaymentBlockCursor(chain.id, silentPaymentAddress, {
						blockHash: tipHeader!.id,
						height: tipHeight,
					});
				});
				if (!begun) {
					return { scannedUtxos: newlyDetectedUtxos, status: "superseded", tipHeight };
				}
				ctx.spentIndex = spentIndex;
				backfill = started;
				startHeight = tipHeight + 1;
			}

			// Outputs waiting on a spend check that no spent index will settle (their check got no
			// answer, or a backfill predates the index): ask the explorer. A backfill begun above
			// settles them from its index instead.
			if (!ctx.spentIndex) {
				await verifySpends(ctx, await getUnverifiedOutputs(chain.id, silentPaymentAddress));
			}

			// 4. Unconfirmed payments matter only near the tip: a catch-up skips the mempool.
			if (tipHeight - startHeight < BLOCK_HEADERS_PER_REQUEST) {
				const mempoolMatches = await scanMempoolFromExplorer({
					chain,
					explorerApi,
					knownLabels: ctx.knownLabels,
					labelMap: ctx.labelMap,
					recipientKeys: localKeys,
					silentPaymentAddress,
					unspent: ctx.unspent,
				});
				newlyDetectedUtxos.push(...mempoolMatches);
			}

			let lastSuccessfulHeight = startHeight - 1;
			const runStartedAt = Date.now();
			const requestsAtRunStart = explorerRequestsStarted();
			const backfillStartedAt = backfill?.nextHeight;

			const updateProgress = (state: "backfilling" | "synced" | "error", errorMessage?: string) => {
				const newBlocksLeft = Math.max(0, tipHeight - lastSuccessfulHeight);
				const history = backfill
					? {
							done: backfill.topHeight - backfill.nextHeight,
							total: backfill.topHeight - backfill.stopHeight + 1,
						}
					: undefined;

				// The rate of this run once it has one, else the last run's.
				const scanned =
					Math.max(0, lastSuccessfulHeight - (startHeight - 1)) +
					(backfill && backfillStartedAt !== undefined
						? Math.max(0, backfillStartedAt - backfill.nextHeight)
						: 0);
				const elapsedSeconds = (Date.now() - runStartedAt) / 1000;
				if (scanned > 0 && elapsedSeconds >= 2) {
					// No faster than the explorers keep up for hours, at this run's blocks a request: a
					// burst on a server with an hourly budget runs a hundred times faster than the scan
					// does once the budget is spent, and would promise minutes for a matter of hours.
					const requests = Math.max(1, explorerRequestsStarted() - requestsAtRunStart);
					const sustained = sustainedExplorerRequestRate(explorerApis) * (scanned / requests);
					const measured = scanned / elapsedSeconds;
					rememberScanRate(scanKey, sustained > 0 ? Math.min(measured, sustained) : measured);
				}
				const rate = scanRates.get(scanKey);
				const left = newBlocksLeft + (history ? history.total - history.done : 0);

				// The part under way: the new blocks since the cursor first, then the history. Neither
				// counts from the wallet's birthday, which made a few new blocks look like a full rescan.
				const onHistory = newBlocksLeft === 0 && history !== undefined;
				const [done, total, at] = onHistory
					? [history.done, history.total, backfill!.nextHeight]
					: [
							lastSuccessfulHeight - (startHeight - 1),
							tipHeight - (startHeight - 1),
							lastSuccessfulHeight,
						];
				setSilentPaymentLocalScanProgress(chain.id, silentPaymentAddress, {
					birthdayHeight: effectiveBirthday,
					chainId: chain.id,
					currentHeight: Math.max(0, at),
					errorMessage,
					etaSeconds: state !== "synced" && rate && left > 0 ? Math.round(left / rate) : undefined,
					fallbackExplorerDown: fallbackExplorerUnreachable(explorerApis) || undefined,
					history,
					isScanning: state === "backfilling",
					newBlocksLeft,
					percentage:
						state === "synced"
							? 100
							: Math.min(99, Math.max(0, Math.floor((done / Math.max(1, total)) * 100))),
					state,
					tipHeight,
					totalBlocksToScan: Math.max(0, total),
				});
			};
			updateProgress("backfilling");

			const batchLimit = maxBlocks ?? MAX_SCAN_BLOCKS_PER_RUN;
			const endHeight = Math.min(tipHeight, startHeight + batchLimit - 1);
			let blocksLeft = batchLimit;
			let scanHaltedDueToError = false;
			let superseded = false;
			// The first scanned block must extend the saved cursor, unless the scan restarts elsewhere.
			let expectedPrevHash =
				!reorgDetected && savedCursor && savedCursor.height === startHeight - 1
					? savedCursor.blockHash
					: undefined;
			const deadline = Date.now() + timeBudgetMs;
			/**
			 * A run takes block windows until its time is up or its explorer's hour of requests is
			 * spent: the next run picks another explorer, or waits for this one.
			 */
			const mayTakeWindow = () => Date.now() < deadline && !explorerBudgetSpent(explorerApi);
			// The search of older blocks leaves part of a capped server's hour to the new blocks, so
			// payments keep showing while it waits; once its share is used the run reads from a
			// server without a cap, if one answers.
			if (backfill && !explorerBudgetLeftForHistory(explorerApi)) {
				const other = usableExplorerApis(explorerApis).find(
					(api) => api !== explorerApi && explorerBudgetLeftForHistory(api),
				);
				if (other) {
					explorerApi = other;
					ctx.explorerApis = [other, ...explorerApis.filter((api) => api !== other)];
				}
			}
			const mayTakeHistoryWindow = () =>
				mayTakeWindow() && explorerBudgetLeftForHistory(explorerApi);
			// While a backfill runs, a window's spends are indexed before any of its blocks counts as
			// scanned, so the cursor never gets ahead of the index.
			const listWindow = async (headers: EsploraBlockHeader[]) => {
				const listings = await Promise.allSettled(
					headers.map((h) =>
						h.tx_count === 1
							? Promise.resolve<BlockListing>({ api: explorerApi, listed: [] })
							: fetchListing(h, ctx),
					),
				);
				const index = ctx.spentIndex;
				if (backfill && index && indexSpends(index, headers, listings)) {
					await unlessSuperseded(() =>
						saveSilentPaymentSpentIndex(chain.id, silentPaymentAddress, index),
					);
				}
				return listings;
			};
			/**
			 * Headers and listings of blocks `from..to`. The next window is fetched while the current
			 * one is scanned, so the explorer is kept busy through the scan's CPU time and the header
			 * round trip; a window the run gives up on settles unobserved.
			 */
			const fetchWindow = (from: number, to: number) => {
				const pending = (async () => {
					const headers = await fetchHeaderRange(explorerApi, from, to);
					const listings = await listWindow(headers);
					// The raw blocks the window needs, all at once rather than one per block as the scan
					// reaches it. Which blocks need one does not depend on what the scan finds: an SP
					// output is Taproot, so a block spending one already qualifies by its listing.
					const raws = headers.map((header, i) => {
						const listing = listings[i];
						if (listing?.status !== "fulfilled") return undefined;
						const { api, listed } = listing.value;
						if (!listed.some((tx, j) => j > 0 && needsRawBlock(tx, ctx))) return undefined;
						const raw = fetchRawBlockForScan(api, header, listed);
						raw.catch(() => {});
						return raw;
					});
					return { headers, listings, raws };
				})();
				pending.catch(() => {});
				return pending;
			};

			// 5. Forward from the cursor. Listings of a window are fetched in parallel, but blocks are
			// scanned and the cursor advanced strictly in height order: a block may spend an output
			// found in the block before it. The cursor is written once a window, and on the way out
			// at the last block scanned: each write is a vault round trip, and scanning a block again
			// after a lost write records nothing new.
			let unsavedCursor: { blockHash: string; height: number } | undefined;
			/** Write the cursor the run has reached; false if a rescan superseded the run. */
			const saveCursor = async (): Promise<boolean> => {
				const cursor = unsavedCursor;
				if (!cursor) return !isSuperseded();
				const saved = await unlessSuperseded(() =>
					saveSilentPaymentBlockCursor(chain.id, silentPaymentAddress, cursor),
				);
				if (saved) unsavedCursor = undefined;
				return saved;
			};
			let nextWindow =
				lastSuccessfulHeight < endHeight && mayTakeWindow()
					? fetchWindow(startHeight, Math.min(endHeight, startHeight + SCAN_WINDOW_BLOCKS - 1))
					: undefined;
			blockLoop: while (nextWindow) {
				const window = nextWindow;
				nextWindow = undefined;
				try {
					const { headers, listings, raws } = await window;
					const windowStart = headers[0]!.height;
					const windowEnd = headers[headers.length - 1]!.height;
					if (expectedPrevHash && headers[0]!.previousblockhash !== expectedPrevHash) {
						throw new Error(`Block ${windowStart} does not extend the last scanned block`);
					}
					if (windowEnd < endHeight && mayTakeWindow()) {
						nextWindow = fetchWindow(
							windowEnd + 1,
							Math.min(endHeight, windowEnd + SCAN_WINDOW_BLOCKS),
						);
					}

					for (const [i, header] of headers.entries()) {
						const listing = listings[i]!;
						if (listing.status === "rejected") {
							throw listing.reason;
						}
						const found = await scanListedBlock(header, listing.value, ctx, false, raws[i]);
						newlyDetectedUtxos.push(...found.filter((m) => !m.unblindFailed));

						// Found outputs are real either way, but the cursor now belongs to the rescan.
						if (isSuperseded()) {
							superseded = true;
							break blockLoop;
						}
						unsavedCursor = { blockHash: header.id, height: header.height };
						lastSuccessfulHeight = header.height;
						expectedPrevHash = header.id;
						blocksLeft--;
						updateProgress("backfilling");
					}
					if (!(await saveCursor())) {
						superseded = true;
						break;
					}
				} catch (err) {
					// The blocks before the failed one stay scanned.
					try {
						if (!(await saveCursor())) superseded = true;
					} catch {
						// The next run scans them again.
					}
					scanHaltedDueToError = true;
					updateProgress("error", describeExplorerError(err, "Failed to scan block", explorerApis));
					break;
				}
			}
			// A window fetched ahead but not scanned: let it settle before the run goes on.
			await nextWindow?.catch(() => undefined);

			// 6. The backfill, newest first, with what is left of the run; the window below is fetched
			// while one is scanned, as going forward.
			const backfillWindow = (stopHeight: number, top: number, budget: number) =>
				fetchWindow(Math.max(stopHeight, top - Math.min(SCAN_WINDOW_BLOCKS, budget) + 1), top);
			let nextBackfillWindow =
				backfill && !scanHaltedDueToError && !superseded && blocksLeft > 0 && mayTakeHistoryWindow()
					? backfillWindow(backfill.stopHeight, backfill.nextHeight, blocksLeft)
					: undefined;
			let rewinds = 0;
			while (nextBackfillWindow && backfill) {
				const window = nextBackfillWindow;
				nextBackfillWindow = undefined;
				try {
					const { headers, listings, raws } = await window;
					const low = headers[0]!.height;
					const top = headers[headers.length - 1]!.height;
					if (headers[headers.length - 1]!.id !== backfill.nextHash) {
						// The block above named another block: a reorg in the backfill's range, an explorer
						// that served two chains, or a header without its parent's hash. Step back up and
						// rescan from the chain as it is now.
						if (++rewinds > MAX_BACKFILL_REWINDS_PER_RUN) {
							throw new Error(`Block ${top} is not the block the one above it names`);
						}
						const height = Math.min(backfill.topHeight, top + BACKFILL_REWIND_BLOCKS);
						const [anchor] = await fetchBlockHeaders(explorerApi, height, height);
						const rewound = { ...backfill, nextHash: anchor!.id, nextHeight: height };
						if (
							!(await unlessSuperseded(async () => {
								// The blocks above the window may be the replaced ones: undo what they recorded,
								// which rescanning them records again from the chain as it is now.
								await rollBackSilentPaymentBlocks(chain.id, silentPaymentAddress, top + 1, height);
								const index = ctx.spentIndex;
								if (index && dropIndexedSpends(index, top + 1, height)) {
									await saveSilentPaymentSpentIndex(chain.id, silentPaymentAddress, index);
								}
								await saveSilentPaymentBackfill(chain.id, silentPaymentAddress, rewound);
							}))
						) {
							superseded = true;
							break;
						}
						ctx.unspent = await loadWatchedOutpoints(chain.id, silentPaymentAddress);
						backfill = rewound;
						nextBackfillWindow = backfillWindow(backfill.stopHeight, height, blocksLeft);
						continue;
					}
					const budgetLeft = blocksLeft - headers.length;
					if (low > backfill.stopHeight && budgetLeft > 0 && mayTakeHistoryWindow()) {
						nextBackfillWindow = backfillWindow(backfill.stopHeight, low - 1, budgetLeft);
					}

					const found: TrackedSilentPaymentUtxo[] = [];
					for (let i = headers.length - 1; i >= 0; i--) {
						const listing = listings[i]!;
						if (listing.status === "rejected") {
							throw listing.reason;
						}
						found.push(...(await scanListedBlock(headers[i]!, listing.value, ctx, true, raws[i])));
					}
					newlyDetectedUtxos.push(...found.filter((m) => !m.unblindFailed));
					// Every block after them is in the index already, this window's included.
					await checkSpends(ctx, found);

					if (isSuperseded()) {
						superseded = true;
						break;
					}
					const next =
						low > backfill.stopHeight
							? { ...backfill, nextHash: headers[0]!.previousblockhash ?? "", nextHeight: low - 1 }
							: null;
					if (!next) {
						// The whole gap is indexed: settle the outputs tracked before it, then drop the index.
						await checkSpends(ctx, await getUnverifiedOutputs(chain.id, silentPaymentAddress));
					}
					const saved = await unlessSuperseded(async () => {
						await saveSilentPaymentBackfill(chain.id, silentPaymentAddress, next);
						if (!next) await saveSilentPaymentSpentIndex(chain.id, silentPaymentAddress, null);
					});
					if (!saved) {
						superseded = true;
						break;
					}
					backfill = next;
					if (!backfill) ctx.spentIndex = null;
					blocksLeft -= headers.length;
					updateProgress("backfilling");
				} catch (err) {
					scanHaltedDueToError = true;
					updateProgress("error", describeExplorerError(err, "Failed to scan block", explorerApis));
					break;
				}
			}
			await nextBackfillWindow?.catch(() => undefined);

			const forwardCaughtUp = lastSuccessfulHeight >= tipHeight;
			const caughtUp = !scanHaltedDueToError && !superseded && forwardCaughtUp;
			await reconcileTrackedUtxos({
				caughtUp,
				chainId: chain.id,
				fullyScanned: caughtUp && !backfill,
				silentPaymentAddress,
			});

			if (superseded) {
				return { scannedUtxos: newlyDetectedUtxos, status: "superseded", tipHeight };
			}
			if (scanHaltedDueToError) {
				return { scannedUtxos: newlyDetectedUtxos, status: "halted", tipHeight };
			}

			// The time budget or block cap may end the run before the tip or the backfill's end.
			const done = forwardCaughtUp && !backfill;
			updateProgress(done ? "synced" : "backfilling");

			return {
				scannedUtxos: newlyDetectedUtxos,
				status: done ? "synced" : "partial",
				tipHeight,
			};
		} finally {
			zeroizeBuffer(scanPrivCopy);
		}
	})();

	activeScanPromises.set(scanKey, scanPromise);
	try {
		return await scanPromise;
	} finally {
		activeScanPromises.delete(scanKey);
	}
}

/** A rescan's state: scan from `birthdayHeight`, no cursor, no backfill, no spent index. */
async function applyRescanReset(
	chainId: string,
	silentPaymentAddress: string,
	birthdayHeight: number,
): Promise<void> {
	await saveSilentPaymentBirthday(chainId, silentPaymentAddress, birthdayHeight);
	await saveSilentPaymentBlockCursor(chainId, silentPaymentAddress, null);
	await saveSilentPaymentBackfill(chainId, silentPaymentAddress, null);
	await saveSilentPaymentSpentIndex(chainId, silentPaymentAddress, null);
}

/**
 * Reset the local block cursor to `birthdayHeight - 1` so the next wallet scan starts from
 * `birthdayHeight`.
 */
export async function rescanFromExplorer(options: {
	birthdayHeight: number;
	chain: LiquidChainRecord;
	silentPaymentAddress: string;
}): Promise<void> {
	const { birthdayHeight, chain, silentPaymentAddress } = options;
	const scanKey = buildScanKey(chain.id, silentPaymentAddress);
	const normalizedHeight = Math.max(0, Math.trunc(birthdayHeight));
	scanGenerations.set(scanKey, (scanGenerations.get(scanKey) ?? 0) + 1);
	rescanResets.set(scanKey, normalizedHeight);
	await applyRescanReset(chain.id, silentPaymentAddress, normalizedHeight);
	lastMempoolScanAt.delete(scanKey);
	seenMempoolTxids.delete(scanKey);
	setSilentPaymentLocalScanProgress(chain.id, silentPaymentAddress, null);
}

/** Pause before a catch-up retries a failed run, and how many failures in a row it tolerates. */
export const CATCH_UP_RETRY_DELAY_MS = 30_000;
export const MAX_CATCH_UP_FAILURES = 10;

/**
 * Keep running `syncFromExplorer` until the cursor reaches the tip, a block fails, or the vault
 * locks, so a long backlog (an explicit rescan, a wallet offline for days) is not limited to one
 * run per portfolio refresh. One catch-up per account; a second call joins the running one, which
 * follows a rescan's reset cursor. The scan key copy it holds is wiped when it ends.
 */
export function startExplorerCatchUp(options: {
	chain: LiquidChainRecord;
	maxBlocksPerRun?: number;
	recipientKeys: SilentPaymentRecipientKeys;
	/**
	 * As for `syncFromExplorer`. A restored wallet whose first run failed before it chose where to
	 * start is still restored when the catch-up retries: without it, the retry would start at the
	 * tip and never scan the history the wallet was restored for.
	 */
	restoredWallet?: RestoredWallet;
	retryDelayMs?: number;
	silentPaymentAddress: string;
}): Promise<void> {
	const {
		chain,
		maxBlocksPerRun,
		recipientKeys,
		restoredWallet,
		retryDelayMs = CATCH_UP_RETRY_DELAY_MS,
		silentPaymentAddress,
	} = options;
	const scanKey = buildScanKey(chain.id, silentPaymentAddress);
	const existing = activeCatchUps.get(scanKey);
	if (existing) {
		return existing;
	}

	// Copied before the first await: the caller wipes its own copy right after this returns.
	const localKeys: SilentPaymentRecipientKeys = {
		scanKey: {
			privateKey: new Uint8Array(recipientKeys.scanKey.privateKey),
			publicKey: new Uint8Array(recipientKeys.scanKey.publicKey),
		},
		spendKey: {
			privateKey: new Uint8Array(0),
			publicKey: new Uint8Array(recipientKeys.spendKey.publicKey),
		},
	};

	const catchUp = (async () => {
		try {
			let failures = 0;
			while (await isSilentPaymentStoreUnlocked()) {
				let status: ExplorerScanResult["status"];
				try {
					({ status } = await syncFromExplorer({
						chain,
						maxBlocks: maxBlocksPerRun ?? CATCH_UP_MAX_BLOCKS_PER_RUN,
						recipientKeys: localKeys,
						restoredWallet,
						silentPaymentAddress,
						timeBudgetMs: CATCH_UP_TIME_BUDGET_MS,
					}));
				} catch (err) {
					console.warn("[sp-local-scanner] Catch-up run failed:", err);
					status = "halted";
				}
				if (status === "synced") return;
				if (status !== "halted") {
					failures = 0;
					continue;
				}
				// A rate limit or an unreachable explorer passes: wait, then go on.
				if (++failures > MAX_CATCH_UP_FAILURES) {
					console.warn("[sp-local-scanner] Catch-up scan stopped after repeated failures");
					return;
				}
				// Jittered, so wallets behind one IP that failed together do not retry together.
				await new Promise((resolve) =>
					setTimeout(resolve, retryDelayMs * (0.75 + Math.random() * 0.5)),
				);
			}
		} finally {
			zeroizeBuffer(localKeys.scanKey.privateKey);
			activeCatchUps.delete(scanKey);
		}
	})();

	activeCatchUps.set(scanKey, catchUp);
	return catchUp;
}
