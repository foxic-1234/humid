import type { SecureVaultStorage } from "@/core/secure-vault/types";

export type TrackedSilentPaymentUtxo = {
	address: string; // One-time stealth Taproot address (e.g. tex1p... or ex1p...)
	amountSats: string;
	assetBlindingFactorHex?: string;
	blindingKeyHex?: string; // bk_k hex (ELIP-352)
	/**
	 * Height of the block that mined it; absent while unconfirmed. A reorg rolls back what was
	 * recorded from the blocks it replaces.
	 */
	blockHeight?: number;
	blockTime?: number | null;
	chainId: string;
	confirmed?: boolean; // false for mempool (unconfirmed), true for mined
	createdAt: number;
	labelIndex?: number; // BIP-352 label index (0 = change)
	labelTweakHex?: string; // 32-byte hex scalar label tweak ℓ
	outputIndex: number;
	rawAssetId: string;
	recipientAddress: string; // Owning account's static SP address (tlqsp1... or lqsp1...)
	scriptPubKeyHex: string;
	scriptType?: "p2tr";
	spent: boolean;
	/** Height of the block that mined the spend; absent while the spend is unconfirmed. */
	spentBlockHeight?: number;
	/** Block time of the spending transaction; null or absent while it is unconfirmed. */
	spentBlockTime?: number | null;
	/** L-BTC fee of the spending transaction, for showing a send the LWK wallet does not see. */
	spentFeeSats?: string;
	spentInTxid?: string;
	/**
	 * When an unconfirmed spend (seen in the mempool or made by this wallet) was first recorded. A
	 * spend that is not mined in time is dropped, and the output counts as unspent again.
	 */
	spentSeenAt?: number;
	/**
	 * Found by a newest-first scan, which had passed the later blocks before it knew the output:
	 * whether one of them spent it is not known yet. Kept out of the balance until checked.
	 */
	spendUnverified?: true;
	tweakHex?: string; // 32-byte hex scalar tweak tk = H(S || k) used to derive one-time private key on the fly
	txid: string;
	/**
	 * P_k matched but the output could not be unblinded with bk_k. bk_k is deterministic, but the
	 * rangeproof lies in the witness, which a block's merkle root does not commit to: the wallet
	 * scanner tries a second explorer's copy of the block before recording this. An explicit rescan
	 * re-verifies the output. Amount and asset of such a record are meaningless.
	 */
	unblindFailed?: boolean;
	valueBlindingFactorHex?: string;
};

export const SP_STORAGE_KEY = "humid_silent_payment_utxos_v2";
const SP_BLOCK_CURSOR_KEY_PREFIX = "sp_block_cursor_";
const SP_BACKFILL_KEY_PREFIX = "sp_backfill_";
const SP_SPENT_INDEX_KEY_PREFIX = "sp_spent_index_";
const SP_BIRTHDAY_KEY_PREFIX = "sp_birthday_";
const SP_LABELS_KEY_PREFIX = "sp_labels_";

export type SilentPaymentBlockCursor = {
	blockHash: string;
	height: number;
};

/** How far a scan has come, in the terms the wallet shows it to the user. */
export type SilentPaymentScanPhases = {
	/** Seconds until the new blocks and the history are both scanned, at the recent rate. */
	etaSeconds?: number;
	/** A newest-first scan of older blocks, which runs after the newest ones are checked. */
	history?: { done: number; total: number };
	/** Blocks between the cursor and the chain tip still to check. */
	newBlocksLeft?: number;
};

export type SilentPaymentLocalScanProgress = SilentPaymentScanPhases & {
	birthdayHeight?: number;
	chainId: string;
	currentHeight: number;
	errorMessage?: string;
	isScanning: boolean;
	percentage: number;
	state: "backfilling" | "idle" | "error" | "synced";
	tipHeight: number;
	totalBlocksToScan: number;
};

const localScanProgressMap = new Map<string, SilentPaymentLocalScanProgress>();

/**
 * A BIP-352 label m >= 1 the user created: its own static SP address, which pays the same account.
 * The name never leaves the wallet.
 */
export type SilentPaymentLabel = {
	address: string; // Labeled static SP address (B_scan, B_spend + ℓ_m·G)
	createdAt: number;
	index: number;
	name: string;
};

// SP data (tk, bk_k, cursors) lives only in the secure vault. While the vault is locked there is
// no SP data: reads return nothing and writes fail. Writes throw, so sync never advances its
// cursor past an event it failed to store.

let testVaultStorage: SecureVaultStorage | null = null;

export function setSpStoreVaultForTesting(storage: SecureVaultStorage | null): void {
	testVaultStorage = storage;
	localScanProgressMap.clear();
}

async function getVaultStorage(): Promise<SecureVaultStorage | null> {
	if (testVaultStorage) {
		return testVaultStorage;
	}

	try {
		const vaultBg = await import("@/core/secure-vault/background");
		return vaultBg.getOptionalUnlockedSecureVaultStorage();
	} catch {
		// Outside the extension background context there is no vault.
		return null;
	}
}

/** False while the vault is locked: SP reads then return nothing, which does not mean "no SP data". */
export async function isSilentPaymentStoreUnlocked(): Promise<boolean> {
	return (await getVaultStorage()) !== null;
}

async function storeGetItem<T>(key: string): Promise<T | null> {
	const vault = await getVaultStorage();
	if (!vault) return null;

	const raw = await vault.getItem(key);
	return raw === null ? null : (JSON.parse(raw) as T);
}

async function storeSetItem<T>(key: string, value: T): Promise<void> {
	const vault = await getVaultStorage();
	if (!vault) {
		throw new Error(`Secure vault is locked: cannot save ${key}`);
	}

	await vault.setItem(key, JSON.stringify(value));
}

let storeLockQueue: Promise<unknown> = Promise.resolve();

function withStoreLock<T>(operation: () => Promise<T>): Promise<T> {
	const next = storeLockQueue.then(operation, operation);
	storeLockQueue = next.then(
		() => {},
		() => {},
	);
	return next;
}

export async function getTrackedSilentPaymentUtxos(): Promise<TrackedSilentPaymentUtxo[]> {
	try {
		const items = await storeGetItem<TrackedSilentPaymentUtxo[]>(SP_STORAGE_KEY);
		return Array.isArray(items) ? items : [];
	} catch (e) {
		console.error("[sp-store] Failed to load tracked Silent Payment UTXOs:", e);
		return [];
	}
}

/**
 * The tracked list for a read-modify-write. Unlike `getTrackedSilentPaymentUtxos`, a failed or
 * malformed read throws: writing back an empty list would erase every tracked output.
 */
async function readTrackedListForWrite(): Promise<TrackedSilentPaymentUtxo[]> {
	const items = await storeGetItem<unknown>(SP_STORAGE_KEY);
	if (items === null) return [];
	if (!Array.isArray(items)) {
		throw new Error("[sp-store] Stored Silent Payment UTXO list is malformed");
	}
	return items as TrackedSilentPaymentUtxo[];
}

/**
 * Insert or update a tracked UTXO. An update never un-spends or un-confirms a record (events may be
 * replayed after a rescan); reorg rollbacks go through `rollBackSilentPaymentBlocks`.
 */
export async function saveTrackedSilentPaymentUtxo(utxo: TrackedSilentPaymentUtxo): Promise<void> {
	return withStoreLock(async () => {
		const list = await readTrackedListForWrite();
		const idx = list.findIndex((u) => u.txid === utxo.txid && u.outputIndex === utxo.outputIndex);
		if (idx >= 0) {
			const prev = list[idx];
			const confirmed = prev.confirmed === true || utxo.confirmed === true;
			// An output unblinded once stays unblinded: a later copy of its transaction whose
			// rangeproof does not open (an explorer can serve one) must not zero its amount.
			const keepUnblinded = utxo.unblindFailed === true && prev.unblindFailed !== true;
			list[idx] = {
				...prev,
				...utxo,
				...(keepUnblinded
					? {
							amountSats: prev.amountSats,
							assetBlindingFactorHex: prev.assetBlindingFactorHex,
							rawAssetId: prev.rawAssetId,
							unblindFailed: prev.unblindFailed,
							valueBlindingFactorHex: prev.valueBlindingFactorHex,
						}
					: {}),
				blindingKeyHex: utxo.blindingKeyHex ?? prev.blindingKeyHex,
				blockHeight: utxo.blockHeight ?? (confirmed ? prev.blockHeight : undefined),
				blockTime: utxo.blockTime ?? (confirmed ? (prev.blockTime ?? null) : null),
				confirmed,
				createdAt: prev.createdAt,
				labelIndex: utxo.labelIndex ?? prev.labelIndex,
				labelTweakHex: utxo.labelTweakHex ?? prev.labelTweakHex,
				spent: prev.spent || utxo.spent,
				spentBlockHeight: utxo.spentBlockHeight ?? prev.spentBlockHeight,
				spentBlockTime: utxo.spentBlockTime ?? prev.spentBlockTime,
				spentFeeSats: utxo.spentFeeSats ?? prev.spentFeeSats,
				spentInTxid: utxo.spentInTxid ?? prev.spentInTxid,
				// An output already known stays checked when a newest-first scan finds it again.
				spendUnverified: prev.spendUnverified && utxo.spendUnverified ? true : undefined,
			};
		} else {
			list.push(utxo);
		}

		await storeSetItem(SP_STORAGE_KEY, list);
	});
}

/** Apply `update` to one tracked UTXO in place; a missing record is a no-op. */
async function updateTrackedSilentPaymentUtxo(
	txid: string,
	outputIndex: number,
	update: (utxo: TrackedSilentPaymentUtxo) => void,
): Promise<void> {
	return withStoreLock(async () => {
		const list = await readTrackedListForWrite();
		const target = list.find((u) => u.txid === txid && u.outputIndex === outputIndex);
		if (!target) return;

		update(target);
		await storeSetItem(SP_STORAGE_KEY, list);
	});
}

/**
 * bk_k stays on the record: a reorged-out spend makes the output unspent again, and it is needed
 * to spend it then. `spend.confirmed: false` marks an unconfirmed spend, which expires unless a
 * scanned block confirms it (see `expireUnconfirmedSilentPaymentSpend`).
 */
export async function markSilentPaymentUtxoSpent(
	txid: string,
	outputIndex: number,
	spentInTxid?: string,
	spend?: {
		blockHeight?: number;
		blockTime?: number | null;
		confirmed?: boolean;
		feeSats?: string;
	},
): Promise<void> {
	await updateTrackedSilentPaymentUtxo(txid, outputIndex, (target) => {
		const wasSpent = target.spent;
		const replaced = spentInTxid !== undefined && spentInTxid !== target.spentInTxid;
		target.spent = true;
		delete target.spendUnverified;
		if (spentInTxid) {
			target.spentInTxid = spentInTxid;
		}
		if (spend?.blockTime !== undefined) {
			target.spentBlockTime = spend.blockTime;
			target.spentBlockHeight = spend.blockHeight;
		}
		if (spend?.confirmed === true || typeof target.spentBlockTime === "number") {
			delete target.spentSeenAt;
		} else if (spend?.confirmed === false) {
			// A spend already recorded without a deadline (say, a confirmed one) never gets one.
			if (!wasSpent || replaced) {
				target.spentSeenAt = Date.now();
			}
		}
		if (spend?.feeSats !== undefined) {
			target.spentFeeSats = spend.feeSats;
		}
	});
}

/**
 * Make an output unspent again when its unconfirmed spend was first recorded before `seenBefore`
 * and no scanned block has confirmed it since. Returns whether the record changed.
 */
export async function expireUnconfirmedSilentPaymentSpend(
	txid: string,
	outputIndex: number,
	seenBefore: number,
): Promise<boolean> {
	let changed = false;
	await updateTrackedSilentPaymentUtxo(txid, outputIndex, (target) => {
		if (
			!target.spent ||
			target.spentBlockTime != null ||
			target.spentSeenAt === undefined ||
			target.spentSeenAt >= seenBefore
		) {
			return;
		}
		target.spent = false;
		target.spentInTxid = undefined;
		target.spentBlockTime = undefined;
		delete target.spentBlockHeight;
		target.spentFeeSats = undefined;
		delete target.spentSeenAt;
		changed = true;
	});
	return changed;
}

/**
 * Undo what blocks `fromHeight..toHeight` (no upper end without `toHeight`) recorded for the
 * account, before a reorg's replacement blocks are scanned: a payment they mined becomes
 * unconfirmed again, and a spend they mined an unconfirmed spend. Scanning the replacement blocks
 * confirms both again; whatever they no longer hold expires as any unconfirmed record does. A
 * spend stays a spend meanwhile, so the balance never counts money that may be gone. No request
 * is made. Returns how many records changed.
 */
export async function rollBackSilentPaymentBlocks(
	chainId: string,
	silentPaymentAddress: string,
	fromHeight: number,
	toHeight = Infinity,
): Promise<number> {
	const owner = silentPaymentAddress.toLowerCase();
	const inRange = (height: number | undefined) =>
		height !== undefined && height >= fromHeight && height <= toHeight;
	let changed = 0;
	await withStoreLock(async () => {
		const list = await readTrackedListForWrite();
		const now = Date.now();
		for (const u of list) {
			if (u.chainId !== chainId || u.recipientAddress.toLowerCase() !== owner) continue;
			let touched = false;
			if (u.confirmed && inRange(u.blockHeight)) {
				u.confirmed = false;
				u.blockTime = null;
				delete u.blockHeight;
				// The expiry of an unconfirmed payment counts from now, not from when it was first found.
				u.createdAt = now;
				touched = true;
			}
			if (u.spent && inRange(u.spentBlockHeight)) {
				u.spentBlockTime = null;
				delete u.spentBlockHeight;
				u.spentSeenAt = now;
				touched = true;
			}
			if (touched) changed++;
		}
		if (changed > 0) await storeSetItem(SP_STORAGE_KEY, list);
	});
	return changed;
}

/**
 * Forget an output whose funding tx left the mempool without being mined. Returns whether a record
 * was removed.
 */
export async function forgetSilentPaymentUtxo(txid: string, outputIndex: number): Promise<boolean> {
	return withStoreLock(async () => {
		const list = await readTrackedListForWrite();
		const kept = list.filter((u) => !(u.txid === txid && u.outputIndex === outputIndex));
		if (kept.length === list.length) return false;
		await storeSetItem(SP_STORAGE_KEY, kept);
		return true;
	});
}

/**
 * A tracked UTXO can be spent if it is unspent, was unblinded, and carries its spending tweak tk.
 * `assetFilter` narrows the result to the native asset (any of `policyAssetIds`) or one asset.
 */
export function isSpendableSilentPaymentUtxo(
	u: TrackedSilentPaymentUtxo,
	assetFilter?: {
		isNative?: boolean;
		policyAssetIds?: (string | undefined)[];
		rawAssetId?: string;
	},
): boolean {
	if (u.spent || u.unblindFailed || u.spendUnverified || !u.tweakHex) return false;

	if (assetFilter) {
		const { isNative, policyAssetIds, rawAssetId } = assetFilter;
		if (isNative) {
			const validPolicies = policyAssetIds?.filter(Boolean) as string[] | undefined;
			if (validPolicies && validPolicies.length > 0) {
				return validPolicies.includes(u.rawAssetId);
			}
		} else if (rawAssetId) {
			return u.rawAssetId === rawAssetId;
		}
	}

	return true;
}

/**
 * Unspent, unblinded SP UTXOs owned by one account: `silentPaymentAddress` is the account's static
 * SP address, which every tracked record stores as `recipientAddress` (change included).
 */
export async function getUnspentSilentPaymentUtxos(
	chainId: string,
	silentPaymentAddress: string,
): Promise<TrackedSilentPaymentUtxo[]> {
	const owner = silentPaymentAddress.toLowerCase();
	const all = await getTrackedSilentPaymentUtxos();
	return all.filter(
		(u) =>
			!u.spent &&
			!u.unblindFailed &&
			// Its spend is not checked yet: counting it could show money that is gone.
			!u.spendUnverified &&
			u.chainId === chainId &&
			u.recipientAddress.toLowerCase() === owner,
	);
}

/**
 * How many of the account's payments are left out of the balance until their spend is checked:
 * while a backfill runs, the outputs tracked before its gap, which may have been spent in it.
 */
export async function countHeldSilentPaymentUtxos(
	chainId: string,
	silentPaymentAddress: string,
): Promise<number> {
	const owner = silentPaymentAddress.toLowerCase();
	return (await getTrackedSilentPaymentUtxos()).filter(
		(u) =>
			u.spendUnverified &&
			!u.spent &&
			!u.unblindFailed &&
			u.chainId === chainId &&
			u.recipientAddress.toLowerCase() === owner,
	).length;
}

function buildBlockCursorKey(chainId: string, silentPaymentAddress: string): string {
	return `${SP_BLOCK_CURSOR_KEY_PREFIX}${chainId}_${silentPaymentAddress.toLowerCase()}`;
}

function buildProgressKey(chainId: string, silentPaymentAddress: string): string {
	return `${chainId}_${silentPaymentAddress.toLowerCase()}`;
}

/** Birthdays are per account and network: block heights of two networks are not comparable. */
function buildBirthdayKey(chainId: string, silentPaymentAddress: string): string {
	return `${SP_BIRTHDAY_KEY_PREFIX}${chainId}_${silentPaymentAddress.toLowerCase()}`;
}

/**
 * A newest-first scan of `stopHeight..topHeight` in progress: `nextHeight` is the next block to
 * scan going down, and `nextHash` its hash as the block above it named.
 */
export type SilentPaymentBackfill = {
	nextHash: string;
	nextHeight: number;
	stopHeight: number;
	topHeight: number;
};

function buildBackfillKey(chainId: string, silentPaymentAddress: string): string {
	return `${SP_BACKFILL_KEY_PREFIX}${chainId}_${silentPaymentAddress.toLowerCase()}`;
}

export async function getSilentPaymentBackfill(
	chainId: string,
	silentPaymentAddress: string,
): Promise<SilentPaymentBackfill | null> {
	const val = await storeGetItem<SilentPaymentBackfill>(
		buildBackfillKey(chainId, silentPaymentAddress),
	);
	return val &&
		typeof val.nextHeight === "number" &&
		typeof val.stopHeight === "number" &&
		typeof val.topHeight === "number" &&
		typeof val.nextHash === "string"
		? val
		: null;
}

export async function saveSilentPaymentBackfill(
	chainId: string,
	silentPaymentAddress: string,
	backfill: SilentPaymentBackfill | null,
): Promise<void> {
	return withStoreLock(async () => {
		const key = buildBackfillKey(chainId, silentPaymentAddress);
		if (backfill !== null) {
			await storeSetItem(key, backfill);
			return;
		}
		const vault = await getVaultStorage();
		if (!vault) {
			throw new Error(`Secure vault is locked: cannot clear ${key}`);
		}
		await vault.deleteItem(key);
	});
}

/**
 * Spends of Taproot outputs (every SP output is one) in the blocks scanned while a backfill runs,
 * keyed by a fingerprint of the spent outpoint: an output the backfill finds, or one tracked before
 * its gap, is checked against it instead of asking the explorer about the output. `overflow`: the
 * index outgrew its cap and was dropped; checks then ask the explorer.
 */
export type SilentPaymentSpentIndex = {
	entries: Record<
		string,
		[spentInTxid: string, blockTime: number | null, feeSats: string | null, blockHeight: number]
	>;
	overflow?: true;
	/**
	 * Hex key of the fingerprints, made with the index and kept only in the vault, so nobody can
	 * craft a spend whose fingerprint matches one of the wallet's outputs.
	 */
	salt: string;
};

function buildSpentIndexKey(chainId: string, silentPaymentAddress: string): string {
	return `${SP_SPENT_INDEX_KEY_PREFIX}${chainId}_${silentPaymentAddress.toLowerCase()}`;
}

export async function getSilentPaymentSpentIndex(
	chainId: string,
	silentPaymentAddress: string,
): Promise<SilentPaymentSpentIndex | null> {
	const val = await storeGetItem<SilentPaymentSpentIndex>(
		buildSpentIndexKey(chainId, silentPaymentAddress),
	);
	// Without a salt its fingerprints could be ground: checks then ask the explorer instead.
	return val &&
		typeof val.entries === "object" &&
		val.entries !== null &&
		typeof val.salt === "string"
		? val
		: null;
}

export async function saveSilentPaymentSpentIndex(
	chainId: string,
	silentPaymentAddress: string,
	index: SilentPaymentSpentIndex | null,
): Promise<void> {
	return withStoreLock(async () => {
		const key = buildSpentIndexKey(chainId, silentPaymentAddress);
		if (index !== null) {
			await storeSetItem(key, index);
			return;
		}
		const vault = await getVaultStorage();
		if (!vault) {
			throw new Error(`Secure vault is locked: cannot clear ${key}`);
		}
		await vault.deleteItem(key);
	});
}

/** Flag outputs whose spend must be checked again (see `spendUnverified`). */
export async function markSilentPaymentSpendsUnverified(
	outpoints: Array<{ outputIndex: number; txid: string }>,
): Promise<void> {
	if (outpoints.length === 0) return;
	const keys = new Set(outpoints.map((o) => `${o.txid}:${o.outputIndex}`));
	await withStoreLock(async () => {
		const list = await readTrackedListForWrite();
		for (const u of list) {
			if (!u.spent && keys.has(`${u.txid}:${u.outputIndex}`)) u.spendUnverified = true;
		}
		await storeSetItem(SP_STORAGE_KEY, list);
	});
}

/** The explorer reported the output unspent: it counts in the balance again. */
export async function clearSilentPaymentSpendCheck(
	txid: string,
	outputIndex: number,
): Promise<void> {
	await updateTrackedSilentPaymentUtxo(txid, outputIndex, (target) => {
		delete target.spendUnverified;
	});
}

export async function getSilentPaymentBlockCursor(
	chainId: string,
	silentPaymentAddress: string,
): Promise<SilentPaymentBlockCursor | null> {
	try {
		const val = await storeGetItem<SilentPaymentBlockCursor>(
			buildBlockCursorKey(chainId, silentPaymentAddress),
		);
		if (
			val &&
			typeof val === "object" &&
			typeof val.height === "number" &&
			typeof val.blockHash === "string"
		) {
			return val;
		}
		return null;
	} catch (e) {
		console.error("[sp-store] Failed to get block scan cursor:", e);
		return null;
	}
}

export async function saveSilentPaymentBlockCursor(
	chainId: string,
	silentPaymentAddress: string,
	cursor: SilentPaymentBlockCursor | null,
): Promise<void> {
	return withStoreLock(async () => {
		const key = buildBlockCursorKey(chainId, silentPaymentAddress);
		if (cursor === null) {
			const vault = await getVaultStorage();
			if (!vault) {
				throw new Error(`Secure vault is locked: cannot clear ${key}`);
			}
			await vault.deleteItem(key);
			return;
		}
		await storeSetItem(key, cursor);
	});
}

export function getSilentPaymentLocalScanProgress(
	chainId: string,
	silentPaymentAddress: string,
): SilentPaymentLocalScanProgress | null {
	return localScanProgressMap.get(buildProgressKey(chainId, silentPaymentAddress)) ?? null;
}

export function setSilentPaymentLocalScanProgress(
	chainId: string,
	silentPaymentAddress: string,
	progress: SilentPaymentLocalScanProgress | null,
): void {
	const key = buildProgressKey(chainId, silentPaymentAddress);
	if (progress === null) {
		localScanProgressMap.delete(key);
	} else {
		localScanProgressMap.set(key, progress);
	}
}

export async function getSilentPaymentBirthday(
	chainId: string,
	silentPaymentAddress: string,
): Promise<number | null> {
	try {
		const val = await storeGetItem<number>(buildBirthdayKey(chainId, silentPaymentAddress));
		return typeof val === "number" ? val : null;
	} catch (e) {
		console.error("[sp-store] Failed to get silent payment birthday:", e);
		return null;
	}
}

export async function saveSilentPaymentBirthday(
	chainId: string,
	silentPaymentAddress: string,
	height: number,
): Promise<void> {
	return withStoreLock(async () => {
		try {
			await storeSetItem(buildBirthdayKey(chainId, silentPaymentAddress), height);
		} catch (e) {
			console.error("[sp-store] Failed to save silent payment birthday:", e);
		}
	});
}

/** Labels are per account and network, like the birthday. */
function buildLabelsKey(chainId: string, silentPaymentAddress: string): string {
	return `${SP_LABELS_KEY_PREFIX}${chainId}_${silentPaymentAddress.toLowerCase()}`;
}

/** The account's labels on a network, by ascending index. */
export async function getSilentPaymentLabels(
	chainId: string,
	silentPaymentAddress: string,
): Promise<SilentPaymentLabel[]> {
	try {
		const labels = await storeGetItem<SilentPaymentLabel[]>(
			buildLabelsKey(chainId, silentPaymentAddress),
		);
		return Array.isArray(labels) ? labels.toSorted((a, b) => a.index - b.index) : [];
	} catch (e) {
		console.error("[sp-store] Failed to load silent payment labels:", e);
		return [];
	}
}

/**
 * Change the account's labels under the store lock, so two edits never overwrite each other.
 * `update` gets the current labels and returns the new list; a failed write throws.
 */
export async function updateSilentPaymentLabels(
	chainId: string,
	silentPaymentAddress: string,
	update: (labels: SilentPaymentLabel[]) => Promise<SilentPaymentLabel[]> | SilentPaymentLabel[],
): Promise<SilentPaymentLabel[]> {
	return withStoreLock(async () => {
		// Read strictly, unlike `getSilentPaymentLabels`: a failed or malformed read throws, since
		// writing back a list built on nothing would erase every label.
		const key = buildLabelsKey(chainId, silentPaymentAddress);
		const stored = await storeGetItem<unknown>(key);
		if (stored !== null && !Array.isArray(stored)) {
			throw new Error("[sp-store] Stored Silent Payment label list is malformed");
		}
		const labels = ((stored ?? []) as SilentPaymentLabel[]).toSorted((a, b) => a.index - b.index);

		const next = await update(labels);
		await storeSetItem(key, next);
		return next;
	});
}
