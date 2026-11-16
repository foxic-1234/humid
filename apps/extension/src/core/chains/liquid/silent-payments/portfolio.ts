import type {
	LiquidActivityEntry,
	LiquidWalletAccount,
} from "../application/backends/LiquidWalletBackend";
import type { LiquidChainRecord } from "../chains/LiquidChainRecord";
import type { LiquidPortfolio, LiquidUtxoSnapshot } from "../contract";
import { type RestoredWallet, startExplorerCatchUp, syncFromExplorer } from "./localScanner";
import {
	getSilentPaymentLabels,
	getTrackedSilentPaymentUtxos,
	getUnspentSilentPaymentUtxos,
	isSilentPaymentStoreUnlocked,
	type TrackedSilentPaymentUtxo,
} from "./store";
import type { SilentPaymentRecipientKeys } from "./types";

/** How long a portfolio refresh waits for the wallet's explorer scan before showing stored data. */
const DEFAULT_EXPLORER_SCAN_WAIT_MS = 5_000;
let explorerScanWaitMs = DEFAULT_EXPLORER_SCAN_WAIT_MS;

/** Test-only: how long a refresh waits for the scan; no argument restores the default. */
export function setExplorerScanWaitForTesting(ms = DEFAULT_EXPLORER_SCAN_WAIT_MS): void {
	explorerScanWaitMs = ms;
}

/**
 * Augment a portfolio snapshot with the account's tracked Silent Payment UTXOs, found by the
 * wallet's own scan over the block explorer (`syncFromExplorer`).
 *
 * The SP store is readable only while the vault is unlocked. While it is locked, the SP outputs
 * of `previous` (the last saved portfolio) are carried over, so a locked refresh does not drop them.
 * `restoredWallet` marks a wallet restored from its recovery phrase (see `syncFromExplorer`).
 */
export async function augmentPortfolioWithSilentPayments(
	snapshot: LiquidPortfolio,
	chain: LiquidChainRecord,
	silentPaymentAddress?: string,
	recipientKeys?: SilentPaymentRecipientKeys,
	previous?: Pick<LiquidPortfolio, "utxos">,
	restoredWallet?: RestoredWallet,
): Promise<LiquidPortfolio> {
	if (!silentPaymentAddress) {
		return snapshot;
	}

	if (!(await isSilentPaymentStoreUnlocked())) {
		return mergeSilentPaymentUtxos(
			snapshot,
			(previous?.utxos ?? []).filter((u) => u.silentPayment),
		);
	}

	if (recipientKeys) {
		const run = syncFromExplorer({
			chain,
			recipientKeys,
			restoredWallet,
			silentPaymentAddress,
		}).then(
			({ status }) => status,
			(explorerErr: unknown) => {
				console.warn("[sp-portfolio] Wallet explorer scan failed:", explorerErr);
				return "failed" as const;
			},
		);
		// A run near the tip ends in a second or two; a longer one (a backlog, a slow explorer)
		// does not hold the refresh, which shows what is stored so far.
		let timer: ReturnType<typeof setTimeout> | undefined;
		const status = await Promise.race([
			run,
			new Promise<"running">((resolve) => {
				timer = setTimeout(() => resolve("running"), explorerScanWaitMs);
			}),
		]);
		clearTimeout(timer);
		// A backlog longer than one run, a run still going, or a failed run keeps going in the
		// background (a failure after a pause); its finds show up on the next refresh.
		if (status !== "synced") {
			void startExplorerCatchUp({ chain, recipientKeys, restoredWallet, silentPaymentAddress });
		}
	}

	const spUtxos = await getUnspentSilentPaymentUtxos(chain.id, silentPaymentAddress);

	return mergeSilentPaymentUtxos(
		snapshot,
		spUtxos.map((spUtxo) => ({
			address: spUtxo.address,
			amountSats: spUtxo.amountSats,
			confidential: false,
			rawAssetId: spUtxo.rawAssetId,
			scriptPubKey: spUtxo.scriptPubKeyHex,
			silentPayment: true,
			spendable: true,
			txid: spUtxo.txid,
			txOut: `${spUtxo.txid}:${spUtxo.outputIndex}`,
			vout: spUtxo.outputIndex,
		})),
	);
}

function mergeSilentPaymentUtxos(
	snapshot: LiquidPortfolio,
	spUtxos: LiquidUtxoSnapshot[],
): LiquidPortfolio {
	if (spUtxos.length === 0) {
		return snapshot;
	}

	const mergedAssets = snapshot.assets.map((asset) => ({ ...asset }));
	const mergedUtxos = [...snapshot.utxos];

	for (const spUtxo of spUtxos) {
		if (mergedUtxos.some((u) => u.txid === spUtxo.txid && u.vout === spUtxo.vout)) {
			continue;
		}

		mergedUtxos.push(spUtxo);

		// The snapshot always carries the native asset, so a missing entry is an issued asset. Anyone
		// can send any asset to a public SP address: it is unverified until a registry says otherwise.
		const asset = mergedAssets.find((a) => a.rawAssetId === spUtxo.rawAssetId);
		if (asset) {
			asset.amountSats = (BigInt(asset.amountSats) + BigInt(spUtxo.amountSats)).toString();
		} else {
			mergedAssets.push({
				amountSats: spUtxo.amountSats,
				decimals: 8,
				isNative: false,
				metadata: {
					isNative: false,
					issuerDomain: null,
					verified: false,
				},
				name: "Asset",
				rawAssetId: spUtxo.rawAssetId,
				symbol: "TOKEN",
			});
		}
	}

	return {
		assets: mergedAssets,
		utxos: mergedUtxos,
	};
}

/** What the account's tracked SP outputs add to one transaction, for one asset. */
type SilentPaymentTxEffect = {
	/** Sum of the account's SP outputs the transaction created (change included). */
	created: bigint;
	/** Sum of the account's SP outputs the transaction spent. */
	spent: bigint;
	/** Created outputs on the account's address or a user label (m != 0), i.e. not change. */
	incoming: TrackedSilentPaymentUtxo[];
	feeSats?: string;
	/** Block time; null while unconfirmed. */
	timestamp: number | null;
	/** Whether `timestamp` is a known block time rather than a record's creation time. */
	exactTime: boolean;
};

/**
 * The asset's whole activity, newest first: LWK's history merged with the account's Silent Payment
 * outputs. LWK computes each entry from its own scripts only, so it misses SP inputs (spent as
 * external UTXOs) and SP outputs (incoming payments and SP change). Each LWK entry is corrected by
 * its transaction's SP effect, and a transaction LWK does not see at all (paid to or only from SP
 * outputs) gets its own entry.
 */
export async function mergeActivityWithSilentPayments(
	lwkItems: LiquidActivityEntry[],
	chain: LiquidChainRecord,
	account: LiquidWalletAccount,
	rawAssetId: string,
): Promise<LiquidActivityEntry[]> {
	if (!account.silentPaymentAddress) {
		return lwkItems;
	}

	const owner = account.silentPaymentAddress.toLowerCase();
	const isNativeAsset = (id: string) =>
		id === account.rawPolicyAssetId || id === chain.settings.policyAsset;
	const isNative = isNativeAsset(rawAssetId);

	// A failed unblind has no amount to count.
	const tracked = (await getTrackedSilentPaymentUtxos()).filter(
		(u) =>
			u.chainId === chain.id &&
			u.recipientAddress.toLowerCase() === owner &&
			!u.unblindFailed &&
			((isNative && isNativeAsset(u.rawAssetId)) || u.rawAssetId === rawAssetId),
	);

	const effects = new Map<string, SilentPaymentTxEffect>();
	const effectOf = (txid: string) => {
		let effect = effects.get(txid);
		if (!effect) {
			effect = { created: 0n, exactTime: false, incoming: [], spent: 0n, timestamp: null };
			effects.set(txid, effect);
		}
		return effect;
	};
	for (const u of tracked) {
		const funding = effectOf(u.txid);
		funding.created += BigInt(u.amountSats);
		if (u.labelIndex !== 0) funding.incoming.push(u);
		if (typeof u.blockTime === "number") {
			funding.timestamp = u.blockTime;
			funding.exactTime = true;
		} else if (u.confirmed !== false && u.blockTime !== null && !funding.exactTime) {
			funding.timestamp = Math.floor(u.createdAt / 1000);
		}
		if (u.spent && u.spentInTxid) {
			const spending = effectOf(u.spentInTxid);
			spending.spent += BigInt(u.amountSats);
			spending.feeSats ??= u.spentFeeSats;
			if (u.spentBlockTime != null) {
				spending.timestamp = u.spentBlockTime;
				spending.exactTime = true;
			}
		}
	}

	const labelNames = new Map(
		(await getSilentPaymentLabels(chain.id, account.silentPaymentAddress)).map((label) => [
			label.index,
			label.name,
		]),
	);
	const silentPaymentFields = (effect: SilentPaymentTxEffect) => {
		const labelIndex = effect.incoming.find((u) => u.labelIndex !== undefined)?.labelIndex;
		return {
			isSilentPayment: true,
			...(labelIndex !== undefined && labelNames.has(labelIndex)
				? { silentPaymentLabel: labelNames.get(labelIndex) }
				: {}),
		};
	};
	const withNet = (
		base: Omit<LiquidActivityEntry, "amountSats" | "direction">,
		net: bigint,
		effect: SilentPaymentTxEffect,
	): LiquidActivityEntry => ({
		...base,
		amountSats: (net < 0n ? -net : net).toString(),
		direction: net < 0n ? "sent" : "received",
		// "Silent Payment" marks a payment received on the SP address, not a send that spent SP outputs.
		...(net > 0n && effect.incoming.length > 0 ? silentPaymentFields(effect) : {}),
	});

	const items: LiquidActivityEntry[] = [];
	for (const item of lwkItems) {
		const effect = effects.get(item.txid);
		effects.delete(item.txid);
		if (!effect) {
			items.push(item);
			continue;
		}
		const lwkNet = item.direction === "sent" ? -BigInt(item.amountSats) : BigInt(item.amountSats);
		const net = lwkNet + effect.created - effect.spent;
		if (net !== 0n) items.push(withNet(item, net, effect));
	}

	for (const [txid, effect] of effects) {
		const net = effect.created - effect.spent;
		// SP change whose spend the wallet does not know is not income.
		if (net === 0n || (effect.spent === 0n && effect.incoming.length === 0)) continue;
		items.push(
			withNet(
				{
					feeSats: net < 0n ? (effect.feeSats ?? "0") : "0",
					timestamp: effect.timestamp,
					txid,
				},
				net,
				effect,
			),
		);
	}

	// Newest first: pending (null timestamp) on top, then by descending timestamp.
	return items.toSorted((a, b) => {
		if (a.timestamp === null && b.timestamp === null) return 0;
		if (a.timestamp === null) return -1;
		if (b.timestamp === null) return 1;
		return b.timestamp - a.timestamp;
	});
}
