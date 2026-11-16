import { zeroizeRecipientKeys } from "@humid/sp-core";

import { createLwkWalletBackend } from "./adapters/lwk/createLwkWalletBackend";
import { getWalletCreatedAt, isRestoredKeySource } from "./adapters/lwk/getLocalRootSeedMaterial";
import { createLwkLiquidIdentityBackend } from "./adapters/lwk/identity/createLwkLiquidIdentityBackend";
import { getSyncWorkerClient } from "./adapters/lwk/sync-worker/createSyncWorkerClient";
import { createLiquidWalletConnectAdapter } from "./adapters/walletconnect/createLiquidWalletConnectAdapter";
import { createLiquidRpcRouter } from "./application/createLiquidRpcRouter";
import { createBuiltInLiquidChains } from "./chains/createBuiltInLiquidChains";
import { LIQUID_CHAIN_GROUP_ID } from "./chains/LiquidChainRecord";
import type { LiquidAccountRuntime, LiquidChainGroup } from "./contract";
import {
	mergeActivityWithSilentPayments,
	augmentPortfolioWithSilentPayments,
	buildExplorerApis,
	countHeldSilentPaymentUtxos,
	createSilentPaymentLabel,
	fallbackExplorerUnreachable,
	getSilentPaymentBackfill,
	getSilentPaymentBirthday,
	getSilentPaymentBlockCursor,
	getSilentPaymentLabels,
	getSilentPaymentLocalScanProgress,
	getSilentPaymentScanRate,
	renameSilentPaymentLabel,
	rescanFromExplorer,
	restoreExplorerLimiters,
	type RestoredWallet,
	type SilentPaymentLabel,
	type SilentPaymentRecipientKeys,
	startExplorerCatchUp,
} from "./silent-payments";

const toLabelView = ({ address, index, name }: SilentPaymentLabel) => ({ address, index, name });

const ACTIVITY_PAGE_SIZE = 25;

export function createLiquidChainGroup(): LiquidChainGroup {
	const identityBackend = createLwkLiquidIdentityBackend();
	const walletBackend = createLwkWalletBackend();
	const walletRpcDispatcher = createLiquidRpcRouter({
		identityBackend,
		walletBackend,
	});

	const accountRuntime: LiquidAccountRuntime = {
		async estimateMaxSend(input, estimate) {
			const account = await walletBackend.resolveAccount(input);
			try {
				const rawAssetId = estimate.rawAssetId ?? account.rawPolicyAssetId;
				await walletBackend.syncAccount(account);

				return await walletBackend.estimateMaxSend(account, estimate, rawAssetId);
			} finally {
				account.wipePrivateData?.();
			}
		},
		async getActivity(input, rawAssetId, cursor) {
			const account = await walletBackend.resolveAccount(input);
			try {
				// The whole LWK history: SP-only transactions are merged in by time, so pages are cut
				// after the merge. The cursor keeps the worker's meaning, an offset into the list.
				const lwk = await getSyncWorkerClient().readActivity({
					chain: input.chain,
					cursor: null,
					descriptor: account.descriptor,
					limit: Number.MAX_SAFE_INTEGER,
					rawAssetId,
				});
				const all = await mergeActivityWithSilentPayments(
					lwk.items,
					input.chain,
					account,
					rawAssetId,
				);
				const parsed = cursor ? Number.parseInt(cursor, 10) : 0;
				const offset = Number.isInteger(parsed) && parsed >= 0 ? parsed : 0;
				const items = all.slice(offset, offset + ACTIVITY_PAGE_SIZE);
				const nextOffset = offset + items.length;

				return { items, nextCursor: nextOffset < all.length ? String(nextOffset) : null };
			} finally {
				account.wipePrivateData?.();
			}
		},
		async getReceiveAddress(input) {
			const account = await walletBackend.resolveAccount(input);
			try {
				const standard = walletBackend.getReceiveAddress(account);
				const sp = walletBackend.getSilentPaymentAddress?.(account);

				return {
					...standard,
					unconfidential: walletBackend.getSigningAddress(account).unconfidential,
					scanPublicKey: sp?.scanPublicKey,
					silentPaymentAddress: sp?.address ?? account.silentPaymentAddress,
					spendPublicKey: sp?.spendPublicKey,
				};
			} finally {
				account.wipePrivateData?.();
			}
		},
		async inspectTransfer(input, transfer) {
			const account = await walletBackend.resolveAccount(input);
			try {
				const rawAssetId = transfer.rawAssetId ?? account.rawPolicyAssetId;

				return await walletBackend.inspectTransfer(account, transfer, rawAssetId);
			} finally {
				account.wipePrivateData?.();
			}
		},
		async resolveAccountIdentifier(input) {
			const account = await walletBackend.resolveAccount(input);
			account.wipePrivateData?.();

			return account.accountIdentifier;
		},
		async resolveScanTarget(input) {
			const account = await walletBackend.resolveAccount(input);

			// The scan target is watch-only / scan-only. Never expose b_spend
			// (spend private key) to the scan target runtime or background polling engine.
			const scanOnlyKeys: SilentPaymentRecipientKeys | undefined = account.silentPaymentKeys
				? {
						scanKey: {
							privateKey: new Uint8Array(account.silentPaymentKeys.scanKey.privateKey),
							publicKey: new Uint8Array(account.silentPaymentKeys.scanKey.publicKey),
						},
						spendKey: {
							privateKey: new Uint8Array(0),
							publicKey: new Uint8Array(account.silentPaymentKeys.spendKey.publicKey),
						},
					}
				: undefined;

			// Wipe ephemeral account secret keys immediately. The b_scan copy belongs to the caller,
			// which zeroizes it with `zeroizeRecipientKeys` once done.
			account.wipePrivateData?.();

			return {
				chain: input.chain,
				descriptor: account.descriptor,
				restoredWallet: isRestoredKeySource(input.keyManagerState, input.keySourceId),
				silentPaymentAddress: account.silentPaymentAddress,
				silentPaymentKeys: scanOnlyKeys,
				walletCreatedAt: getWalletCreatedAt(input.keyManagerState, input.keySourceId),
			};
		},
		async scanPortfolio(target, previous) {
			const snapshot = await getSyncWorkerClient().scanAndRead({
				chain: target.chain,
				descriptor: target.descriptor,
			});

			// A restored wallet's first SP scan starts before its earliest LWK transaction and the date
			// the user gave for it; the history is read only if that scan has no birthday yet.
			const restoredWallet: RestoredWallet | undefined = target.restoredWallet
				? {
						walletCreatedAt: target.walletCreatedAt,
						earliestTxHeight: async () => {
							const heights: number[] = [];
							for (const asset of snapshot.assets) {
								const { items } = await getSyncWorkerClient().readActivity({
									chain: target.chain,
									cursor: null,
									descriptor: target.descriptor,
									limit: Number.MAX_SAFE_INTEGER,
									rawAssetId: asset.rawAssetId,
								});
								for (const item of items) {
									if (item.blockHeight !== undefined) heights.push(item.blockHeight);
								}
							}
							return heights.length > 0 ? Math.min(...heights) : undefined;
						},
					}
				: undefined;

			return augmentPortfolioWithSilentPayments(
				{ assets: snapshot.assets, utxos: snapshot.utxos },
				target.chain,
				target.silentPaymentAddress,
				target.silentPaymentKeys,
				previous,
				restoredWallet,
			);
		},
		async sendTransfer(input, transfer) {
			const account = await walletBackend.resolveAccount(input);
			try {
				const rawAssetId = transfer.rawAssetId ?? account.rawPolicyAssetId;
				await walletBackend.syncAccount(account);

				return await walletBackend.sendTransfer(account, transfer, rawAssetId);
			} finally {
				account.wipePrivateData?.();
			}
		},
		async getSilentPaymentScanStatus(input, scanInput) {
			const chain = input.chain;
			const chainId = scanInput?.chainId ?? chain.id;
			const target = await accountRuntime.resolveScanTarget(input);
			try {
				if (target.silentPaymentAddress) {
					const address = target.silentPaymentAddress;
					// While older blocks are searched, the payments that search keeps out of the balance.
					const heldPayments = () => countHeldSilentPaymentUtxos(chainId, address);
					const progress = getSilentPaymentLocalScanProgress(chainId, address);
					if (progress) {
						return progress.history
							? { ...progress, heldPayments: await heldPayments() }
							: progress;
					}

					await restoreExplorerLimiters();
					const [cursor, birthday, backfill, rate] = await Promise.all([
						getSilentPaymentBlockCursor(chainId, target.silentPaymentAddress),
						getSilentPaymentBirthday(chainId, target.silentPaymentAddress),
						getSilentPaymentBackfill(chainId, target.silentPaymentAddress),
						getSilentPaymentScanRate(chainId, target.silentPaymentAddress),
					]);

					// No run since the service worker started: a backfill left in the store is history
					// still to scan, which the next refresh resumes, not a synced wallet.
					if (backfill) {
						const history = {
							done: backfill.topHeight - backfill.nextHeight,
							total: backfill.topHeight - backfill.stopHeight + 1,
						};
						const historyLeft = history.total - history.done;
						return {
							birthdayHeight: birthday ?? undefined,
							chainId,
							currentHeight: backfill.nextHeight,
							// The last run's rate, so the time left shows before the next run measures one.
							etaSeconds: rate && historyLeft > 0 ? Math.round(historyLeft / rate) : undefined,
							fallbackExplorerDown:
								fallbackExplorerUnreachable(buildExplorerApis(chain)) || undefined,
							heldPayments: await heldPayments(),
							history,
							isScanning: false,
							newBlocksLeft: 0,
							percentage: Math.min(99, Math.floor((history.done / history.total) * 100)),
							state: "backfilling",
							tipHeight: cursor?.height ?? backfill.topHeight,
							totalBlocksToScan: history.total,
						};
					}

					return {
						birthdayHeight: birthday ?? undefined,
						chainId,
						currentHeight: cursor?.height ?? 0,
						isScanning: false,
						percentage: 100,
						state: cursor ? "synced" : "idle",
						tipHeight: cursor?.height ?? 0,
						totalBlocksToScan: 0,
					};
				}

				return {
					chainId,
					currentHeight: 0,
					isScanning: false,
					percentage: 100,
					state: "idle",
					tipHeight: 0,
					totalBlocksToScan: 0,
				};
			} finally {
				zeroizeRecipientKeys(target.silentPaymentKeys);
			}
		},
		async rescanSilentPayments(input, rescanInput) {
			const chain = input.chain;
			const { birthdayHeight } = rescanInput;
			const target = await accountRuntime.resolveScanTarget(input);
			try {
				if (!target.silentPaymentKeys || !target.silentPaymentAddress) {
					throw new Error("No Silent Payment keys available for rescan");
				}

				await rescanFromExplorer({
					birthdayHeight,
					chain,
					silentPaymentAddress: target.silentPaymentAddress,
				});
				// Runs until the tip, not one run per refresh; it copies the scan key before this
				// method's `finally` wipes the target's copy.
				void startExplorerCatchUp({
					chain,
					recipientKeys: target.silentPaymentKeys,
					silentPaymentAddress: target.silentPaymentAddress,
				});
			} finally {
				zeroizeRecipientKeys(target.silentPaymentKeys);
			}
		},
		async listSilentPaymentLabels(input) {
			const target = await accountRuntime.resolveScanTarget(input);
			// Only the account's SP address is needed: the labels and their addresses are stored.
			zeroizeRecipientKeys(target.silentPaymentKeys);
			if (!target.silentPaymentAddress) return { labels: [] };

			const labels = await getSilentPaymentLabels(input.chain.id, target.silentPaymentAddress);
			return { labels: labels.map(toLabelView) };
		},
		async createSilentPaymentLabel(input, params) {
			const target = await accountRuntime.resolveScanTarget(input);
			try {
				if (!target.silentPaymentKeys || !target.silentPaymentAddress) {
					throw new Error("No Silent Payment keys available for this account");
				}

				return toLabelView(
					await createSilentPaymentLabel({
						chain: input.chain,
						name: params.name,
						recipientKeys: target.silentPaymentKeys,
						silentPaymentAddress: target.silentPaymentAddress,
					}),
				);
			} finally {
				zeroizeRecipientKeys(target.silentPaymentKeys);
			}
		},
		async renameSilentPaymentLabel(input, params) {
			const target = await accountRuntime.resolveScanTarget(input);
			zeroizeRecipientKeys(target.silentPaymentKeys);
			if (!target.silentPaymentAddress) {
				throw new Error("No Silent Payment address for this account");
			}

			return toLabelView(
				await renameSilentPaymentLabel({
					chainId: input.chain.id,
					index: params.index,
					name: params.name,
					silentPaymentAddress: target.silentPaymentAddress,
				}),
			);
		},
	};

	return {
		accountRuntime,
		chains: createBuiltInLiquidChains(),
		id: LIQUID_CHAIN_GROUP_ID,
		walletConnectAdapter: createLiquidWalletConnectAdapter({
			identityBackend,
			walletBackend,
		}),
		walletRpcDispatcher,
	};
}
