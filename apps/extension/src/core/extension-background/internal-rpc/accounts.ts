import { createAccountRegistry } from "@/core/accounts/application/account-registry";
import type { AccountModelState } from "@/core/accounts/application/account-registry/model/account-model";
import { getSelectedAccountGroup } from "@/core/accounts/application/account-registry/operations/getSelectedAccountGroup";
import { accountsRpc } from "@/core/accounts/application/accounts-rpc/model/rpc";
import type {
	AccountsState,
	ActivityPage,
	CreateAccountInput,
	CreateSilentPaymentLabelInput,
	EstimateMaxSendInput,
	EstimateMaxSendResult,
	GetActivityInput,
	ImportAccountInput,
	ListSilentPaymentLabelsInput,
	ListSilentPaymentLabelsResult,
	PortfolioSnapshot,
	ReceiveAddress,
	RemoveAccountInput,
	RemoveWalletInput,
	RenameAccountInput,
	RenameSilentPaymentLabelInput,
	RevealRecoveryPhraseInput,
	SendTransferInput,
	SendTransferResult,
	SetSelectedAccountInput,
	SilentPaymentLabelView,
	TransferReview,
} from "@/core/accounts/application/accounts-rpc/model/types";
import { LIQUID_WALLET_DESCRIPTOR_CHANGED_EVENT } from "@/core/chains/liquid/domain/LiquidRpc";
import { keyManagerSecretMaterial } from "@/core/key-manager/secret-material";
import { addImportedSeedToKeyManagerState } from "@/core/key-manager/state/import-seed";
import { removeWalletFromKeyManagerState } from "@/core/key-manager/state/remove-wallet";
import { toWalletCreatedAt } from "@/core/key-manager/state/wallet-created-at";
import { walletVaultBackground } from "@/core/secure-vault/application/wallet-vault/background";

import type { RequestHandlerMap } from "../transport";
import { emitWalletEvent } from "../wallet-events";

export type SilentPaymentLabelsDeps = {
	create: (input: CreateSilentPaymentLabelInput) => Promise<SilentPaymentLabelView>;
	list: (input?: ListSilentPaymentLabelsInput) => Promise<ListSilentPaymentLabelsResult>;
	rename: (input: RenameSilentPaymentLabelInput) => Promise<SilentPaymentLabelView>;
};

function readAccountsState(model: AccountModelState): AccountsState {
	return {
		accountGroups: Object.values(model.accountGroups),
		selectedAccountGroupId: getSelectedAccountGroup(model).id,
	};
}

export type AccountsRuntimeDeps = {
	getActivity: (input: GetActivityInput) => Promise<ActivityPage>;
	getPortfolio: () => Promise<PortfolioSnapshot>;
	getReceiveAddress: () => Promise<ReceiveAddress>;
	inspectTransfer: (input: SendTransferInput) => Promise<TransferReview>;
	estimateMaxSend: (input: EstimateMaxSendInput) => Promise<EstimateMaxSendResult>;
	refreshPortfolio: () => Promise<PortfolioSnapshot>;
	sendTransfer: (input: SendTransferInput) => Promise<SendTransferResult>;
	getSilentPaymentScanStatus?: (
		input?: import("@/core/accounts/application/accounts-rpc/model/types").GetSilentPaymentScanStatusInput,
	) => Promise<
		import("@/core/accounts/application/accounts-rpc/model/types").SilentPaymentScanStatusResult
	>;
	rescanSilentPayments?: (
		input: import("@/core/accounts/application/accounts-rpc/model/types").RescanSilentPaymentsInput,
	) => Promise<void>;
	// BIP-352 labels of the selected account on the given (default: selected) chain. Wired by root.
	silentPaymentLabels?: SilentPaymentLabelsDeps;
	purgeAccountPortfolio: (accountGroupId: string) => Promise<void>;
	purgeAccountWalletConnectSessions: (accountGroupIds: readonly string[]) => Promise<void>;
};

export function createAccountsInternalHandlers(deps: AccountsRuntimeDeps): RequestHandlerMap {
	const requireLabels = (): SilentPaymentLabelsDeps => {
		if (!deps.silentPaymentLabels) {
			throw new Error("Silent Payment labels are not supported in this runtime");
		}
		return deps.silentPaymentLabels;
	};

	return {
		[accountsRpc.methods.getState]: () =>
			readAccountsState(walletVaultBackground.keyManager.getState().accountModel),
		[accountsRpc.methods.setSelected]: async (message) => {
			const { accountGroupId } = message.data as SetSelectedAccountInput;
			const model = walletVaultBackground.keyManager.getState().accountModel;

			if (!model.accountGroups[accountGroupId]) {
				throw new Error(`Unknown account group: ${accountGroupId}`);
			}

			const next = await walletVaultBackground.keyManager.updateState((current) => ({
				...current,
				accountModel: { ...current.accountModel, selectedAccountGroupId: accountGroupId },
			}));

			emitWalletEvent("accountsChanged");
			emitWalletEvent(LIQUID_WALLET_DESCRIPTOR_CHANGED_EVENT);

			return readAccountsState(next.accountModel);
		},
		[accountsRpc.methods.rename]: async (message) => {
			const { accountGroupId, name } = message.data as RenameAccountInput;
			const trimmed = name.trim();

			if (!trimmed) throw new Error("Account name cannot be empty.");

			const model = walletVaultBackground.keyManager.getState().accountModel;

			if (!model.accountGroups[accountGroupId]) {
				throw new Error(`Unknown account group: ${accountGroupId}`);
			}

			const now = Date.now();
			const next = await walletVaultBackground.keyManager.updateState((current) => ({
				...current,
				accountModel: {
					...current.accountModel,
					accountGroups: {
						...current.accountModel.accountGroups,
						[accountGroupId]: {
							...current.accountModel.accountGroups[accountGroupId],
							name: trimmed,
							updatedAt: now,
						},
					},
					updatedAt: now,
				},
			}));

			return readAccountsState(next.accountModel);
		},
		[accountsRpc.methods.createAccount]: async (message) => {
			const { name } = (message.data ?? {}) as CreateAccountInput;
			const accountRegistry = createAccountRegistry();

			const next = await walletVaultBackground.keyManager.updateState((current) => {
				const selectedGroup = getSelectedAccountGroup(current.accountModel);
				const { accountGroup, accountModel } = accountRegistry.createNextAccountGroup({
					accountModel: current.accountModel,
					name,
					walletId: selectedGroup.walletId,
				});

				return {
					...current,
					accountModel: { ...accountModel, selectedAccountGroupId: accountGroup.id },
				};
			});

			emitWalletEvent("accountsChanged");
			emitWalletEvent(LIQUID_WALLET_DESCRIPTOR_CHANGED_EVENT);

			return readAccountsState(next.accountModel);
		},
		[accountsRpc.methods.importAccount]: async (message) => {
			const { mnemonic, name, walletCreatedAt } = message.data as ImportAccountInput;

			if (!keyManagerSecretMaterial.isValidMnemonic(mnemonic)) {
				throw new Error("Invalid recovery phrase.");
			}

			const seedMaterial = keyManagerSecretMaterial.normalizeMnemonic(mnemonic);
			const next = await walletVaultBackground.keyManager.updateState((current) =>
				addImportedSeedToKeyManagerState(current, {
					name,
					seedMaterial,
					walletCreatedAt: toWalletCreatedAt(walletCreatedAt),
				}),
			);

			emitWalletEvent("accountsChanged");
			emitWalletEvent(LIQUID_WALLET_DESCRIPTOR_CHANGED_EVENT);

			return readAccountsState(next.accountModel);
		},
		[accountsRpc.methods.removeAccount]: async (message) => {
			const { accountGroupId } = message.data as RemoveAccountInput;
			const accountRegistry = createAccountRegistry();

			await deps.purgeAccountWalletConnectSessions([accountGroupId]);

			const sessionsBefore = Object.keys(
				walletVaultBackground.keyManager.getState().accountModel.dappSessions,
			).length;

			const next = await walletVaultBackground.keyManager.updateState((current) => {
				const { accountModel } = accountRegistry.removeAccountGroup({
					accountGroupId,
					accountModel: current.accountModel,
				});

				return { ...current, accountModel };
			});

			await deps.purgeAccountPortfolio(accountGroupId);

			emitWalletEvent("accountsChanged");
			emitWalletEvent(LIQUID_WALLET_DESCRIPTOR_CHANGED_EVENT);
			if (Object.keys(next.accountModel.dappSessions).length < sessionsBefore) {
				emitWalletEvent("wallet_sessionChanged");
			}

			return readAccountsState(next.accountModel);
		},
		[accountsRpc.methods.removeWallet]: async (message) => {
			const { walletId } = message.data as RemoveWalletInput;

			const stateBefore = walletVaultBackground.keyManager.getState();
			const wallet = stateBefore.accountModel.wallets[walletId];

			if (!wallet) {
				throw new Error(`Unknown wallet: ${walletId}`);
			}

			const removedAccountGroupIds = wallet.accountGroupIds;

			await deps.purgeAccountWalletConnectSessions(removedAccountGroupIds);

			const sessionsBefore = Object.keys(stateBefore.accountModel.dappSessions).length;

			const next = await walletVaultBackground.keyManager.updateState((current) =>
				removeWalletFromKeyManagerState(current, { walletId }),
			);

			await Promise.all(
				removedAccountGroupIds.map((accountGroupId) => deps.purgeAccountPortfolio(accountGroupId)),
			);

			emitWalletEvent("accountsChanged");
			emitWalletEvent(LIQUID_WALLET_DESCRIPTOR_CHANGED_EVENT);
			if (Object.keys(next.accountModel.dappSessions).length < sessionsBefore) {
				emitWalletEvent("wallet_sessionChanged");
			}

			return readAccountsState(next.accountModel);
		},
		[accountsRpc.methods.revealRecoveryPhrase]: (message) => {
			const { accountGroupId } = message.data as RevealRecoveryPhraseInput;
			const state = walletVaultBackground.keyManager.getState();
			const group = state.accountModel.accountGroups[accountGroupId];

			if (!group) throw new Error(`Unknown account group: ${accountGroupId}`);

			const wallet = state.accountModel.wallets[group.walletId];
			const secret = wallet ? state.secretMaterials[wallet.keySourceId] : undefined;

			if (!secret || (secret.kind !== "seed" && secret.kind !== "mnemonic")) {
				throw new Error("This account has no revealable recovery phrase.");
			}

			return { phrase: secret.value };
		},
		[accountsRpc.methods.getReceiveAddress]: () => deps.getReceiveAddress(),
		[accountsRpc.methods.getPortfolio]: () => deps.getPortfolio(),
		[accountsRpc.methods.refreshPortfolio]: () => deps.refreshPortfolio(),
		[accountsRpc.methods.getActivity]: (message) =>
			deps.getActivity(message.data as GetActivityInput),
		[accountsRpc.methods.inspectTransfer]: (message) =>
			deps.inspectTransfer(message.data as SendTransferInput),
		[accountsRpc.methods.estimateMaxSend]: (message) =>
			deps.estimateMaxSend(message.data as EstimateMaxSendInput),
		[accountsRpc.methods.sendTransfer]: (message) =>
			deps.sendTransfer(message.data as SendTransferInput),
		[accountsRpc.methods.getSilentPaymentScanStatus]: (message) => {
			if (!deps.getSilentPaymentScanStatus) {
				throw new Error("Silent payment scan status is not supported in this runtime");
			}
			return deps.getSilentPaymentScanStatus(
				message.data as import("@/core/accounts/application/accounts-rpc/model/types").GetSilentPaymentScanStatusInput,
			);
		},
		[accountsRpc.methods.rescanSilentPayments]: (message) => {
			if (!deps.rescanSilentPayments) {
				throw new Error("Silent payment rescan is not supported in this runtime");
			}
			return deps.rescanSilentPayments(
				message.data as import("@/core/accounts/application/accounts-rpc/model/types").RescanSilentPaymentsInput,
			);
		},
		[accountsRpc.methods.listSilentPaymentLabels]: (message) =>
			requireLabels().list(message.data as ListSilentPaymentLabelsInput | undefined),
		[accountsRpc.methods.createSilentPaymentLabel]: (message) =>
			requireLabels().create(message.data as CreateSilentPaymentLabelInput),
		[accountsRpc.methods.renameSilentPaymentLabel]: (message) =>
			requireLabels().rename(message.data as RenameSilentPaymentLabelInput),
	};
}
