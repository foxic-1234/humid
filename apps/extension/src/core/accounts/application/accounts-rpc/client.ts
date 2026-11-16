import { requestBackground } from "@/core/extension-rpc";

import { accountsRpc } from "./model/rpc";
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
	RecoveryPhrase,
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
} from "./model/types";

function getState(): Promise<AccountsState> {
	return requestBackground<AccountsState>(accountsRpc.methods.getState);
}

function setSelected(input: SetSelectedAccountInput): Promise<AccountsState> {
	return requestBackground<AccountsState>(accountsRpc.methods.setSelected, input);
}

function rename(input: RenameAccountInput): Promise<AccountsState> {
	return requestBackground<AccountsState>(accountsRpc.methods.rename, input);
}

function revealRecoveryPhrase(input: RevealRecoveryPhraseInput): Promise<RecoveryPhrase> {
	return requestBackground<RecoveryPhrase>(accountsRpc.methods.revealRecoveryPhrase, input);
}

function getReceiveAddress(): Promise<ReceiveAddress> {
	return requestBackground<ReceiveAddress>(accountsRpc.methods.getReceiveAddress);
}

function getPortfolio(): Promise<PortfolioSnapshot> {
	return requestBackground<PortfolioSnapshot>(accountsRpc.methods.getPortfolio);
}

function refreshPortfolio(): Promise<PortfolioSnapshot> {
	return requestBackground<PortfolioSnapshot>(accountsRpc.methods.refreshPortfolio);
}

function getActivity(input: GetActivityInput): Promise<ActivityPage> {
	return requestBackground<ActivityPage>(accountsRpc.methods.getActivity, input);
}

function inspectTransfer(input: SendTransferInput): Promise<TransferReview> {
	return requestBackground<TransferReview>(accountsRpc.methods.inspectTransfer, input);
}

function estimateMaxSend(input: EstimateMaxSendInput): Promise<EstimateMaxSendResult> {
	return requestBackground<EstimateMaxSendResult>(accountsRpc.methods.estimateMaxSend, input);
}

function sendTransfer(input: SendTransferInput): Promise<SendTransferResult> {
	return requestBackground<SendTransferResult>(accountsRpc.methods.sendTransfer, input);
}

function getSilentPaymentScanStatus(
	input?: import("./model/types").GetSilentPaymentScanStatusInput,
): Promise<import("./model/types").SilentPaymentScanStatusResult> {
	return requestBackground<import("./model/types").SilentPaymentScanStatusResult>(
		accountsRpc.methods.getSilentPaymentScanStatus,
		input,
	);
}

function rescanSilentPayments(
	input: import("./model/types").RescanSilentPaymentsInput,
): Promise<void> {
	return requestBackground<void>(accountsRpc.methods.rescanSilentPayments, input);
}

function listSilentPaymentLabels(
	input?: ListSilentPaymentLabelsInput,
): Promise<ListSilentPaymentLabelsResult> {
	return requestBackground<ListSilentPaymentLabelsResult>(
		accountsRpc.methods.listSilentPaymentLabels,
		input,
	);
}

/** Create the next label; resolves with its address. */
function createSilentPaymentLabel(
	input: CreateSilentPaymentLabelInput,
): Promise<SilentPaymentLabelView> {
	return requestBackground<SilentPaymentLabelView>(
		accountsRpc.methods.createSilentPaymentLabel,
		input,
	);
}

function renameSilentPaymentLabel(
	input: RenameSilentPaymentLabelInput,
): Promise<SilentPaymentLabelView> {
	return requestBackground<SilentPaymentLabelView>(
		accountsRpc.methods.renameSilentPaymentLabel,
		input,
	);
}

function createAccount(input: CreateAccountInput): Promise<AccountsState> {
	return requestBackground<AccountsState>(accountsRpc.methods.createAccount, input);
}

function importAccount(input: ImportAccountInput): Promise<AccountsState> {
	return requestBackground<AccountsState>(accountsRpc.methods.importAccount, input);
}

function removeAccount(input: RemoveAccountInput): Promise<AccountsState> {
	return requestBackground<AccountsState>(accountsRpc.methods.removeAccount, input);
}

function removeWallet(input: RemoveWalletInput): Promise<AccountsState> {
	return requestBackground<AccountsState>(accountsRpc.methods.removeWallet, input);
}

export const accountsClient = {
	createAccount,
	createSilentPaymentLabel,
	estimateMaxSend,
	getActivity,
	getPortfolio,
	getReceiveAddress,
	getSilentPaymentScanStatus,
	getState,
	importAccount,
	inspectTransfer,
	listSilentPaymentLabels,
	refreshPortfolio,
	removeAccount,
	removeWallet,
	rename,
	renameSilentPaymentLabel,
	rescanSilentPayments,
	revealRecoveryPhrase,
	sendTransfer,
	setSelected,
};
