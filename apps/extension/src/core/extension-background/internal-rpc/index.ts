import type {
	ActivityPage,
	EstimateMaxSendInput,
	EstimateMaxSendResult,
	GetActivityInput,
	PortfolioSnapshot,
	ReceiveAddress,
	SendTransferInput,
	SendTransferResult,
	TransferReview,
} from "@/core/accounts/application/accounts-rpc/model/types";
import type { ChainGroup } from "@/core/chains/application/ChainGroup";
import { walletVaultRpc } from "@/core/secure-vault/application/wallet-vault/model/rpc";
import type { ConfirmationRequest } from "@/helpers/background";

import type { ConfirmationResponder } from "../confirmations";
import type { RequestHandlerMap } from "../transport";
import { createAccountsInternalHandlers, type SilentPaymentLabelsDeps } from "./accounts";
import { createChainsInternalHandlers } from "./chains";
import { walletVaultInternalHandlers } from "./wallet-vault";
import { walletConnectInternalHandlers } from "./walletconnect";

export type { SilentPaymentLabelsDeps } from "./accounts";
export { syncWalletVaultAuthStore } from "./wallet-vault";

export type CreateInternalRpcHandlersInput = {
	chainGroups: readonly Pick<ChainGroup, "chains" | "id">[];
	confirmations: ConfirmationResponder;
	estimateMaxSend: (input: EstimateMaxSendInput) => Promise<EstimateMaxSendResult>;
	getActivity: (input: GetActivityInput) => Promise<ActivityPage>;
	getPortfolio: () => Promise<PortfolioSnapshot>;
	getReceiveAddress: () => Promise<ReceiveAddress>;
	inspectTransfer: (input: SendTransferInput) => Promise<TransferReview>;
	purgeAccountPortfolio: (accountGroupId: string) => Promise<void>;
	purgeAccountWalletConnectSessions: (accountGroupIds: readonly string[]) => Promise<void>;
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
	onWalletUnlocked?: () => void;
	silentPaymentLabels?: SilentPaymentLabelsDeps;
};

export function createInternalRpcHandlers({
	chainGroups,
	confirmations,
	estimateMaxSend,
	getActivity,
	getPortfolio,
	getReceiveAddress,
	inspectTransfer,
	purgeAccountPortfolio,
	purgeAccountWalletConnectSessions,
	refreshPortfolio,
	sendTransfer,
	getSilentPaymentScanStatus,
	onWalletUnlocked,
	rescanSilentPayments,
	silentPaymentLabels,
}: CreateInternalRpcHandlersInput): RequestHandlerMap {
	return {
		ping: (message) => {
			return {
				message: "pong",
				request: message.data ?? null,
			};
		},
		confirm: async (message) => {
			const data = message.data as Partial<ConfirmationRequest> | undefined;

			const decision = await confirmations.confirm({
				title: data?.title ?? "Confirm action?",
				message: data?.message,
				data: data?.data,
				timeoutMs: data?.timeoutMs,
			});

			return decision.approved;
		},
		...walletVaultInternalHandlers,
		[walletVaultRpc.methods.unlock]: async (message, sender) => {
			const res = await walletVaultInternalHandlers[walletVaultRpc.methods.unlock](message, sender);
			try {
				onWalletUnlocked?.();
			} catch (e) {
				console.warn("[internal-rpc] onWalletUnlocked hook failed:", e);
			}
			return res;
		},
		...walletConnectInternalHandlers,
		...createChainsInternalHandlers(chainGroups),
		...createAccountsInternalHandlers({
			estimateMaxSend,
			getActivity,
			getPortfolio,
			getReceiveAddress,
			inspectTransfer,
			purgeAccountPortfolio,
			purgeAccountWalletConnectSessions,
			refreshPortfolio,
			sendTransfer,
			getSilentPaymentScanStatus,
			rescanSilentPayments,
			silentPaymentLabels,
		}),
	};
}
