import type {
	CreateSilentPaymentLabelInput,
	GetSilentPaymentScanStatusInput,
	ListSilentPaymentLabelsResult,
	RenameSilentPaymentLabelInput,
	RescanSilentPaymentsInput,
	SilentPaymentLabelView,
	SilentPaymentScanStatusResult,
} from "@/core/accounts/application/accounts-rpc/model/types";
import type { ChainGroup } from "@/core/chains/application/ChainGroup";
import type { LiquidWalletRpcContext } from "@/core/chains/liquid/application/createLiquidRpcRouter";

import type {
	LiquidActivityPage,
	LiquidAssetBalance,
	LiquidUtxoSnapshot,
	ResolveLiquidWalletAccountInput,
} from "./application/backends/LiquidWalletBackend";

export type { LiquidActivityPage, LiquidAssetBalance, LiquidUtxoSnapshot };
import type { LiquidChainRecord } from "./chains/LiquidChainRecord";
import type {
	LiquidEstimateMaxSendResult,
	LiquidSendTransferResult,
	LiquidTransferReview,
} from "./domain/LiquidRpc";

export type LiquidReceiveAddress = {
	address: string;
	index: number;
	scanPublicKey?: string;
	silentPaymentAddress?: string;
	spendPublicKey?: string;
	unconfidential: string;
};

export type LiquidPortfolio = {
	assets: LiquidAssetBalance[];
	utxos: LiquidUtxoSnapshot[];
};

export type LiquidScanTarget = {
	chain: LiquidChainRecord;
	descriptor: string;
	silentPaymentAddress?: string;
	silentPaymentKeys?: import("./silent-payments/types").SilentPaymentRecipientKeys;
	/** Restored from a recovery phrase: its first SP scan starts before its earliest transaction. */
	restoredWallet?: boolean;
	/** For a restored wallet: when the user says it was created (ms since epoch), if they said. */
	walletCreatedAt?: number;
};

export type LiquidPopupTransferInput = {
	amount: string;
	rawAssetId?: string;
	recipientAddress: string;
	sendAll?: boolean;
};

export type LiquidPopupEstimateMaxSendInput = {
	rawAssetId?: string;
	recipientAddress: string;
};

export type LiquidAccountRuntime = {
	estimateMaxSend: (
		input: ResolveLiquidWalletAccountInput,
		estimate: LiquidPopupEstimateMaxSendInput,
	) => Promise<LiquidEstimateMaxSendResult>;
	getActivity: (
		input: ResolveLiquidWalletAccountInput,
		rawAssetId: string,
		cursor: string | null,
	) => Promise<LiquidActivityPage>;
	getReceiveAddress: (input: ResolveLiquidWalletAccountInput) => Promise<LiquidReceiveAddress>;
	inspectTransfer: (
		input: ResolveLiquidWalletAccountInput,
		transfer: LiquidPopupTransferInput,
	) => Promise<LiquidTransferReview>;
	resolveAccountIdentifier: (input: ResolveLiquidWalletAccountInput) => Promise<string>;
	resolveScanTarget: (input: ResolveLiquidWalletAccountInput) => Promise<LiquidScanTarget>;
	/**
	 * Scan a watch-only target into a portfolio — vault-independent (no keys needed). With the vault
	 * locked, Silent Payment outputs are carried over from `previous`, the last saved portfolio.
	 */
	scanPortfolio: (
		target: LiquidScanTarget,
		previous?: Pick<LiquidPortfolio, "utxos">,
	) => Promise<LiquidPortfolio>;
	sendTransfer: (
		input: ResolveLiquidWalletAccountInput,
		transfer: LiquidPopupTransferInput,
	) => Promise<LiquidSendTransferResult>;
	getSilentPaymentScanStatus?: (
		input: ResolveLiquidWalletAccountInput,
		params?: GetSilentPaymentScanStatusInput,
	) => Promise<SilentPaymentScanStatusResult>;
	rescanSilentPayments?: (
		input: ResolveLiquidWalletAccountInput,
		params: RescanSilentPaymentsInput,
	) => Promise<void>;
	/** The account's BIP-352 labels (m >= 1) on `input.chain`. */
	listSilentPaymentLabels?: (
		input: ResolveLiquidWalletAccountInput,
	) => Promise<ListSilentPaymentLabelsResult>;
	/** Create the next label and store it before its address is returned. */
	createSilentPaymentLabel?: (
		input: ResolveLiquidWalletAccountInput,
		params: CreateSilentPaymentLabelInput,
	) => Promise<SilentPaymentLabelView>;
	renameSilentPaymentLabel?: (
		input: ResolveLiquidWalletAccountInput,
		params: RenameSilentPaymentLabelInput,
	) => Promise<SilentPaymentLabelView>;
};

export type LiquidChainGroup = ChainGroup<LiquidWalletRpcContext, LiquidChainRecord> & {
	accountRuntime: LiquidAccountRuntime;
};
