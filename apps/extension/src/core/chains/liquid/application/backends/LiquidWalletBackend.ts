import type {
	AccountGroupId,
	KeySourceId,
} from "@/core/accounts/application/account-registry/model/identifiers";
import type { KeyManagerState, UpdateKeyManagerState } from "@/core/key-manager/types";

import type { LiquidChainRecord } from "../../chains/LiquidChainRecord";
import type { LiquidAssetId, LiquidAssetMetadata } from "../../domain/LiquidAsset";
import type { LiquidChainId } from "../../domain/LiquidChain";
import type {
	LiquidEstimateMaxSendParams,
	LiquidEstimateMaxSendResult,
	LiquidGetWalletDescriptorParams,
	LiquidSendTransferParams,
	LiquidSendTransferResult,
	LiquidTransferReview,
	LiquidUTXO,
	LiquidWalletDescriptorEntry,
} from "../../domain/LiquidRpc";
import type {
	LiquidSignMessageResult,
	LiquidSignMessageReview,
	ParsedLiquidSignMessageParams,
} from "../../domain/message/types";
import type {
	LiquidSignPsetResult,
	LiquidSignPsetReview,
	ReviewedLiquidSignPsetParams,
} from "../../domain/pset/types";

export type LiquidWalletAccount = {
	accountGroupId?: AccountGroupId;
	accountGroupIndex?: number;
	accountIdentifier: string;
	keySourceId?: KeySourceId;
	chain: LiquidChainRecord;
	chainId: LiquidChainId;
	descriptor: string;
	dwid: string;
	implementation: unknown;
	policyAssetId: LiquidAssetId;
	rawPolicyAssetId: string;
	silentPaymentAddress?: string;
	silentPaymentKeys?: import("../../silent-payments/types").SilentPaymentRecipientKeys;
	/** Securely zeroize in-memory private key material associated with this account. */
	wipePrivateData?: () => void;
};

export type ResolveLiquidWalletAccountInput = {
	accountGroupId?: AccountGroupId;
	accountGroupIndex?: number;
	chain: LiquidChainRecord;
	keyManagerState: KeyManagerState;
	keySourceId?: KeySourceId;
	updateKeyManagerState?: UpdateKeyManagerState;
};

export type LiquidActivityEntry = {
	amountSats: string;
	/** Height of the block that confirmed the transaction; absent while unconfirmed. */
	blockHeight?: number;
	direction: "received" | "sent";
	feeSats: string;
	isSilentPayment?: boolean;
	/** Name of the user's label (m >= 1) a Silent Payment was received on. */
	silentPaymentLabel?: string;
	timestamp: number | null;
	txid: string;
};

export type LiquidActivityPage = {
	items: LiquidActivityEntry[];
	nextCursor: string | null;
};

export type LiquidAssetBalance = {
	amountSats: string;
	decimals: number;
	isNative: boolean;
	metadata: LiquidAssetMetadata;
	name: string;
	rawAssetId: string;
	symbol: string;
};

export type LiquidBlindingSecrets = {
	asset: string;
	assetBlindingFactor: string;
	value: number;
	valueBlindingFactor: string;
};

export type LiquidUtxoSnapshot = {
	address: string;
	amountSats: string;
	blindingSecrets?: LiquidBlindingSecrets;
	confidential: boolean;
	derivationPath?: string;
	rawAssetId: string;
	scriptPubKey: string;
	/** A Silent Payment output, merged in from the SP store rather than read by LWK. */
	silentPayment?: true;
	spendable: boolean;
	txid: string;
	txOut: string;
	vout: number;
};

/**
 * A wallet output the contract flow may fund from, with what the signing module needs.
 *
 * This never leaves the wallet. `LiquidUTXO` is what a dapp is answered with.
 */
export type LiquidFundingUtxo = LiquidUTXO & {
	blindingSecrets?: LiquidBlindingSecrets;
	derivationPath?: string;
};

export type LiquidWalletSnapshot = {
	assets: LiquidAssetBalance[];
	utxos: LiquidUtxoSnapshot[];
};

export type LiquidWalletBackend = {
	estimateMaxSend: (
		account: LiquidWalletAccount,
		params: LiquidEstimateMaxSendParams,
		rawAssetId: string,
	) => Promise<LiquidEstimateMaxSendResult>;
	getActivity: (account: LiquidWalletAccount, rawAssetId: string) => LiquidActivityEntry[];
	getAddress: (
		account: LiquidWalletAccount,
		index: number,
	) => { address: string; unconfidential: string };
	getBalance: (account: LiquidWalletAccount, rawAssetId: string) => string;
	getReceiveAddress: (account: LiquidWalletAccount) => { address: string; index: number };
	/**
	 * The wallet's static Silent Payment address (B_scan, B_spend).
	 */
	getSilentPaymentAddress?: (account: LiquidWalletAccount) => {
		address: string;
		scanPublicKey: string;
		spendPublicKey: string;
	};
	getSigningAddress: (account: LiquidWalletAccount) => {
		address: string;
		index: number;
		unconfidential: string;
	};
	getDescriptorEntries: (
		account: LiquidWalletAccount,
		params: LiquidGetWalletDescriptorParams,
	) => Promise<LiquidWalletDescriptorEntry[]>;
	getUtxos: (account: LiquidWalletAccount, rawAssetId: string) => LiquidUTXO[];
	getExplicitUtxos: (account: LiquidWalletAccount, rawAssetId: string) => LiquidUTXO[];
	getFundingUtxos: (account: LiquidWalletAccount, rawAssetId: string) => LiquidFundingUtxo[];
	getTipHeight: (account: LiquidWalletAccount) => number;
	inspectTransfer: (
		account: LiquidWalletAccount,
		params: LiquidSendTransferParams,
		rawAssetId: string,
	) => Promise<LiquidTransferReview>;
	inspectMessageSigning: (
		account: LiquidWalletAccount,
		params: ParsedLiquidSignMessageParams,
	) => Promise<LiquidSignMessageReview>;
	resolveAccount: (input: ResolveLiquidWalletAccountInput) => Promise<LiquidWalletAccount>;
	sendTransfer: (
		account: LiquidWalletAccount,
		params: LiquidSendTransferParams,
		rawAssetId: string,
	) => Promise<LiquidSendTransferResult>;
	signMessage: (
		account: LiquidWalletAccount,
		params: ParsedLiquidSignMessageParams,
	) => Promise<LiquidSignMessageResult>;
	blindAndInspectPset: (
		account: LiquidWalletAccount,
		psetBase64: string,
	) => Promise<LiquidSignPsetReview>;
	signPset: (
		account: LiquidWalletAccount,
		params: ReviewedLiquidSignPsetParams,
	) => Promise<LiquidSignPsetResult>;
	syncAccount: (account: LiquidWalletAccount) => Promise<void>;
};
