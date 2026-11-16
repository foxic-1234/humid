import type { AccountGroupRecord } from "../../account-registry/model/account-group";
import type { AccountGroupId, WalletId } from "../../account-registry/model/identifiers";

export type AccountsState = {
	accountGroups: AccountGroupRecord[];
	selectedAccountGroupId: AccountGroupId;
};

export type SetSelectedAccountInput = {
	accountGroupId: AccountGroupId;
};

export type RenameAccountInput = {
	accountGroupId: AccountGroupId;
	name: string;
};

export type CreateAccountInput = {
	name?: string;
};

export type ImportAccountInput = {
	mnemonic: string;
	name?: string;
	/** When the user says the wallet was created (ms since epoch), if they said. */
	walletCreatedAt?: number;
};

export type RemoveAccountInput = {
	accountGroupId: AccountGroupId;
};

export type RemoveWalletInput = {
	walletId: WalletId;
};

export type RevealRecoveryPhraseInput = {
	accountGroupId: AccountGroupId;
};

export type RecoveryPhrase = {
	phrase: string;
};

export type ReceiveAddress = {
	address: string;
	index: number;
	scanPublicKey?: string;
	silentPaymentAddress?: string;
	spendPublicKey?: string;
	unconfidential: string;
};

export type SendTransferInput = {
	amount: string;
	rawAssetId?: string;
	recipientAddress: string;
	sendAll?: boolean;
};

export type EstimateMaxSendInput = {
	rawAssetId?: string;
	recipientAddress: string;
};

export type EstimateMaxSendResult = {
	feeSats: string;
	maxAmount: string;
};

export type TransferReview = {
	amount: string;
	assetId: string;
	isSilentPayment?: boolean;
	recipientAddress: string;
	recipientConfidential: boolean;
};

export type SendTransferResult = {
	txid: string;
};

export type PortfolioAsset = {
	amountSats: string;
	decimals: number;
	isNative: boolean;
	metadata: unknown;
	name: string;
	rawAssetId: string;
	symbol: string;
};

export type PortfolioUtxo = {
	address: string;
	amountSats: string;
	confidential: boolean;
	rawAssetId: string;
	scriptPubKey: string;
	/** A Liquid Silent Payment output (see `LiquidUtxoSnapshot`). */
	silentPayment?: true;
	spendable: boolean;
	txid: string;
	txOut: string;
	vout: number;
};

export type PortfolioData = {
	assets: PortfolioAsset[];
	utxos: PortfolioUtxo[];
};

export type ActivityEntry = {
	amountSats: string;
	direction: "received" | "sent";
	feeSats: string;
	isSilentPayment?: boolean;
	/** Name of the user's label (m >= 1) a Silent Payment was received on. */
	silentPaymentLabel?: string;
	timestamp: number | null;
	txid: string;
};

export type ActivityPage = {
	items: ActivityEntry[];
	nextCursor: string | null;
};

export type GetActivityInput = {
	cursor: string | null;
	rawAssetId: string;
};

export type PortfolioSnapshot = {
	data: PortfolioData | null;
	error: string | null;
	isSyncing: boolean;
	syncedAt: number | null;
};

export type SilentPaymentScanStatusResult = {
	backfillHeight?: number;
	birthdayHeight?: number;
	chainId: string;
	currentHeight: number;
	errorMessage?: string;
	/** Wallet scanning: seconds until the new blocks and the history are scanned, if known. */
	etaSeconds?: number;
	/** Wallet scanning: a fallback explorer does not answer, so a long scan is far slower. */
	fallbackExplorerDown?: boolean;
	/**
	 * Wallet scanning, while `history` is left: payments kept out of the balance until the history
	 * is scanned, as it may hold their spend.
	 */
	heldPayments?: number;
	/** Wallet scanning: the newest-first scan of older blocks, while one is left. */
	history?: { done: number; total: number };
	isScanning: boolean;
	/** Wallet scanning: blocks between the cursor and the tip still to check. */
	newBlocksLeft?: number;
	percentage: number;
	state: "backfilling" | "idle" | "error" | "synced";
	tipHeight: number;
	totalBlocksToScan?: number;
};

export type GetSilentPaymentScanStatusInput = {
	chainId?: string;
};

export type RescanSilentPaymentsInput = {
	birthdayHeight: number;
	chainId?: string;
};

/** A BIP-352 label m >= 1 of the account: its own static SP address and the user's name for it. */
export type SilentPaymentLabelView = {
	address: string;
	index: number;
	name: string;
};

/** `chainId` picks the network (default: the selected one); the account is the selected one. */
export type ListSilentPaymentLabelsInput = {
	chainId?: string;
};

export type ListSilentPaymentLabelsResult = {
	labels: SilentPaymentLabelView[];
};

export type CreateSilentPaymentLabelInput = {
	chainId?: string;
	name: string;
};

export type RenameSilentPaymentLabelInput = {
	chainId?: string;
	index: number;
	name: string;
};
