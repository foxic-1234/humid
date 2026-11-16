import type { secp256k1 } from "@noble/curves/secp256k1.js";

export type SilentPaymentNetwork = "mainnet" | "testnet" | "regtest";

export interface SilentPaymentKeyPair {
	privateKey: Uint8Array;
	publicKey: Uint8Array; // 33 bytes compressed
}

export interface SilentPaymentRecipientKeys {
	scanKey: SilentPaymentKeyPair; // b_scan / B_scan (BIP-352)
	spendKey: SilentPaymentKeyPair; // b_spend / B_spend (BIP-352)
}

export interface SilentPaymentAddressInfo {
	address: string;
	network: SilentPaymentNetwork;
	scanPublicKey: Uint8Array; // 33 bytes compressed B_scan
	spendPublicKey: Uint8Array; // 33 bytes compressed B_spend
	hrp?: string;
	version?: number;
}

export interface CandidateTaprootOutput {
	targetXOnly: Uint8Array;
}

export interface MatchedCandidateOutput<T extends CandidateTaprootOutput> {
	candidate: T;
	k: number;
	matchResult: {
		labelIndex?: number;
		labelTweak?: bigint;
		matched: true;
		point: InstanceType<typeof secp256k1.Point>;
	};
	tk: bigint;
}

export interface EligibleInput {
	outpoint: { txid: string; vout: number };
	pubkey: Uint8Array; // 33 bytes compressed
}

export interface SpTxInput {
	txid: string; // 64 hex chars
	vout: number; // output index (high flags cleared or raw)
	isCoinbase?: boolean;
	isPegin?: boolean;
	witness?: (string | Uint8Array)[];
	scriptsig?: string | Uint8Array;
	prevoutScriptPubKey?: string | Uint8Array;
	prevoutScriptPubKeyType?: string;
}

export interface SpTxOutput {
	outputIndex?: number;
	scriptPubKey: Uint8Array | string; // Uint8Array (34 bytes) or hex string (68 hex chars)
	value?: bigint | number | string;
	asset?: string;
}

export interface SpTransaction {
	txid?: string;
	vin: SpTxInput[];
	vout: SpTxOutput[];
}

export interface TxTweakResult {
	tweak: Uint8Array; // 33-byte compressed curve point (input_hash · A)
	outpointL: Uint8Array; // 36-byte consensus serialized smallest outpoint
	A: Uint8Array; // 33-byte compressed aggregated input pubkey
	inputHash: Uint8Array; // 32-byte tagged hash
}

export interface SpRecipientMatch {
	candidate: {
		outputIndex: number;
		scriptPubKey: Uint8Array | string;
		targetXOnly: Uint8Array;
	};
	k: number;
	outputIndex: number;
	targetXOnly: Uint8Array;
	scriptPubKeyHex: string;
	labelIndex?: number;
	labelTweak?: bigint;
	tk: bigint;
	point: InstanceType<typeof secp256k1.Point>;
	S: Uint8Array; // 33-byte compressed shared secret point S
}

export interface SpInputKeyCandidate {
	privateKey: Uint8Array | bigint;
	publicKey?: Uint8Array;
	scriptPubKey?: string | Uint8Array;
	isTaproot?: boolean;
}

export interface AggregateSenderInputsOptions {
	inputPubkeys?: Uint8Array[];
	inputScripts?: Array<string | Uint8Array | undefined>;
	isTaprootInputs?: boolean[];
}

export interface AggregateSenderInputsResult {
	aScalar: bigint;
	aBytes: Uint8Array;
	A: Uint8Array;
	normalizedInputs: Array<{
		privateKey: Uint8Array;
		publicKey: Uint8Array;
		wasNegated: boolean;
		isTaproot: boolean;
	}>;
}
