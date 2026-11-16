import {
	bytesEqual,
	deriveLabeledSilentPaymentAddress,
	deriveOneTimePrivateKey,
	encodeConfidentialTaprootAddress,
	HRP_LIQUID_MAINNET,
	HRP_LIQUID_TESTNET,
	isSilentPaymentAddress,
	isTaprootScriptPubKey,
	normalizeTaprootInputKey,
	parseSilentPaymentAddress,
	toScalarBigInt,
	verifyInputPublicKeyScript,
	zeroizeBuffer,
	type SilentPaymentAddressInfo,
} from "@humid/sp-core";
import { secp256k1 } from "@noble/curves/secp256k1.js";
import { numberToBytesBE } from "@noble/curves/utils.js";
import { bytesToHex, hexToBytes } from "@noble/hashes/utils.js";
import type { ExternalUtxo, Pset, TxBuilder, WalletTxOut } from "lwk_wasm";

import {
	WALLET_RPC_ERROR_REASONS,
	WalletRpcInvalidParamsError,
	WalletRpcResourceUnavailableError,
} from "@/core/wallet-rpc/errors";

import type { LiquidWalletAccount } from "../../../../application/backends/LiquidWalletBackend";
import { isLiquidMainnetChain } from "../../../../chains/LiquidChainRecord";
import type {
	LiquidEstimateMaxSendParams,
	LiquidEstimateMaxSendResult,
	LiquidSendTransferParams,
	LiquidSendTransferResult,
	LiquidTransferReview,
} from "../../../../domain/LiquidRpc";
import { toLiquidAssetId } from "../../../../domain/validation";
import {
	buildExplorerApis,
	pickExplorerApi,
	createSilentPaymentOutput,
	fetchWithRetryAndBackoff,
	getUnspentSilentPaymentUtxos,
	isSpendableSilentPaymentUtxo,
	markSilentPaymentUtxoSpent,
	saveTrackedSilentPaymentUtxo,
	type TrackedSilentPaymentUtxo,
} from "../../../../silent-payments";
import { loadLwkWasm, type LwkWasmModule } from "../../loadLwkWasm";
import { getSyncWorkerClient } from "../../sync-worker/createSyncWorkerClient";
import type { LwkLiquidAccountImplementation } from "../../types";
import { getLwkImplementation } from "../getLwkImplementation";
import { readWalletBalanceForAsset } from "../readWalletData";

const LIQUID_EXPLICIT_DUST_LIMIT_SATS = 600n;

// Witness weight of a BIP-341 key-path spend: item count + push length + 64-byte Schnorr signature.
const TAPROOT_KEYPATH_MAX_WEIGHT_TO_SATISFY = 66;

function invalidTransfer(message: string, data?: Record<string, unknown>) {
	return new WalletRpcInvalidParamsError(
		message,
		data,
		WALLET_RPC_ERROR_REASONS.INVALID_TRANSFER_REQUEST,
	);
}

function transferFailed(message: string, cause?: unknown) {
	const failure = new WalletRpcResourceUnavailableError(
		message,
		undefined,
		WALLET_RPC_ERROR_REASONS.WALLET_TRANSFER_FAILED,
	);
	if (cause !== undefined) failure.cause = cause;
	return failure;
}

/** LWK could not fund the transaction (amount plus fee, or the fee alone). */
class InsufficientFundsError extends WalletRpcInvalidParamsError {}

const outpointKey = (txid: string, vout: number) => `${txid.toLowerCase()}:${vout}`;

const sumSats = (utxos: TrackedSilentPaymentUtxo[]) =>
	utxos.reduce((sum, u) => sum + BigInt(u.amountSats), 0n);

/**
 * Builds an LWK ExternalUtxo for a tracked Silent Payment UTXO from its real funding transaction.
 *
 * The prevout committed to by the Taproot sighash must be the on-chain output byte for byte, so it
 * is taken from `fundingTxHex` rather than reconstructed. The output is unblinded with the stored
 * ELIP-352 blinding key bk_k and must agree with the tracker's amount and asset.
 */
function spUtxoToExternalUtxo(
	lwk: LwkWasmModule,
	u: TrackedSilentPaymentUtxo,
	fundingTxHex: string,
): ExternalUtxo {
	const fail = (reason: string): never => {
		throw invalidTransfer(`Cannot spend Silent Payment UTXO ${u.txid}:${u.outputIndex}: ${reason}`);
	};

	const tx = new lwk.Transaction(fundingTxHex);
	if (tx.txid().toString().toLowerCase() !== u.txid.toLowerCase()) {
		fail("funding transaction does not match the UTXO txid.");
	}
	const txOut = tx.output(u.outputIndex) ?? fail("funding transaction has no such output.");
	if (txOut.scriptPubkey().toString().toLowerCase() !== u.scriptPubKeyHex.toLowerCase()) {
		fail("funding output scriptPubKey does not match the tracked Taproot output.");
	}

	let secrets: ReturnType<typeof txOut.unblind>;
	const explicitValue = txOut.value();
	const explicitAsset = txOut.asset();
	if (explicitValue !== undefined && explicitAsset) {
		secrets = lwk.TxOutSecrets.fromExplicit(explicitAsset, explicitValue);
	} else {
		const bk = hexToBytes(u.blindingKeyHex ?? fail("blinding key bk_k is missing."));
		try {
			secrets = txOut.unblind(lwk.SecretKey.fromBytes(bk));
		} catch {
			fail("output cannot be unblinded with the stored blinding key.");
		} finally {
			zeroizeBuffer(bk);
		}
	}

	if (
		secrets!.value() !== BigInt(u.amountSats) ||
		secrets!.asset().toString().toLowerCase() !== u.rawAssetId.toLowerCase()
	) {
		fail("unblinded amount or asset does not match the tracked record.");
	}

	return new lwk.ExternalUtxo(
		u.outputIndex,
		tx,
		secrets!,
		TAPROOT_KEYPATH_MAX_WEIGHT_TO_SATISFY,
		true,
	);
}

/** The account's own unspent SP UTXOs; other accounts on the same chain hold keys this one lacks. */
async function getAccountUnspentSpUtxos(
	account: LiquidWalletAccount,
): Promise<TrackedSilentPaymentUtxo[]> {
	if (!account.silentPaymentAddress) return [];
	return getUnspentSilentPaymentUtxos(account.chainId, account.silentPaymentAddress);
}

/** Spendable SP UTXOs of one asset, largest first. */
function spendableSpUtxosOf(
	utxos: TrackedSilentPaymentUtxo[],
	rawAssetId: string,
): TrackedSilentPaymentUtxo[] {
	return utxos
		.filter((u) => isSpendableSilentPaymentUtxo(u, { rawAssetId }))
		.sort((a, b) => (BigInt(b.amountSats) > BigInt(a.amountSats) ? 1 : -1));
}

/** Fetches the raw hex of a Silent Payment UTXO's funding transaction from the chain's Esplora API. */
async function fetchFundingTxHex(account: LiquidWalletAccount, txid: string): Promise<string> {
	const url = `${pickExplorerApi(buildExplorerApis(account.chain))}/tx/${txid}/hex`;
	let res: Response;
	try {
		res = await fetchWithRetryAndBackoff(url, undefined, 10_000);
	} catch (error) {
		throw transferFailed(
			`Could not fetch the funding transaction ${txid} of a Silent Payment UTXO.`,
			error,
		);
	}
	if (!res.ok) {
		throw transferFailed(
			`Could not fetch the funding transaction ${txid} of a Silent Payment UTXO (HTTP ${res.status}).`,
		);
	}
	return (await res.text()).trim();
}

/**
 * Derives the 32-byte Taproot one-time spending private key for a tracked Silent Payment UTXO.
 */
export function deriveSpSpendingPrivateKey(
	bSpend: Uint8Array | bigint | undefined,
	u: TrackedSilentPaymentUtxo,
): Uint8Array {
	if (!bSpend) {
		throw invalidTransfer(
			"Cannot spend Silent Payment UTXO: spend private key is missing from wallet account.",
		);
	}
	if (!u.tweakHex) {
		throw invalidTransfer(
			`Cannot spend Silent Payment UTXO ${u.txid}:${u.outputIndex}: tweakHex is missing.`,
		);
	}
	const bSpendScalar = toScalarBigInt(bSpend);
	const tk = toScalarBigInt(hexToBytes(u.tweakHex));
	const labelTweak = u.labelTweakHex ? toScalarBigInt(hexToBytes(u.labelTweakHex)) : 0n;

	let P = secp256k1.Point.BASE.multiply(bSpendScalar).add(secp256k1.Point.BASE.multiply(tk));
	if (labelTweak !== 0n) {
		P = P.add(secp256k1.Point.BASE.multiply(labelTweak));
	}
	const key = deriveOneTimePrivateKey(bSpendScalar, tk, P, labelTweak);
	assertKeyMatchesTaprootOutput(key, u);
	return key;
}

/**
 * Fail before signing if d·G does not commit to the UTXO's Taproot output key. A mismatch (e.g. a
 * missing label tweak) would otherwise only surface as a consensus rejection at broadcast.
 */
function assertKeyMatchesTaprootOutput(key: Uint8Array, u: TrackedSilentPaymentUtxo): void {
	const spk = u.scriptPubKeyHex.toLowerCase();
	const expectedXOnly = spk.length === 68 && spk.startsWith("5120") ? spk.slice(4) : null;
	const derivedXOnly = bytesToHex(secp256k1.getPublicKey(key, true).slice(1));
	if (expectedXOnly === null || derivedXOnly !== expectedXOnly) {
		zeroizeBuffer(key);
		throw invalidTransfer(
			`Cannot spend Silent Payment UTXO ${u.txid}:${u.outputIndex}: derived spending key does not match its Taproot output key.`,
		);
	}
}

/** A validated recipient: an ordinary Liquid address, or a Silent Payment address. */
type TransferRecipient = { address: string; sp?: SilentPaymentAddressInfo };

function assertNoMemo(params: LiquidSendTransferParams): void {
	if (params.memo) {
		throw new WalletRpcInvalidParamsError(
			"Liquid transfer memos are not supported by this wallet backend yet.",
			{ memo: params.memo },
			WALLET_RPC_ERROR_REASONS.UNSUPPORTED_MEMO,
		);
	}
}

/** Validates the recipient (address, network) and the dust floor of the amount. */
function resolveRecipient(
	lwk: LwkWasmModule,
	account: LiquidWalletAccount,
	params: LiquidSendTransferParams,
	rawAssetId: string,
): TransferRecipient & { confidential: boolean } {
	const assertAboveDust = (outputKind: string) => {
		if (
			rawAssetId === account.rawPolicyAssetId &&
			!params.sendAll &&
			BigInt(params.amount) < LIQUID_EXPLICIT_DUST_LIMIT_SATS
		) {
			throw invalidTransfer(
				`The transfer amount is below the network dust limit of 600 satoshis (0.000006 L-BTC) for ${outputKind}.`,
				{ amount: params.amount },
			);
		}
	};

	if (isSilentPaymentAddress(params.recipientAddress)) {
		const sp = parseSilentPaymentAddress(params.recipientAddress);
		validateSilentPaymentRecipientNetwork(account, sp);
		assertAboveDust("stealth Taproot outputs");
		return { address: sp.address, confidential: true, sp };
	}

	let address: InstanceType<LwkWasmModule["Address"]>;
	try {
		address = new lwk.Address(params.recipientAddress);
	} catch {
		throw invalidTransfer("Invalid Liquid recipient address.", {
			recipientAddress: params.recipientAddress,
		});
	}
	validateRecipientNetwork(account, address);
	if (!address.isBlinded()) assertAboveDust("unconfidential outputs");
	return { address: address.toString(), confidential: address.isBlinded() };
}

export async function inspectTransfer(
	account: LiquidWalletAccount,
	params: LiquidSendTransferParams,
	rawAssetId: string,
): Promise<LiquidTransferReview> {
	assertNoMemo(params);
	const recipient = resolveRecipient(await loadLwkWasm(), account, params, rawAssetId);

	return {
		accountIdentifier: account.accountIdentifier,
		amount: params.amount,
		assetId: toLiquidAssetId(account.chainId, rawAssetId),
		chainId: account.chainId,
		isSilentPayment: recipient.sp !== undefined,
		memo: params.memo,
		policyAssetId: account.policyAssetId,
		recipientAddress: recipient.address,
		recipientConfidential: recipient.confidential,
	};
}

/**
 * A confidential P2TR address with the same size as the real ELIP-352 output, for builds made
 * before the inputs (and therefore P_k) are known.
 */
function placeholderSpAddress(account: LiquidWalletAccount, spendPublicKey: Uint8Array): string {
	return encodeConfidentialTaprootAddress(
		spendPublicKey.slice(1),
		secp256k1.Point.BASE.toRawBytes(true),
		account.chain.settings.network,
	);
}

/**
 * Everything one build needs. LWK takes the outpoints, external UTXOs and drain address by value,
 * so each build creates them anew.
 */
type BuildSpec = {
	/** Wallet inputs to use; null lets LWK pick (all L-BTC, enough of an issued asset). */
	walletOutpoints: string[] | null;
	spInputs: TrackedSilentPaymentUtxo[];
	recipient: string;
	/** L-BTC change address; LWK's own wallet change address if absent. */
	change?: string;
};

class SendBuilder {
	private readonly fundingTxHexes = new Map<string, string>();

	constructor(
		private readonly lwk: LwkWasmModule,
		private readonly account: LiquidWalletAccount,
		private readonly implementation: LwkLiquidAccountImplementation,
		private readonly params: LiquidSendTransferParams,
		private readonly rawAssetId: string,
	) {}

	private get drainsLbtc(): boolean {
		return Boolean(this.params.sendAll) && this.rawAssetId === this.account.rawPolicyAssetId;
	}

	async build(spec: BuildSpec): Promise<Pset> {
		const { lwk } = this;
		let builder: TxBuilder = new lwk.TxBuilder(this.implementation.network);
		if (spec.walletOutpoints) {
			builder = builder.setWalletUtxos(spec.walletOutpoints.map((op) => new lwk.OutPoint(op)));
		}
		if (spec.spInputs.length > 0) {
			const external: ExternalUtxo[] = [];
			for (const u of spec.spInputs) {
				let hex = this.fundingTxHexes.get(u.txid);
				if (hex === undefined) {
					hex = await fetchFundingTxHex(this.account, u.txid);
					this.fundingTxHexes.set(u.txid, hex);
				}
				external.push(spUtxoToExternalUtxo(lwk, u, hex));
			}
			builder = builder.addExternalUtxos(external);
		}

		const recipient = new lwk.Address(spec.recipient);
		const amount = BigInt(this.params.amount);
		if (this.drainsLbtc) {
			builder = builder.drainLbtcWallet().drainLbtcTo(recipient);
		} else if (!recipient.isBlinded()) {
			builder = builder.addExplicitRecipient(
				recipient,
				amount,
				lwk.AssetId.fromString(this.rawAssetId),
			);
		} else if (this.rawAssetId === this.account.rawPolicyAssetId) {
			builder = builder.addLbtcRecipient(recipient, amount);
		} else {
			builder = builder.addRecipient(recipient, amount, lwk.AssetId.fromString(this.rawAssetId));
		}
		if (spec.change && !this.drainsLbtc) {
			builder = builder.drainLbtcTo(new lwk.Address(spec.change));
		}

		try {
			return builder.finish(this.implementation.wollet);
		} catch (error) {
			// LWK's `Error::InsufficientFunds` displays as "Insufficient funds: missing …".
			if (String(error).includes("Insufficient funds")) {
				throw new InsufficientFundsError(
					"Insufficient funds: not enough to cover the transfer amount plus network fees. Please use Max or fund your wallet.",
					undefined,
					WALLET_RPC_ERROR_REASONS.INVALID_TRANSFER_REQUEST,
				);
			}
			throw error;
		}
	}

	/** The L-BTC fee LWK computed for a built PSET. */
	feeOf(pset: Pset): bigint {
		const details = this.implementation.wollet.psetDetails(pset);
		const balance = details.balance();
		try {
			return balance.feesIn(this.lwk.AssetId.fromString(this.account.rawPolicyAssetId));
		} finally {
			balance.free();
			details.free();
		}
	}
}

/**
 * Silent Payment inputs for a send. SP UTXOs are spent only when the wallet cannot pay alone, and
 * then as few as possible (largest first), so received stealth payments are not linked on-chain
 * without need. Sending everything spends all of them.
 */
async function selectSpInputs(
	builder: SendBuilder,
	account: LiquidWalletAccount,
	implementation: LwkLiquidAccountImplementation,
	params: LiquidSendTransferParams,
	rawAssetId: string,
	placeholderRecipient: string,
	placeholderChange: string | undefined,
): Promise<TrackedSilentPaymentUtxo[]> {
	const policy = account.rawPolicyAssetId;
	const isNative = rawAssetId === policy;
	const unspent = await getAccountUnspentSpUtxos(account);
	const spLbtc = spendableSpUtxosOf(unspent, policy);
	const walletBalance = (asset: string) =>
		BigInt(readWalletBalanceForAsset(implementation.wollet, account.chainId, asset));

	if (params.sendAll && isNative) return spLbtc;

	const amount = BigInt(params.amount);
	const spAssetCandidates = isNative ? [] : spendableSpUtxosOf(unspent, rawAssetId);
	const assetAvailable = walletBalance(rawAssetId) + sumSats(isNative ? spLbtc : spAssetCandidates);
	if (!params.sendAll && amount > assetAvailable) {
		throw invalidTransfer(
			`Insufficient funds: Requested amount (${amount} sats) exceeds total available balance (${assetAvailable} sats).`,
		);
	}

	// Issued asset: all of it when sending everything, else only what the wallet lacks.
	const spAsset: TrackedSilentPaymentUtxo[] = [];
	if (!isNative) {
		let have = walletBalance(rawAssetId);
		for (const u of spAssetCandidates) {
			if (!params.sendAll && have >= amount) break;
			spAsset.push(u);
			have += BigInt(u.amountSats);
		}
	}

	if (spLbtc.length === 0) return spAsset;

	// LWK always adds an L-BTC change output, which must stay above dust.
	const lbtcOut = isNative ? amount : 0n;
	const lbtcCovers = (have: bigint, fee: bigint) =>
		have >= lbtcOut + fee + LIQUID_EXPLICIT_DUST_LIMIT_SATS;
	const build = (spInputs: TrackedSilentPaymentUtxo[]) =>
		builder.build({
			change: placeholderChange,
			recipient: placeholderRecipient,
			spInputs,
			walletOutpoints: null,
		});

	// The wallet's own L-BTC first: SP funding transactions are fetched only if they are needed.
	try {
		if (lbtcCovers(walletBalance(policy), builder.feeOf(await build(spAsset)))) return spAsset;
	} catch (error) {
		if (!(error instanceof InsufficientFundsError)) throw error;
	}

	// The fee only grows with inputs, so a build with every L-BTC candidate bounds it from above.
	// If even that build cannot be funded, it reports the shortfall.
	const feeBound = builder.feeOf(await build([...spAsset, ...spLbtc]));
	const spLbtcInputs: TrackedSilentPaymentUtxo[] = [];
	let lbtcHave = walletBalance(policy);
	for (const u of spLbtc) {
		if (lbtcCovers(lbtcHave, feeBound)) break;
		spLbtcInputs.push(u);
		lbtcHave += BigInt(u.amountSats);
	}
	return [...spAsset, ...spLbtcInputs];
}

/** A built PSET's inputs as "txid:vout" keys, in input order. */
function psetInputKeys(pset: Pset): string[] {
	return pset
		.inputs()
		.map((input) => outpointKey(input.previousTxid().toString(), input.previousVout()));
}

/**
 * Private keys, public keys and scripts of every input, for the ELIP-352 sender aggregation.
 * Every derived buffer is pushed to `keyBuffers` for zeroization by the caller.
 */
function collectSenderInputKeys(
	inputKeys: string[],
	walletUtxos: Map<string, WalletTxOut>,
	spKeys: Map<string, { key: Uint8Array; utxo: TrackedSilentPaymentUtxo }>,
	implementation: LwkLiquidAccountImplementation,
	keyBuffers: Uint8Array[],
) {
	const inputPrivkeys: Uint8Array[] = [];
	const inputPubkeys: Uint8Array[] = [];
	const inputScripts: string[] = [];
	const push = (privateKey: Uint8Array, publicKey: Uint8Array, script: string) => {
		inputPrivkeys.push(privateKey);
		inputPubkeys.push(publicKey);
		inputScripts.push(script);
		keyBuffers.push(privateKey);
	};

	for (const op of inputKeys) {
		const sp = spKeys.get(op);
		if (sp) {
			const norm = normalizeTaprootInputKey(new Uint8Array(sp.key));
			push(new Uint8Array(norm.privateKey), norm.publicKey, sp.utxo.scriptPubKeyHex.toLowerCase());
			continue;
		}

		const utxo = walletUtxos.get(op);
		if (!utxo) {
			throw invalidTransfer(`Silent Payment send failed: UTXO ${op} was not found in wallet UTXOs`);
		}
		if (!implementation.deriveInputKey) {
			throw invalidTransfer(
				"Silent Payment send failed: account implementation does not support key derivation (deriveInputKey is missing)",
			);
		}
		const key = implementation.deriveInputKey(utxo.extInt() === 1, utxo.wildcardIndex());
		if (!key?.privateKey || !key.publicKey) {
			throw invalidTransfer(`Silent Payment send failed: failed to derive key for UTXO ${op}`);
		}
		keyBuffers.push(key.privateKey);

		// The derived key pair must be consistent and own the spent output.
		if (!bytesEqual(secp256k1.getPublicKey(key.privateKey, true), key.publicKey)) {
			throw invalidTransfer(
				`Silent Payment send failed: derived public key does not match private key · G for UTXO ${op}`,
			);
		}
		const spk = utxo.scriptPubkey().toString().toLowerCase();
		if (!verifyInputPublicKeyScript(key.publicKey, spk)) {
			throw invalidTransfer(
				`Silent Payment send failed: derived public key does not match scriptPubKey for UTXO ${op}`,
			);
		}

		if (isTaprootScriptPubKey(spk)) {
			const norm = normalizeTaprootInputKey(new Uint8Array(key.privateKey));
			push(new Uint8Array(norm.privateKey), norm.publicKey, spk);
		} else {
			push(new Uint8Array(key.privateKey), key.publicKey, spk);
		}
	}

	return { inputPrivkeys, inputPubkeys, inputScripts };
}

type SpOutputRecord = {
	address: string;
	blindingKeyHex: string;
	labelIndex?: number;
	labelTweakHex?: string;
	recipientAddress: string;
	scriptPubKeyHex: string;
	tweakHex: string;
};

/**
 * Builds, signs and broadcasts a transfer with LWK's TxBuilder from the wallet's own UTXOs plus,
 * when needed, Silent Payment UTXOs as external inputs.
 *
 * An ELIP-352 output key P_k depends on the transaction inputs, so a send with an SP output is
 * built twice: first with same-size placeholder outputs to learn the inputs LWK picks, then with
 * those inputs pinned and the real outputs. Pinned inputs and same-size outputs give the same fee.
 */
export async function sendTransfer(
	account: LiquidWalletAccount,
	params: LiquidSendTransferParams,
	rawAssetId: string,
): Promise<LiquidSendTransferResult> {
	assertNoMemo(params);

	const implementation = getLwkImplementation(account);
	const lwk = await loadLwkWasm();
	const recipient = resolveRecipient(lwk, account, params, rawAssetId);
	const builder = new SendBuilder(lwk, account, implementation, params, rawAssetId);
	const isMainnet = isLiquidMainnetChain(account.chain);

	// Change of a send to an SP address goes to the sender's own SP change label m = 0, so the
	// change output looks like the payment (anti-fingerprinting).
	const spChangeKeys =
		recipient.sp && !params.sendAll && account.silentPaymentAddress
			? account.silentPaymentKeys
			: undefined;

	const keyBuffers: Uint8Array[] = [];

	try {
		const placeholderRecipient = recipient.sp
			? placeholderSpAddress(account, recipient.sp.spendPublicKey)
			: recipient.address;
		const placeholderChange = spChangeKeys
			? placeholderSpAddress(account, spChangeKeys.spendKey.publicKey)
			: undefined;

		const spInputs = await selectSpInputs(
			builder,
			account,
			implementation,
			params,
			rawAssetId,
			placeholderRecipient,
			placeholderChange,
		);

		const spKeys = new Map<string, { key: Uint8Array; utxo: TrackedSilentPaymentUtxo }>();
		for (const u of spInputs) {
			const key = deriveSpSpendingPrivateKey(account.silentPaymentKeys?.spendKey.privateKey, u);
			keyBuffers.push(key);
			spKeys.set(outpointKey(u.txid, u.outputIndex), { key, utxo: u });
		}

		let pset = await builder.build({
			change: placeholderChange,
			recipient: placeholderRecipient,
			spInputs,
			walletOutpoints: null,
		});

		let spRecord: SpOutputRecord | null = null;
		let spChangeRecord: SpOutputRecord | null = null;

		if (recipient.sp) {
			const inputKeys = psetInputKeys(pset);
			const walletUtxos = new Map(
				implementation.wollet
					.utxos()
					.map((u) => [outpointKey(u.outpoint().txid().toString(), u.outpoint().vout()), u]),
			);
			const senderKeys = collectSenderInputKeys(
				inputKeys,
				walletUtxos,
				spKeys,
				implementation,
				keyBuffers,
			);
			const outpoints = inputKeys.map((op) => {
				const [txid, vout] = op.split(":");
				return { txid, vout: Number(vout) };
			});

			const spOutput = createSilentPaymentOutput({
				...senderKeys,
				k: 0,
				network: account.chain.settings.network,
				outpoints,
				recipientAddress: recipient.sp.address,
			});
			spRecord = {
				address: spOutput.confidentialAddress,
				blindingKeyHex: spOutput.blindingKeyHex,
				recipientAddress: recipient.sp.address,
				scriptPubKeyHex: bytesToHex(spOutput.destinationScriptPubKey),
				tweakHex: spOutput.tweakHex,
			};

			if (spChangeKeys) {
				const label = deriveLabeledSilentPaymentAddress(
					spChangeKeys,
					0,
					isMainnet ? "mainnet" : "testnet",
				);
				// Outputs to one scan key share the counter k (BIP-352).
				const sameScanKey = bytesEqual(spChangeKeys.scanKey.publicKey, recipient.sp.scanPublicKey);
				const changeOutput = createSilentPaymentOutput({
					...senderKeys,
					k: sameScanKey ? 1 : 0,
					network: account.chain.settings.network,
					outpoints,
					recipientAddress: label.address,
				});
				spChangeRecord = {
					address: changeOutput.confidentialAddress,
					blindingKeyHex: changeOutput.blindingKeyHex,
					labelIndex: 0,
					labelTweakHex: bytesToHex(numberToBytesBE(label.labelTweak, 32)),
					// The owning account's static SP address, not the m=0 labeled one: records are keyed
					// by owner, and `labelIndex: 0` already marks this output as change.
					recipientAddress: account.silentPaymentAddress!,
					scriptPubKeyHex: bytesToHex(changeOutput.destinationScriptPubKey),
					tweakHex: changeOutput.tweakHex,
				};
			}

			const spOutpoints = new Set(spKeys.keys());
			pset = await builder.build({
				change: spChangeRecord?.address,
				recipient: spRecord.address,
				spInputs,
				walletOutpoints: inputKeys.filter((op) => !spOutpoints.has(op)),
			});

			// P_k commits to exactly the inputs it was derived from.
			const expected = [...inputKeys].sort();
			const actual = psetInputKeys(pset).sort();
			if (expected.length !== actual.length || expected.some((op, i) => op !== actual[i])) {
				throw invalidTransfer(
					`Silent Payment security check failed: final PSET inputs do not match inputs used for tweak derivation (A). Expected: [${expected.join(", ")}], got: [${actual.join(", ")}]`,
				);
			}
		}

		// Locate the SP outputs in the final PSET; refuse dust L-BTC outputs.
		const outputs = pset.outputs();
		const locate = (record: SpOutputRecord, role: string) => {
			const spk = record.scriptPubKeyHex.toLowerCase();
			const index = outputs.findIndex((o) => o.scriptPubkey().toString().toLowerCase() === spk);
			if (index === -1) {
				throw transferFailed(
					`Silent Payment verification failed: ${role} scriptPubKey ${spk} was not found in final PSET outputs.`,
				);
			}
			return { amount: outputs[index].amount() ?? 0n, index };
		};
		for (const out of outputs) {
			const amount = out.amount() ?? 0n;
			if (
				out.scriptPubkey().toString().length > 0 &&
				out.asset()?.toString() === account.rawPolicyAssetId &&
				amount > 0n &&
				amount < LIQUID_EXPLICIT_DUST_LIMIT_SATS
			) {
				throw invalidTransfer(
					`Transaction produces a dust output of ${amount} satoshis, which is below the Liquid dust limit (600 satoshis). Please adjust the transfer amount or use Max to drain your balance.`,
				);
			}
		}
		const spPayment = spRecord && locate(spRecord, "recipient");
		const spChange = spChangeRecord && locate(spChangeRecord, "change");
		const feeSats = builder.feeOf(pset).toString();

		// Sign: the wallet signer covers wallet inputs, SP inputs get a Taproot key-path signature.
		// LWK's signer throws when it adds no signature, as for a PSET that spends only SP UTXOs.
		const spendsWalletUtxo = pset
			.inputs()
			.some(
				(input) => !spKeys.has(outpointKey(input.previousTxid().toString(), input.previousVout())),
			);
		const signedPset = spendsWalletUtxo ? implementation.signer.sign(pset) : pset;
		signedPset.inputs().forEach((input, index) => {
			const sp = spKeys.get(outpointKey(input.previousTxid().toString(), input.previousVout()));
			if (sp) signedPset.signTaprootKeypath(index, sp.key);
		});

		const finalizedPset = implementation.wollet.finalize(signedPset);
		const { txid } = await getSyncWorkerClient().broadcast({
			chain: account.chain,
			psetBase64: finalizedPset.toString(),
		});

		// The transaction is broadcast: a failed local write must not report the send as failed. The
		// wallet scan finds the same spends and outputs when it reaches the transaction.
		const bestEffort = async (write: Promise<void>) => {
			try {
				await write;
			} catch (error) {
				console.warn(
					"[sendTransfer] Could not record Silent Payment state after broadcast:",
					error,
				);
			}
		};

		for (const { utxo } of spKeys.values()) {
			// The fee lets the activity feed show a send the LWK wallet does not see (SP inputs only).
			await bestEffort(
				markSilentPaymentUtxoSpent(utxo.txid, utxo.outputIndex, txid, {
					blockTime: null,
					confirmed: false,
					feeSats,
				}),
			);
		}

		const save = (
			record: SpOutputRecord,
			output: { amount: bigint; index: number },
			asset: string,
		) =>
			bestEffort(
				saveTrackedSilentPaymentUtxo({
					address: record.address,
					amountSats: output.amount.toString(),
					blindingKeyHex: record.blindingKeyHex,
					chainId: account.chainId,
					// Just broadcast: scanning its block confirms it.
					confirmed: false,
					createdAt: Date.now(),
					labelIndex: record.labelIndex,
					labelTweakHex: record.labelTweakHex,
					outputIndex: output.index,
					rawAssetId: asset,
					recipientAddress: record.recipientAddress,
					scriptPubKeyHex: record.scriptPubKeyHex,
					spent: false,
					tweakHex: record.tweakHex,
					txid,
				}),
			);

		// A payment to our own SP address is ours to track right away.
		if (
			spRecord &&
			spPayment &&
			spRecord.recipientAddress.toLowerCase() === account.silentPaymentAddress?.toLowerCase()
		) {
			await save(spRecord, spPayment, rawAssetId);
		}
		if (spChangeRecord && spChange) {
			await save(spChangeRecord, spChange, account.rawPolicyAssetId);
		}

		return { txid };
	} catch (error) {
		if (error instanceof WalletRpcInvalidParamsError) {
			throw error;
		}
		if (error instanceof WalletRpcResourceUnavailableError) {
			throw error;
		}
		throw transferFailed("Could not build, sign, and broadcast the Liquid transfer.", error);
	} finally {
		// Zeroize every transient private key buffer.
		for (const buf of keyBuffers) {
			zeroizeBuffer(buf);
		}
	}
}

/**
 * Estimate the maximum sendable amount, Silent Payment UTXOs included.
 *
 * - Issued (non-native) asset: the fee is paid separately in L-BTC, so "max" is the full asset
 *   balance (`feeSats: "0"`).
 * - Native L-BTC: build a drain PSET (every L-BTC input → recipient) and subtract LWK's fee.
 */
export async function estimateMaxSend(
	account: LiquidWalletAccount,
	params: LiquidEstimateMaxSendParams,
	rawAssetId: string,
): Promise<LiquidEstimateMaxSendResult> {
	const implementation = getLwkImplementation(account);
	const spUtxos = spendableSpUtxosOf(await getAccountUnspentSpUtxos(account), rawAssetId);
	const balance =
		BigInt(readWalletBalanceForAsset(implementation.wollet, account.chainId, rawAssetId)) +
		sumSats(spUtxos);

	if (rawAssetId !== account.rawPolicyAssetId) {
		return { feeSats: "0", maxAmount: balance.toString() };
	}
	if (balance === 0n) {
		return { feeSats: "0", maxAmount: "0" };
	}

	const lwk = await loadLwkWasm();
	const drainParams = { amount: "0", recipientAddress: params.recipientAddress, sendAll: true };

	try {
		const recipient = resolveRecipient(lwk, account, drainParams, rawAssetId);
		const builder = new SendBuilder(lwk, account, implementation, drainParams, rawAssetId);
		const pset = await builder.build({
			recipient: recipient.sp
				? placeholderSpAddress(account, recipient.sp.spendPublicKey)
				: recipient.address,
			spInputs: spUtxos,
			walletOutpoints: null,
		});
		const fee = builder.feeOf(pset);
		pset.free();

		return {
			feeSats: fee.toString(),
			maxAmount: (balance > fee ? balance - fee : 0n).toString(),
		};
	} catch (error) {
		if (error instanceof WalletRpcInvalidParamsError) {
			throw error;
		}
		const failure = new WalletRpcResourceUnavailableError(
			"Could not estimate the maximum sendable Liquid amount.",
			undefined,
			WALLET_RPC_ERROR_REASONS.WALLET_TRANSFER_FAILED,
		);
		failure.cause = error;
		throw failure;
	}
}

function validateRecipientNetwork(
	account: LiquidWalletAccount,
	recipientAddress: { isMainnet: () => boolean; toString: () => string },
): void {
	if (recipientAddress.isMainnet() !== isLiquidMainnetChain(account.chain)) {
		throw invalidTransfer("Liquid recipient address network does not match the connected chain.", {
			chainId: account.chainId,
			recipientAddress: recipientAddress.toString(),
		});
	}
}

function validateSilentPaymentRecipientNetwork(
	account: LiquidWalletAccount,
	spInfo: SilentPaymentAddressInfo,
): void {
	const expectedHrp = isLiquidMainnetChain(account.chain) ? HRP_LIQUID_MAINNET : HRP_LIQUID_TESTNET;
	if (spInfo.hrp !== expectedHrp) {
		throw invalidTransfer("Liquid recipient address network does not match the connected chain.", {
			chainId: account.chainId,
			recipientAddress: spInfo.address,
		});
	}
}
