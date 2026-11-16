import { secp256k1 } from "@noble/curves/secp256k1.js";
import { ripemd160 } from "@noble/hashes/ripemd160.js";
import { sha256 } from "@noble/hashes/sha2.js";
import { bytesToHex, hexToBytes } from "@noble/hashes/utils.js";

import {
	aggregatePublicKeys,
	computeInputsHash,
	deriveSharedSecretFromTweak,
	deriveSharedSecretRecipient,
	findSmallestOutpoint,
	isFutureSegwitScriptPubKey,
	K_MAX,
	matchCandidateOutputs,
	precomputeLabelPoints,
	toScalarBigInt,
} from "./crypto";
import { parseRawElementsTransaction } from "./rawTx";
import type {
	EligibleInput,
	SpRecipientMatch,
	SpTransaction,
	SpTxInput,
	TxTweakResult,
} from "./types";

/**
 * BIP-341 NUMS (Nothing Up My Sleeve) point H x-coordinate (32 bytes = 64 hex chars).
 * H = lift_x(0x50929b74c1a04954b78b4b6035e97a5e078a5a0f28ec96d547bfee9ace803ac0).
 * Inputs spending via Taproot script-path where the internal key is NUMS H
 * MUST be skipped from shared secret derivation (BIP-352 / ELIP-352).
 */
export const NUMS_H_HEX = "50929b74c1a04954b78b4b6035e97a5e078a5a0f28ec96d547bfee9ace803ac0";

/**
 * Error thrown when a transaction input lacks prevout information required
 * to determine BIP-352 / ELIP-352 eligibility and compute the transaction tweak.
 */
export class MissingPrevoutError extends Error {
	readonly txid?: string;
	readonly vout?: number;

	constructor(message: string, txid?: string, vout?: number) {
		super(message);
		this.name = "MissingPrevoutError";
		this.txid = txid;
		this.vout = vout;
		Object.setPrototypeOf(this, MissingPrevoutError.prototype);
	}
}

/**
 * Standard hash160 helper (RIPEMD160(SHA256(data))).
 */
export function hash160(data: Uint8Array): Uint8Array {
	return ripemd160(sha256(data));
}

/**
 * Extract 32-byte Taproot x-only public key from a scriptPubKey (Uint8Array or hex).
 * Standard scriptPubKey: 0x51 0x20 <32-byte pubkey> (34 bytes or 68 hex chars starting with "5120").
 */
export function extractTaprootXOnly(scriptPubKey: Uint8Array | string): Uint8Array | null {
	if (typeof scriptPubKey === "string") {
		return extractTaprootXOnlyFromHex(scriptPubKey);
	}
	if (scriptPubKey.length === 34 && scriptPubKey[0] === 0x51 && scriptPubKey[1] === 0x20) {
		return scriptPubKey.slice(2, 34);
	}
	return null;
}

/**
 * Extract 32-byte Taproot x-only public key from hex-encoded scriptPubKey (witness v1).
 */
export function extractTaprootXOnlyFromHex(scriptPubKeyHex?: string): Uint8Array | null {
	if (!scriptPubKeyHex || typeof scriptPubKeyHex !== "string" || scriptPubKeyHex.length !== 68) {
		return null;
	}
	const lower = scriptPubKeyHex.toLowerCase();
	if (!lower.startsWith("5120")) {
		return null;
	}
	try {
		return hexToBytes(lower.slice(4, 68));
	} catch {
		return null;
	}
}

/**
 * Fast filter to check if a transaction contains at least one Taproot output.
 */
export function hasTaprootOutput(tx: SpTransaction): boolean {
	return tx.vout.some((out) => extractTaprootXOnly(out.scriptPubKey) !== null);
}

/**
 * Extract BIP-352 / ELIP-352 eligible inputs for Silent Payments shared secret derivation.
 * Pure function: does NOT execute network calls or fetch.
 *
 * Rules:
 * 1. Coinbase inputs are ignored.
 * 2. Peg-in inputs MUST be excluded from aggregated public key A (ELIP-352).
 * 3. Taproot v1_p2tr:
 *    - Key-path spend: extracted from prevout scriptPubKey (lifted with 02 prefix).
 *    - Script-path spend: extracted from prevout scriptPubKey UNLESS control block internal key == NUMS H (BIP-352).
 * 4. SegWit v0 P2WPKH: extracted from witness[1] (33-byte compressed pubkey) and verified against prevout spk (0014 || hash160(pubkey)).
 * 5. Nested SegWit P2SH-P2WPKH: extracted from witness[1], verified against redeemScript and P2SH prevout spk.
 * 6. Legacy P2PKH: extracted from scriptSig (compressed 33-byte pubkey) verified against prevout spk hash160.
 */
export function extractEligibleInputs(vinList: SpTxInput[]): EligibleInput[] {
	const eligibleInputs: EligibleInput[] = [];

	for (const vin of vinList) {
		if (vin.isCoinbase) continue;
		if (vin.isPegin) continue; // ELIP-352: peg-in inputs excluded from A

		const spk =
			typeof vin.prevoutScriptPubKey === "string"
				? vin.prevoutScriptPubKey.toLowerCase()
				: vin.prevoutScriptPubKey
					? bytesToHex(vin.prevoutScriptPubKey).toLowerCase()
					: "";
		const spkType = vin.prevoutScriptPubKeyType?.toLowerCase() ?? "";

		// BIP-352 / ELIP-352: Strict rejection if input lacks prevout scriptPubKey.
		// A transaction missing prevouts cannot be checked for eligibility,
		// and must be recognized as unprocessed rather than computing tweak on partial inputs.
		if (!spk) {
			throw new MissingPrevoutError(
				`Missing prevoutScriptPubKey for input ${vin.txid ?? "unknown"}:${vin.vout ?? 0}; cannot determine eligibility`,
				vin.txid,
				vin.vout,
			);
		}

		const witness = vin.witness?.map((w) =>
			typeof w === "string" ? w.toLowerCase() : bytesToHex(w).toLowerCase(),
		);
		const scriptSig =
			typeof vin.scriptsig === "string"
				? vin.scriptsig.toLowerCase()
				: vin.scriptsig
					? bytesToHex(vin.scriptsig).toLowerCase()
					: "";

		// 1. Taproot (v1_p2tr) - key-path and script-path spends (BIP-352 / ELIP-352):
		const isTaprootSpk = spkType === "v1_p2tr" || (spk.length === 68 && spk.startsWith("5120"));
		if (isTaprootSpk && spk.length === 68 && witness && witness.length > 0) {
			const witnessStack = [...witness];

			// Handle BIP-341 annex: if stack has >= 2 items and last item starts with 0x50, remove annex
			if (witnessStack.length > 1) {
				const lastItem = witnessStack[witnessStack.length - 1];
				if (lastItem && lastItem.length >= 2 && lastItem.startsWith("50")) {
					witnessStack.pop();
				}
			}

			// Key-path spend: single witness item (signature)
			if (witnessStack.length === 1) {
				try {
					const xOnlyHex = spk.slice(4, 68);
					// BIP-340 canonical lift to even-y (02 prefix)
					const pubkey = hexToBytes(`02${xOnlyHex}`);
					const pt = secp256k1.Point.fromHex(pubkey);
					pt.assertValidity();
					eligibleInputs.push({
						outpoint: { txid: vin.txid, vout: vin.vout },
						pubkey,
					});
					continue;
				} catch {
					// Skip malformed pubkey
				}
			}

			// Script-path spend: witnessStack length > 1
			// Last element is the BIP-341 control block (<1-byte control> <32-byte internal key> [<merkle path>])
			if (witnessStack.length > 1) {
				const controlBlockHex = witnessStack[witnessStack.length - 1] ?? "";
				// Valid control block length is 33 + 32*m bytes (66 + 64*m hex characters)
				if (controlBlockHex.length >= 66 && (controlBlockHex.length - 66) % 64 === 0) {
					const internalKeyHex = controlBlockHex.slice(2, 66).toLowerCase();
					// BIP-352: Skip if internal key is NUMS H
					if (internalKeyHex === NUMS_H_HEX) {
						continue;
					}

					try {
						// Non-NUMS script-path spend contributes the Taproot output key (lifted to even-y)
						const xOnlyHex = spk.slice(4, 68);
						const pubkey = hexToBytes(`02${xOnlyHex}`);
						const pt = secp256k1.Point.fromHex(pubkey);
						pt.assertValidity();
						eligibleInputs.push({
							outpoint: { txid: vin.txid, vout: vin.vout },
							pubkey,
						});
						continue;
					} catch {
						// Skip malformed pubkey
					}
				}
			}
		}

		// 2. SegWit v0 P2WPKH:
		// Witness has 2 elements: [signature, 33-byte compressed pubkey]
		// Prevout spk MUST strictly match OP_0 0x14 <hash160(pubkey)> (44 hex chars: "0014" + hash160)
		if (witness && witness.length === 2) {
			const candidatePkHex = witness[1] ?? "";
			if (
				candidatePkHex.length === 66 &&
				(candidatePkHex.startsWith("02") || candidatePkHex.startsWith("03"))
			) {
				try {
					const pubkey = hexToBytes(candidatePkHex);
					const pt = secp256k1.Point.fromHex(pubkey);
					pt.assertValidity();

					const pkh = hash160(pubkey);
					const expectedSpk = "0014" + bytesToHex(pkh).toLowerCase();

					if (spk === expectedSpk) {
						eligibleInputs.push({
							outpoint: { txid: vin.txid, vout: vin.vout },
							pubkey,
						});
						continue;
					}
				} catch {
					// Skip malformed pubkey
				}
			}
		}

		// 3. Nested SegWit P2SH-P2WPKH:
		// Witness has 2 elements: [signature, 33-byte compressed pubkey]
		// scriptSig contains redeemScript: "160014" + hash160(pubkey) (or "0014" + hash160(pubkey))
		// Prevout spk MUST strictly match OP_HASH160 0x14 <hash160(redeemScript)> OP_EQUAL ("a914" + hash + "87")
		if (witness && witness.length === 2 && scriptSig) {
			const candidatePkHex = witness[1] ?? "";
			if (
				candidatePkHex.length === 66 &&
				(candidatePkHex.startsWith("02") || candidatePkHex.startsWith("03"))
			) {
				try {
					const pubkey = hexToBytes(candidatePkHex);
					const pt = secp256k1.Point.fromHex(pubkey);
					pt.assertValidity();

					const pkh = hash160(pubkey);
					const redeemScriptHex = "0014" + bytesToHex(pkh).toLowerCase();
					const pushRedeemScriptHex = "16" + redeemScriptHex;

					const isScriptSigMatch =
						scriptSig === pushRedeemScriptHex || scriptSig === redeemScriptHex;

					if (isScriptSigMatch) {
						const redeemScriptBytes = hexToBytes(redeemScriptHex);
						const expectedP2shSpk =
							"a914" + bytesToHex(hash160(redeemScriptBytes)).toLowerCase() + "87";

						if (spk === expectedP2shSpk) {
							eligibleInputs.push({
								outpoint: { txid: vin.txid, vout: vin.vout },
								pubkey,
							});
							continue;
						}
					}
				} catch {
					// Skip malformed pubkey
				}
			}
		}

		// 4. Legacy P2PKH:
		// No witness allowed.
		// SPK MUST strictly be OP_DUP OP_HASH160 0x14 <20-byte hash> OP_EQUALVERIFY OP_CHECKSIG ("76a914" + 20-bytes + "88ac")
		// scriptSig contains compressed pubkey whose hash160 matches the SPK hash.
		const isP2pkhSpk =
			spkType === "p2pkh" ||
			(spk.length === 50 && spk.startsWith("76a914") && spk.endsWith("88ac"));
		if (
			(!witness || witness.length === 0) &&
			isP2pkhSpk &&
			spk.length === 50 &&
			scriptSig &&
			scriptSig.length >= 66
		) {
			const expectedSpkHash = spk.slice(6, 46);
			try {
				const scriptSigBytes = hexToBytes(scriptSig);
				// Search for 33-byte compressed pubkey matching expected hash160 (scanned from back as per BIP-352)
				for (let i = scriptSigBytes.length; i >= 33; i--) {
					const candidate = scriptSigBytes.slice(i - 33, i);
					if (candidate[0] === 0x02 || candidate[0] === 0x03) {
						const candidateHashHex = bytesToHex(hash160(candidate)).toLowerCase();
						if (candidateHashHex === expectedSpkHash) {
							const pt = secp256k1.Point.fromHex(candidate);
							pt.assertValidity();
							eligibleInputs.push({
								outpoint: { txid: vin.txid, vout: vin.vout },
								pubkey: candidate,
							});
							break;
						}
					}
				}
			} catch {
				// Skip malformed scriptSig
			}
		}
	}

	return eligibleInputs;
}

/**
 * Compute a transaction's ELIP-352 / BIP-352 input data, everything a recipient's shared secret
 * needs:
 *
 * 1. Ensure transaction has at least one Taproot output.
 * 2. Extract eligible inputs (excluding peg-in from A).
 * 3. A = sum(eligible_inputs.pubkey)
 * 4. outpoint_L = smallest outpoint among ALL non-coinbase inputs (including peg-in).
 * 5. input_hash = taggedHash("BIP0352/Inputs", outpoint_L || A)
 *
 * @returns { outpointL, A, inputHash } or null if not an SP candidate transaction
 */
export function computeTxInputs(tx: SpTransaction | string): Omit<TxTweakResult, "tweak"> | null {
	const parsedTx = typeof tx === "string" ? parseRawElementsTransaction(tx) : tx;

	// Quick check: must have at least one Taproot output
	if (!hasTaprootOutput(parsedTx)) {
		return null;
	}

	// BIP-352 / ELIP-352: skip the whole transaction if any input spends a SegWit v>1 output.
	// Peg-in prevouts live on the Bitcoin chain and are already excluded from A.
	for (const vin of parsedTx.vin ?? []) {
		if (vin.isCoinbase || vin.isPegin || !vin.prevoutScriptPubKey) continue;
		if (isFutureSegwitScriptPubKey(vin.prevoutScriptPubKey)) {
			return null;
		}
	}

	// Extract eligible inputs
	const eligibleInputs = extractEligibleInputs(parsedTx.vin ?? []);
	if (eligibleInputs.length === 0) {
		return null;
	}

	// Compute aggregated public key A
	let A: Uint8Array;
	try {
		A = aggregatePublicKeys(eligibleInputs.map((i) => i.pubkey));
	} catch {
		return null;
	}

	// Smallest outpoint among all non-coinbase inputs (ELIP-352: peg-in inputs included in outpoint_L)
	const allOutpoints = (parsedTx.vin ?? [])
		.filter((v) => !v.isCoinbase)
		.map((v) => ({ txid: v.txid, vout: v.vout }));

	const outpointL = findSmallestOutpoint(
		allOutpoints.length > 0 ? allOutpoints : eligibleInputs.map((i) => i.outpoint),
	);

	// Compute input_hash
	const inputHash = computeInputsHash(outpointL, A);

	return { A, inputHash, outpointL };
}

/**
 * Compute transaction tweak once per transaction (ELIP-352 / BIP-352): the input data of
 * `computeTxInputs` and tweak = input_hash · A, which a tweak server serves to every recipient.
 *
 * @returns { tweak, outpointL, A, inputHash } or null if not an SP candidate transaction
 */
export function computeTxTweak(tx: SpTransaction | string): TxTweakResult | null {
	const inputs = computeTxInputs(tx);
	if (!inputs) {
		return null;
	}
	const hashScalar = toScalarBigInt(inputs.inputHash);

	// Compute tweak point = input_hash · A
	const senderPoint = secp256k1.Point.fromHex(inputs.A);
	const tweakPoint = senderPoint.multiply(hashScalar);
	if (tweakPoint.equals(secp256k1.Point.ZERO)) {
		return null;
	}

	return { ...inputs, tweak: tweakPoint.toRawBytes(true) };
}

/**
 * Match a transaction's Taproot outputs against a recipient's keys using the precomputed tweak.
 * Pure function: does NOT perform confidential transaction unblinding.
 *
 * @param tx The transaction (SpTransaction or raw hex string)
 * @param tweak Precomputed 33-byte tweak point from computeTxTweak (input_hash · A)
 * @param b_scan Recipient scan private key scalar (bigint or 32-byte Uint8Array)
 * @param B_spend Recipient spend public key (33 bytes compressed)
 * @param labels Optional array of label indices or precomputed label Map
 * @param kMax Maximum recipient counter (defaults to K_MAX = 2323)
 */
export function matchTxForRecipient(
	tx: SpTransaction | string,
	tweak: Uint8Array | InstanceType<typeof secp256k1.Point>,
	b_scan: bigint | Uint8Array,
	B_spend: Uint8Array,
	labels?: number[] | Map<string, { labelIndex: number; labelTweak: bigint }>,
	kMax = K_MAX,
): SpRecipientMatch[] {
	const parsedTx = typeof tx === "string" ? parseRawElementsTransaction(tx) : tx;

	// Derive shared secret S = b_scan · tweak = b_scan · (input_hash · A)
	const S = deriveSharedSecretFromTweak(b_scan, tweak);

	// Precompute label points if an index array is supplied
	const labelMap = Array.isArray(labels) ? precomputeLabelPoints(b_scan, labels) : labels;

	return matchTxOutputs(parsedTx, S, B_spend, labelMap, kMax);
}

/**
 * Scan a transaction for a recipient without a tweak server: the shared secret comes straight from
 * the transaction's inputs, S = (input_hash · b_scan) · A, one scalar multiplication instead of the
 * tweak's and the shared secret's. Same matches as `computeTxTweak` + `matchTxForRecipient`.
 *
 * @returns the matches, or [] if the transaction is not an SP candidate
 */
export function scanTxForRecipient(
	tx: SpTransaction | string,
	b_scan: bigint | Uint8Array,
	B_spend: Uint8Array,
	labels?: number[] | Map<string, { labelIndex: number; labelTweak: bigint }>,
	kMax = K_MAX,
): SpRecipientMatch[] {
	const parsedTx = typeof tx === "string" ? parseRawElementsTransaction(tx) : tx;
	const inputs = computeTxInputs(parsedTx);
	if (!inputs) {
		return [];
	}
	const S = deriveSharedSecretRecipient(b_scan, inputs.inputHash, inputs.A);
	const labelMap = Array.isArray(labels) ? precomputeLabelPoints(b_scan, labels) : labels;
	return matchTxOutputs(parsedTx, S, B_spend, labelMap, kMax);
}

/** Match a transaction's Taproot outputs against B_spend for the shared secret S. */
function matchTxOutputs(
	parsedTx: SpTransaction,
	S: Uint8Array,
	B_spend: Uint8Array,
	labelMap: Map<string, { labelIndex: number; labelTweak: bigint }> | undefined,
	kMax: number,
): SpRecipientMatch[] {
	// Collect candidate Taproot outputs
	const candidateOutputs: Array<{
		outputIndex: number;
		scriptPubKey: Uint8Array | string;
		targetXOnly: Uint8Array;
	}> = [];

	for (let i = 0; i < (parsedTx.vout ?? []).length; i++) {
		const out = parsedTx.vout[i];
		const targetXOnly = extractTaprootXOnly(out.scriptPubKey);
		if (!targetXOnly) continue;

		const outputIndex = out.outputIndex ?? i;
		candidateOutputs.push({
			outputIndex,
			scriptPubKey: out.scriptPubKey,
			targetXOnly,
		});
	}

	if (candidateOutputs.length === 0) {
		return [];
	}

	// Match candidate outputs iteratively (k = 0, 1, ...)
	const matches = matchCandidateOutputs(candidateOutputs, B_spend, S, labelMap, kMax);

	return matches.map((m) => {
		const { candidate, k, matchResult, tk } = m;
		const scriptPubKeyHex =
			typeof candidate.scriptPubKey === "string"
				? candidate.scriptPubKey.toLowerCase()
				: bytesToHex(candidate.scriptPubKey).toLowerCase();

		return {
			candidate,
			k,
			labelIndex: matchResult.labelIndex,
			labelTweak: matchResult.labelTweak,
			outputIndex: candidate.outputIndex,
			point: matchResult.point,
			S,
			scriptPubKeyHex,
			targetXOnly: candidate.targetXOnly,
			tk,
		};
	});
}
