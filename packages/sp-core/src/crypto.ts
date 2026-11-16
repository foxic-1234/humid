import { secp256k1 } from "@noble/curves/secp256k1.js";
import { bytesToNumberBE, numberToBytesBE } from "@noble/curves/utils.js";
import { ripemd160 } from "@noble/hashes/ripemd160.js";
import { sha256 } from "@noble/hashes/sha2.js";
import { bytesToHex, concatBytes, hexToBytes, utf8ToBytes } from "@noble/hashes/utils.js";

import type {
	AggregateSenderInputsOptions,
	AggregateSenderInputsResult,
	CandidateTaprootOutput,
	MatchedCandidateOutput,
	SpInputKeyCandidate,
} from "./types";

/** Secp256k1 curve order q (n). */
export const CURVE_ORDER_Q: bigint = secp256k1.CURVE.n;

/**
 * ELIP-352 blinding key tag — the exact 26-byte ASCII string
 * "LiquidSilentPayments/Blind". Disjoint from BIP-352's "BIP0352/SharedSecret"
 * so the blinding key and output tweak, though both derived from S, do not
 * reveal each other.
 */
export const BLIND_TAG = "LiquidSilentPayments/Blind";

/** BIP-352 tags for shared secret and input hash derivation. */
export const SHARED_SECRET_TAG = "BIP0352/SharedSecret";
export const INPUTS_TAG = "BIP0352/Inputs";

/**
 * BIP-352 per-recipient-group limit.
 * A sender MUST fail if a recipient group exceeds K_MAX.
 * A receiver MUST NOT scan past k = K_MAX.
 */
export const K_MAX = 2323;

/**
 * Standard BIP 340 / BIP 352 tagged hash:
 * SHA256(SHA256(tag) || SHA256(tag) || data)
 */
export function taggedHash(tag: string, ...data: Uint8Array[]): Uint8Array {
	const tagHash = sha256(utf8ToBytes(tag));
	return sha256(concatBytes(tagHash, tagHash, ...data));
}

/**
 * Serialize an outpoint according to ELIP-352 / BIP-352:
 * 32-byte internal txid followed by 4-byte little-endian vout.
 *
 * ELIP-352: Elements overloads the high bits of vout as issuance (bit 31)
 * and peg-in (bit 30) flags. vout here is always the parsed index with both
 * flags cleared (vout & 0x3fffffff).
 *
 * @param txidHex 64-char hex string in display order (reversed from internal)
 * @param vout Output index (high bits cleared if present)
 */
export function outpointToBytes(txidHex: string, vout: number): Uint8Array {
	if (txidHex.length !== 64) {
		throw new Error(`Invalid txid length: expected 64 hex chars, got ${txidHex.length}`);
	}
	const txidBytes = hexToBytes(txidHex);
	const reversedTxid = new Uint8Array(32);
	for (let i = 0; i < 32; i++) {
		reversedTxid[i] = txidBytes[31 - i];
	}
	// ELIP-352: clear issuance (bit 31) and pegin (bit 30) flags
	const cleanVout = vout & 0x3fffffff;
	const voutBytes = new Uint8Array(4);
	const view = new DataView(voutBytes.buffer);
	view.setUint32(0, cleanVout, true); // little-endian
	return concatBytes(reversedTxid, voutBytes);
}

/**
 * Serialize an outpoint from a txid already in internal byte order.
 * Used for test vectors where txids are given in internal byte order.
 */
export function outpointToBytesInternal(txidHex: string, vout: number): Uint8Array {
	if (txidHex.length !== 64) {
		throw new Error(`Invalid txid length: expected 64 hex chars, got ${txidHex.length}`);
	}
	const txidBytes = hexToBytes(txidHex);
	const cleanVout = vout & 0x3fffffff;
	const voutBytes = new Uint8Array(4);
	const view = new DataView(voutBytes.buffer);
	view.setUint32(0, cleanVout, true); // little-endian
	return concatBytes(txidBytes, voutBytes);
}

/**
 * Find the lexicographically smallest outpoint among all transaction inputs (BIP-352 outpoint_L).
 */
export function findSmallestOutpoint(
	outpoints: Array<{ txid: string; vout: number }>,
	internalByteOrder = false,
): Uint8Array {
	if (outpoints.length === 0) {
		throw new Error("Cannot find smallest outpoint: list is empty");
	}
	const serializeFn = internalByteOrder ? outpointToBytesInternal : outpointToBytes;
	const serialized = outpoints.map((op) => serializeFn(op.txid, op.vout));
	serialized.sort((a, b) => {
		for (let i = 0; i < a.length; i++) {
			if (a[i] !== b[i]) return a[i] - b[i];
		}
		return 0;
	});
	return serialized[0];
}

/**
 * Aggregate multiple secp256k1 public keys by point addition: A = A_1 + A_2 + ... + A_n.
 */
export function aggregatePublicKeys(pubkeys: Uint8Array[]): Uint8Array {
	if (pubkeys.length === 0) {
		throw new Error("Cannot aggregate public keys: list is empty");
	}
	let totalPoint = secp256k1.Point.fromHex(pubkeys[0]);
	for (let i = 1; i < pubkeys.length; i++) {
		totalPoint = totalPoint.add(secp256k1.Point.fromHex(pubkeys[i]));
	}
	if (totalPoint.equals(secp256k1.Point.ZERO)) {
		throw new Error("Aggregated public key is the point at infinity");
	}
	return totalPoint.toRawBytes(true);
}

/**
 * Compute BIP-352 input_hash:
 * input_hash = tagged_hash("BIP0352/Inputs", outpoint_L || A_sum)
 */
export function computeInputsHash(
	smallestOutpointBytes: Uint8Array,
	sumPubkeys: Uint8Array,
): Uint8Array {
	return taggedHash(INPUTS_TAG, smallestOutpointBytes, sumPubkeys);
}

/** Convert a scalar bigint or bytes to a verified bigint in [1, q - 1]. */
export function toScalarBigInt(scalar: bigint | Uint8Array): bigint {
	const num = typeof scalar === "bigint" ? scalar : bytesToNumberBE(scalar);
	if (num <= 0n || num >= CURVE_ORDER_Q) {
		throw new Error(
			`Invalid scalar: value must be in range [1, n - 1] (got ${num >= CURVE_ORDER_Q ? ">= curve order n" : "<= 0"})`,
		);
	}
	return num;
}

/** Serialize 32-bit unsigned integer to 4-byte big-endian buffer. */
export function ser32(num: number): Uint8Array {
	const buffer = new Uint8Array(4);
	const view = new DataView(buffer.buffer);
	view.setUint32(0, num, false);
	return buffer;
}

/**
 * Sender shared secret derivation (BIP-352):
 * S = (input_hash * a) * B_scan
 *
 * @param inputHash 32-byte scalar input_hash or bigint
 * @param a Aggregated input private key scalar a
 * @param B_scan Recipient scan public key B_scan (33 bytes compressed)
 * @returns 33-byte compressed curve point S
 */
export function deriveSharedSecretSender(
	inputHash: bigint | Uint8Array,
	a: bigint | Uint8Array,
	B_scan: Uint8Array,
): Uint8Array {
	if (inputHash === undefined || inputHash === null) {
		throw new Error("ELIP-352 / BIP-352: inputHash is required for shared secret derivation");
	}
	const aScalar = toScalarBigInt(a);
	const hashScalar = toScalarBigInt(inputHash);
	const tweakedPrivKey = (aScalar * hashScalar) % CURVE_ORDER_Q;
	if (tweakedPrivKey === 0n) {
		throw new Error("Tweaked sender private key is 0");
	}

	const scanPoint = secp256k1.Point.fromHex(B_scan);
	const sharedPoint = scanPoint.multiply(tweakedPrivKey);
	return sharedPoint.toRawBytes(true);
}

/**
 * Recipient shared secret derivation (BIP-352):
 * S = (input_hash * b_scan) * A
 *
 * One scalar multiplication of A, as the sender's side does: equal to b_scan * (input_hash * A),
 * and the product of two scalars in [1, n - 1] is never 0 mod the prime n.
 *
 * @param b_scan Recipient scan private key scalar
 * @param inputHash 32-byte scalar input_hash or bigint
 * @param A Sender aggregated public key A (33 bytes compressed)
 * @returns 33-byte compressed curve point S
 */
export function deriveSharedSecretRecipient(
	b_scan: bigint | Uint8Array,
	inputHash: bigint | Uint8Array,
	A: Uint8Array,
): Uint8Array {
	if (inputHash === undefined || inputHash === null) {
		throw new Error("ELIP-352 / BIP-352: inputHash is required for shared secret derivation");
	}
	const bScanScalar = toScalarBigInt(b_scan);
	const hashScalar = toScalarBigInt(inputHash);
	const tweakedScanKey = (bScanScalar * hashScalar) % CURVE_ORDER_Q;

	const senderPoint = secp256k1.Point.fromHex(A);
	const sharedPoint = senderPoint.multiply(tweakedScanKey);
	return sharedPoint.toRawBytes(true);
}

/**
 * Compute shared secret S directly from a transaction tweak point:
 * S = b_scan · tweak
 * where tweak = input_hash · A
 */
export function deriveSharedSecretFromTweak(
	b_scan: bigint | Uint8Array,
	tweak: Uint8Array | InstanceType<typeof secp256k1.Point>,
): Uint8Array {
	const bScanScalar = toScalarBigInt(b_scan);
	const tweakPoint = tweak instanceof secp256k1.Point ? tweak : secp256k1.Point.fromHex(tweak);
	const sharedPoint = tweakPoint.multiply(bScanScalar);
	return sharedPoint.toRawBytes(true);
}

/**
 * BIP-352 output tweak:
 * t_k = hash("BIP0352/SharedSecret", serP(S) || ser32(k))
 *
 * ELIP-352 / BIP-352: If t_k = 0 or t_k ≥ n, this MUST be treated as a
 * failure — the sender fails to construct this output and the receiver
 * fails to scan past it. Throws an error to match deriveBlindingKey behavior.
 */
export function computeOutputTweak(S: Uint8Array, k: number): bigint {
	const tweakHash = taggedHash(SHARED_SECRET_TAG, concatBytes(S, ser32(k)));
	const tk = bytesToNumberBE(tweakHash);
	if (tk === 0n || tk >= CURVE_ORDER_Q) {
		throw new Error(
			`BIP-352 / ELIP-352: output tweak t_k is 0 or >= n for k=${k} — MUST treat as failure, not skip`,
		);
	}
	return tk;
}

/**
 * ELIP-352 blinding key derivation:
 * bk_k = int(hash("LiquidSilentPayments/Blind", serP(S) || ser32(k)))
 *
 * If bk_k = 0 or bk_k ≥ n, this MUST be treated as a failure (not skipped).
 * The probability is ~2^-128 and cannot be triggered by an attacker without
 * solving ECDH.
 *
 * @param S 33-byte compressed shared secret point
 * @param k Output index
 * @returns { bk: blinding key scalar, BK: blinding public key BK_k = bk_k·G }
 */
export function deriveBlindingKey(S: Uint8Array, k: number): { bk: bigint; BK: Uint8Array } {
	const hash = taggedHash(BLIND_TAG, concatBytes(S, ser32(k)));
	const bk = bytesToNumberBE(hash);
	if (bk === 0n || bk >= CURVE_ORDER_Q) {
		throw new Error("ELIP-352: bk_k is 0 or >= n — MUST treat as failure, not skip");
	}
	const BK = secp256k1.Point.BASE.multiply(bk).toRawBytes(true);
	return { bk, BK };
}

const LABEL_TAG = "BIP0352/Label";

/**
 * Compute BIP-352 label scalar tweak for label index m:
 * ℓ = tagged_hash("BIP0352/Label", b_scan || ser32(m)) mod q
 */
export function computeLabelTweak(b_scan: bigint | Uint8Array, m: number): bigint {
	const bScanScalar = toScalarBigInt(b_scan);
	const bScanBytes = numberToBytesBE(bScanScalar, 32);
	try {
		const labelHash = taggedHash(LABEL_TAG, concatBytes(bScanBytes, ser32(m)));
		const tk = bytesToNumberBE(labelHash) % CURVE_ORDER_Q;
		if (tk === 0n) {
			throw new Error(`Label tweak for index ${m} is zero — choose a different label index`);
		}
		return tk;
	} finally {
		bScanBytes.fill(0);
	}
}

/**
 * Compute labeled spend public key:
 * B_spend_m = B_spend + [ℓ]G
 */
export function deriveLabeledSpendPublicKey(B_spend: Uint8Array, labelTweak: bigint): Uint8Array {
	const spendPoint = secp256k1.Point.fromHex(B_spend);
	const labelPoint = secp256k1.Point.BASE.multiply(labelTweak);
	const labeledPoint = spendPoint.add(labelPoint);
	if (labeledPoint.equals(secp256k1.Point.ZERO)) {
		throw new Error("Derived labeled spend public key is the point at infinity");
	}
	return labeledPoint.toRawBytes(true); // 33 bytes compressed
}

/**
 * Generate output Taproot public key P_k:
 * P_k = B_spend + [t_k]G
 *
 * Returns the 32-byte x-only public key for the witness v1 scriptPubKey,
 * the 33-byte compressed representation, and the curve point P.
 */
export function deriveOneTimePublicKey(
	B_spend: Uint8Array,
	tk: bigint,
): {
	compressed: Uint8Array;
	point: InstanceType<typeof secp256k1.Point>;
	xOnly: Uint8Array;
} {
	const spendPoint = secp256k1.Point.fromHex(B_spend);
	const tweakPoint = secp256k1.Point.BASE.multiply(tk);
	const P = spendPoint.add(tweakPoint);
	if (P.equals(secp256k1.Point.ZERO)) {
		throw new Error("Derived one-time public key is the point at infinity");
	}

	const xOnly = numberToBytesBE(P.x, 32);
	const compressed = P.toRawBytes(true);
	return { compressed, point: P, xOnly };
}

/**
 * Precompute [ℓ_m]G points for a list of label indices:
 * Maps compressed hex of [ℓ_m]G -> label index m.
 */
export function precomputeLabelPoints(
	b_scan: bigint | Uint8Array,
	labelIndices: number[],
): Map<string, { labelIndex: number; labelTweak: bigint }> {
	const map = new Map<string, { labelIndex: number; labelTweak: bigint }>();
	for (const m of labelIndices) {
		const labelTweak = computeLabelTweak(b_scan, m);
		if (labelTweak === 0n) continue;
		const pt = secp256k1.Point.BASE.multiply(labelTweak);
		map.set(pt.toHex(true).toLowerCase(), { labelIndex: m, labelTweak });
	}
	return map;
}

/**
 * Match a candidate Taproot output x-only public key against both:
 * 1. Base (unlabeled) spending key: P = B_spend + [t_k]G
 * 2. Labeled keys: P = B_spend + [t_k]G + [ℓ_m]G  <=>  P - [t_k]G - B_spend = [ℓ_m]G
 *
 * Returns match result with matched label index (or undefined if unlabeled),
 * the curve point P, and the effective tweak.
 */
export function matchOutputWithLabels(
	targetXOnly: Uint8Array,
	B_spend: Uint8Array,
	tk: bigint,
	labelMap?: Map<string, { labelIndex: number; labelTweak: bigint }>,
): OutputMatch {
	return matchOutputAgainstBase(targetXOnly, deriveOneTimePublicKey(B_spend, tk), labelMap, () =>
		liftEvenY(targetXOnly),
	);
}

type CurvePoint = InstanceType<typeof secp256k1.Point>;

type OutputMatch = {
	labelIndex?: number;
	labelTweak?: bigint;
	matched: boolean;
	point?: CurvePoint;
};

/** The even-y curve point with x-coordinate `xOnly` (BIP-340), or null if there is none. */
function liftEvenY(xOnly: Uint8Array): CurvePoint | null {
	try {
		return secp256k1.Point.fromHex(`02${bytesToHex(xOnly)}`);
	} catch {
		return null;
	}
}

/**
 * `matchOutputWithLabels` for a base key B_spend + [t_k]G computed once per k, shared by every
 * candidate output. `lift` gives the candidate's even-y point, needed only for labels.
 */
function matchOutputAgainstBase(
	targetXOnly: Uint8Array,
	base: { point: CurvePoint; xOnly: Uint8Array },
	labelMap: Map<string, { labelIndex: number; labelTweak: bigint }> | undefined,
	lift: () => CurvePoint | null,
): OutputMatch {
	// 1. Check unlabeled base key first
	if (bytesEqual(base.xOnly, targetXOnly)) {
		return {
			matched: true,
			point: base.point,
		};
	}

	// 2. If labelMap is provided, test candidate difference points
	if (labelMap && labelMap.size > 0) {
		// Lift targetXOnly to curve point with even-y (BIP 340 canonical representation)
		const Peven = lift();
		if (!Peven) {
			// targetXOnly not on curve
			return { matched: false };
		}
		try {
			const baseSum = base.point;

			// Test D1 = Peven - tkPoint - spendPoint
			const D1 = Peven.subtract(baseSum);
			const d1Hex = D1.toHex(true).toLowerCase();
			const match1 = labelMap.get(d1Hex);
			if (match1) {
				return {
					labelIndex: match1.labelIndex,
					labelTweak: match1.labelTweak,
					matched: true,
					point: Peven,
				};
			}

			// Test D2 = (-Peven) - tkPoint - spendPoint (when original P had odd y)
			const D2 = Peven.negate().subtract(baseSum);
			const d2Hex = D2.toHex(true).toLowerCase();
			const match2 = labelMap.get(d2Hex);
			if (match2) {
				return {
					labelIndex: match2.labelIndex,
					labelTweak: match2.labelTweak,
					matched: true,
					point: Peven.negate(),
				};
			}
		} catch {
			// A difference at infinity has no encoding; the base check above already covers it.
		}
	}

	return { matched: false };
}

/**
 * Scan candidate Taproot outputs iteratively per BIP-352 / ELIP-352:
 *
 * Loop k = 0, 1, 2, ... < kMax:
 * 1. Compute output tweak t_k = hash("BIP0352/SharedSecret", serP(S) || ser32(k)).
 * 2. If t_k == 0 or t_k >= n: abort scanning (sentinel per BIP-352 spec).
 * 3. Search for a matching candidate among all currently unmatched candidate outputs.
 * 4. If a match is found:
 *    - Remove the candidate from the unmatched pool.
 *    - Record the match (including candidate, k, tk, and matchResult).
 *    - Increment k and continue to look for k + 1.
 * 5. If no candidate matches t_k:
 *    - Terminate scanning (per BIP-352: "fails to scan past this index").
 */
export function matchCandidateOutputs<T extends CandidateTaprootOutput>(
	candidates: readonly T[],
	B_spend: Uint8Array,
	S: Uint8Array,
	labelMap?: Map<string, { labelIndex: number; labelTweak: bigint }>,
	kMax = K_MAX,
): MatchedCandidateOutput<T>[] {
	const remaining = [...candidates];
	const matches: MatchedCandidateOutput<T>[] = [];
	// A candidate's even-y point, lifted at most once across every k.
	const lifted = new Map<T, CurvePoint | null>();
	const liftOf = (candidate: T) => () => {
		if (!lifted.has(candidate)) lifted.set(candidate, liftEvenY(candidate.targetXOnly));
		return lifted.get(candidate) ?? null;
	};
	let k = 0;

	while (k < kMax && remaining.length > 0) {
		const tk = computeOutputTweak(S, k);
		// B_spend + [t_k]G is the same for every candidate: computed once per k.
		const base = deriveOneTimePublicKey(B_spend, tk);

		let matchedIdx = -1;
		let matchResult: OutputMatch | null = null;

		for (let i = 0; i < remaining.length; i++) {
			const res = matchOutputAgainstBase(
				remaining[i].targetXOnly,
				base,
				labelMap,
				liftOf(remaining[i]),
			);
			if (res.matched && res.point) {
				matchedIdx = i;
				matchResult = res;
				break;
			}
		}

		if (matchedIdx === -1 || !matchResult || !matchResult.point) {
			break;
		}

		const matchedCandidate = remaining[matchedIdx];
		remaining.splice(matchedIdx, 1);

		matches.push({
			candidate: matchedCandidate,
			k,
			matchResult: {
				labelIndex: matchResult.labelIndex,
				labelTweak: matchResult.labelTweak,
				matched: true,
				point: matchResult.point,
			},
			tk,
		});

		k++;
	}

	return matches;
}

/**
 * Derive spending private key for this UTXO (BIP-352):
 * d = b_spend + t_k + ℓ (mod q)
 *
 * CRITICAL TAPROOT PARITY RULE (BIP 340):
 * If the resulting curve point P has an odd y-coordinate, the private key d MUST be negated:
 * d <- q - d (mod q)
 * so that d * G matches the even-y representative of P.
 */
export function deriveOneTimePrivateKey(
	b_spend: bigint | Uint8Array,
	tk: bigint,
	P: InstanceType<typeof secp256k1.Point>,
	labelTweak: bigint = 0n,
): Uint8Array {
	const bSpendScalar = toScalarBigInt(b_spend);
	const pRaw = (bSpendScalar + tk + labelTweak) % CURVE_ORDER_Q;

	if (pRaw === 0n) {
		throw new Error("Derived one-time private key is zero (b_spend + t_k + ℓ ≡ 0 mod n)");
	}

	const p = P.hasEvenY() ? pRaw : (CURVE_ORDER_Q - pRaw) % CURVE_ORDER_Q;
	return numberToBytesBE(p, 32);
}

/**
 * Create standard Elements/Liquid Taproot scriptPubKey (witness v1):
 * OP_1 (0x51) <32-byte push (0x20)> <32-byte x-only public key>
 */
export function createTaprootScriptPubKey(xOnlyPubKey: Uint8Array): Uint8Array {
	if (xOnlyPubKey.length !== 32) {
		throw new Error(`Invalid Taproot x-only public key length: ${xOnlyPubKey.length}`);
	}
	return concatBytes(new Uint8Array([0x51, 0x20]), xOnlyPubKey);
}

/**
 * Create standard Elements/Bitcoin P2WPKH scriptPubKey (witness v0):
 * OP_0 (0x00) <20-byte push (0x14)> <20-byte RIPEMD160(SHA256(pubkey))>
 */
function createP2wpkhScriptPubKey(compressedPubKey: Uint8Array): Uint8Array {
	if (compressedPubKey.length !== 33) {
		throw new Error(`Invalid compressed public key length: ${compressedPubKey.length}`);
	}
	const pkh = ripemd160(sha256(compressedPubKey));
	return concatBytes(new Uint8Array([0x00, 0x14]), pkh);
}

/**
 * Returns lowercase hex representation of standard P2WPKH scriptPubKey for compressed public key.
 */
export function toP2wpkhScriptPubKeyHex(compressedPubKey: Uint8Array): string {
	return bytesToHex(createP2wpkhScriptPubKey(compressedPubKey)).toLowerCase();
}

/**
 * Verifies if a derived public key matches a given UTXO scriptPubKey hex string.
 * Supports standard SegWit v0 (P2WPKH: 0014<20_bytes>) and SegWit v1 (P2TR: 5120<32_bytes>).
 */
export function verifyInputPublicKeyScript(
	publicKey: Uint8Array,
	scriptPubKeyHex: string,
): boolean {
	const spk = scriptPubKeyHex.toLowerCase();
	// P2WPKH: OP_0 <20-byte hash160> (44 hex chars)
	if (spk.startsWith("0014") && spk.length === 44) {
		if (publicKey.length !== 33) {
			return false;
		}
		const expected = toP2wpkhScriptPubKeyHex(publicKey);
		return spk === expected;
	}
	// P2TR: OP_1 <32-byte x-only pubkey> (68 hex chars)
	if (spk.startsWith("5120") && spk.length === 68) {
		const xOnly = publicKey.length === 33 ? publicKey.slice(1) : publicKey;
		if (xOnly.length !== 32) {
			return false;
		}
		const expected = "5120" + bytesToHex(xOnly).toLowerCase();
		return spk === expected;
	}
	return false;
}

/**
 * Checks whether a scriptPubKey represents a standard SegWit v1 (P2TR) Taproot script:
 * OP_1 (0x51) 0x20 <32-byte x-only pubkey> (34 bytes / 68 hex chars).
 */
export function isTaprootScriptPubKey(scriptPubKey: string | Uint8Array): boolean {
	const spk =
		typeof scriptPubKey === "string"
			? scriptPubKey.toLowerCase()
			: bytesToHex(scriptPubKey).toLowerCase();
	return spk.startsWith("5120") && spk.length === 68;
}

/**
 * Checks whether a scriptPubKey represents a standard SegWit v0 (P2WPKH) script:
 * OP_0 (0x00) 0x14 <20-byte pubkey hash> (22 bytes / 44 hex chars).
 */
export function isP2wpkhScriptPubKey(scriptPubKey: string | Uint8Array): boolean {
	const spk =
		typeof scriptPubKey === "string"
			? scriptPubKey.toLowerCase()
			: bytesToHex(scriptPubKey).toLowerCase();
	return spk.startsWith("0014") && spk.length === 44;
}

/**
 * Checks whether a scriptPubKey is a witness program of version 2..16:
 * OP_2..OP_16 (0x52..0x60) followed by a single 2..40-byte push, as defined by BIP-141.
 *
 * BIP-352 (inherited by ELIP-352): a transaction spending any such output MUST be skipped by the
 * receiver, and the sender MUST NOT build silent payment outputs over it.
 */
export function isFutureSegwitScriptPubKey(scriptPubKey: string | Uint8Array): boolean {
	const spk = typeof scriptPubKey === "string" ? hexToBytes(scriptPubKey) : scriptPubKey;
	if (spk.length < 4 || spk.length > 42) return false;
	const version = spk[0];
	const pushLength = spk[1];
	return version >= 0x52 && version <= 0x60 && pushLength >= 2 && spk.length === pushLength + 2;
}

/**
 * Normalizes a Taproot (x-only) input private key according to BIP-352 / BIP-340:
 *
 * Taproot outputs commit only to the x-coordinate of the public key.
 * When extracting eligible inputs, the recipient / scanner always lifts the x-only
 * public key to an even-y coordinate (0x02 prefix).
 *
 * To match the recipient, if the sender's private key produces a public point with an
 * odd y-coordinate, the sender MUST negate the private key:
 *   d <- (n - d) mod n
 * so that d · G produces the even-y representative (02 || xOnly).
 *
 * If the point already has an even y-coordinate, the private key is returned unmodified.
 */
export function normalizeTaprootInputKey(privateKey: Uint8Array | bigint): {
	privateKey: Uint8Array;
	publicKey: Uint8Array; // 33 bytes compressed (guaranteed even-y: starts with 0x02)
	wasNegated: boolean;
} {
	const privScalar = toScalarBigInt(privateKey);
	const pt = secp256k1.Point.BASE.multiply(privScalar);

	if (pt.hasEvenY()) {
		return {
			privateKey: numberToBytesBE(privScalar, 32),
			publicKey: pt.toRawBytes(true),
			wasNegated: false,
		};
	}

	const negatedScalar = (CURVE_ORDER_Q - privScalar) % CURVE_ORDER_Q;
	const negatedPt = secp256k1.Point.BASE.multiply(negatedScalar);

	return {
		privateKey: numberToBytesBE(negatedScalar, 32),
		publicKey: negatedPt.toRawBytes(true),
		wasNegated: true,
	};
}

/**
 * Constant-time byte array equality comparison.
 */
export function bytesEqual(a: Uint8Array, b: Uint8Array): boolean {
	if (a.length !== b.length) return false;
	let diff = 0;
	for (let i = 0; i < a.length; i++) {
		diff |= a[i] ^ b[i];
	}
	return diff === 0;
}

/**
 * Aggregates sender input private keys and public keys according to BIP-352 / ELIP-352:
 *
 * 1. For each input:
 *    - If the input spends a Taproot (x-only) output:
 *      Normalize key parity: negate the private key if its public point has an odd y-coordinate,
 *      and use the even-y public key (02 || xOnly) in public key aggregation.
 *    - If the input is not Taproot (e.g. SegWit v0 P2WPKH or legacy P2PKH):
 *      Use the private key and compressed public key as-is without parity negation.
 * 2. Sum the normalized private keys: a = sum(d_i) mod n.
 *    If a == 0, abort with error (per BIP-352).
 * 3. A = sum(P_i) = a · G.
 */
export function aggregateSenderInputs(
	inputs: Array<Uint8Array | bigint | SpInputKeyCandidate>,
	options?: AggregateSenderInputsOptions,
): AggregateSenderInputsResult {
	if (!inputs || inputs.length === 0) {
		throw new Error("ELIP-352 / BIP-352: cannot aggregate inputs: input list is empty");
	}

	let sumScalar = 0n;
	const normalizedInputs: AggregateSenderInputsResult["normalizedInputs"] = [];
	const pubkeysForA: Uint8Array[] = [];

	for (let i = 0; i < inputs.length; i++) {
		const item = inputs[i];
		let rawPriv: Uint8Array | bigint;
		let itemPub: Uint8Array | undefined = options?.inputPubkeys?.[i];
		let itemSpk: string | Uint8Array | undefined = options?.inputScripts?.[i];
		let itemIsTaproot: boolean | undefined = options?.isTaprootInputs?.[i];

		if (item instanceof Uint8Array || typeof item === "bigint") {
			rawPriv = item;
		} else {
			rawPriv = item.privateKey;
			if (itemPub === undefined && item.publicKey) itemPub = item.publicKey;
			if (itemSpk === undefined && item.scriptPubKey) itemSpk = item.scriptPubKey;
			if (itemIsTaproot === undefined && item.isTaproot !== undefined)
				itemIsTaproot = item.isTaproot;
		}

		if (itemSpk && isFutureSegwitScriptPubKey(itemSpk)) {
			throw new Error(
				"ELIP-352 / BIP-352: cannot create silent payment outputs: an input spends a SegWit version > 1 output",
			);
		}

		// Detect if this input is a Taproot input:
		// 1) Explicit boolean flag
		// 2) ScriptPubKey is P2TR (5120...)
		// 3) Explicit 32-byte public key (x-only pubkey is exclusively Taproot)
		const isTaproot = Boolean(
			itemIsTaproot === true ||
			(itemSpk && isTaprootScriptPubKey(itemSpk)) ||
			(itemPub && itemPub.length === 32),
		);

		let finalPrivBytes: Uint8Array;
		let finalPubBytes: Uint8Array;
		let wasNegated = false;

		if (isTaproot) {
			const norm = normalizeTaprootInputKey(rawPriv);
			finalPrivBytes = norm.privateKey;
			finalPubBytes = norm.publicKey; // guaranteed 02 || xOnly
			wasNegated = norm.wasNegated;

			if (itemPub) {
				const expectedXOnly = finalPubBytes.subarray(1);
				if (itemPub.length === 32) {
					if (!bytesEqual(itemPub, expectedXOnly)) {
						throw new Error("ELIP-352 / BIP-352: provided publicKey does not match privateKey · G");
					}
				} else if (itemPub.length === 33) {
					if (!bytesEqual(itemPub.subarray(1), expectedXOnly)) {
						throw new Error("ELIP-352 / BIP-352: provided publicKey does not match privateKey · G");
					}
				} else {
					throw new Error(
						"ELIP-352 / BIP-352: invalid publicKey length for taproot input (expected 32 or 33 bytes)",
					);
				}
			}
		} else {
			const privScalar = toScalarBigInt(rawPriv);
			finalPrivBytes = numberToBytesBE(privScalar, 32);
			const derivedPub = secp256k1.getPublicKey(finalPrivBytes, true);

			if (itemPub) {
				if (itemPub.length !== 33 || !bytesEqual(itemPub, derivedPub)) {
					throw new Error("ELIP-352 / BIP-352: provided publicKey does not match privateKey · G");
				}
			}
			finalPubBytes = derivedPub;
		}

		const privVal = bytesToNumberBE(finalPrivBytes);
		sumScalar = (sumScalar + privVal) % CURVE_ORDER_Q;

		normalizedInputs.push({
			privateKey: finalPrivBytes,
			publicKey: finalPubBytes,
			wasNegated,
			isTaproot,
		});
		pubkeysForA.push(finalPubBytes);
	}

	if (sumScalar === 0n) {
		throw new Error("ELIP-352 / BIP-352: aggregated input private key scalar is 0");
	}

	const aBytes = numberToBytesBE(sumScalar, 32);
	const A = aggregatePublicKeys(pubkeysForA);

	return {
		aScalar: sumScalar,
		aBytes,
		A,
		normalizedInputs,
	};
}
