import {
	aggregateSenderInputs,
	computeInputsHash,
	computeOutputTweak,
	createTaprootScriptPubKey,
	deriveBlindingKey,
	deriveOneTimePublicKey,
	deriveSharedSecretSender,
	encodeConfidentialTaprootAddress,
	findSmallestOutpoint,
	K_MAX,
	parseSilentPaymentAddress,
	type SilentPaymentNetwork,
	zeroizeAggregateSenderInputs,
	zeroizeBuffer,
} from "@humid/sp-core";
import { numberToBytesBE } from "@noble/curves/utils.js";
import { bytesToHex } from "@noble/hashes/utils.js";

import type { LiquidSpOutputData } from "./types";

/** The transaction's input keys and outpoints: `a` and `input_hash` are always derived from them. */
export type CreateSilentPaymentOutputParams = {
	inputPrivkeys: Uint8Array[];
	inputPubkeys: Uint8Array[]; // public keys of `inputPrivkeys`, to detect Taproot parity
	inputScripts: string[]; // scriptPubKeys of the spent outputs, to detect Taproot
	/**
	 * BIP-352 / ELIP-352 output counter k (0, 1, ...): the output's index among outputs to THIS
	 * recipient's scan key, not the transaction vout.
	 */
	k: number;
	/**
	 * The network the transaction is built for: it sets the output's address. The SP address cannot
	 * tell, since `tlqsp` stands for both testnet and regtest.
	 */
	network: SilentPaymentNetwork;
	outpoints: Array<{ txid: string; vout: number }>; // all transaction outpoints, for input_hash
	recipientAddress: string;
};

/**
 * Construct a Liquid Silent Payment output per ELIP-352:
 *
 * 1. Compute shared secret S = input_hash · a · B_scan (BIP-352)
 * 2. Output tweak t_k = hash("BIP0352/SharedSecret", serP(S) || ser32(k))
 * 3. Output public key P_k = B_spend + [t_k]G
 * 4. Blinding key bk_k = int(hash("LiquidSilentPayments/Blind", serP(S) || ser32(k)))
 * 5. BK_k = bk_k · G
 * 6. scriptPubKey = OP_1 <x_only(P_k)>
 *
 * The actual CT blinding (asset/amount commitments, surjection proof, range proof)
 * is performed by the wallet's CT layer (e.g. lwk) using BK_k as the blinding key.
 */
export function createSilentPaymentOutput(
	params: CreateSilentPaymentOutputParams,
): LiquidSpOutputData {
	const addressInfo = parseSilentPaymentAddress(params.recipientAddress);
	const { k, network } = params;

	if ((addressInfo.network === "mainnet") !== (network === "mainnet")) {
		throw new Error(
			`Silent Payment address ${addressInfo.hrp} does not belong to the ${network} network`,
		);
	}

	// ELIP-352 / BIP-352: sender MUST fail if k exceeds K_MAX
	if (k >= K_MAX) {
		throw new Error(`ELIP-352: output index k=${k} exceeds K_MAX (${K_MAX})`);
	}
	if (params.inputPrivkeys.length === 0 || params.outpoints.length === 0) {
		throw new Error(
			"ELIP-352 / BIP-352: createSilentPaymentOutput requires the transaction's input keys and outpoints",
		);
	}

	// BIP-352 input key aggregation with Taproot parity normalization
	const agg = aggregateSenderInputs(params.inputPrivkeys, {
		inputPubkeys: params.inputPubkeys,
		inputScripts: params.inputScripts,
	});

	try {
		const A = agg.A;
		const inputHash = computeInputsHash(findSmallestOutpoint(params.outpoints), A);

		// 1. Shared secret S = input_hash · a · B_scan (BIP-352)
		const S = deriveSharedSecretSender(inputHash, agg.aBytes, addressInfo.scanPublicKey);

		// 2. Output tweak t_k = hash("BIP0352/SharedSecret", serP(S) || ser32(k))
		const tk = computeOutputTweak(S, k);

		// 3. Output public key P_k = B_spend + [t_k]G
		const P = deriveOneTimePublicKey(addressInfo.spendPublicKey, tk);
		const destinationScriptPubKey = createTaprootScriptPubKey(P.xOnly);

		// 4. Blinding key bk_k (ELIP-352 specific)
		const { bk, BK } = deriveBlindingKey(S, k);
		const bkBytes = numberToBytesBE(bk, 32);
		const blindingKeyHex = bytesToHex(bkBytes);
		zeroizeBuffer(bkBytes);

		// 5. Confidential address for the blinded Taproot output
		const confidentialAddress = encodeConfidentialTaprootAddress(P.xOnly, BK, network);

		return {
			blindingKeyHex,
			blindingPublicKey: BK,
			confidentialAddress,
			destinationScriptPubKey,
			ephemeralPublicKey: A,
			k,
			oneTimePoint: P.compressed,
			taprootPublicKey: P.xOnly,
			tweakHex: bytesToHex(numberToBytesBE(tk, 32)),
		};
	} finally {
		// Zeroize the aggregated private key scalar `a` and every normalized input key.
		zeroizeAggregateSenderInputs(agg);
	}
}
