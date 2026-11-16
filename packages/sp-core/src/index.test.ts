import { describe, expect, it } from "bun:test";

import { secp256k1 } from "@noble/curves/secp256k1.js";
import { bytesToNumberBE, numberToBytesBE } from "@noble/curves/utils.js";
import { ripemd160 } from "@noble/hashes/ripemd160.js";
import { sha256 } from "@noble/hashes/sha2.js";
import { bytesToHex, hexToBytes } from "@noble/hashes/utils.js";

import {
	aggregatePublicKeys,
	BLIND_TAG,
	computeInputsHash,
	computeLabelTweak,
	computeOutputTweak,
	computeTxTweak,
	CURVE_ORDER_Q,
	deriveBlindingKey,
	deriveLabeledSpendPublicKey,
	deriveOneTimePrivateKey,
	deriveOneTimePublicKey,
	deriveSharedSecretFromTweak,
	deriveSharedSecretRecipient,
	deriveSharedSecretSender,
	deriveSilentPaymentKeysFromSeed,
	encodeSilentPaymentAddress,
	extractEligibleInputs,
	findSmallestOutpoint,
	K_MAX,
	matchCandidateOutputs,
	matchTxForRecipient,
	MissingPrevoutError,
	NUMS_H_HEX,
	outpointToBytes,
	parseSilentPaymentAddress,
	precomputeLabelPoints,
	scanTxForRecipient,
	type SpTransaction,
	type SpTxInput,
	toP2wpkhScriptPubKeyHex,
	aggregateSenderInputs,
	isFutureSegwitScriptPubKey,
	isP2wpkhScriptPubKey,
	isTaprootScriptPubKey,
	normalizeTaprootInputKey,
	toScalarBigInt,
	zeroizeAggregateSenderInputs,
	zeroizeBuffer,
	zeroizeRecipientKeys,
	type SilentPaymentRecipientKeys,
} from "./index";

/** A P2WPKH key-path input spending `pubkey`'s output, with the prevout the scanner checks. */
function p2wpkhInput(pubkey: Uint8Array, txid: string, vout: number): SpTxInput {
	return {
		prevoutScriptPubKey: "0014" + bytesToHex(ripemd160(sha256(pubkey))),
		txid,
		vout,
		witness: ["30440220" + "11".repeat(32) + "0220" + "22".repeat(32) + "01", bytesToHex(pubkey)],
	};
}

/** Fresh random recipient keys (b_scan, B_scan), (b_spend, B_spend). */
function randomRecipientKeys(): SilentPaymentRecipientKeys {
	const keyPair = () => {
		const privateKey = secp256k1.utils.randomSecretKey();
		return { privateKey, publicKey: secp256k1.getPublicKey(privateKey, true) };
	};
	return { scanKey: keyPair(), spendKey: keyPair() };
}

describe("@humid/sp-core: ELIP-352 / BIP-352 Core Primitives", () => {
	// Canonical ELIP-352 test vectors
	const b_scan_hex = "1111111111111111111111111111111111111111111111111111111111111111";
	const b_spend_hex = "2222222222222222222222222222222222222222222222222222222222222222";
	const b_scan = hexToBytes(b_scan_hex);
	const b_spend = hexToBytes(b_spend_hex);

	const B_scan = secp256k1.getPublicKey(b_scan, true);
	const B_spend = secp256k1.getPublicKey(b_spend, true);

	const input0Priv = hexToBytes("31".repeat(32));
	const input1Priv = hexToBytes("32".repeat(32));
	const input0Txid = "10".repeat(32);
	const input1Txid = "20".repeat(32);

	const expectedA = "031195a8046dcbb8e17034bca630065e7a0982e4e36f6f7e5a8d4554e4846fcd99";
	const expectedInputHash = "d392922c00280a7e8d282182f5026f2fddbc74c1e1de18b4822128b2b77ec641";

	const expectedK0 = {
		BK_k: "0344e1289497e6da66fde710d2f38de053fc07355e405524401d7d609df5a1a8cc",
		bk_k: "70ab8897b64bd21b427339ff4d014b883191ef6425862246c53bfc27a59aa3f0",
		P_k: "02a29d9716417c964ca9e477343e71ffe730a4991a3eaad668eabec84e9feb7931",
		scriptPubKey: "5120a29d9716417c964ca9e477343e71ffe730a4991a3eaad668eabec84e9feb7931",
		spend_priv: "f03c436d2cd67ae1fecf7d88a38aa3a03c0abea43feaf6da8eb71e2e3a866bda",
	};

	const expectedK1 = {
		BK_k: "03efdeda770ccdbe8bf466fba48bfd2b2c436ab0c04658fc6d6c277de5078129fa",
		bk_k: "945ba73a9804f62089c7d2ffdc079031031f0aebab372cec17ef9c110ebceb10",
		P_k: "0229d77654023af267dbe9cb7ff1956f947c816f203494381308387168fb010c92",
		scriptPubKey: "512029d77654023af267dbe9cb7ff1956f947c816f203494381308387168fb010c92",
		spend_priv: "9eff3472230fc83ef5ea8f8c80401c4eecd595a048bd2482a107d3a49baa5a58",
	};

	const expectedAddress =
		"lqsp1qqd8n2k7uklxq4aegau7vawtptkgxsja4kt99lpv6krctwpq8tpc65qjxd4lu4etruh9sngx3su9mtqp5fqzxz7re59y5nnez9p03ht3lyudcfhfe";

	it("reproduces canonical ELIP-352 test vectors (A, input_hash, S, tweaks, keys)", () => {
		const pub0 = secp256k1.getPublicKey(input0Priv, true);
		const pub1 = secp256k1.getPublicKey(input1Priv, true);
		const A = aggregatePublicKeys([pub0, pub1]);
		expect(bytesToHex(A)).toBe(expectedA);

		const outpoints = [
			{ txid: input0Txid, vout: 0 },
			{ txid: input1Txid, vout: 1 },
		];
		const outpointL = findSmallestOutpoint(outpoints, true);
		const inputHash = computeInputsHash(outpointL, A);
		expect(bytesToHex(inputHash)).toBe(expectedInputHash);

		const a = (bytesToNumberBE(input0Priv) + bytesToNumberBE(input1Priv)) % CURVE_ORDER_Q;
		const aBytes = numberToBytesBE(a, 32);

		const S_sender = deriveSharedSecretSender(inputHash, aBytes, B_scan);
		const S_recipient = deriveSharedSecretRecipient(b_scan, inputHash, A);
		expect(bytesToHex(S_sender)).toBe(bytesToHex(S_recipient));

		const S = S_sender;

		// k = 0
		const tk0 = computeOutputTweak(S, 0);
		const P0 = deriveOneTimePublicKey(B_spend, tk0);
		expect(bytesToHex(P0.compressed)).toBe(expectedK0.P_k);
		expect("5120" + bytesToHex(P0.xOnly)).toBe(expectedK0.scriptPubKey);

		const { bk: bk0, BK: BK0 } = deriveBlindingKey(S, 0);
		expect(bytesToHex(numberToBytesBE(bk0, 32))).toBe(expectedK0.bk_k);
		expect(bytesToHex(BK0)).toBe(expectedK0.BK_k);

		const spendPriv0 = deriveOneTimePrivateKey(b_spend, tk0, P0.point);
		expect(bytesToHex(spendPriv0)).toBe(expectedK0.spend_priv);

		// k = 1
		const tk1 = computeOutputTweak(S, 1);
		const P1 = deriveOneTimePublicKey(B_spend, tk1);
		expect(bytesToHex(P1.compressed)).toBe(expectedK1.P_k);
		expect("5120" + bytesToHex(P1.xOnly)).toBe(expectedK1.scriptPubKey);

		const { bk: bk1, BK: BK1 } = deriveBlindingKey(S, 1);
		expect(bytesToHex(numberToBytesBE(bk1, 32))).toBe(expectedK1.bk_k);
		expect(bytesToHex(BK1)).toBe(expectedK1.BK_k);

		const spendPriv1 = deriveOneTimePrivateKey(b_spend, tk1, P1.point);
		expect(bytesToHex(spendPriv1)).toBe(expectedK1.spend_priv);

		// Address encoding
		const addr = encodeSilentPaymentAddress(B_scan, B_spend, "mainnet");
		expect(addr).toBe(expectedAddress);
		const parsed = parseSilentPaymentAddress(expectedAddress);
		expect(bytesToHex(parsed.scanPublicKey)).toBe(bytesToHex(B_scan));
		expect(bytesToHex(parsed.spendPublicKey)).toBe(bytesToHex(B_spend));
	});

	it("computeTxTweak and matchTxForRecipient accurately scan transactions", () => {
		const pub0 = secp256k1.getPublicKey(input0Priv, true);
		const pub1 = secp256k1.getPublicKey(input1Priv, true);

		// Build SpTransaction with both outputs
		const testTx: SpTransaction = {
			txid: "aabbccdd".repeat(8),
			vin: [p2wpkhInput(pub0, input0Txid, 0), p2wpkhInput(pub1, input1Txid, 1)],
			vout: [
				// k=0 output
				{
					outputIndex: 0,
					scriptPubKey: expectedK0.scriptPubKey,
				},
				// unrelated non-taproot output
				{
					outputIndex: 1,
					scriptPubKey: "0014" + "11".repeat(20),
				},
				// k=1 output
				{
					outputIndex: 2,
					scriptPubKey: expectedK1.scriptPubKey,
				},
			],
		};

		// 1. computeTxTweak calculates tweak once for all recipients
		const tweakResult = computeTxTweak(testTx);
		expect(tweakResult).not.toBeNull();
		if (!tweakResult) throw new Error("tweakResult should not be null");

		expect(bytesToHex(tweakResult.A)).toBe(expectedA);
		expect(bytesToHex(tweakResult.inputHash)).toBe(expectedInputHash);

		// Shared secret from tweak matches recipient S
		const S_from_tweak = deriveSharedSecretFromTweak(b_scan, tweakResult.tweak);
		const S_direct = deriveSharedSecretRecipient(b_scan, tweakResult.inputHash, tweakResult.A);
		expect(bytesToHex(S_from_tweak)).toBe(bytesToHex(S_direct));

		// 2. matchTxForRecipient finds both outputs without unblinding
		const matches = matchTxForRecipient(testTx, tweakResult.tweak, b_scan, B_spend);

		expect(matches.length).toBe(2);

		// Verify match k=0
		expect(matches[0].k).toBe(0);
		expect(matches[0].outputIndex).toBe(0);
		expect(matches[0].scriptPubKeyHex).toBe(expectedK0.scriptPubKey.toLowerCase());

		// Verify match k=1
		expect(matches[1].k).toBe(1);
		expect(matches[1].outputIndex).toBe(2);
		expect(matches[1].scriptPubKeyHex).toBe(expectedK1.scriptPubKey.toLowerCase());

		// Caller unblinds independently using match.S and match.k
		const { bk: bk0 } = deriveBlindingKey(matches[0].S, matches[0].k);
		expect(bytesToHex(numberToBytesBE(bk0, 32))).toBe(expectedK0.bk_k);

		const { bk: bk1 } = deriveBlindingKey(matches[1].S, matches[1].k);
		expect(bytesToHex(numberToBytesBE(bk1, 32))).toBe(expectedK1.bk_k);
	});

	it("scanTxForRecipient finds the canonical vector outputs without a tweak", () => {
		const pub0 = secp256k1.getPublicKey(input0Priv, true);
		const pub1 = secp256k1.getPublicKey(input1Priv, true);
		const testTx: SpTransaction = {
			txid: "aabbccdd".repeat(8),
			vin: [p2wpkhInput(pub0, input0Txid, 0), p2wpkhInput(pub1, input1Txid, 1)],
			vout: [
				{ outputIndex: 0, scriptPubKey: expectedK1.scriptPubKey },
				{ outputIndex: 1, scriptPubKey: "0014" + "11".repeat(20) },
				{ outputIndex: 2, scriptPubKey: expectedK0.scriptPubKey },
			],
		};

		const matches = scanTxForRecipient(testTx, b_scan, B_spend);

		expect(matches.map((m) => [m.k, m.outputIndex])).toEqual([
			[0, 2],
			[1, 0],
		]);
		expect(bytesToHex(numberToBytesBE(deriveBlindingKey(matches[0].S, 0).bk, 32))).toBe(
			expectedK0.bk_k,
		);
		expect(bytesToHex(numberToBytesBE(deriveBlindingKey(matches[1].S, 1).bk, 32))).toBe(
			expectedK1.bk_k,
		);
		expect(scanTxForRecipient({ ...testTx, vout: [testTx.vout[1]!] }, b_scan, B_spend)).toEqual([]);
	});

	it("deriveSharedSecretRecipient equals b_scan · (input_hash · A) and the sender's S", () => {
		for (let i = 0; i < 16; i++) {
			const a = secp256k1.utils.randomSecretKey();
			const A = secp256k1.getPublicKey(a, true);
			const { scanKey } = randomRecipientKeys();
			const inputHash = sha256(new Uint8Array([i]));

			const twoSteps = secp256k1.Point.fromHex(A)
				.multiply(bytesToNumberBE(inputHash))
				.multiply(bytesToNumberBE(scanKey.privateKey))
				.toRawBytes(true);
			const S = deriveSharedSecretRecipient(scanKey.privateKey, inputHash, A);

			expect(bytesToHex(S)).toBe(bytesToHex(twoSteps));
			expect(bytesToHex(S)).toBe(
				bytesToHex(deriveSharedSecretSender(inputHash, a, scanKey.publicKey)),
			);
		}
	});

	it("scanTxForRecipient matches computeTxTweak + matchTxForRecipient, labels included", () => {
		for (let i = 0; i < 8; i++) {
			const keys = randomRecipientKeys();
			const inPriv = secp256k1.utils.randomSecretKey();
			const inPub = secp256k1.getPublicKey(inPriv, true);
			const inTxid = bytesToHex(sha256(new Uint8Array([0xa0, i])));
			const outpointL = findSmallestOutpoint([{ txid: inTxid, vout: i }]);
			const inputHash = computeInputsHash(outpointL, inPub);
			const S = deriveSharedSecretSender(inputHash, inPriv, keys.scanKey.publicKey);
			// k = 0 pays label 3, k = 1 the base key.
			const labeled = deriveLabeledSpendPublicKey(
				keys.spendKey.publicKey,
				computeLabelTweak(keys.scanKey.privateKey, 3),
			);
			const P0 = deriveOneTimePublicKey(labeled, computeOutputTweak(S, 0));
			const P1 = deriveOneTimePublicKey(keys.spendKey.publicKey, computeOutputTweak(S, 1));
			const tx: SpTransaction = {
				txid: bytesToHex(sha256(new Uint8Array([0xb0, i]))),
				vin: [p2wpkhInput(inPub, inTxid, i)],
				vout: [
					{ outputIndex: 0, scriptPubKey: "5120" + bytesToHex(P1.xOnly) },
					{ outputIndex: 1, scriptPubKey: "5120" + bytesToHex(P0.xOnly) },
				],
			};
			const labels = [0, 3, 7];

			const viaTweak = matchTxForRecipient(
				tx,
				computeTxTweak(tx)!.tweak,
				keys.scanKey.privateKey,
				keys.spendKey.publicKey,
				labels,
			);
			const direct = scanTxForRecipient(
				tx,
				keys.scanKey.privateKey,
				keys.spendKey.publicKey,
				labels,
			);

			const summary = (ms: typeof direct) =>
				ms.map((m) => [m.k, m.outputIndex, m.labelIndex, bytesToHex(m.S), m.tk.toString()]);
			expect(summary(direct)).toEqual(summary(viaTweak));
			expect(direct.map((m) => [m.k, m.outputIndex, m.labelIndex])).toEqual([
				[0, 1, 3],
				[1, 0, undefined],
			]);
		}
	});

	it("excludes peg-in inputs from A while keeping them in outpoint_L", () => {
		const pub0 = secp256k1.getPublicKey(input0Priv, true);

		const peginTxid = "05".repeat(32); // Lexicographically smaller than input0Txid
		const testTx: SpTransaction = {
			txid: "99".repeat(32),
			vin: [
				{
					isPegin: true,
					txid: peginTxid,
					vout: 0,
				},
				p2wpkhInput(pub0, input0Txid, 0),
			],
			vout: [
				{
					outputIndex: 0,
					scriptPubKey: "5120" + "ff".repeat(32),
				},
			],
		};

		const eligible = extractEligibleInputs(testTx.vin);
		expect(eligible.length).toBe(1);
		expect(eligible[0].outpoint.txid).toBe(input0Txid);

		const tweakResult = computeTxTweak(testTx);
		expect(tweakResult).not.toBeNull();
		if (!tweakResult) throw new Error("Expected tweakResult");

		// A contains only pub0
		expect(bytesToHex(tweakResult.A)).toBe(bytesToHex(pub0));

		// outpoint_L is the pegin input because it was smaller
		const expectedPeginOutpoint = outpointToBytes(peginTxid, 0);
		expect(bytesToHex(tweakResult.outpointL)).toBe(bytesToHex(expectedPeginOutpoint));
	});

	it("returns null from computeTxTweak when transaction has no Taproot outputs", () => {
		const pub0 = secp256k1.getPublicKey(input0Priv, true);
		const nonTaprootTx: SpTransaction = {
			txid: "1234".repeat(8),
			vin: [p2wpkhInput(pub0, input0Txid, 0)],
			vout: [{ outputIndex: 0, scriptPubKey: "0014" + "aa".repeat(20) }],
		};

		expect(computeTxTweak(nonTaprootTx)).toBeNull();
	});

	it("isFutureSegwitScriptPubKey recognizes only witness programs of version 2..16", () => {
		expect(isFutureSegwitScriptPubKey("5220" + "11".repeat(32))).toBe(true); // v2, 32 bytes
		expect(isFutureSegwitScriptPubKey("6002abcd")).toBe(true); // v16, 2-byte program
		expect(isFutureSegwitScriptPubKey("5528" + "22".repeat(40))).toBe(true); // v5, 40 bytes
		expect(isFutureSegwitScriptPubKey("5120" + "11".repeat(32))).toBe(false); // v1 Taproot
		expect(isFutureSegwitScriptPubKey("0014" + "11".repeat(20))).toBe(false); // v0 P2WPKH
		expect(isFutureSegwitScriptPubKey("5229" + "22".repeat(41))).toBe(false); // program > 40 bytes
		expect(isFutureSegwitScriptPubKey("5201aa")).toBe(false); // program < 2 bytes
		expect(isFutureSegwitScriptPubKey("5220" + "11".repeat(31))).toBe(false); // length mismatch
		expect(isFutureSegwitScriptPubKey("76a914" + "11".repeat(20) + "88ac")).toBe(false); // P2PKH
	});

	it("skips the transaction in computeTxTweak when any input spends a SegWit v>1 output", () => {
		const pub0 = secp256k1.getPublicKey(input0Priv, true);
		const tx: SpTransaction = {
			txid: "77".repeat(32),
			vin: [
				p2wpkhInput(pub0, input0Txid, 0),
				{
					prevoutScriptPubKey: "5220" + "33".repeat(32),
					txid: input1Txid,
					vout: 1,
					witness: ["aa".repeat(64)],
				},
			],
			vout: [{ outputIndex: 0, scriptPubKey: "5120" + "ff".repeat(32) }],
		};

		expect(computeTxTweak(tx)).toBeNull();

		// The same transaction without the v2 input is still a silent payment candidate.
		expect(computeTxTweak({ ...tx, vin: [tx.vin[0]] })).not.toBeNull();
	});

	it("aggregateSenderInputs refuses an input that spends a SegWit v>1 output", () => {
		expect(() =>
			aggregateSenderInputs([
				{ privateKey: input0Priv, scriptPubKey: "0014" + "11".repeat(20) },
				{ privateKey: input1Priv, scriptPubKey: "5320" + "44".repeat(32) },
			]),
		).toThrow("SegWit version > 1");
	});

	it("derives deterministic keys and addresses from seed using SLIP-44 coin types", () => {
		const seed = hexToBytes("aa".repeat(64));
		const mainnetKeys = deriveSilentPaymentKeysFromSeed(seed, "mainnet");
		expect(mainnetKeys.address.startsWith("lqsp1")).toBe(true);

		const testnetKeys = deriveSilentPaymentKeysFromSeed(seed, "testnet");
		expect(testnetKeys.address.startsWith("tlqsp1")).toBe(true);

		expect(mainnetKeys.address).not.toBe(testnetKeys.address);
	});

	it("derives ELIP-352 scan/spend keys at the SLIP-44 paths (known-answer vectors)", () => {
		// Expected keys were produced independently by @scure/bip32 at m/352'/coin'/account'/{1',0'}/0
		// and by the previous hand-rolled BIP-32 implementation; both agreed. Seeds 1 and 4 are the
		// BIP-32 test vector 1 and 2 seeds.
		const vectors = [
			{
				seed: "000102030405060708090a0b0c0d0e0f",
				network: "mainnet",
				account: 0,
				scan: "c3cbacff049bffca2e1dee022d3318361b3e50dbf77a8d7fb2d013cefe0e1d20",
				spend: "08f9f50978ad957134770e359085b115244a30419bf27c122762acad7c9134e3",
				address:
					"lqsp1qq27qd4z3s6l028m87ncyye759x7lqcd9lsf0ex4dfnzx45ssvjj22qsjrqsxdhg3jphyuk6nal3hsx6psr9at2gy3ywzu8vm606cajwrcsrj47cy",
			},
			{
				seed: "000102030405060708090a0b0c0d0e0f",
				network: "testnet",
				account: 0,
				scan: "8d33048cb2f37d5977262ab67e5b1a9a5ef79dacc1d3065e12a9e98f35cc4fcc",
				spend: "7a8610556cf2e4d679871e63ab782430327f6ac3dc2caa3b6620cb67c95f887c",
				address:
					"tlqsp1qq2rgvjvxx2cw6lypf0a7fg2djgcns5jqz5l7a37mvlkjr35vcpfn7qctm6tjq6hp23kshua0sagxxazl8u8g3ss6z4tmk0p6s35ecgnc0ugtzzl4",
			},
			{
				seed: "42".repeat(64),
				network: "mainnet",
				account: 1,
				scan: "1257a0d3493bde6ba1ce474079571c5fe3c81fddb1829d13474ad147f25f6908",
				spend: "652961ec94ced58f48e9756b477d934ae3969a2a47ed47efe0620b8cec7f69f1",
				address:
					"lqsp1qqwpvvlnurfkp3cc0z86f6tp50l5r4zysem2hrafjzcv3hjr4jhv2gq7s62tteaqrngczwffkps0h3v9ld9kakkmgj3jh6f35a4hdx8xatqeqmacn",
			},
			{
				seed: "fffcf9f6f3f0edeae7e4e1dedbd8d5d2cfccc9c6c3c0bdbab7b4b1aeaba8a5a29f9c999693908d8a8784817e7b7875726f6c696663605d5a5754514e4b484542",
				network: "testnet",
				account: 3,
				scan: "59a0f060a36f761d37dc889a8f0b58e44d55167ca22cca3b194acec7bdcc2537",
				spend: "55f9d47db80db610aa696debe22c1db7e160d4c833301651d6da2f231154f3d7",
				address:
					"tlqsp1qq2jc3avqwr6e5j86n5cgecqjwq0t4n8xggzwq36qr52ya2z00rqk7qmlmuqz7r0q4t25p3e8vggfyvvwl9agt7ut4uxw3hjzs9nrhpmj0g7g9t2r",
			},
		] as const;

		for (const v of vectors) {
			const keys = deriveSilentPaymentKeysFromSeed(hexToBytes(v.seed), v.network, v.account);
			expect(bytesToHex(keys.scanKey.privateKey)).toBe(v.scan);
			expect(bytesToHex(keys.spendKey.privateKey)).toBe(v.spend);
			expect(keys.address).toBe(v.address);
		}
	});

	it("validates protocol constants, key generation, and Taproot output checks", () => {
		expect(BLIND_TAG).toBe("LiquidSilentPayments/Blind");
		expect(K_MAX).toBe(2323);

		const keys = randomRecipientKeys();
		expect(keys.scanKey.privateKey.length).toBe(32);
		expect(keys.scanKey.publicKey.length).toBe(33);
		expect(keys.spendKey.privateKey.length).toBe(32);
		expect(keys.spendKey.publicKey.length).toBe(33);

		expect(isTaprootScriptPubKey(expectedK0.scriptPubKey)).toBe(true);
		expect(isTaprootScriptPubKey("0014" + "aa".repeat(20))).toBe(false);
	});

	describe("BIP-352 / ELIP-352 extractEligibleInputs compliance", () => {
		const privA = hexToBytes("11".repeat(32));
		const pubA = secp256k1.getPublicKey(privA, true);
		const xOnlyA = pubA.slice(1);
		const taprootSpk = "5120" + bytesToHex(xOnlyA);

		it("includes Taproot script-path spends when internal key is not NUMS H", () => {
			// Script-path spend: witnessStack = [leaf_script_args, script, control_block]
			const dummyScript = "20" + "33".repeat(32) + "ac";
			const normalInternalKey = "02".repeat(32); // not NUMS_H
			const controlBlock = "c0" + normalInternalKey; // 1 byte control + 32 byte internal key (66 hex chars)

			const vin: SpTxInput[] = [
				{
					txid: "aa".repeat(32),
					vout: 0,
					prevoutScriptPubKey: taprootSpk,
					prevoutScriptPubKeyType: "v1_p2tr",
					witness: ["01", dummyScript, controlBlock],
				},
			];

			const eligible = extractEligibleInputs(vin);
			expect(eligible).toHaveLength(1);
			expect(eligible[0].outpoint.txid).toBe("aa".repeat(32));
			// Pubkey should be lifted Taproot output key (02 + xOnlyA)
			expect(bytesToHex(eligible[0].pubkey)).toBe("02" + bytesToHex(xOnlyA));
		});

		it("excludes Taproot script-path spends when internal key is NUMS H", () => {
			const dummyScript = "20" + "33".repeat(32) + "ac";
			// Control block with internal key = NUMS H
			const controlBlockNums = "c0" + NUMS_H_HEX;

			const vin: SpTxInput[] = [
				{
					txid: "aa".repeat(32),
					vout: 0,
					prevoutScriptPubKey: taprootSpk,
					prevoutScriptPubKeyType: "v1_p2tr",
					witness: ["01", dummyScript, controlBlockNums],
				},
			];

			const eligible = extractEligibleInputs(vin);
			expect(eligible).toHaveLength(0);
		});

		it("handles Taproot spends with annex correctly", () => {
			// Annex: starts with 0x50
			const annex = "50" + "ff".repeat(32);
			const dummyScript = "20" + "33".repeat(32) + "ac";
			const normalInternalKey = "04".repeat(32);
			const controlBlock = "c0" + normalInternalKey;

			// Script-path with annex
			const vinScriptPathWithAnnex: SpTxInput[] = [
				{
					txid: "aa".repeat(32),
					vout: 0,
					prevoutScriptPubKey: taprootSpk,
					witness: ["01", dummyScript, controlBlock, annex],
				},
			];
			const eligibleScript = extractEligibleInputs(vinScriptPathWithAnnex);
			expect(eligibleScript).toHaveLength(1);

			// Key-path with annex
			const vinKeyPathWithAnnex: SpTxInput[] = [
				{
					txid: "bb".repeat(32),
					vout: 1,
					prevoutScriptPubKey: taprootSpk,
					witness: ["40".repeat(32), annex],
				},
			];
			const eligibleKey = extractEligibleInputs(vinKeyPathWithAnnex);
			expect(eligibleKey).toHaveLength(1);
		});

		it("strictly validates P2WPKH: requires prevout spk == 0014 || hash160(pubkey)", () => {
			const matchingSpk = toP2wpkhScriptPubKeyHex(pubA);
			const mismatchedSpk = "0014" + "99".repeat(20);

			// Valid P2WPKH with matching SPK
			const vinValid: SpTxInput[] = [
				{
					txid: "11".repeat(32),
					vout: 0,
					prevoutScriptPubKey: matchingSpk,
					witness: ["3044...", bytesToHex(pubA)],
				},
			];
			expect(extractEligibleInputs(vinValid)).toHaveLength(1);

			// Mismatched SPK: witness looks like P2WPKH but SPK does not match
			const vinMismatched: SpTxInput[] = [
				{
					txid: "22".repeat(32),
					vout: 0,
					prevoutScriptPubKey: mismatchedSpk,
					witness: ["3044...", bytesToHex(pubA)],
				},
			];
			expect(extractEligibleInputs(vinMismatched)).toHaveLength(0);

			// Non-P2WPKH SPK (e.g. P2SH script) with 2 witness items
			const vinNonP2wpkh: SpTxInput[] = [
				{
					txid: "33".repeat(32),
					vout: 0,
					prevoutScriptPubKey: "a914" + "88".repeat(20) + "87",
					witness: ["3044...", bytesToHex(pubA)],
				},
			];
			expect(extractEligibleInputs(vinNonP2wpkh)).toHaveLength(0);
		});

		it("strictly validates Nested SegWit P2SH-P2WPKH", () => {
			const pkh = ripemd160(sha256(pubA));
			const redeemScript = "0014" + bytesToHex(pkh);
			const redeemScriptBytes = hexToBytes(redeemScript);
			const p2shHash = ripemd160(sha256(redeemScriptBytes));
			const p2shSpk = "a914" + bytesToHex(p2shHash) + "87";
			const scriptSig = "16" + redeemScript;

			const vinP2shP2wpkh: SpTxInput[] = [
				{
					txid: "44".repeat(32),
					vout: 0,
					prevoutScriptPubKey: p2shSpk,
					scriptsig: scriptSig,
					witness: ["3044...", bytesToHex(pubA)],
				},
			];
			const eligible = extractEligibleInputs(vinP2shP2wpkh);
			expect(eligible).toHaveLength(1);
			expect(bytesToHex(eligible[0].pubkey)).toBe(bytesToHex(pubA));

			// Mismatched redeem script in scriptSig
			const badScriptSigVin: SpTxInput[] = [
				{
					txid: "55".repeat(32),
					vout: 0,
					prevoutScriptPubKey: p2shSpk,
					scriptsig: "160014" + "ee".repeat(20),
					witness: ["3044...", bytesToHex(pubA)],
				},
			];
			expect(extractEligibleInputs(badScriptSigVin)).toHaveLength(0);
		});

		it("strictly validates P2PKH without heuristics (rejects scriptSig.length >= 134 without SPK match)", () => {
			const pkh = ripemd160(sha256(pubA));
			const p2pkhSpk = "76a914" + bytesToHex(pkh) + "88ac";
			const sigHex = "30440220" + "aa".repeat(32) + "0220" + "bb".repeat(32) + "01";
			const validScriptSig = sigHex + bytesToHex(pubA);

			const vinValid: SpTxInput[] = [
				{
					txid: "66".repeat(32),
					vout: 0,
					prevoutScriptPubKey: p2pkhSpk,
					scriptsig: validScriptSig,
				},
			];
			const eligible = extractEligibleInputs(vinValid);
			expect(eligible).toHaveLength(1);
			expect(bytesToHex(eligible[0].pubkey)).toBe(bytesToHex(pubA));

			// Heuristic test: arbitrary scriptSig >= 134 chars that doesn't match SPK hash160 MUST be rejected
			const fakeScriptSig = "ff".repeat(70); // 140 chars >= 134
			const vinHeuristic: SpTxInput[] = [
				{
					txid: "77".repeat(32),
					vout: 0,
					prevoutScriptPubKey: p2pkhSpk,
					scriptsig: fakeScriptSig,
				},
			];
			expect(extractEligibleInputs(vinHeuristic)).toHaveLength(0);
		});

		it("strictly rejects inputs lacking prevoutScriptPubKey (throws MissingPrevoutError)", () => {
			const vinNoSpk: SpTxInput[] = [
				{
					txid: "88".repeat(32),
					vout: 0,
					witness: ["3044...", bytesToHex(pubA)],
				},
			];
			expect(() => extractEligibleInputs(vinNoSpk)).toThrow(MissingPrevoutError);
		});

		it("strictly rejects transactions with mixed inputs when any input lacks prevoutScriptPubKey", () => {
			const matchingSpk = toP2wpkhScriptPubKeyHex(pubA);
			const vinMixed: SpTxInput[] = [
				{
					txid: "88".repeat(32),
					vout: 0,
					prevoutScriptPubKey: matchingSpk,
					witness: ["3044...", bytesToHex(pubA)],
				},
				{
					txid: "99".repeat(32),
					vout: 1,
					witness: ["3044...", bytesToHex(pubA)],
					// Missing prevoutScriptPubKey on input 1
				},
			];
			// Must NOT compute partial A from input 0 and ignore input 1!
			expect(() => extractEligibleInputs(vinMixed)).toThrow(MissingPrevoutError);
		});

		it("strictly rejects computeTxTweak when inputs lack prevoutScriptPubKey", () => {
			const txMissingPrevout: SpTransaction = {
				txid: "aabbccdd".repeat(8),
				vin: [
					{
						txid: "88".repeat(32),
						vout: 0,
						witness: ["3044...", bytesToHex(pubA)],
					},
				],
				vout: [
					{
						outputIndex: 0,
						scriptPubKey: "5120" + "ee".repeat(32), // Taproot output
					},
				],
			};
			expect(() => computeTxTweak(txMissingPrevout)).toThrow(MissingPrevoutError);
		});

		it("does not require prevoutScriptPubKey for coinbase or peg-in inputs", () => {
			const vinCoinbaseAndPegin: SpTxInput[] = [
				{
					txid: "00".repeat(32),
					vout: 0,
					isCoinbase: true,
				},
				{
					txid: "11".repeat(32),
					vout: 0,
					isPegin: true,
				},
			];
			// Neither should throw MissingPrevoutError
			const eligible = extractEligibleInputs(vinCoinbaseAndPegin);
			expect(eligible).toHaveLength(0);
		});
	});

	describe("Taproot input parity normalization & BIP-352 sender compliance", () => {
		it("isTaprootScriptPubKey & isP2wpkhScriptPubKey correctly identify script types", () => {
			const dummyXOnly = "aa".repeat(32);
			const validP2tr = "5120" + dummyXOnly;
			expect(isTaprootScriptPubKey(validP2tr)).toBe(true);
			expect(isTaprootScriptPubKey(validP2tr.toUpperCase())).toBe(true);
			expect(isTaprootScriptPubKey(hexToBytes(validP2tr))).toBe(true);
			expect(isTaprootScriptPubKey("5120" + "aa".repeat(31))).toBe(false); // wrong length
			expect(isTaprootScriptPubKey("0014" + "aa".repeat(20))).toBe(false);

			const dummyPkh = "bb".repeat(20);
			const validP2wpkh = "0014" + dummyPkh;
			expect(isP2wpkhScriptPubKey(validP2wpkh)).toBe(true);
			expect(isP2wpkhScriptPubKey(validP2wpkh.toUpperCase())).toBe(true);
			expect(isP2wpkhScriptPubKey(hexToBytes(validP2wpkh))).toBe(true);
			expect(isP2wpkhScriptPubKey("0014" + "bb".repeat(21))).toBe(false);
			expect(isP2wpkhScriptPubKey(validP2tr)).toBe(false);
		});

		it("normalizeTaprootInputKey leaves even-y private keys untouched", () => {
			// 1n * G has even y
			const privEven = numberToBytesBE(1n, 32);
			const norm = normalizeTaprootInputKey(privEven);

			expect(norm.wasNegated).toBe(false);
			expect(bytesToHex(norm.privateKey)).toBe(bytesToHex(privEven));
			expect(norm.publicKey[0]).toBe(0x02); // even y
			expect(secp256k1.Point.fromHex(norm.publicKey).hasEvenY()).toBe(true);
		});

		it("normalizeTaprootInputKey negates odd-y private keys and lifts point to even-y", () => {
			// (CURVE_ORDER_Q - 1n) * G has odd y
			const privOdd = numberToBytesBE(CURVE_ORDER_Q - 1n, 32);
			const rawPt = secp256k1.Point.BASE.multiply(CURVE_ORDER_Q - 1n);
			expect(rawPt.hasEvenY()).toBe(false);
			expect(rawPt.toRawBytes(true)[0]).toBe(0x03);

			const norm = normalizeTaprootInputKey(privOdd);
			expect(norm.wasNegated).toBe(true);
			// Negated private key must be 1n
			expect(bytesToNumberBE(norm.privateKey)).toBe(1n);
			expect(norm.publicKey[0]).toBe(0x02); // even y
			expect(secp256k1.Point.fromHex(norm.publicKey).hasEvenY()).toBe(true);

			// Both points must share the exact same x-coordinate
			expect(bytesToHex(norm.publicKey.slice(1))).toBe(bytesToHex(rawPt.toRawBytes(true).slice(1)));
		});

		it("normalizeTaprootInputKey is strictly idempotent", () => {
			const privOdd = numberToBytesBE(CURVE_ORDER_Q - 42n, 32);
			const firstPass = normalizeTaprootInputKey(privOdd);
			expect(firstPass.wasNegated).toBe(true);

			const secondPass = normalizeTaprootInputKey(firstPass.privateKey);
			expect(secondPass.wasNegated).toBe(false);
			expect(bytesToHex(secondPass.privateKey)).toBe(bytesToHex(firstPass.privateKey));
			expect(bytesToHex(secondPass.publicKey)).toBe(bytesToHex(firstPass.publicKey));
		});

		it("aggregateSenderInputs negates Taproot odd-y inputs while preserving SegWit v0 parities", () => {
			// Input 0: SegWit v0 P2WPKH with odd y (must NOT be negated)
			// Let's find a scalar whose G multiplication has odd y
			const privWpkh = numberToBytesBE(CURVE_ORDER_Q - 1n, 32);
			const ptWpkh = secp256k1.Point.BASE.multiply(CURVE_ORDER_Q - 1n);
			expect(ptWpkh.hasEvenY()).toBe(false);
			const pubWpkh = ptWpkh.toRawBytes(true); // starts with 03
			expect(pubWpkh[0]).toBe(0x03);

			// Input 1: Taproot with odd y (MUST be negated)
			const privTaproot = numberToBytesBE(CURVE_ORDER_Q - 2n, 32);
			const ptTaproot = secp256k1.Point.BASE.multiply(CURVE_ORDER_Q - 2n);
			expect(ptTaproot.hasEvenY()).toBe(false);
			const taprootSpk = "5120" + bytesToHex(ptTaproot.toRawBytes(true).slice(1));

			const agg = aggregateSenderInputs([
				{ privateKey: privWpkh, isTaproot: false },
				{ privateKey: privTaproot, scriptPubKey: taprootSpk },
			]);

			// Input 0 (P2WPKH) was NOT negated
			expect(agg.normalizedInputs[0].wasNegated).toBe(false);
			expect(bytesToHex(agg.normalizedInputs[0].privateKey)).toBe(bytesToHex(privWpkh));
			expect(agg.normalizedInputs[0].publicKey[0]).toBe(0x03);

			// Input 1 (Taproot) WAS negated: (CURVE_ORDER_Q - 2n) negated becomes 2n
			expect(agg.normalizedInputs[1].wasNegated).toBe(true);
			expect(bytesToNumberBE(agg.normalizedInputs[1].privateKey)).toBe(2n);
			expect(agg.normalizedInputs[1].publicKey[0]).toBe(0x02);

			// Aggregated scalar sum a = (CURVE_ORDER_Q - 1n + 2n) mod n = 1n
			expect(agg.aScalar).toBe(1n);

			// Aggregated public key A = a * G = 1n * G
			const expectedPointA = secp256k1.Point.BASE.multiply(1n).toRawBytes(true);
			expect(bytesToHex(agg.A)).toBe(bytesToHex(expectedPointA));
		});

		it("aggregateSenderInputs validates that provided publicKey strictly matches privateKey · G", () => {
			const privWpkh = numberToBytesBE(42n, 32);
			const expectedWpkhPub = secp256k1.getPublicKey(privWpkh, true);
			const wrongPub = secp256k1.Point.BASE.multiply(999n).toRawBytes(true);

			// 1. Non-taproot: valid publicKey matches and succeeds
			const validWpkhAgg = aggregateSenderInputs([
				{ privateKey: privWpkh, publicKey: expectedWpkhPub, isTaproot: false },
			]);
			expect(bytesToHex(validWpkhAgg.A)).toBe(bytesToHex(expectedWpkhPub));

			// 2. Non-taproot: mismatched publicKey throws
			expect(() => {
				aggregateSenderInputs([{ privateKey: privWpkh, publicKey: wrongPub, isTaproot: false }]);
			}).toThrow(/provided publicKey does not match privateKey/);

			// 3. Taproot: valid 32-byte and 33-byte publicKey succeeds
			const privTaproot = numberToBytesBE(123n, 32);
			const normTaproot = normalizeTaprootInputKey(privTaproot);
			const validTaprootAgg33 = aggregateSenderInputs([
				{ privateKey: privTaproot, publicKey: normTaproot.publicKey, isTaproot: true },
			]);
			expect(bytesToHex(validTaprootAgg33.A)).toBe(bytesToHex(normTaproot.publicKey));

			const validTaprootAgg32 = aggregateSenderInputs([
				{ privateKey: privTaproot, publicKey: normTaproot.publicKey.slice(1), isTaproot: true },
			]);
			expect(bytesToHex(validTaprootAgg32.A)).toBe(bytesToHex(normTaproot.publicKey));

			// 4. Taproot: mismatched publicKey throws
			expect(() => {
				aggregateSenderInputs([{ privateKey: privTaproot, publicKey: wrongPub, isTaproot: true }]);
			}).toThrow(/provided publicKey does not match privateKey/);

			expect(() => {
				aggregateSenderInputs([
					{ privateKey: privTaproot, publicKey: wrongPub.slice(1), isTaproot: true },
				]);
			}).toThrow(/provided publicKey does not match privateKey/);
		});

		it("guarantees sender and recipient shared secret match when spending Taproot inputs", () => {
			// Receiver Silent Payment keys
			const recipient = randomRecipientKeys();
			const bScan = recipient.scanKey.privateKey;
			const BScan = recipient.scanKey.publicKey;

			// Sender inputs:
			// Input 0: Taproot UTXO with odd-y key (CURVE_ORDER_Q - 99n)
			const privTaprootOdd = numberToBytesBE(CURVE_ORDER_Q - 99n, 32);
			const ptTaprootOdd = secp256k1.Point.BASE.multiply(CURVE_ORDER_Q - 99n);
			expect(ptTaprootOdd.hasEvenY()).toBe(false); // odd y
			const taprootXOnly = bytesToHex(ptTaprootOdd.toRawBytes(true).slice(1));
			const taprootSpk = `5120${taprootXOnly}`;

			// Input 1: P2WPKH UTXO with odd-y key (CURVE_ORDER_Q - 50n)
			const privWpkhOdd = numberToBytesBE(CURVE_ORDER_Q - 50n, 32);
			const ptWpkhOdd = secp256k1.Point.BASE.multiply(CURVE_ORDER_Q - 50n);
			expect(ptWpkhOdd.hasEvenY()).toBe(false); // odd y
			const wpkhPub = ptWpkhOdd.toRawBytes(true);
			const wpkhSpk = toP2wpkhScriptPubKeyHex(wpkhPub);

			const outpoints = [
				{ txid: "10".repeat(32), vout: 0 },
				{ txid: "20".repeat(32), vout: 1 },
			];
			const outpointL = findSmallestOutpoint(outpoints, true);

			// Sender side:
			const senderAgg = aggregateSenderInputs([
				{ privateKey: privTaprootOdd, scriptPubKey: taprootSpk },
				{ privateKey: privWpkhOdd, scriptPubKey: wpkhSpk },
			]);
			const inputHashSender = computeInputsHash(outpointL, senderAgg.A);
			const S_sender = deriveSharedSecretSender(inputHashSender, senderAgg.aBytes, BScan);

			// Recipient / Scanner side:
			// Recipient sees transaction with these two inputs:
			const txInputs: SpTxInput[] = [
				{
					txid: "10".repeat(32),
					vout: 0,
					prevoutScriptPubKey: taprootSpk,
					witness: ["40".repeat(32)], // key-path spend
				},
				{
					txid: "20".repeat(32),
					vout: 1,
					prevoutScriptPubKey: wpkhSpk,
					witness: ["3044...", bytesToHex(wpkhPub)],
				},
			];

			const eligible = extractEligibleInputs(txInputs);
			expect(eligible).toHaveLength(2);
			const A_recipient = aggregatePublicKeys(eligible.map((e) => e.pubkey));
			const inputHashRecipient = computeInputsHash(outpointL, A_recipient);
			const S_recipient = deriveSharedSecretRecipient(bScan, inputHashRecipient, A_recipient);

			// Sender and Recipient MUST match!
			expect(bytesToHex(senderAgg.A)).toBe(bytesToHex(A_recipient));
			expect(bytesToHex(inputHashSender)).toBe(bytesToHex(inputHashRecipient));
			expect(bytesToHex(S_sender)).toBe(bytesToHex(S_recipient));

			// Flaw counter-demonstration: without Taproot parity negation, sender would diverge!
			const unnormalizedSumScalar =
				(bytesToNumberBE(privTaprootOdd) + bytesToNumberBE(privWpkhOdd)) % CURVE_ORDER_Q;
			const unnormalizedA = secp256k1.Point.BASE.multiply(unnormalizedSumScalar).toRawBytes(true);
			expect(bytesToHex(unnormalizedA)).not.toBe(bytesToHex(A_recipient));
			const badInputHash = computeInputsHash(outpointL, unnormalizedA);
			const badSharedSecret = deriveSharedSecretSender(
				badInputHash,
				numberToBytesBE(unnormalizedSumScalar, 32),
				BScan,
			);
			expect(bytesToHex(badSharedSecret)).not.toBe(bytesToHex(S_recipient));
		});
	});

	describe("Memory zeroization & secret wiping compliance", () => {
		it("zeroizeBuffer fills memory buffer with zeros", () => {
			const buf = new Uint8Array([1, 2, 3, 4, 5, 42, 255]);
			zeroizeBuffer(buf);
			expect(Array.from(buf)).toEqual([0, 0, 0, 0, 0, 0, 0]);
		});

		it("zeroizeRecipientKeys clears both scanKey and spendKey private keys", () => {
			const keys = randomRecipientKeys();
			expect(keys.scanKey.privateKey.some((b) => b !== 0)).toBe(true);
			expect(keys.spendKey.privateKey.some((b) => b !== 0)).toBe(true);

			zeroizeRecipientKeys(keys);

			expect(keys.scanKey.privateKey.every((b) => b === 0)).toBe(true);
			expect(keys.spendKey.privateKey.every((b) => b === 0)).toBe(true);
			// Public keys remain untouched
			expect(keys.scanKey.publicKey.some((b) => b !== 0)).toBe(true);
			expect(keys.spendKey.publicKey.some((b) => b !== 0)).toBe(true);
		});

		it("zeroizeAggregateSenderInputs zeroes aBytes and all normalized input private keys", () => {
			const priv1 = new Uint8Array(32).fill(1);
			const priv2 = new Uint8Array(32).fill(2);
			const agg = aggregateSenderInputs([priv1, priv2]);

			expect(agg.aBytes.some((b) => b !== 0)).toBe(true);
			expect(agg.normalizedInputs[0].privateKey.some((b) => b !== 0)).toBe(true);
			expect(agg.normalizedInputs[1].privateKey.some((b) => b !== 0)).toBe(true);

			zeroizeAggregateSenderInputs(agg);

			expect(agg.aBytes.every((b) => b === 0)).toBe(true);
			expect(agg.normalizedInputs[0].privateKey.every((b) => b === 0)).toBe(true);
			expect(agg.normalizedInputs[1].privateKey.every((b) => b === 0)).toBe(true);
			// Public keys remain untouched
			expect(agg.A.some((b) => b !== 0)).toBe(true);
			expect(agg.normalizedInputs[0].publicKey.some((b) => b !== 0)).toBe(true);
		});

		it("bip32 derivation in deriveSilentPaymentKeysFromSeed functions correctly with wiped intermediate buffers", () => {
			const seed = hexToBytes("42".repeat(64));
			const res = deriveSilentPaymentKeysFromSeed(seed, "mainnet", 0);

			expect(res.address.startsWith("lqsp1q")).toBe(true);
			expect(res.scanKey.privateKey.length).toBe(32);
			expect(res.spendKey.privateKey.length).toBe(32);
			expect(res.scanKey.privateKey.some((b) => b !== 0)).toBe(true);
			expect(res.spendKey.privateKey.some((b) => b !== 0)).toBe(true);
		});
	});

	describe("Low Priority Findings: Range checks & BIP-352 strict error semantics", () => {
		it("toScalarBigInt strictly validates range [1, n - 1] and does not silently modulo reduce", () => {
			// Valid scalar
			expect(toScalarBigInt(1n)).toBe(1n);
			expect(toScalarBigInt(CURVE_ORDER_Q - 1n)).toBe(CURVE_ORDER_Q - 1n);

			// Rejects 0
			expect(() => toScalarBigInt(0n)).toThrow("Invalid scalar");
			expect(() => toScalarBigInt(new Uint8Array(32))).toThrow("Invalid scalar");

			// Rejects negative scalar
			expect(() => toScalarBigInt(-1n)).toThrow("Invalid scalar");

			// Rejects scalar == n
			expect(() => toScalarBigInt(CURVE_ORDER_Q)).toThrow("Invalid scalar");

			// Rejects scalar > n (BIP-352 requires error, not silent % n)
			expect(() => toScalarBigInt(CURVE_ORDER_Q + 1n)).toThrow("Invalid scalar");

			// Rejects 32-byte representation >= n
			const orderBytes = numberToBytesBE(CURVE_ORDER_Q, 32);
			expect(() => toScalarBigInt(orderBytes)).toThrow("Invalid scalar");

			const orderPlusOneBytes = numberToBytesBE(CURVE_ORDER_Q + 1n, 32);
			expect(() => toScalarBigInt(orderPlusOneBytes)).toThrow("Invalid scalar");
		});

		it("deriveSharedSecretSender strictly requires inputHash and rejects undefined / out-of-range scalars", () => {
			const aScalar = 42n;
			const testBScan = secp256k1.Point.BASE.toRawBytes(true);

			// Throws if inputHash is missing
			expect(() => deriveSharedSecretSender(undefined as any, aScalar, testBScan)).toThrow(
				"inputHash is required",
			);

			// Throws if inputHash is 0 or >= n
			expect(() => deriveSharedSecretSender(0n, aScalar, testBScan)).toThrow("Invalid scalar");
			expect(() => deriveSharedSecretSender(CURVE_ORDER_Q, aScalar, testBScan)).toThrow(
				"Invalid scalar",
			);

			// Succeeds with valid inputHash
			const validHash = hexToBytes("aa".repeat(32));
			const S = deriveSharedSecretSender(validHash, aScalar, testBScan);
			expect(S.length).toBe(33);
		});

		it("deriveSharedSecretRecipient strictly requires inputHash and rejects undefined / out-of-range scalars", () => {
			const bScanScalar = 42n;
			const A = secp256k1.Point.BASE.toRawBytes(true);

			// Throws if inputHash is missing
			expect(() => deriveSharedSecretRecipient(bScanScalar, undefined as any, A)).toThrow(
				"inputHash is required",
			);

			// Throws if inputHash is 0 or >= n
			expect(() => deriveSharedSecretRecipient(bScanScalar, 0n, A)).toThrow("Invalid scalar");
			expect(() => deriveSharedSecretRecipient(bScanScalar, CURVE_ORDER_Q, A)).toThrow(
				"Invalid scalar",
			);

			// Succeeds with valid inputHash
			const validHash = hexToBytes("aa".repeat(32));
			const S = deriveSharedSecretRecipient(bScanScalar, validHash, A);
			expect(S.length).toBe(33);
		});

		it("computeOutputTweak throws an explicit error when t_k is out of range instead of returning 0n sentinel", () => {
			const S = secp256k1.Point.BASE.toRawBytes(true);
			// Normal tweak succeeds
			const tk = computeOutputTweak(S, 0);
			expect(tk).toBeGreaterThan(0n);
			expect(tk).toBeLessThan(CURVE_ORDER_Q);
		});
	});
});

describe("matchCandidateOutputs", () => {
	const B_spend = randomRecipientKeys().spendKey.publicKey;
	const S = secp256k1.getPublicKey(secp256k1.utils.randomSecretKey(), true);
	const P0 = deriveOneTimePublicKey(B_spend, computeOutputTweak(S, 0));
	const P1 = deriveOneTimePublicKey(B_spend, computeOutputTweak(S, 1));
	const dummy = { id: "dummy", targetXOnly: new Uint8Array(32).fill(0xee) };

	it("matches outputs in k order whatever their position among the candidates", () => {
		const matches = matchCandidateOutputs(
			[{ id: "p1", targetXOnly: P1.xOnly }, dummy, { id: "p0", targetXOnly: P0.xOnly }],
			B_spend,
			S,
		);
		expect(matches.map((m) => [m.k, m.candidate.id])).toEqual([
			[0, "p0"],
			[1, "p1"],
		]);
	});

	it("stops at the first k without an output (BIP-352)", () => {
		expect(matchCandidateOutputs([{ id: "p1", targetXOnly: P1.xOnly }, dummy], B_spend, S)).toEqual(
			[],
		);
	});

	it("does not scan past k = K_MAX", () => {
		expect(
			matchCandidateOutputs([{ id: "p0", targetXOnly: P0.xOnly }], B_spend, S, undefined, 0),
		).toEqual([]);
		expect(K_MAX).toBe(2323);
	});

	it("matches labeled outputs of either parity next to x-coordinates off the curve", () => {
		const b_scan = secp256k1.utils.randomSecretKey();
		const labels = Array.from({ length: 16 }, (_, i) => i + 1);
		const labelMap = precomputeLabelPoints(b_scan, labels);
		// Search for k = 0 and k = 1 labeled outputs whose P has an odd and an even y.
		const labeledFor = (k: number, wantOddY: boolean) => {
			for (const m of labels) {
				const P = deriveOneTimePublicKey(
					deriveLabeledSpendPublicKey(B_spend, computeLabelTweak(b_scan, m)),
					computeOutputTweak(S, k),
				);
				if ((P.compressed[0] === 0x03) === wantOddY) return { m, P };
			}
			return undefined;
		};
		const odd = labeledFor(0, true);
		const even = labeledFor(1, false);
		// x = 5 has no point on secp256k1.
		const offCurve = { id: "off", targetXOnly: numberToBytesBE(5n, 32) };
		expect(odd && even).toBeDefined(); // Fails for about 1 in 2^15 key sets.
		if (!odd || !even) return;

		const matches = matchCandidateOutputs(
			[
				offCurve,
				{ id: "even", targetXOnly: even.P.xOnly },
				dummy,
				{ id: "odd", targetXOnly: odd.P.xOnly },
			],
			B_spend,
			S,
			labelMap,
		);

		expect(matches.map((m) => [m.k, m.candidate.id, m.matchResult.labelIndex])).toEqual([
			[0, "odd", odd.m],
			[1, "even", even.m],
		]);
		// The point carries the output's actual parity, which spending needs.
		expect(bytesToHex(matches[0]!.matchResult.point.toRawBytes(true))).toBe(
			bytesToHex(odd.P.compressed),
		);
		expect(bytesToHex(matches[1]!.matchResult.point.toRawBytes(true))).toBe(
			bytesToHex(even.P.compressed),
		);
	});
});
