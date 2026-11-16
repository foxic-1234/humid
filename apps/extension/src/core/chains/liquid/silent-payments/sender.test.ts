import { describe, expect, it } from "bun:test";

import {
	computeInputsHash,
	CURVE_ORDER_Q,
	deriveBlindingKey,
	deriveLabeledSilentPaymentAddress,
	deriveOneTimePrivateKey,
	deriveSharedSecretRecipient,
	encodeSilentPaymentAddress,
	findSmallestOutpoint,
	matchCandidateOutputs,
	precomputeLabelPoints,
	type SilentPaymentRecipientKeys,
} from "@humid/sp-core";
import { schnorr, secp256k1 } from "@noble/curves/secp256k1.js";
import { numberToBytesBE } from "@noble/curves/utils.js";
import { ripemd160 } from "@noble/hashes/ripemd160.js";
import { sha256 } from "@noble/hashes/sha2.js";
import { bytesToHex } from "@noble/hashes/utils.js";

import { createSilentPaymentOutput, type CreateSilentPaymentOutputParams } from "./sender";

/** Fresh random recipient keys (b_scan, B_scan), (b_spend, B_spend). */
function randomRecipientKeys(): SilentPaymentRecipientKeys {
	const keyPair = () => {
		const privateKey = secp256k1.utils.randomSecretKey();
		return { privateKey, publicKey: secp256k1.getPublicKey(privateKey, true) };
	};
	return { scanKey: keyPair(), spendKey: keyPair() };
}

function addressOf(recipient: SilentPaymentRecipientKeys): string {
	return encodeSilentPaymentAddress(
		recipient.scanKey.publicKey,
		recipient.spendKey.publicKey,
		"testnet",
	);
}

/** The inputs of a transaction spending one random P2WPKH output. */
function p2wpkhInputs(): Omit<CreateSilentPaymentOutputParams, "k" | "recipientAddress"> {
	const privateKey = secp256k1.utils.randomSecretKey();
	const publicKey = secp256k1.getPublicKey(privateKey, true);
	return {
		inputPrivkeys: [privateKey],
		inputPubkeys: [publicKey],
		inputScripts: ["0014" + bytesToHex(ripemd160(sha256(publicKey)))],
		network: "testnet",
		outpoints: [{ txid: "ab".repeat(32), vout: 1 }],
	};
}

/** The recipient's side: S from b_scan, the sender's A and the transaction's outpoints. */
function recipientSharedSecret(
	recipient: SilentPaymentRecipientKeys,
	A: Uint8Array,
	outpoints: Array<{ txid: string; vout: number }>,
): Uint8Array {
	const inputHash = computeInputsHash(findSmallestOutpoint(outpoints), A);
	return deriveSharedSecretRecipient(recipient.scanKey.privateKey, inputHash, A);
}

function expectSpendable(
	recipient: SilentPaymentRecipientKeys,
	match: ReturnType<typeof matchCandidateOutputs>[number],
): void {
	const d = deriveOneTimePrivateKey(
		recipient.spendKey.privateKey,
		match.tk,
		match.matchResult.point,
		match.matchResult.labelTweak ?? 0n,
	);
	const sighash = new Uint8Array(32).fill(0x77);
	const xOnly = match.matchResult.point.toRawBytes(true).slice(1);
	expect(schnorr.verify(schnorr.sign(sighash, d), sighash, xOnly)).toBe(true);
}

describe("createSilentPaymentOutput", () => {
	it("refuses k >= K_MAX = 2323", () => {
		expect(() =>
			createSilentPaymentOutput({
				...p2wpkhInputs(),
				k: 2323,
				recipientAddress: addressOf(randomRecipientKeys()),
			}),
		).toThrow("exceeds K_MAX");
	});

	it("refuses to build an output without the transaction's input keys or outpoints", () => {
		const recipientAddress = addressOf(randomRecipientKeys());
		const inputs = p2wpkhInputs();
		expect(() =>
			createSilentPaymentOutput({ ...inputs, inputPrivkeys: [], k: 0, recipientAddress }),
		).toThrow("requires the transaction's input keys and outpoints");
		expect(() =>
			createSilentPaymentOutput({ ...inputs, k: 0, outpoints: [], recipientAddress }),
		).toThrow("requires the transaction's input keys and outpoints");
	});

	it("builds an output the recipient finds, unblinds with bk_k and can spend", () => {
		const recipient = randomRecipientKeys();
		const inputs = p2wpkhInputs();
		const spOutput = createSilentPaymentOutput({
			...inputs,
			k: 0,
			recipientAddress: addressOf(recipient),
		});

		expect(spOutput.confidentialAddress.startsWith("tlq1p")).toBe(true);
		expect(bytesToHex(spOutput.ephemeralPublicKey)).toBe(bytesToHex(inputs.inputPubkeys[0]));

		const S = recipientSharedSecret(recipient, spOutput.ephemeralPublicKey, inputs.outpoints);
		const [match, ...rest] = matchCandidateOutputs(
			[{ id: "0", targetXOnly: spOutput.destinationScriptPubKey.slice(2) }],
			recipient.spendKey.publicKey,
			S,
		);
		expect(rest).toHaveLength(0);
		expect(match.k).toBe(0);
		expect(bytesToHex(deriveBlindingKey(S, 0).BK)).toBe(bytesToHex(spOutput.blindingPublicKey));
		expectSpendable(recipient, match);
	});

	it("encodes the output address for the transaction's network, not the SP address's HRP", () => {
		const recipientAddress = addressOf(randomRecipientKeys());
		const outputOn = (network: CreateSilentPaymentOutputParams["network"]) =>
			createSilentPaymentOutput({ ...p2wpkhInputs(), k: 0, network, recipientAddress });

		// The same tlqsp address pays a testnet or a regtest output.
		expect(outputOn("testnet").confidentialAddress.startsWith("tlq1p")).toBe(true);
		expect(outputOn("regtest").confidentialAddress.startsWith("el1p")).toBe(true);
		expect(() => outputOn("mainnet")).toThrow("does not belong to the mainnet network");
	});

	it("pays a labeled address so that the recipient matches it with its label", () => {
		const recipient = randomRecipientKeys();
		const labeled = deriveLabeledSilentPaymentAddress(recipient, 3, "testnet");
		const inputs = p2wpkhInputs();
		const spOutput = createSilentPaymentOutput({
			...inputs,
			k: 0,
			recipientAddress: labeled.address,
		});

		const S = recipientSharedSecret(recipient, spOutput.ephemeralPublicKey, inputs.outpoints);
		const [match] = matchCandidateOutputs(
			[{ id: "0", targetXOnly: spOutput.destinationScriptPubKey.slice(2) }],
			recipient.spendKey.publicKey,
			S,
			precomputeLabelPoints(recipient.scanKey.privateKey, [1, 2, 3]),
		);
		expect(match.matchResult.labelIndex).toBe(3);
		expectSpendable(recipient, match);
	});

	it("gives outputs k = 0 and k = 1 that the recipient finds at any vout", () => {
		const recipient = randomRecipientKeys();
		const inputs = p2wpkhInputs();
		const recipientAddress = addressOf(recipient);
		const out0 = createSilentPaymentOutput({ ...inputs, k: 0, recipientAddress });
		const out1 = createSilentPaymentOutput({ ...inputs, k: 1, recipientAddress });

		const S = recipientSharedSecret(recipient, out0.ephemeralPublicKey, inputs.outpoints);
		const matches = matchCandidateOutputs(
			[
				{ id: "vout0", targetXOnly: out1.destinationScriptPubKey.slice(2) },
				{ id: "vout1", targetXOnly: new Uint8Array(32).fill(0xee) },
				{ id: "vout2", targetXOnly: out0.destinationScriptPubKey.slice(2) },
			],
			recipient.spendKey.publicKey,
			S,
		);
		expect(matches.map((m) => [m.k, m.candidate.id])).toEqual([
			[0, "vout2"],
			[1, "vout0"],
		]);
		for (const m of matches) expectSpendable(recipient, m);
	});

	it("negates an odd-y Taproot input key, so A is the even-y point", () => {
		const recipient = randomRecipientKeys();
		// (n - 1)·G = -G has odd y; its Taproot output key is the even-y G.
		const privOdd = numberToBytesBE(CURVE_ORDER_Q - 1n, 32);
		const pubOdd = secp256k1.getPublicKey(privOdd, true);
		expect(pubOdd[0]).toBe(0x03);
		const outpoints = [{ txid: "33".repeat(32), vout: 0 }];

		const spOutput = createSilentPaymentOutput({
			inputPrivkeys: [privOdd],
			inputPubkeys: [pubOdd],
			inputScripts: ["5120" + bytesToHex(pubOdd.slice(1))],
			k: 0,
			network: "testnet",
			outpoints,
			recipientAddress: addressOf(recipient),
		});

		expect(bytesToHex(spOutput.ephemeralPublicKey)).toBe(
			bytesToHex(secp256k1.Point.BASE.toRawBytes(true)),
		);
		expect("ephemeralPrivateKey" in spOutput).toBe(false);

		const S = recipientSharedSecret(recipient, spOutput.ephemeralPublicKey, outpoints);
		const matches = matchCandidateOutputs(
			[{ id: "0", targetXOnly: spOutput.destinationScriptPubKey.slice(2) }],
			recipient.spendKey.publicKey,
			S,
		);
		expect(matches).toHaveLength(1);
		expectSpendable(recipient, matches[0]);
	});
});
