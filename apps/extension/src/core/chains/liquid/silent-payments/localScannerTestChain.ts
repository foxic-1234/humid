// Test-only: a chain of real raw Liquid blocks behind a fake Esplora, and Silent Payments to put in
// it, shared by the scanner's tests and benchmark.
import {
	computeInputsHash,
	computeOutputTweak,
	findSmallestOutpoint,
	toScalarBigInt,
} from "@humid/sp-core";
import { encodeRawElementsBlock, encodeRawElementsTransaction } from "@humid/sp-core/testing";
import { secp256k1 } from "@noble/curves/secp256k1.js";
import { ripemd160 } from "@noble/hashes/ripemd160.js";
import { sha256 } from "@noble/hashes/sha2.js";
import { bytesToHex, hexToBytes } from "@noble/hashes/utils.js";

import type { SilentPaymentRecipientKeys } from "./types";

export const PAYMENT_SATS = 5_000_000n;

export function keyPair(last: number) {
	const privateKey = new Uint8Array(32);
	privateKey[31] = last;
	return { privateKey, publicKey: secp256k1.getPublicKey(privateKey, true) };
}

export function createTestRecipientKeys(): SilentPaymentRecipientKeys {
	return { scanKey: keyPair(0x11), spendKey: keyPair(0x22) };
}

export function buildPaymentTx(
	keys: SilentPaymentRecipientKeys,
	nonce: number,
	labelTweak?: bigint,
) {
	const inPrivKey = new Uint8Array(32);
	inPrivKey[31] = nonce;
	const inPubKey = secp256k1.getPublicKey(inPrivKey, true);
	const parentSpkHex = "0014" + bytesToHex(ripemd160(sha256(inPubKey)));

	const parentTx = encodeRawElementsTransaction({
		vin: [{ isCoinbase: true, txid: "00".repeat(32), vout: 0 }],
		vout: [{ scriptPubKeyHex: parentSpkHex, valueSats: 10_000_000n }],
	});

	const inputHash = computeInputsHash(
		findSmallestOutpoint([{ txid: parentTx.txid, vout: 0 }]),
		inPubKey,
	);
	const S = secp256k1.Point.fromHex(inPubKey)
		.multiply(toScalarBigInt(inputHash))
		.multiply(toScalarBigInt(keys.scanKey.privateKey))
		.toRawBytes(true);
	let spendPoint = secp256k1.Point.fromHex(keys.spendKey.publicKey);
	if (labelTweak !== undefined) {
		spendPoint = spendPoint.add(secp256k1.Point.BASE.multiply(labelTweak));
	}
	const P0 = spendPoint.add(secp256k1.Point.BASE.multiply(computeOutputTweak(S, 0)));
	const spkHex = "5120" + bytesToHex(P0.toRawBytes(true).slice(1));

	const validTx = encodeRawElementsTransaction({
		vin: [{ txid: parentTx.txid, vout: 0, witness: ["", bytesToHex(inPubKey)] }],
		vout: [{ scriptPubKeyHex: spkHex, valueSats: PAYMENT_SATS }],
	});

	const esploraTx = {
		status: { block_height: 100, block_time: 1_700_000_000, confirmed: true },
		txid: validTx.txid,
		vin: [
			{
				prevout: { scriptpubkey: parentSpkHex, scriptpubkey_type: "v0_p2wpkh" },
				txid: parentTx.txid,
				vout: 0,
				witness: ["", bytesToHex(inPubKey)],
			},
		],
		vout: [
			{
				output_index: 0,
				scriptpubkey: spkHex,
				scriptpubkey_type: "v1_p2tr",
			},
		],
	};

	const blockTx: BlockTx = { json: esploraTx, rawHex: validTx.rawHex };

	return { blockTx, esploraTx, parentTx, validTx };
}

/** A non-coinbase block transaction as the fake explorer serves it: JSON listing and raw bytes. */
export type BlockTx = { json: unknown; rawHex: string };

/** Hash of a block in the chain of the most recently created `fakeExplorer`. */
export let blockHash: (height: number) => string = () => {
	throw new Error("No fake explorer yet");
};

/**
 * A chain of real raw Liquid blocks: each has a coinbase plus `txsByHeight[height]`, and commits to
 * its parent. Blocks are built on first use, so equal `txsByHeight` give equal chains.
 */
export function fakeChain(txsByHeight: Record<number, BlockTx[]>) {
	const blocks: Array<{ hash: string; json: unknown[]; rawHex: string }> = [];
	const at = (height: number) => {
		while (blocks.length <= height) {
			const h = blocks.length;
			const coinbase = encodeRawElementsTransaction({
				vin: [
					{
						isCoinbase: true,
						scriptSig: h.toString(16).padStart(8, "0"),
						txid: "00".repeat(32),
						vout: 0xffffffff,
					},
				],
				vout: [{ scriptPubKeyHex: "6a", valueSats: 0 }],
			});
			const coinbaseJson = {
				txid: coinbase.txid,
				vin: [{ is_coinbase: true, txid: "00".repeat(32), vout: 0xffffffff }],
				vout: [{ scriptpubkey: "6a" }],
			};
			const txs = txsByHeight[h] ?? [];
			const block = encodeRawElementsBlock({
				height: h,
				prevBlockHash: h === 0 ? "00".repeat(32) : blocks[h - 1]!.hash,
				time: 1_700_000_000 + h * 60,
				txs: [coinbase.rawHex, ...txs.map((t) => t.rawHex)],
			});
			blocks.push({
				hash: block.blockHash,
				json: [coinbaseJson, ...txs.map((t) => t.json)],
				rawHex: block.rawHex,
			});
		}
		return blocks[height]!;
	};
	return { at, byHash: (hash: string) => blocks.find((b) => b.hash === hash) };
}

/** A block transaction spending the Taproot output `txid:0` whose scriptPubKey is `spk`. */
export function spendOf(txid: string, spk: string): BlockTx {
	const raw = encodeRawElementsTransaction({
		vin: [{ txid, vout: 0, witness: ["aa".repeat(64)] }],
		vout: [{ scriptPubKeyHex: "0014" + "55".repeat(20), valueSats: 1 }],
	});
	return {
		json: {
			fee: 30,
			txid: raw.txid,
			vin: [
				{
					prevout: { scriptpubkey: spk, scriptpubkey_type: "v1_p2tr" },
					txid,
					vout: 0,
					witness: ["aa".repeat(64)],
				},
			],
			vout: [{ scriptpubkey: "0014" + "55".repeat(20) }],
		},
		rawHex: raw.rawHex,
	};
}

/**
 * Fake Esplora over `fakeChain(txsByHeight)` up to `tip`; `extra` answers the remaining paths.
 */
export function fakeExplorer(
	tip: number,
	txsByHeight: Record<number, BlockTx[]>,
	extra: (path: string) => Response | undefined,
	requests: string[] = [],
	headerOverride: (header: Record<string, unknown>) => Record<string, unknown> = (h) => h,
) {
	const chainOf = fakeChain(txsByHeight);
	blockHash = (height: number) => chainOf.at(height).hash;
	const handler = (async (input: string) => {
		const path = new URL(input).pathname;
		requests.push(path);
		const answered = extra(path);
		if (answered) return answered;
		if (path.endsWith("/mempool/recent") || path.endsWith("/mempool/txids")) {
			return new Response(JSON.stringify([]), { status: 200 });
		}
		if (path.endsWith("/blocks/tip/height")) {
			return new Response(String(tip), { status: 200 });
		}
		const heightMatch = /\/block-height\/(\d+)$/.exec(path);
		if (heightMatch) {
			return new Response(blockHash(Number(heightMatch[1])), { status: 200 });
		}
		const blocksMatch = /\/blocks\/(\d+)$/.exec(path);
		if (blocksMatch) {
			const top = Math.min(tip, Number(blocksMatch[1]));
			const headers = [];
			for (let h = top; h >= Math.max(0, top - 9); h--) {
				headers.push(
					headerOverride({
						height: h,
						id: blockHash(h),
						previousblockhash: h === 0 ? undefined : blockHash(h - 1),
						timestamp: 1_700_000_000 + h * 60,
						tx_count: (txsByHeight[h]?.length ?? 0) + 1,
					}),
				);
			}
			return new Response(JSON.stringify(headers), { status: 200 });
		}
		const blockMatch = /\/block\/([0-9a-f]{64})\/(txs|raw)$/.exec(path);
		const block = blockMatch ? chainOf.byHash(blockMatch[1]!) : undefined;
		if (block && blockMatch![2] === "txs") {
			return new Response(JSON.stringify(block.json), { status: 200 });
		}
		if (block && blockMatch![2] === "raw") {
			return new Response(new Uint8Array(hexToBytes(block.rawHex)), { status: 200 });
		}
		if (path.includes("/outspend/")) {
			return new Response(JSON.stringify({ spent: false }), { status: 200 });
		}
		return new Response("Not found", { status: 404 });
	}) as unknown as typeof fetch;

	return handler;
}
