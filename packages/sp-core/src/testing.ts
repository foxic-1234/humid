// Test-only fixtures for ELIP-352 consumers: `@humid/sp-core/testing`, not part of the main entry.
import { sha256 } from "@noble/hashes/sha2.js";
import { bytesToHex, hexToBytes } from "@noble/hashes/utils.js";

import {
	computeMerkleRoot,
	ISSUANCE_FLAG,
	NULL_OUTPOINT,
	parseRawElementsTransaction,
	PEGIN_FLAG,
} from "./rawTx";

export interface RawElementsTxOptions {
	version?: number;
	vin: Array<{
		txid: string;
		vout: number;
		isCoinbase?: boolean;
		isPegin?: boolean;
		isIssuance?: boolean;
		scriptSig?: string;
		sequence?: number;
		witness?: string[];
	}>;
	vout: Array<{
		assetHex?: string;
		valueSats?: bigint | number;
		scriptPubKeyHex: string;
		nonceHex?: string;
	}>;
	locktime?: number;
}

/** Bitcoin CompactSize (varint) encoding of `n`, as hex; the inverse of `ByteReader.readVarint`. */
export function compactSizeHex(n: number): string {
	if (!Number.isSafeInteger(n) || n < 0) {
		throw new Error(`Invalid CompactSize value: ${n}`);
	}
	if (n < 0xfd) return n.toString(16).padStart(2, "0");
	const le = (bytes: number) => {
		const buf = new Uint8Array(bytes);
		let rest = BigInt(n);
		for (let i = 0; i < bytes; i++) {
			buf[i] = Number(rest & 0xffn);
			rest >>= 8n;
		}
		return bytesToHex(buf);
	};
	if (n <= 0xffff) return "fd" + le(2);
	if (n <= 0xffffffff) return "fe" + le(4);
	return "ff" + le(8);
}

/**
 * Encode an Elements consensus raw transaction hex and compute its txid.
 *
 * A fixture encoder for tests: outputs are always explicit, issuance amounts are a fixed 1 and
 * proofs are empty. Wallet transactions are built by LWK, never with this.
 */
export function encodeRawElementsTransaction({
	version = 2,
	vin,
	vout,
	locktime = 0,
}: RawElementsTxOptions): { rawHex: string; txid: string } {
	const isWitness = vin.some((v) => v.witness && v.witness.length > 0);
	const parts: string[] = [];

	// 1. Version
	const vBuf = new Uint8Array(4);
	new DataView(vBuf.buffer).setUint32(0, version, true);
	parts.push(bytesToHex(vBuf));

	// 2. Flags: bit 0 = witness present
	const flagsOffset = parts.join("").length / 2;
	parts.push(isWitness ? "01" : "00");

	// 3. Inputs
	parts.push(compactSizeHex(vin.length));
	for (const input of vin) {
		const txidBytes = hexToBytes(input.txid);
		const revTxid = new Uint8Array(32);
		for (let i = 0; i < 32; i++) revTxid[i] = txidBytes[31 - i]!;
		parts.push(bytesToHex(revTxid));

		// A coinbase input spends the null outpoint: vout 0xffffffff, no flags.
		let rawVout = input.isCoinbase ? NULL_OUTPOINT : input.vout & 0x3fffffff;
		if (input.isPegin) rawVout |= PEGIN_FLAG;
		if (input.isIssuance) rawVout |= ISSUANCE_FLAG;
		const voutBuf = new Uint8Array(4);
		new DataView(voutBuf.buffer).setUint32(0, rawVout, true);
		parts.push(bytesToHex(voutBuf));

		const sigHex = input.scriptSig ?? "";
		const sigLen = sigHex.length / 2;
		parts.push(compactSizeHex(sigLen));
		if (sigHex) parts.push(sigHex);

		const seqBuf = new Uint8Array(4);
		new DataView(seqBuf.buffer).setUint32(0, input.sequence ?? 0xffffffff, true);
		parts.push(bytesToHex(seqBuf));

		if (input.isIssuance) {
			parts.push("00".repeat(32)); // blinding nonce
			parts.push("00".repeat(32)); // entropy
			// Explicit amount of 1: an issuance with both amounts null is invalid in Elements.
			parts.push("01" + "0000000000000001");
			parts.push("00"); // null inflation keys
		}
	}

	// 4. Outputs
	parts.push(compactSizeHex(vout.length));
	for (const out of vout) {
		const assetHex = out.assetHex ?? "50".repeat(32);
		const assetBytes = hexToBytes(assetHex);
		const revAsset = new Uint8Array(32);
		for (let i = 0; i < 32; i++) revAsset[i] = assetBytes[31 - i]!;
		parts.push("01" + bytesToHex(revAsset));

		const valBytes = new Uint8Array(8);
		new DataView(valBytes.buffer).setBigUint64(0, BigInt(out.valueSats ?? 0), false);
		parts.push("01" + bytesToHex(valBytes));

		if (out.nonceHex) {
			parts.push("01" + out.nonceHex);
		} else {
			parts.push("00");
		}

		const spkHex = out.scriptPubKeyHex;
		const spkLen = spkHex.length / 2;
		parts.push(compactSizeHex(spkLen));
		parts.push(spkHex);
	}

	// 5. Locktime
	const lockBuf = new Uint8Array(4);
	new DataView(lockBuf.buffer).setUint32(0, locktime, true);
	parts.push(bytesToHex(lockBuf));

	const noWitnessEnd = parts.join("").length / 2;

	// 6. Witness
	if (isWitness) {
		for (const input of vin) {
			parts.push("00"); // issuance amount rangeproof len 0
			parts.push("00"); // issuance inflation rangeproof len 0
			const stack = input.witness ?? [];
			parts.push(compactSizeHex(stack.length));
			for (const item of stack) {
				const itemLen = item.length / 2;
				parts.push(compactSizeHex(itemLen));
				parts.push(item);
			}
			parts.push("00"); // pegin witness len 0
		}
		for (let i = 0; i < vout.length; i++) {
			parts.push("00"); // surjection proof len 0
			parts.push("00"); // rangeproof len 0
		}
	}

	const rawHex = parts.join("");
	const raw = hexToBytes(rawHex);
	const noWit = raw.slice(0, noWitnessEnd);
	noWit[flagsOffset] = 0x00;
	const h1 = sha256(noWit);
	const h2 = sha256(h1);
	const revTxid = new Uint8Array(32);
	for (let i = 0; i < 32; i++) revTxid[i] = h2[31 - i]!;
	const txid = bytesToHex(revTxid);

	return { rawHex, txid };
}

function uint32LEHex(n: number): string {
	const b = new Uint8Array(4);
	new DataView(b.buffer).setUint32(0, n >>> 0, true);
	return bytesToHex(b);
}

/**
 * Serialize a Liquid block (dynafed header with the block height) whose merkle root commits to
 * `txs`, raw transaction hexes with the coinbase first. Returns the block hash as explorers show it.
 */
export function encodeRawElementsBlock({
	height,
	prevBlockHash,
	time = 0,
	txs,
}: {
	height: number;
	prevBlockHash: string;
	time?: number;
	txs: string[];
}): { blockHash: string; rawHex: string } {
	const leaves = txs.map((tx) => hexToBytes(parseRawElementsTransaction(tx).txid!).reverse());
	const header =
		uint32LEHex(0xa0000000) + // version 0x20000000 with the dynafed bit
		bytesToHex(hexToBytes(prevBlockHash).reverse()) +
		bytesToHex(computeMerkleRoot(leaves)) +
		uint32LEHex(time) +
		uint32LEHex(height) +
		// current params: compact entry with an empty signblockscript; proposed params: null entry
		"01" +
		compactSizeHex(0) +
		uint32LEHex(0) +
		"00".repeat(32) +
		"00";
	const blockHash = bytesToHex(sha256(sha256(hexToBytes(header))).reverse());
	const rawHex = header + compactSizeHex(0) + compactSizeHex(txs.length) + txs.join("");

	return { blockHash, rawHex };
}
