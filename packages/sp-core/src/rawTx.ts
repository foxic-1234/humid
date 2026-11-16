import { sha256 } from "@noble/hashes/sha2.js";
import { bytesToHex, hexToBytes } from "@noble/hashes/utils.js";

import type { SpTransaction, SpTxInput, SpTxOutput } from "./types";

export class ByteReader {
	at = 0;
	constructor(public bytes: Uint8Array) {}

	get remaining(): number {
		return this.bytes.length - this.at;
	}

	readBytes(count: number): Uint8Array {
		if (this.at + count > this.bytes.length) {
			throw new Error(
				`Unexpected end of transaction buffer reading ${count} bytes at offset ${this.at}`,
			);
		}
		const slice = this.bytes.slice(this.at, this.at + count);
		this.at += count;
		return slice;
	}

	readHex(count: number): string {
		return bytesToHex(this.readBytes(count));
	}

	readReversedHex(count: number): string {
		const b = this.readBytes(count);
		const rev = new Uint8Array(count);
		for (let i = 0; i < count; i++) {
			rev[i] = b[count - 1 - i];
		}
		return bytesToHex(rev);
	}

	readUint8(): number {
		if (this.at >= this.bytes.length) {
			throw new Error("Unexpected end of transaction buffer reading uint8");
		}
		return this.bytes[this.at++];
	}

	readUint32LE(): number {
		const b = this.readBytes(4);
		return (b[0] | (b[1] << 8) | (b[2] << 16) | (b[3] << 24)) >>> 0;
	}

	readUint64BE(): bigint {
		const b = this.readBytes(8);
		let res = 0n;
		for (let i = 0; i < 8; i++) {
			res = (res << 8n) | BigInt(b[i]);
		}
		return res;
	}

	readVarint(): number {
		const first = this.readUint8();
		if (first < 0xfd) return first;
		if (first === 0xfd) {
			const b = this.readBytes(2);
			return b[0] | (b[1] << 8);
		}
		if (first === 0xfe) {
			return this.readUint32LE();
		}
		const b = this.readBytes(8);
		const low = (b[0] | (b[1] << 8) | (b[2] << 16) | (b[3] << 24)) >>> 0;
		const high = (b[4] | (b[5] << 8) | (b[6] << 16) | (b[7] << 24)) >>> 0;
		return low + high * 0x100000000;
	}

	skip(count: number): void {
		if (this.at + count > this.bytes.length) {
			throw new Error(`Cannot skip ${count} bytes at offset ${this.at}`);
		}
		this.at += count;
	}
}

export const ISSUANCE_FLAG = 0x80000000;
export const PEGIN_FLAG = 0x40000000;
export const NULL_OUTPOINT = 0xffffffff;

/**
 * Read ConfidentialValue from ByteReader according to Elements consensus.
 * 0x00: null (undefined)
 * 0x01: explicit (8 bytes BE uint64)
 * 0x08 | 0x09: commitment point (32 bytes)
 */
export function readConfidentialValue(reader: ByteReader): bigint | undefined {
	const prefix = reader.readUint8();
	if (prefix === 0x00) return undefined;
	if (prefix === 0x01) return reader.readUint64BE();
	if (prefix === 0x08 || prefix === 0x09) {
		reader.skip(32);
		return undefined;
	}
	throw new Error(`Invalid confidential value prefix: 0x${prefix.toString(16)}`);
}

/**
 * Read ConfidentialAsset from ByteReader according to Elements consensus.
 * 0x00: null (undefined)
 * 0x01: explicit asset (32 bytes, reversed to display hex)
 * 0x0a | 0x0b: commitment generator (32 bytes)
 */
export function readConfidentialAsset(reader: ByteReader): string | undefined {
	const prefix = reader.readUint8();
	if (prefix === 0x00) return undefined;
	if (prefix === 0x01) {
		const b = reader.readBytes(32);
		const rev = new Uint8Array(32);
		for (let j = 0; j < 32; j++) rev[j] = b[31 - j];
		return bytesToHex(rev);
	}
	if (prefix === 0x0a || prefix === 0x0b) {
		reader.skip(32);
		return undefined;
	}
	throw new Error(`Invalid confidential asset prefix: 0x${prefix.toString(16)}`);
}

/**
 * Read ConfidentialNonce from ByteReader according to Elements consensus.
 * 0x00: null
 * 0x01 | 0x02 | 0x03: commitment / pubkey (32 bytes)
 */
export function readConfidentialNonce(reader: ByteReader): void {
	const prefix = reader.readUint8();
	if (prefix === 0x00) return;
	if (prefix === 0x01 || prefix === 0x02 || prefix === 0x03) {
		reader.skip(32);
		return;
	}
	throw new Error(`Invalid confidential nonce prefix: 0x${prefix.toString(16)}`);
}

/**
 * Read a witness stack vector according to consensus.
 */
export function readWitnessStack(reader: ByteReader): string[] {
	const stackCount = reader.readVarint();
	const stack: string[] = [];
	for (let s = 0; s < stackCount; s++) {
		const itemLen = reader.readVarint();
		const itemBytes = reader.readBytes(itemLen);
		stack.push(bytesToHex(itemBytes));
	}
	return stack;
}

/**
 * Parse an Elements consensus-encoded raw transaction hex into SpTransaction.
 */
export function parseRawElementsTransaction(rawHex: string): SpTransaction {
	const reader = new ByteReader(hexToBytes(rawHex.trim()));
	const { tx } = readElementsTransaction(reader);
	if (reader.remaining !== 0) {
		throw new Error("Trailing bytes after Elements transaction");
	}
	return tx;
}

/**
 * Read one Elements transaction at the reader's offset. Returns it with its txid in internal byte
 * order (the merkle tree leaf) and its full serialization.
 */
function readElementsTransaction(reader: ByteReader): {
	internalTxid: Uint8Array;
	rawBytes: Uint8Array;
	tx: SpTransaction;
} {
	const start = reader.at;

	// 1. Version (4 bytes LE)
	reader.readUint32LE();

	// 2. Elements flags: single flags byte (bit 0 = witness present), NOT the BIP-144 marker
	const flagsOffset = reader.at - start;
	const flags = reader.readUint8();
	if ((flags & ~0x01) !== 0) {
		throw new Error(`Unsupported Elements tx flags: ${flags}`);
	}
	const isWitness = (flags & 0x01) === 1;

	// 3. Inputs
	const vinCount = reader.readVarint();
	const vin: SpTxInput[] = [];

	for (let i = 0; i < vinCount; i++) {
		const txid = reader.readReversedHex(32);
		const rawVout = reader.readUint32LE();
		const scriptLen = reader.readVarint();
		const scriptSigBytes = reader.readBytes(scriptLen);
		const scriptsig = bytesToHex(scriptSigBytes);
		reader.readUint32LE(); // sequence

		const isCoinbase = rawVout === NULL_OUTPOINT && /^0+$/.test(txid);
		const isPegin = !isCoinbase && (rawVout & PEGIN_FLAG) !== 0;
		const isIssuance = !isCoinbase && (rawVout & ISSUANCE_FLAG) !== 0;

		// Clean vout (clear flags for non-coinbase)
		const cleanVout = isCoinbase ? rawVout : rawVout & 0x3fffffff;

		// Elements input-attached issuance data:
		if (isIssuance) {
			// blindingNonce (32), entropy (32)
			reader.skip(64);
			// amount
			readConfidentialValue(reader);
			// inflation keys
			readConfidentialValue(reader);
		}

		vin.push({
			isCoinbase,
			isPegin,
			scriptsig,
			txid,
			vout: cleanVout,
		});
	}

	// 4. Outputs
	const voutCount = reader.readVarint();
	const vout: SpTxOutput[] = [];

	for (let i = 0; i < voutCount; i++) {
		const asset = readConfidentialAsset(reader);
		const value = readConfidentialValue(reader);
		readConfidentialNonce(reader);
		const spkLen = reader.readVarint();
		const scriptPubKey = reader.readHex(spkLen);

		vout.push({
			asset,
			outputIndex: i,
			scriptPubKey,
			value,
		});
	}

	// 5. Locktime (4 bytes LE)
	reader.readUint32LE();
	const noWitnessEnd = reader.at - start;

	// 6. Witness data (if witness flag is set)
	if (isWitness) {
		for (let i = 0; i < vinCount; i++) {
			reader.skip(reader.readVarint()); // issuance amount rangeproof
			reader.skip(reader.readVarint()); // inflation keys rangeproof
			vin[i].witness = readWitnessStack(reader); // script witness
			readWitnessStack(reader); // pegin witness (ignored)
		}
		for (let i = 0; i < voutCount; i++) {
			reader.skip(reader.readVarint()); // surjection proof
			reader.skip(reader.readVarint()); // rangeproof
		}
	}

	const rawBytes = reader.bytes.slice(start, reader.at);

	// txid = sha256d(no-witness serialization): flags byte forced to 0, witness section dropped.
	const noWit = rawBytes.slice(0, noWitnessEnd);
	noWit[flagsOffset] = 0x00;
	const internalTxid = sha256d(noWit);

	return { internalTxid, rawBytes, tx: { txid: toDisplayHex(internalTxid), vin, vout } };
}

function sha256d(bytes: Uint8Array): Uint8Array {
	return sha256(sha256(bytes));
}

/** A hash in internal byte order as the reversed hex that RPC and explorers display. */
function toDisplayHex(internal: Uint8Array): string {
	return bytesToHex(internal.slice().reverse());
}

export type ElementsBlockTransaction = {
	rawHex: string;
	tx: SpTransaction;
};

export type ElementsBlock = {
	blockHash: string;
	height: number;
	prevBlockHash: string;
	txs: ElementsBlockTransaction[];
};

/** Bit 31 of the header version marks a dynamic federation (dynafed) header. */
const DYNAFED_VERSION_BIT = 0x80000000;

function skipScript(reader: ByteReader): void {
	reader.skip(reader.readVarint());
}

/** Skip a DynaFedParamEntry: 0 = null, 1 = compact, 2 = full. */
function skipDynaFedParamEntry(reader: ByteReader): void {
	const serializeType = reader.readUint8();
	if (serializeType === 0) return;
	if (serializeType === 1) {
		skipScript(reader); // signblockscript
		reader.skip(4); // signblock_witness_limit
		reader.skip(32); // elided_root
		return;
	}
	if (serializeType === 2) {
		skipScript(reader); // signblockscript
		reader.skip(4); // signblock_witness_limit
		skipScript(reader); // fedpeg_program
		skipScript(reader); // fedpegscript
		const extensionCount = reader.readVarint();
		for (let i = 0; i < extensionCount; i++) {
			reader.skip(reader.readVarint());
		}
		return;
	}
	throw new Error(`Invalid dynafed params entry type: ${serializeType}`);
}

/** Bitcoin-style merkle root over internal-order txids (the last node pairs with itself). */
export function computeMerkleRoot(leaves: Uint8Array[]): Uint8Array {
	if (leaves.length === 0) {
		throw new Error("Cannot compute the merkle root of an empty block");
	}
	let level = leaves;
	while (level.length > 1) {
		const next: Uint8Array[] = [];
		for (let i = 0; i < level.length; i += 2) {
			const left = level[i];
			const right = level[i + 1] ?? left;
			const pair = new Uint8Array(64);
			pair.set(left, 0);
			pair.set(right, 32);
			next.push(sha256d(pair));
		}
		level = next;
	}
	return level[0];
}

/**
 * Parse a raw Elements block (as Esplora's `/block/:hash/raw` serves it) with a Liquid header:
 * block height in the header, then dynafed params and signblock witness, or a legacy
 * challenge/solution proof. Throws unless the transactions hash to the header's merkle root, so
 * every returned transaction is committed to by `blockHash`.
 */
export function parseRawElementsBlock(raw: Uint8Array): ElementsBlock {
	const reader = new ByteReader(raw);

	const version = reader.readUint32LE();
	const prevBlockHash = reader.readBytes(32);
	const merkleRoot = reader.readBytes(32);
	reader.skip(4); // time
	const height = reader.readUint32LE();
	if ((version & DYNAFED_VERSION_BIT) !== 0) {
		skipDynaFedParamEntry(reader); // current
		skipDynaFedParamEntry(reader); // proposed
	} else {
		skipScript(reader); // challenge
	}
	// The block hash covers the header up to here: the signblock witness / solution is excluded.
	const blockHash = toDisplayHex(sha256d(raw.slice(0, reader.at)));
	if ((version & DYNAFED_VERSION_BIT) !== 0) {
		readWitnessStack(reader); // signblock witness
	} else {
		skipScript(reader); // solution
	}

	const txCount = reader.readVarint();
	const txs: ElementsBlockTransaction[] = [];
	const leaves: Uint8Array[] = [];
	for (let i = 0; i < txCount; i++) {
		const { internalTxid, rawBytes, tx } = readElementsTransaction(reader);
		leaves.push(internalTxid);
		txs.push({ rawHex: bytesToHex(rawBytes), tx });
	}
	if (reader.remaining !== 0) {
		throw new Error("Trailing bytes after Elements block");
	}

	const computedRoot = computeMerkleRoot(leaves);
	if (bytesToHex(computedRoot) !== bytesToHex(merkleRoot)) {
		throw new Error(`Block ${blockHash}: transactions do not match the header's merkle root`);
	}

	return { blockHash, height, prevBlockHash: toDisplayHex(prevBlockHash), txs };
}
