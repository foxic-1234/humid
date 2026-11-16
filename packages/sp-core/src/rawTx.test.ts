import { describe, expect, it } from "bun:test";

import { bytesToHex, hexToBytes } from "@noble/hashes/utils.js";

import liquidBlocks from "./__fixtures__/liquid-blocks.json";
import fixtures from "./__fixtures__/testnet-transactions.json";
import { ByteReader, parseRawElementsBlock, parseRawElementsTransaction } from "./rawTx";
import { compactSizeHex, encodeRawElementsBlock, encodeRawElementsTransaction } from "./testing";

describe("parseRawElementsTransaction & encodeRawElementsTransaction (ELIP-352 / Elements Consensus)", () => {
	it("parses real Liquid testnet coinbase transaction and verifies txid", () => {
		const coinbase = fixtures.coinbase;
		const parsed = parseRawElementsTransaction(coinbase.raw);

		expect(parsed.txid).toBe(coinbase.txid);
		expect(parsed.vin).toHaveLength(1);
		expect(parsed.vin[0].isCoinbase).toBe(true);
		expect(parsed.vin[0].isPegin).toBe(false);
		expect(parsed.vout).toHaveLength(2);
		expect(parsed.vout[0].scriptPubKey).toBe(coinbase.vout[0].scriptpubkey);
		expect(parsed.vout[1].scriptPubKey).toBe(coinbase.vout[1].scriptpubkey);
	});

	it("parses real Liquid testnet confidential transaction with rangeproofs & surjection proofs", () => {
		const conf = fixtures.confidential;
		const parsed = parseRawElementsTransaction(conf.raw);

		expect(parsed.txid).toBe(conf.txid);
		expect(parsed.vin).toHaveLength(2);
		expect(parsed.vin[0].witness).toBeDefined();
		expect(parsed.vin[0].witness!.length).toBeGreaterThan(0);
		expect(parsed.vout).toHaveLength(4);
		// Confidential outputs should have undefined explicit value/asset
		expect(parsed.vout[0].scriptPubKey).toBe(conf.vout[0].scriptpubkey);
		expect(parsed.vout[1].scriptPubKey).toBe(conf.vout[1].scriptpubkey);
		expect(parsed.vout[2].scriptPubKey).toBe(conf.vout[2].scriptpubkey);
	});

	it("parses real Liquid testnet transaction with Taproot outputs", () => {
		const tap = fixtures.explicitTaproot;
		const parsed = parseRawElementsTransaction(tap.raw);

		expect(parsed.txid).toBe(tap.txid);
		expect(parsed.vin).toHaveLength(2);
		expect(parsed.vout).toHaveLength(3);
		expect(parsed.vout[0].scriptPubKey).toBe(tap.vout[0].scriptpubkey);
		expect(parsed.vout[1].scriptPubKey).toBe(tap.vout[1].scriptpubkey);
		expect(parsed.vout[0].value).toBe(1n);
		expect(parsed.vout[1].value).toBe(739821n);
	});

	it("correctly encodes and parses transactions with flag 0 (no witness)", () => {
		const encoded = encodeRawElementsTransaction({
			vin: [
				{
					txid: "33".repeat(32),
					vout: 0,
					scriptSig: "deadbeef",
					sequence: 0xffffffff,
				},
			],
			vout: [
				{
					scriptPubKeyHex: "0014" + "aa".repeat(20),
					valueSats: 50000n,
				},
			],
			locktime: 12345,
		});

		const parsed = parseRawElementsTransaction(encoded.rawHex);
		expect(parsed.txid).toBe(encoded.txid);
		expect(parsed.vin).toHaveLength(1);
		expect(parsed.vin[0].scriptsig).toBe("deadbeef");
		expect(parsed.vin[0].witness).toBeUndefined();
		expect(parsed.vout).toHaveLength(1);
		expect(parsed.vout[0].value).toBe(50000n);
	});

	it("correctly encodes and parses transactions with flag 1 (witness present)", () => {
		const encoded = encodeRawElementsTransaction({
			vin: [
				{
					txid: "44".repeat(32),
					vout: 1,
					scriptSig: "",
					sequence: 0xffffffff,
					witness: ["00", "02" + "bb".repeat(32)],
				},
			],
			vout: [
				{
					scriptPubKeyHex: "5120" + "cc".repeat(32),
					valueSats: 99000n,
				},
			],
			locktime: 0,
		});

		const parsed = parseRawElementsTransaction(encoded.rawHex);
		expect(parsed.txid).toBe(encoded.txid);
		expect(parsed.vin).toHaveLength(1);
		expect(parsed.vin[0].witness).toBeDefined();
		expect(parsed.vin[0].witness).toEqual(["00", "02" + "bb".repeat(32)]);
		expect(parsed.vout).toHaveLength(1);
		expect(parsed.vout[0].value).toBe(99000n);
	});

	it("correctly handles transactions with issuance inputs", () => {
		const encoded = encodeRawElementsTransaction({
			vin: [
				{
					txid: "55".repeat(32),
					vout: 0,
					isIssuance: true,
					sequence: 0xffffffff,
				},
			],
			vout: [
				{
					scriptPubKeyHex: "5120" + "ee".repeat(32),
					valueSats: 21000000n,
				},
			],
		});

		const parsed = parseRawElementsTransaction(encoded.rawHex);
		expect(parsed.txid).toBe(encoded.txid);
		expect(parsed.vin).toHaveLength(1);
		expect(parsed.vin[0].vout).toBe(0); // Flag stripped from vout
		expect(parsed.vout[0].value).toBe(21000000n);
	});

	it("correctly handles transactions with peg-in inputs", () => {
		const encoded = encodeRawElementsTransaction({
			vin: [
				{
					txid: "66".repeat(32),
					vout: 2,
					isPegin: true,
					sequence: 0xffffffff,
				},
			],
			vout: [
				{
					scriptPubKeyHex: "5120" + "ff".repeat(32),
					valueSats: 1000000n,
				},
			],
		});

		const parsed = parseRawElementsTransaction(encoded.rawHex);
		expect(parsed.txid).toBe(encoded.txid);
		expect(parsed.vin).toHaveLength(1);
		expect(parsed.vin[0].isPegin).toBe(true);
		expect(parsed.vin[0].vout).toBe(2);
	});

	it("compactSizeHex round-trips through readVarint at every width boundary", () => {
		for (const n of [0, 0xfc, 0xfd, 0xffff, 0x10000, 0xffffffff, 0x100000000]) {
			const reader = new ByteReader(hexToBytes(compactSizeHex(n)));
			expect(reader.readVarint()).toBe(n);
			expect(reader.remaining).toBe(0);
		}
		expect(compactSizeHex(0xfd)).toBe("fdfd00");
		expect(() => compactSizeHex(-1)).toThrow();
	});

	it("encodes 253 outputs and a 253-byte scriptSig, which need a multi-byte varint", () => {
		const scriptSig = "51".repeat(253);
		const { rawHex, txid } = encodeRawElementsTransaction({
			vin: [{ scriptSig, txid: "11".repeat(32), vout: 0, witness: ["aa".repeat(300)] }],
			vout: Array.from({ length: 253 }, (_, i) => ({
				scriptPubKeyHex: "5120" + i.toString(16).padStart(64, "0"),
				valueSats: 1000n,
			})),
		});

		const parsed = parseRawElementsTransaction(rawHex);
		expect(parsed.txid).toBe(txid);
		expect(parsed.vout).toHaveLength(253);
		expect(parsed.vin[0]!.scriptsig).toBe(scriptSig);
		expect(parsed.vin[0]!.witness).toEqual(["aa".repeat(300)]);
	});

	it("rejects transactions with trailing bytes", () => {
		const encoded = encodeRawElementsTransaction({
			vin: [{ txid: "77".repeat(32), vout: 0 }],
			vout: [{ scriptPubKeyHex: "5120" + "00".repeat(32), valueSats: 1000n }],
		});

		expect(() => parseRawElementsTransaction(encoded.rawHex + "deadbeef")).toThrow(
			"Trailing bytes after Elements transaction",
		);
	});

	it("rejects unsupported Elements tx flags", () => {
		const encoded = encodeRawElementsTransaction({
			vin: [{ txid: "88".repeat(32), vout: 0 }],
			vout: [{ scriptPubKeyHex: "5120" + "11".repeat(32), valueSats: 2000n }],
		});

		// Corrupt the flags byte (offset 4, hex chars 8..9) to 0x02
		const corrupted = encoded.rawHex.slice(0, 8) + "02" + encoded.rawHex.slice(10);
		expect(() => parseRawElementsTransaction(corrupted)).toThrow("Unsupported Elements tx flags");
	});
});

describe("parseRawElementsBlock", () => {
	for (const fixture of liquidBlocks) {
		it(`parses a real ${fixture.network} block: hash, height, parent and txids match the explorer`, () => {
			const block = parseRawElementsBlock(hexToBytes(fixture.rawHex));

			expect(block.blockHash).toBe(fixture.blockHash);
			expect(block.height).toBe(fixture.height);
			expect(block.prevBlockHash).toBe(fixture.prevBlockHash);
			expect(block.txs.map((t) => t.tx.txid)).toEqual(fixture.txids);
			for (const { rawHex, tx } of block.txs) {
				expect(parseRawElementsTransaction(rawHex)).toEqual(tx);
			}
		});
	}

	const [mainnet] = liquidBlocks.filter((b) => b.network === "liquid");

	it("rejects a transaction that does not hash to the header's merkle root", () => {
		const block = parseRawElementsBlock(hexToBytes(mainnet.rawHex));
		const second = block.txs[1].rawHex;
		const offset = mainnet.rawHex.indexOf(second);
		expect(offset).toBeGreaterThan(0);
		// Bump the second transaction's version: a valid encoding with a different txid.
		const tampered = mainnet.rawHex.slice(0, offset) + "03" + mainnet.rawHex.slice(offset + 2);

		expect(() => parseRawElementsBlock(hexToBytes(tampered))).toThrow("merkle root");
	});

	it("rejects truncated and trailing data", () => {
		const raw = hexToBytes(mainnet.rawHex);

		expect(() => parseRawElementsBlock(raw.slice(0, raw.length - 1))).toThrow();
		expect(() => parseRawElementsBlock(hexToBytes(bytesToHex(raw) + "00"))).toThrow(
			"Trailing bytes after Elements block",
		);
	});
});

describe("encodeRawElementsBlock", () => {
	it("round-trips through parseRawElementsBlock", () => {
		const coinbase = encodeRawElementsTransaction({
			vin: [{ isCoinbase: true, txid: "00".repeat(32), vout: 0xffffffff }],
			vout: [{ scriptPubKeyHex: "6a", valueSats: 0 }],
		});
		const spend = encodeRawElementsTransaction({
			vin: [{ txid: "11".repeat(32), vout: 1, witness: ["", "22".repeat(33)] }],
			vout: [{ scriptPubKeyHex: "5120" + "33".repeat(32), valueSats: 1000 }],
		});
		const prevBlockHash = "44".repeat(32);

		const encoded = encodeRawElementsBlock({
			height: 7,
			prevBlockHash,
			txs: [coinbase.rawHex, spend.rawHex],
		});
		const block = parseRawElementsBlock(hexToBytes(encoded.rawHex));

		expect(block.blockHash).toBe(encoded.blockHash);
		expect(block.height).toBe(7);
		expect(block.prevBlockHash).toBe(prevBlockHash);
		expect(block.txs.map((t) => t.rawHex)).toEqual([coinbase.rawHex, spend.rawHex]);
		expect(block.txs.map((t) => t.tx.txid)).toEqual([coinbase.txid, spend.txid]);
	});
});
