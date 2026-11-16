import { beforeEach, describe, expect, mock, test } from "bun:test";

import {
	blech32mDecode,
	computeLabelTweak,
	encodeSilentPaymentAddress,
	toP2wpkhScriptPubKeyHex,
} from "@humid/sp-core";
import { secp256k1 } from "@noble/curves/secp256k1.js";
import { bytesToHex } from "@noble/hashes/utils.js";

const POLICY = "6f0279e9ed041c3d710a9f57d0c02928416460c4b722ae3457a11eec381c526d";
const TOKEN = "22".repeat(32);
const CHAIN_ID = "bip122:liquid-testnet";

// The sending account's SP keys. Tracked SP UTXOs below pay P = (b_spend + t_k)·G with t_k = 0x33…33.
const SCAN_PRIV = new Uint8Array(32).fill(4);
const SPEND_PRIV = new Uint8Array(32).fill(5);
const OWN_SP_KEYS = {
	scanKey: { privateKey: SCAN_PRIV, publicKey: secp256k1.getPublicKey(SCAN_PRIV, true) },
	spendKey: { privateKey: SPEND_PRIV, publicKey: secp256k1.getPublicKey(SPEND_PRIV, true) },
};
const OWN_SP_ADDRESS = encodeSilentPaymentAddress(
	OWN_SP_KEYS.scanKey.publicKey,
	OWN_SP_KEYS.spendKey.publicKey,
	"testnet",
);
const SP_TWEAK_HEX = "33".repeat(32);
const SP_FIXTURE_SPK = `5120${secp256k1.Point.BASE.multiply(
	(BigInt(`0x${"05".repeat(32)}`) + BigInt(`0x${SP_TWEAK_HEX}`)) % secp256k1.CURVE.n,
)
	.toHex(true)
	.slice(2)}`;

// Someone else's SP address.
const RECIPIENT_SP =
	"tlqsp1qqvc5jg0y3w4sxdy7yedqmecfcgdplyx7acattladk6g3853k3cn0wqazpyrr39wz9k40jwgha0yqfuwv25hcr20hxyv0alkmk2d7yfgsmcvxauwz";

const WALLET_PRIV = new Uint8Array(32).fill(7);
const WALLET_PUB = secp256k1.getPublicKey(WALLET_PRIV, true);
const WALLET_SPK = toP2wpkhScriptPubKeyHex(WALLET_PUB);

/**
 * A stand-in for LWK's TxBuilder that keeps LWK's own rules: without `setWalletUtxos` it spends
 * every wallet L-BTC UTXO (and an issued asset's UTXOs until the amount is covered), it adds every
 * external UTXO, it always adds an L-BTC change output, and it fails with "Insufficient funds"
 * otherwise. The fee is 100 sats plus 50 per input.
 */
type MockOutput = { amount: bigint; asset: string; spk: string };
type Build = {
	calls: string[];
	externals: string[];
	inputs: string[];
	pinned: string[] | null;
	outputs: MockOutput[];
};

let builds: Build[] = [];
let tamperPinnedInputs: ((inputs: string[]) => string[]) | null = null;
let signedTaprootInputs: number[] = [];
let broadcastCount = 0;

const keyOf = (u: MockUtxo) => `${u.txid}:${u.vout}`;
const feeFor = (inputCount: number) => 100n + 50n * BigInt(inputCount);

type MockUtxo = { asset: string; spk: string; txid: string; value: bigint; vout: number };

function toWalletTxOut(u: MockUtxo) {
	return {
		extInt: () => 0,
		outpoint: () => ({ txid: () => ({ toString: () => u.txid }), vout: () => u.vout }),
		scriptPubkey: () => ({ toString: () => u.spk }),
		wildcardIndex: () => 0,
	};
}

class MockTxBuilder {
	private pinned: string[] | null = null;
	private externals: { asset: string; key: string; value: bigint }[] = [];
	private recipients: MockOutput[] = [];
	private drainTo: string | null = null;
	private calls: string[] = [];

	setWalletUtxos(outpoints: { toString(): string }[]) {
		this.pinned = outpoints.map((o) => o.toString());
		return this;
	}
	addExternalUtxos(utxos: { asset: string; key: string; value: bigint }[]) {
		this.externals.push(...utxos);
		return this;
	}
	addLbtcRecipient(address: MockAddress, satoshi: bigint) {
		if (!address.isBlinded()) throw new Error("Address must be confidential");
		this.calls.push(`lbtc:${satoshi}`);
		this.recipients.push({ amount: satoshi, asset: POLICY, spk: address.spk });
		return this;
	}
	addRecipient(address: MockAddress, satoshi: bigint, asset: { id: string }) {
		if (!address.isBlinded()) throw new Error("Address must be confidential");
		this.calls.push(`asset:${satoshi}`);
		this.recipients.push({ amount: satoshi, asset: asset.id, spk: address.spk });
		return this;
	}
	addExplicitRecipient(address: MockAddress, satoshi: bigint, asset: { id: string }) {
		if (address.isBlinded()) throw new Error("Address must be explicit");
		this.calls.push(`explicit:${satoshi}`);
		this.recipients.push({ amount: satoshi, asset: asset.id, spk: address.spk });
		return this;
	}
	drainLbtcWallet() {
		return this;
	}
	drainLbtcTo(address: MockAddress) {
		this.calls.push("drain");
		this.drainTo = address.spk;
		return this;
	}
	finish(wollet: MockWollet) {
		const utxos = wollet.mockUtxos;
		let walletIn: MockUtxo[];
		if (this.pinned) {
			walletIn = utxos.filter((u) => this.pinned!.includes(keyOf(u)));
		} else {
			walletIn = utxos.filter((u) => u.asset === POLICY);
			for (const asset of new Set(this.recipients.map((r) => r.asset))) {
				if (asset === POLICY) continue;
				let have = this.externals
					.filter((e) => e.asset === asset)
					.reduce((s, e) => s + e.value, 0n);
				const need = this.recipients
					.filter((r) => r.asset === asset)
					.reduce((s, r) => s + r.amount, 0n);
				for (const u of utxos.filter((u) => u.asset === asset)) {
					if (have >= need) break;
					walletIn.push(u);
					have += u.value;
				}
			}
		}

		let inputs = [...walletIn.map(keyOf), ...this.externals.map((e) => e.key)];
		if (this.pinned && tamperPinnedInputs) inputs = tamperPinnedInputs(inputs);

		const inOf = (asset: string) =>
			walletIn.filter((u) => u.asset === asset).reduce((s, u) => s + u.value, 0n) +
			this.externals.filter((e) => e.asset === asset).reduce((s, e) => s + e.value, 0n);
		const outOf = (asset: string) =>
			this.recipients.filter((r) => r.asset === asset).reduce((s, r) => s + r.amount, 0n);

		const outputs: MockOutput[] = [...this.recipients];
		for (const asset of new Set([...walletIn, ...this.externals].map((x) => x.asset))) {
			if (asset === POLICY) continue;
			if (inOf(asset) < outOf(asset))
				throw new Error(`Insufficient funds: missing units for asset ${asset}`);
			if (inOf(asset) > outOf(asset)) {
				outputs.push({ amount: inOf(asset) - outOf(asset), asset, spk: WALLET_SPK });
			}
		}
		const fee = feeFor(inputs.length);
		if (inOf(POLICY) <= outOf(POLICY) + fee) {
			throw new Error(`Insufficient funds: missing units for asset ${POLICY}`);
		}
		outputs.push({
			amount: inOf(POLICY) - outOf(POLICY) - fee,
			asset: POLICY,
			spk: this.drainTo ?? WALLET_SPK,
		});
		outputs.push({ amount: fee, asset: POLICY, spk: "" });

		builds.push({
			calls: this.calls,
			externals: this.externals.map((e) => e.key),
			inputs,
			outputs,
			pinned: this.pinned,
		});
		return makePset(inputs, outputs, fee);
	}
}

function makePset(inputs: string[], outputs: MockOutput[], fee: bigint) {
	return {
		fee,
		free: () => {},
		inputs: () =>
			inputs.map((key) => {
				const [txid, vout] = key.split(":");
				return { previousTxid: () => ({ toString: () => txid }), previousVout: () => Number(vout) };
			}),
		outputs: () =>
			outputs.map((o) => ({
				amount: () => o.amount,
				asset: () => ({ toString: () => o.asset }),
				scriptPubkey: () => ({ toString: () => o.spk }),
			})),
		signTaprootKeypath: (index: number) => {
			signedTaprootInputs.push(index);
		},
		toString: () => "pset",
	};
}

class MockAddress {
	public spk: string;
	constructor(private readonly str: string) {
		const valid = ["tlq1", "lq1", "tex1", "ex1", "irrelevant"];
		if (!valid.some((p) => str.startsWith(p))) throw new Error(`Invalid address: ${str}`);
		this.spk =
			str.startsWith("tlq1") || str.startsWith("lq1")
				? `5120${bytesToHex(blech32mDecode(str)!.witness)}`
				: `spk:${str}`;
	}
	isBlinded() {
		return !this.str.startsWith("tex1") && !this.str.startsWith("ex1");
	}
	isMainnet() {
		return this.str.startsWith("lq1") || this.str.startsWith("ex1");
	}
	toString() {
		return this.str;
	}
}

type MockWollet = ReturnType<typeof makeWollet>;

function makeWollet(utxos: MockUtxo[]) {
	return {
		balance: () => ({
			entries: () => {
				const totals = new Map<string, bigint>();
				for (const u of utxos) totals.set(u.asset, (totals.get(u.asset) ?? 0n) + u.value);
				return totals;
			},
		}),
		finalize: (pset: unknown) => pset,
		mockUtxos: utxos,
		psetDetails: (pset: { fee: bigint }) => ({
			balance: () => ({ feesIn: () => pset.fee, free: () => {} }),
			free: () => {},
		}),
		utxos: () => utxos.map(toWalletTxOut),
	};
}

// Funding transactions of tracked SP UTXOs, served by the mocked Esplora as "funding:<txid>".
const spFunding = new Map<string, { amount: bigint; asset: string }>();
let fundingFetches: string[] = [];
const realFetch = globalThis.fetch;
globalThis.fetch = (async (input: RequestInfo | URL, init?: RequestInit) => {
	const url = typeof input === "string" ? input : input instanceof URL ? input.href : input.url;
	const match = /\/tx\/([0-9a-f]{64})\/hex$/.exec(url);
	if (match) {
		fundingFetches.push(match[1]);
		return new Response(`funding:${match[1]}`);
	}
	return realFetch(input, init);
}) as typeof fetch;

mock.module("../../loadLwkWasm", () => ({
	loadLwkWasm: async () => ({
		Address: MockAddress,
		AssetId: { fromString: (id: string) => ({ id, toString: () => id }) },
		ExternalUtxo: class {
			public asset: string;
			public key: string;
			public value: bigint;
			constructor(vout: number, tx: any, secrets: any) {
				this.key = `${tx.txid().toString()}:${vout}`;
				this.asset = secrets.asset().toString();
				this.value = secrets.value();
			}
		},
		OutPoint: class {
			constructor(private readonly str: string) {}
			toString() {
				return this.str;
			}
		},
		Transaction: class {
			private readonly txidHex: string;
			constructor(hex: string) {
				this.txidHex = hex.replace(/^funding:/, "");
			}
			txid() {
				return { toString: () => this.txidHex };
			}
			output(vout: number) {
				const funding = spFunding.get(`${this.txidHex}:${vout}`);
				if (!funding) return undefined;
				return {
					asset: () => ({ toString: () => funding.asset }),
					scriptPubkey: () => ({ toString: () => SP_FIXTURE_SPK }),
					value: () => funding.amount,
				};
			}
		},
		TxBuilder: MockTxBuilder,
		TxOutSecrets: {
			fromExplicit: (asset: any, value: bigint) => ({ asset: () => asset, value: () => value }),
		},
	}),
}));

mock.module("../../sync-worker/createSyncWorkerClient", () => ({
	getSyncWorkerClient: () => ({
		broadcast: async () => {
			broadcastCount++;
			return { txid: "aa".repeat(32) };
		},
	}),
}));

const { deriveSpSpendingPrivateKey, estimateMaxSend, inspectTransfer, sendTransfer } =
	await import("./index");
const { getTrackedSilentPaymentUtxos, saveTrackedSilentPaymentUtxo } =
	await import("../../../../silent-payments");

beforeEach(async () => {
	const { useMemorySpStore } = await import("../../../../silent-payments/storeTestStorage");
	useMemorySpStore();
	builds = [];
	tamperPinnedInputs = null;
	signedTaprootInputs = [];
	broadcastCount = 0;
	spFunding.clear();
	fundingFetches = [];
});

const walletUtxo = (txid: string, value: bigint, asset = POLICY): MockUtxo => ({
	asset,
	spk: WALLET_SPK,
	txid,
	value,
	vout: 0,
});

function makeAccount(
	utxos: MockUtxo[],
	overrides: { deriveInputKey?: unknown; withSp?: boolean } = {},
) {
	const withSp = overrides.withSp ?? true;
	return {
		accountIdentifier: "acct",
		chain: { id: CHAIN_ID, settings: { explorerUrl: "https://explorer.mock", network: "testnet" } },
		chainId: CHAIN_ID,
		implementation: {
			deriveInputKey:
				"deriveInputKey" in overrides
					? overrides.deriveInputKey
					: () => ({ privateKey: new Uint8Array(WALLET_PRIV), publicKey: WALLET_PUB }),
			network: {},
			signer: { sign: (pset: unknown) => pset },
			wollet: makeWollet(utxos),
		},
		policyAssetId: `${CHAIN_ID}/asset:${POLICY}`,
		rawPolicyAssetId: POLICY,
		...(withSp ? { silentPaymentAddress: OWN_SP_ADDRESS, silentPaymentKeys: OWN_SP_KEYS } : {}),
	} as never;
}

/** Track an SP UTXO of the account, with its funding output served by the mocked Esplora. */
async function trackSpUtxo(txid: string, amount: bigint, asset = POLICY) {
	spFunding.set(`${txid}:0`, { amount, asset });
	await saveTrackedSilentPaymentUtxo({
		address: `tex1p${txid.slice(0, 8)}`,
		amountSats: amount.toString(),
		chainId: CHAIN_ID,
		createdAt: Date.now(),
		outputIndex: 0,
		rawAssetId: asset,
		recipientAddress: OWN_SP_ADDRESS,
		scriptPubKeyHex: SP_FIXTURE_SPK,
		spent: false,
		tweakHex: SP_TWEAK_HEX,
		txid,
	});
}

const W1 = "11".repeat(32);
const W2 = "12".repeat(32);
const SP_SMALL = "31".repeat(32);
const SP_LARGE = "32".repeat(32);
const finalBuild = () => builds[builds.length - 1];

describe("which builder call a recipient gets", () => {
	test("a confidential recipient takes the ordinary L-BTC path", async () => {
		await sendTransfer(
			makeAccount([walletUtxo(W1, 100000n)]),
			{ amount: "5000", recipientAddress: "irrelevant" } as never,
			POLICY,
		);
		expect(builds).toHaveLength(1);
		expect(finalBuild().calls).toEqual(["lbtc:5000"]);
	});

	// Without this the wallet cannot pay an explicit output at all, and a contract action can
	// only spend an explicit one — so nobody could fund one, including from their own wallet.
	test("an unconfidential recipient takes the explicit path", async () => {
		await sendTransfer(
			makeAccount([walletUtxo(W1, 100000n)]),
			{ amount: "5000", recipientAddress: "tex1explicit" } as never,
			POLICY,
		);
		expect(finalBuild().calls).toEqual(["explicit:5000"]);
	});

	test("a confidential recipient of an issued asset keeps the ordinary asset path", async () => {
		await sendTransfer(
			makeAccount([walletUtxo(W1, 100000n), walletUtxo(W2, 100000n, TOKEN)]),
			{ amount: "5000", recipientAddress: "irrelevant" } as never,
			TOKEN,
		);
		expect(finalBuild().calls).toEqual(["asset:5000"]);
	});

	test("an unconfidential recipient of an issued asset takes the same explicit path", async () => {
		await sendTransfer(
			makeAccount([walletUtxo(W1, 100000n), walletUtxo(W2, 100000n, TOKEN)]),
			{ amount: "5000", recipientAddress: "tex1explicit" } as never,
			TOKEN,
		);
		expect(finalBuild().calls).toEqual(["explicit:5000"]);
	});

	test("sending all takes the address as it is, either way", async () => {
		for (const recipientAddress of ["tex1explicit", "irrelevant"]) {
			builds = [];
			await sendTransfer(
				makeAccount([walletUtxo(W1, 100000n)]),
				{ amount: "0", recipientAddress, sendAll: true } as never,
				POLICY,
			);
			expect(finalBuild().calls).toEqual(["drain"]);
		}
	});

	test("a silent payment recipient takes the confidential L-BTC path, with SP change on label m = 0", async () => {
		await sendTransfer(
			makeAccount([walletUtxo(W1, 100000n)]),
			{ amount: "5000", recipientAddress: RECIPIENT_SP } as never,
			POLICY,
		);
		expect(finalBuild().calls).toEqual(["lbtc:5000", "drain"]);

		const [change] = await getTrackedSilentPaymentUtxos();
		expect(change.labelIndex).toBe(0);
		expect(change.recipientAddress).toBe(OWN_SP_ADDRESS);
		expect(change.amountSats).toBe((100000n - 5000n - feeFor(1)).toString());
		expect(finalBuild().outputs[change.outputIndex].spk).toBe(change.scriptPubKeyHex);
	});

	test("rejects a transaction whose L-BTC change is below the dust limit", async () => {
		// 5,650 - 5,000 - 150 fee = 500 sats of change.
		await expect(
			sendTransfer(
				makeAccount([walletUtxo(W1, 5650n)]),
				{ amount: "5000", recipientAddress: "irrelevant" } as never,
				POLICY,
			),
		).rejects.toThrow(/Transaction produces a dust output of 500 satoshis/);
		expect(broadcastCount).toBe(0);
	});
});

describe("two builds for an ELIP-352 output", () => {
	test("the final build pins the wallet inputs of the first and carries the real P_k", async () => {
		await sendTransfer(
			makeAccount([walletUtxo(W1, 4000n), walletUtxo(W2, 100000n)]),
			{ amount: "5000", recipientAddress: RECIPIENT_SP } as never,
			POLICY,
		);

		expect(builds).toHaveLength(2);
		const [placeholder, final] = builds;
		expect(placeholder.pinned).toBeNull();
		expect(final.pinned?.sort()).toEqual([`${W1}:0`, `${W2}:0`]);
		expect(final.inputs.sort()).toEqual(placeholder.inputs.sort());
		// Same input set and same-size outputs give the same fee.
		expect(final.outputs.at(-1)!.amount).toBe(placeholder.outputs.at(-1)!.amount);
		expect(final.outputs[0].spk).not.toBe(placeholder.outputs[0].spk);
	});

	test("rejects before signing if the final PSET inputs diverge from those used for A", async () => {
		tamperPinnedInputs = (inputs) => [...inputs, `${"77".repeat(32)}:1`];

		await expect(
			sendTransfer(
				makeAccount([walletUtxo(W1, 100000n)]),
				{ amount: "5000", recipientAddress: RECIPIENT_SP } as never,
				POLICY,
			),
		).rejects.toThrow(/final PSET inputs do not match inputs used for tweak derivation/);
		expect(broadcastCount).toBe(0);
	});
});

describe("Silent Payment UTXOs are spent only when the wallet falls short", () => {
	test("a wallet that can pay alone leaves SP UTXOs untouched", async () => {
		await trackSpUtxo(SP_LARGE, 50000n);

		await sendTransfer(
			makeAccount([walletUtxo(W1, 100000n)]),
			{ amount: "5000", recipientAddress: "irrelevant" } as never,
			POLICY,
		);

		expect(builds.every((b) => b.externals.length === 0)).toBe(true);
		// The SP funding transaction was never even fetched from the explorer.
		expect(fundingFetches).toEqual([]);
		const [sp] = await getTrackedSilentPaymentUtxos();
		expect(sp.spent).toBe(false);
	});

	test("a short wallet adds as few SP UTXOs as cover the gap, largest first", async () => {
		await trackSpUtxo(SP_SMALL, 3000n);
		await trackSpUtxo(SP_LARGE, 20000n);

		await sendTransfer(
			makeAccount([walletUtxo(W1, 4000n)]),
			{ amount: "10000", recipientAddress: "irrelevant" } as never,
			POLICY,
		);

		expect(finalBuild().externals).toEqual([`${SP_LARGE}:0`]);
		expect(signedTaprootInputs).toEqual([finalBuild().inputs.indexOf(`${SP_LARGE}:0`)]);
		const tracked = await getTrackedSilentPaymentUtxos();
		expect(tracked.find((u) => u.txid === SP_LARGE)?.spent).toBe(true);
		expect(tracked.find((u) => u.txid === SP_SMALL)?.spent).toBe(false);
	});

	test("sending everything spends every SP UTXO", async () => {
		await trackSpUtxo(SP_SMALL, 3000n);
		await trackSpUtxo(SP_LARGE, 20000n);

		await sendTransfer(
			makeAccount([walletUtxo(W1, 4000n)]),
			{ amount: "0", recipientAddress: "irrelevant", sendAll: true } as never,
			POLICY,
		);

		expect(finalBuild().externals.sort()).toEqual([`${SP_SMALL}:0`, `${SP_LARGE}:0`]);
	});

	test("an issued asset is taken from SP UTXOs and the fee from wallet L-BTC", async () => {
		await trackSpUtxo(SP_LARGE, 10000n, TOKEN);
		await trackSpUtxo(SP_SMALL, 5000n);

		await sendTransfer(
			makeAccount([walletUtxo(W1, 50000n)]),
			{ amount: "4000", recipientAddress: RECIPIENT_SP } as never,
			TOKEN,
		);

		expect(finalBuild().calls[0]).toBe("asset:4000");
		expect(finalBuild().externals).toEqual([`${SP_LARGE}:0`]);
	});

	test("rejects an amount above the wallet plus SP balance before building", async () => {
		await trackSpUtxo(SP_LARGE, 1000n);

		await expect(
			sendTransfer(
				makeAccount([walletUtxo(W1, 4000n)]),
				{ amount: "6000", recipientAddress: "irrelevant" } as never,
				POLICY,
			),
		).rejects.toThrow(/exceeds total available balance \(5000 sats\)/);
		expect(builds).toHaveLength(0);
	});

	test("reports missing L-BTC for the fee of an issued-asset send", async () => {
		await trackSpUtxo(SP_LARGE, 10000n, TOKEN);

		await expect(
			sendTransfer(
				makeAccount([]),
				{ amount: "4000", recipientAddress: RECIPIENT_SP } as never,
				TOKEN,
			),
		).rejects.toThrow(
			/Insufficient funds: not enough to cover the transfer amount plus network fees/,
		);
	});

	test("SP UTXOs of another account are never selected", async () => {
		spFunding.set(`${SP_LARGE}:0`, { amount: 50000n, asset: POLICY });
		await saveTrackedSilentPaymentUtxo({
			address: "tex1pother",
			amountSats: "50000",
			chainId: CHAIN_ID,
			createdAt: Date.now(),
			outputIndex: 0,
			rawAssetId: POLICY,
			recipientAddress: "tlqsp1otheraccount",
			scriptPubKeyHex: SP_FIXTURE_SPK,
			spent: false,
			tweakHex: SP_TWEAK_HEX,
			txid: SP_LARGE,
		});

		await expect(
			sendTransfer(
				makeAccount([walletUtxo(W1, 4000n)]),
				{ amount: "10000", recipientAddress: "irrelevant" } as never,
				POLICY,
			),
		).rejects.toThrow(/exceeds total available balance/);
	});
});

describe("wallet input keys used for the ELIP-352 aggregate", () => {
	const sendToSp = (deriveInputKey: unknown, spk = WALLET_SPK) =>
		sendTransfer(
			makeAccount([{ ...walletUtxo(W1, 100000n), spk }], { deriveInputKey }),
			{ amount: "5000", recipientAddress: RECIPIENT_SP } as never,
			POLICY,
		);

	test("rejects if deriveInputKey is missing from account implementation", async () => {
		await expect(sendToSp(undefined)).rejects.toThrow(/does not support key derivation/);
	});

	test("rejects if deriveInputKey fails to derive a key for UTXO", async () => {
		await expect(sendToSp(() => null)).rejects.toThrow(/failed to derive key for UTXO/);
	});

	test("rejects if derived public key does not match UTXO scriptPubKey", async () => {
		await expect(
			sendToSp(
				() => ({ privateKey: new Uint8Array(WALLET_PRIV), publicKey: WALLET_PUB }),
				"0014" + "aa".repeat(20),
			),
		).rejects.toThrow(/derived public key does not match scriptPubKey/);
	});

	test("rejects if deriveInputKey returns public key that does not match private key · G", async () => {
		const mismatchedPub = secp256k1.Point.BASE.multiply(2n).toRawBytes(true);
		await expect(
			sendToSp(
				() => ({ privateKey: new Uint8Array(32).fill(1), publicKey: mismatchedPub }),
				toP2wpkhScriptPubKeyHex(mismatchedPub),
			),
		).rejects.toThrow(/derived public key does not match private key · G/);
	});

	test("normalizes odd-y Taproot input keys", async () => {
		const privOdd = secp256k1.CURVE.n - 1n;
		const privBytes = new Uint8Array(32);
		for (let i = 31, v = privOdd; i >= 0; i--, v >>= 8n) privBytes[i] = Number(v & 0xffn);
		const pubOdd = secp256k1.getPublicKey(privBytes, true);
		expect(pubOdd[0]).toBe(0x03);

		await expect(
			sendToSp(
				() => ({ privateKey: new Uint8Array(privBytes), publicKey: pubOdd }),
				`5120${bytesToHex(pubOdd.slice(1))}`,
			),
		).resolves.toEqual({ txid: "aa".repeat(32) });
	});

	test("every derived private key buffer is zeroized afterwards", async () => {
		const handedOut: Uint8Array[] = [];
		await sendToSp(() => {
			const privateKey = new Uint8Array(WALLET_PRIV);
			handedOut.push(privateKey);
			return { privateKey, publicKey: WALLET_PUB };
		});

		expect(handedOut.length).toBeGreaterThan(0);
		expect(handedOut.every((key) => key.every((b) => b === 0))).toBe(true);
	});
});

describe("ELIP-352 Silent Payment address validation on send", () => {
	const account = makeAccount([walletUtxo(W1, 100000n)]);
	const send = (recipientAddress: string) =>
		sendTransfer(account, { amount: "5000", recipientAddress } as never, POLICY);

	test("rejects Bitcoin and legacy SP addresses and raw hex", async () => {
		for (const address of [
			"sp1qqvc5jg0y3w4sxdy7yedqmecfcgdplyx7acattladk6g3853k3cn0wqazpyrr39wz9k40jwgha0yqfuwv25hcr20hxyv0alkmk2d7yfgsmchp74y4",
			"tsp1qqvc5jg0y3w4sxdy7yedqmecfcgdplyx7acattladk6g3853k3cn0wqazpyrr39wz9k40jwgha0yqfuwv25hcr20hxyv0alkmk2d7yfgsmcrw7qww",
			"tlsp1qqpnzjfpuj96kqe5ncn95r08p8pp58usmmhr4d0l4kmfzy7jx68zdacr5gysvwy4cgk647fezl4usp83e32jlqdf7uc33lh7mwefhc39zr0qwq93f9",
			"034f355bdcb7cc0af728ef3cceb9615d90684bb5b2ca5f859ab0f0b704075871aa02466d7fcae563e5cb09a0d1870bb580344804617879a14949cf22285f1bae3f27",
		]) {
			await expect(send(address)).rejects.toThrow(/Invalid Liquid recipient address/);
		}
	});

	test("rejects network mismatch (mainnet lqsp1... on testnet account)", async () => {
		await expect(
			send(
				"lqsp1qqvc5jg0y3w4sxdy7yedqmecfcgdplyx7acattladk6g3853k3cn0wqazpyrr39wz9k40jwgha0yqfuwv25hcr20hxyv0alkmk2d7yfgsmcr7hsm3",
			),
		).rejects.toThrow(/network does not match the connected chain/);
	});

	test("inspectTransfer applies the same validation and marks SP recipients", async () => {
		const review = await inspectTransfer(
			account,
			{ amount: "5000", recipientAddress: RECIPIENT_SP } as never,
			POLICY,
		);
		expect(review.isSilentPayment).toBe(true);
		expect(review.recipientConfidential).toBe(true);

		await expect(
			inspectTransfer(account, { amount: "100", recipientAddress: RECIPIENT_SP } as never, POLICY),
		).rejects.toThrow(/below the network dust limit/);
	});
});

describe("deriveSpSpendingPrivateKey: key must commit to the UTXO Taproot output", () => {
	const tk = BigInt(`0x${SP_TWEAK_HEX}`);
	const changeLabelTweak = computeLabelTweak(SCAN_PRIV, 0);
	const labeledSpk = `5120${secp256k1.Point.BASE.multiply(
		(BigInt(`0x${"05".repeat(32)}`) + tk + changeLabelTweak) % secp256k1.CURVE.n,
	)
		.toHex(true)
		.slice(2)}`;
	const labeledChange = {
		address: "tex1p_change",
		amountSats: "1000",
		chainId: CHAIN_ID,
		createdAt: 0,
		outputIndex: 1,
		rawAssetId: POLICY,
		recipientAddress: OWN_SP_ADDRESS,
		scriptPubKeyHex: labeledSpk,
		spent: false,
		tweakHex: SP_TWEAK_HEX,
		txid: "ab".repeat(32),
	};

	test("derives a key matching the output when the change label tweak is stored", () => {
		const key = deriveSpSpendingPrivateKey(SPEND_PRIV, {
			...labeledChange,
			labelIndex: 0,
			labelTweakHex: changeLabelTweak.toString(16).padStart(64, "0"),
		});
		expect(bytesToHex(secp256k1.getPublicKey(key, true).slice(1))).toBe(labeledSpk.slice(4));
	});

	test("rejects before signing when the label tweak is missing", () => {
		expect(() => deriveSpSpendingPrivateKey(SPEND_PRIV, labeledChange)).toThrow(
			"derived spending key does not match its Taproot output key",
		);
	});
});

describe("estimateMaxSend", () => {
	test("L-BTC: wallet plus the account's SP UTXOs, minus the drain fee", async () => {
		await trackSpUtxo(SP_LARGE, 20000n);

		const result = await estimateMaxSend(
			makeAccount([walletUtxo(W1, 4000n)]),
			{ recipientAddress: "irrelevant" } as never,
			POLICY,
		);

		expect(result.feeSats).toBe(feeFor(2).toString());
		expect(result.maxAmount).toBe((24000n - feeFor(2)).toString());
	});

	test("an issued asset counts only the account's own SP UTXOs", async () => {
		await trackSpUtxo(SP_LARGE, 1500n, TOKEN);
		await saveTrackedSilentPaymentUtxo({
			address: "tex1pother",
			amountSats: "9000",
			chainId: CHAIN_ID,
			createdAt: Date.now(),
			outputIndex: 0,
			rawAssetId: TOKEN,
			recipientAddress: "tlqsp1otheraccount",
			scriptPubKeyHex: SP_FIXTURE_SPK,
			spent: false,
			tweakHex: SP_TWEAK_HEX,
			txid: SP_SMALL,
		});

		const own = await estimateMaxSend(
			makeAccount([]),
			{ recipientAddress: "irrelevant" } as never,
			TOKEN,
		);
		expect(own).toEqual({ feeSats: "0", maxAmount: "1500" });

		const noSp = await estimateMaxSend(
			makeAccount([], { withSp: false }),
			{ recipientAddress: "irrelevant" } as never,
			TOKEN,
		);
		expect(noSp.maxAmount).toBe("0");
	});
});
