import { loadLwkWasm } from "../adapters/lwk/loadLwkWasm";

export type UnblindedOutput = {
	amountSats: string;
	assetBlindingFactorHex?: string;
	rawAssetId: string;
	valueBlindingFactorHex?: string;
};

/**
 * Unblind output `outputIndex` of `rawTxHex` with the ELIP-352 blinding key bk_k. An explicit
 * output is returned as is. Returns null when the output is missing or cannot be unblinded.
 */
export async function unblindConfidentialOutput(
	rawTxHex: string,
	outputIndex: number,
	blindingPrivateKey: Uint8Array,
): Promise<UnblindedOutput | null> {
	const owned: { free(): void }[] = [];
	const own = <T extends { free(): void }>(obj: T): T => {
		owned.push(obj);
		return obj;
	};

	try {
		const lwk = await loadLwkWasm();
		const tx = own(lwk.Transaction.fromString(rawTxHex));
		const txOutRaw = tx.output(outputIndex);
		if (!txOutRaw) return null;
		const txOut = own(txOutRaw);

		if (!txOut.isPartiallyBlinded()) {
			const value = txOut.value();
			const assetRaw = txOut.asset();
			if (value === undefined || !assetRaw) return null;
			return { amountSats: String(value), rawAssetId: own(assetRaw).toString() };
		}

		const secretKey = own(lwk.SecretKey.fromBytes(blindingPrivateKey));
		const secrets = own(txOut.unblind(secretKey));
		return {
			amountSats: String(secrets.value()),
			assetBlindingFactorHex: own(secrets.assetBlindingFactor()).toString(),
			rawAssetId: own(secrets.asset()).toString(),
			valueBlindingFactorHex: own(secrets.valueBlindingFactor()).toString(),
		};
	} catch (err) {
		console.warn(
			`[sp-unblind] Unblind failed for output ${outputIndex}: ${err instanceof Error ? err.message : String(err)}`,
		);
		return null;
	} finally {
		for (const obj of owned.reverse()) {
			try {
				obj.free();
			} catch {
				// Already freed by wasm-bindgen.
			}
		}
	}
}
