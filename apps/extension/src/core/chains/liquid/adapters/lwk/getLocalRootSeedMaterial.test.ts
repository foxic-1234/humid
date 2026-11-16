import { describe, expect, it } from "bun:test";

import { addImportedSeedToKeyManagerState } from "@/core/key-manager/state/import-seed";
import { createLocalRootKeyManagerState } from "@/core/key-manager/state/local-root";

import { getWalletCreatedAt, isRestoredKeySource } from "./getLocalRootSeedMaterial";

const SEED = "abandon ".repeat(11) + "about";

describe("isRestoredKeySource", () => {
	it("is true for a local root restored from a recovery phrase", () => {
		const state = createLocalRootKeyManagerState({ seedMaterial: SEED, source: "imported" });

		expect(isRestoredKeySource(state)).toBe(true);
	});

	it("is false for a local root generated here, and by default", () => {
		expect(
			isRestoredKeySource(
				createLocalRootKeyManagerState({ seedMaterial: SEED, source: "generated" }),
			),
		).toBe(false);
		expect(isRestoredKeySource(createLocalRootKeyManagerState({ seedMaterial: SEED }))).toBe(false);
	});
});

describe("getWalletCreatedAt", () => {
	const CREATED_AT = Date.UTC(2024, 2, 1);

	it("is the date given for a restored local root", () => {
		const state = createLocalRootKeyManagerState({
			seedMaterial: SEED,
			source: "imported",
			walletCreatedAt: CREATED_AT,
		});

		expect(getWalletCreatedAt(state)).toBe(CREATED_AT);
	});

	it("is the date given for a wallet imported next to another", () => {
		const root = createLocalRootKeyManagerState({ seedMaterial: SEED, source: "generated" });
		const state = addImportedSeedToKeyManagerState(root, {
			seedMaterial: SEED,
			walletCreatedAt: CREATED_AT,
		});
		const imported = Object.values(state.accountModel.keySources).find(
			(record) => record.kind === "imported-mnemonic",
		);

		expect(getWalletCreatedAt(state, imported!.id)).toBe(CREATED_AT);
		expect(getWalletCreatedAt(state)).toBeUndefined();
	});

	it("is none without a date, and for a generated seed even with one", () => {
		expect(
			getWalletCreatedAt(
				createLocalRootKeyManagerState({ seedMaterial: SEED, source: "imported" }),
			),
		).toBeUndefined();
		expect(
			getWalletCreatedAt(
				createLocalRootKeyManagerState({
					seedMaterial: SEED,
					source: "generated",
					walletCreatedAt: CREATED_AT,
				}),
			),
		).toBeUndefined();
	});
});
