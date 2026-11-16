import type { SecureVaultStorage } from "@/core/secure-vault/types";

import { setSpStoreVaultForTesting } from "./store";

/**
 * Test-only: point the SP store at a fresh, empty in-memory vault (the store keeps SP data only
 * in the secure vault). Returns the backing map so a test can inspect what was persisted.
 */
export function useMemorySpStore(): Map<string, string> {
	const memory = new Map<string, string>();
	const storage: SecureVaultStorage = {
		deleteItem: async (key) => {
			memory.delete(key);
		},
		getItem: async (key) => memory.get(key) ?? null,
		setItem: async (key, value) => {
			memory.set(key, value);
		},
		updateItem: async (key, update) => {
			const next = update(memory.get(key) ?? null);
			memory.set(key, next);
			return next;
		},
	};
	setSpStoreVaultForTesting(storage);
	return memory;
}
