const storageMap = new Map<string, any>();
const mockStorageLocal = {
	get: async (keys?: any) => {
		if (!keys) return Object.fromEntries(storageMap.entries());
		if (typeof keys === "string") return { [keys]: storageMap.get(keys) };
		if (Array.isArray(keys)) {
			const res: Record<string, any> = {};
			for (const k of keys) res[k] = storageMap.get(k);
			return res;
		}
		const res: Record<string, any> = {};
		for (const [k, defaultVal] of Object.entries(keys)) {
			res[k] = storageMap.has(k) ? storageMap.get(k) : defaultVal;
		}
		return res;
	},
	set: async (items: Record<string, any>) => {
		for (const [k, v] of Object.entries(items)) {
			storageMap.set(k, v);
		}
	},
	remove: async (keys: string | string[]) => {
		const arr = Array.isArray(keys) ? keys : [keys];
		for (const k of arr) storageMap.delete(k);
	},
	clear: async () => {
		storageMap.clear();
	},
};

(globalThis as any).chrome = {
	runtime: { id: "test-runtime" },
	storage: { local: mockStorageLocal },
};
(globalThis as any).browser = (globalThis as any).chrome;

import { afterAll, beforeEach, describe, expect, it } from "bun:test";

import { setSpStoreVaultForTesting } from "./index";
import { useMemorySpStore } from "./storeTestStorage";

describe("Extension integration", () => {
	beforeEach(async () => {
		(globalThis as any).chrome = {
			runtime: { id: "test-runtime" },
			storage: { local: mockStorageLocal },
		};
		(globalThis as any).browser = (globalThis as any).chrome;
		storageMap.clear();
		useMemorySpStore();
	});

	afterAll(() => {
		setSpStoreVaultForTesting(null);
	});

	describe("onWalletUnlocked hook in internal RPC", () => {
		it("triggers onWalletUnlocked when wallet is unlocked", async () => {
			const { createInternalRpcHandlers } =
				await import("@/core/extension-background/internal-rpc");
			const { walletVaultRpc } =
				await import("@/core/secure-vault/application/wallet-vault/model/rpc");
			const { walletVaultBackground } =
				await import("@/core/secure-vault/application/wallet-vault/background");

			const originalUnlock = walletVaultBackground.unlock;
			walletVaultBackground.unlock = async () => ({
				hasVault: true,
				isUnlocked: true,
			});

			try {
				let unlockedCalled = false;
				const handlers = createInternalRpcHandlers({
					chainGroups: [],
					confirmations: { confirm: async () => ({ approved: true }) } as any,
					estimateMaxSend: async () => ({}) as any,
					getActivity: async () => ({}) as any,
					getPortfolio: async () => ({}) as any,
					getReceiveAddress: async () => ({}) as any,
					inspectTransfer: async () => ({}) as any,
					purgeAccountPortfolio: async () => {},
					purgeAccountWalletConnectSessions: async () => {},
					refreshPortfolio: async () => ({}) as any,
					sendTransfer: async () => ({}) as any,
					onWalletUnlocked: () => {
						unlockedCalled = true;
					},
				});

				const unlockHandler = handlers[walletVaultRpc.methods.unlock];
				expect(unlockHandler).toBeDefined();

				await unlockHandler(
					{ data: { passphrase: "test" }, method: walletVaultRpc.methods.unlock } as any,
					{} as any,
				);

				expect(unlockedCalled).toBe(true);
			} finally {
				walletVaultBackground.unlock = originalUnlock;
			}
		}, 15000);
	});
});
