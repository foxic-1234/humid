import { describe, expect, it } from "bun:test";

import { WalletRpcUserRejectedError } from "@/core/wallet-rpc/errors";
import { DENY_ALL_AUTHORIZATION, type WalletRpcBaseContext } from "@/core/wallet-rpc/types";

import { createWalletMethod } from "./createWalletMethod";

/** A method whose review hands out a resource; `disposed` records every release of it. */
function methodWithResource(execute: () => Promise<string> | string = () => "done") {
	const disposed: string[] = [];
	const method = createWalletMethod<unknown, WalletRpcBaseContext, { resource: string }, string>({
		confirmation: () => ({ title: "Confirm" }),
		dispose: ({ resource }) => {
			disposed.push(resource);
		},
		execute,
		id: "test_method",
		parse: (params) => params,
		review: () => ({ resource: "account-keys" }),
	});
	return { disposed, method };
}

const granted: WalletRpcBaseContext = { authorization: { isGranted: () => true } };

describe("createWalletMethod dispose", () => {
	it("releases the review after execute", async () => {
		const { disposed, method } = methodWithResource();

		expect(await method({}, granted)).toBe("done");
		expect(disposed).toEqual(["account-keys"]);
	});

	it("releases the review only once execute has finished", async () => {
		const order: string[] = [];
		const { disposed, method } = methodWithResource(async () => {
			await Promise.resolve();
			order.push(`execute (disposed: ${disposed.length})`);
			return "done";
		});

		await method({}, granted);

		expect(order).toEqual(["execute (disposed: 0)"]);
		expect(disposed).toHaveLength(1);
	});

	it("releases the review when the user rejects the confirmation", async () => {
		const { disposed, method } = methodWithResource();

		await expect(
			method({}, { authorization: DENY_ALL_AUTHORIZATION, confirm: async () => false }),
		).rejects.toBeInstanceOf(WalletRpcUserRejectedError);
		expect(disposed).toEqual(["account-keys"]);
	});

	it("releases the review when execute throws", async () => {
		const { disposed, method } = methodWithResource(() => {
			throw new Error("broadcast failed");
		});

		await expect(method({}, granted)).rejects.toThrow("broadcast failed");
		expect(disposed).toEqual(["account-keys"]);
	});
});
