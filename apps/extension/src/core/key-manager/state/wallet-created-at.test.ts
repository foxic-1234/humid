import { describe, expect, it } from "bun:test";

import { toWalletCreatedAt, walletCreatedAtFromMonth } from "./wallet-created-at";

describe("toWalletCreatedAt", () => {
	const now = Date.UTC(2026, 10, 2);

	it("keeps no date as none", () => {
		expect(toWalletCreatedAt(undefined, now)).toBeUndefined();
		expect(toWalletCreatedAt(null, now)).toBeUndefined();
	});

	it("keeps a past date and makes a later one now", () => {
		expect(toWalletCreatedAt(Date.UTC(2024, 0, 1), now)).toBe(Date.UTC(2024, 0, 1));
		expect(toWalletCreatedAt(now + 1000, now)).toBe(now);
	});

	it("rejects what is not a date", () => {
		for (const value of ["2024-01", -1, Number.NaN, Number.POSITIVE_INFINITY]) {
			expect(() => toWalletCreatedAt(value, now)).toThrow("Invalid wallet creation date.");
		}
	});
});

describe("walletCreatedAtFromMonth", () => {
	it("is the start of the month, local time", () => {
		expect(walletCreatedAtFromMonth("2024-03")).toBe(new Date(2024, 2, 1).getTime());
	});

	it("is none for an empty or malformed month", () => {
		for (const value of ["", "2024", "2024-13", "2024-00", "03-2024"]) {
			expect(walletCreatedAtFromMonth(value)).toBeUndefined();
		}
	});
});
