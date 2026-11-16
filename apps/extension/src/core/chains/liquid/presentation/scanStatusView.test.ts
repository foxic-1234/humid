import { describe, expect, it } from "bun:test";

import type { SilentPaymentScanStatusResult } from "@/core/accounts/application/accounts-rpc/model/types";

import { describeScanStatus, formatTimeLeft } from "./scanStatusView";

const status = (patch: Partial<SilentPaymentScanStatusResult>): SilentPaymentScanStatusResult => ({
	chainId: "liquid-testnet",
	currentHeight: 2_681_973,
	isScanning: false,
	percentage: 100,
	state: "synced",
	tipHeight: 2_681_973,
	...patch,
});

describe("describeScanStatus", () => {
	it("says the wallet is up to date at the block it checked", () => {
		expect(describeScanStatus(status({}))).toEqual({
			detail: "Checked up to block #2,681,973",
			kind: "done",
			title: "Private payments up to date",
		});
	});

	it("counts the new blocks left, not the wallet's whole history", () => {
		expect(
			describeScanStatus(
				status({
					etaSeconds: 30,
					isScanning: true,
					newBlocksLeft: 12,
					percentage: 60,
					state: "backfilling",
				}),
			),
		).toEqual({
			detail: "12 blocks left · less than a minute left",
			kind: "progress",
			percent: 60,
			title: "Checking new blocks",
		});
	});

	it("tells that new payments already show while older blocks are searched", () => {
		expect(
			describeScanStatus(
				status({
					etaSeconds: 25 * 60,
					history: { done: 405, total: 70_688 },
					isScanning: true,
					newBlocksLeft: 0,
					percentage: 0,
					state: "backfilling",
				}),
			),
		).toEqual({
			detail: "New payments show up right away. 405 of 70,688 blocks checked · about 25 min left",
			kind: "progress",
			percent: 0,
			title: "Searching older payments",
		});
	});

	it("tells that earlier payments return to the balance once the search ends", () => {
		const searching = (heldPayments: number) =>
			describeScanStatus(
				status({
					heldPayments,
					history: { done: 405, total: 70_688 },
					isScanning: true,
					newBlocksLeft: 0,
					state: "backfilling",
				}),
			)?.detail;

		expect(searching(3)).toBe(
			"New payments show up right away; 3 earlier payments return to the balance once the search ends. 405 of 70,688 blocks checked",
		);
		expect(searching(1)).toContain("; 1 earlier payment returns to the balance");
		expect(searching(0)).toBe("New payments show up right away. 405 of 70,688 blocks checked");
	});

	it("says why a history search is slow while a backup explorer is unreachable", () => {
		expect(
			describeScanStatus(
				status({
					etaSeconds: 674 * 3600,
					fallbackExplorerDown: true,
					history: { done: 1300, total: 111_847 },
					isScanning: true,
					newBlocksLeft: 0,
					state: "backfilling",
				}),
			)?.detail,
		).toBe(
			"New payments show up right away. 1,300 of 111,847 blocks checked · about 674 h left A backup block explorer is unreachable from this network, so the search is much slower than usual.",
		);
	});

	it("says a history search between runs continues shortly", () => {
		expect(
			describeScanStatus(
				status({
					history: { done: 35_344, total: 70_688 },
					newBlocksLeft: 0,
					state: "backfilling",
				}),
			),
		).toMatchObject({
			detail:
				"New payments show up right away. 35,344 of 70,688 blocks checked · continues shortly",
			percent: 50,
		});
	});

	it("gives the time left between runs once a run has measured its rate", () => {
		expect(
			describeScanStatus(
				status({
					etaSeconds: 90 * 60,
					history: { done: 44_700, total: 70_689 },
					newBlocksLeft: 0,
					state: "backfilling",
				}),
			),
		).toMatchObject({
			detail:
				"New payments show up right away. 44,700 of 70,689 blocks checked · about 1 h 30 min left",
		});
	});

	it("shows a failed scan as paused, with the explorer's reason", () => {
		expect(
			describeScanStatus(
				status({ errorMessage: "The block explorer is limiting requests.", state: "error" }),
			),
		).toEqual({
			detail: "The block explorer is limiting requests.",
			kind: "paused",
			title: "Scanning paused",
		});
	});

	it("has nothing to say before the first scan", () => {
		expect(
			describeScanStatus(status({ currentHeight: 0, state: "idle", tipHeight: 0 })),
		).toBeNull();
	});
});

describe("formatTimeLeft", () => {
	it("rounds to minutes and hours", () => {
		expect(formatTimeLeft(20)).toBe("less than a minute");
		expect(formatTimeLeft(12 * 60 + 10)).toBe("about 12 min");
		expect(formatTimeLeft(2 * 3600)).toBe("about 2 h");
		expect(formatTimeLeft(2 * 3600 + 5 * 60)).toBe("about 2 h 5 min");
	});
});
