import type { SilentPaymentScanStatusResult } from "@/core/accounts/application/accounts-rpc/model/types";

/**
 * What the home screen says about Silent Payments scanning, in the user's terms:
 * - `progress`: blocks are being checked; `percent` fills the bar;
 * - `done`: every block up to the tip is checked;
 * - `paused`: the explorer failed, a retry follows.
 */
export type ScanStatusView =
	| { detail: string; kind: "progress"; percent: number; title: string }
	| { detail: string; kind: "done"; title: string }
	| { detail: string; kind: "paused"; title: string };

const blocks = (n: number) => `${n.toLocaleString("en-US")} ${n === 1 ? "block" : "blocks"}`;

/** "less than a minute", "about 12 min", "about 2 h 5 min". */
export function formatTimeLeft(seconds: number): string {
	if (seconds < 60) return "less than a minute";
	const minutes = Math.round(seconds / 60);
	if (minutes < 60) return `about ${minutes} min`;
	const hours = Math.floor(minutes / 60);
	const rest = minutes % 60;
	return rest === 0 ? `about ${hours} h` : `about ${hours} h ${rest} min`;
}

const withTimeLeft = (text: string, etaSeconds: number | undefined) =>
	etaSeconds !== undefined && etaSeconds > 0
		? `${text} · ${formatTimeLeft(etaSeconds)} left`
		: text;

/** The home screen's view of a scan status; null when there is nothing to say. */
export function describeScanStatus(status: SilentPaymentScanStatusResult): ScanStatusView | null {
	if (status.state === "error") {
		return {
			detail: status.errorMessage ?? "The block explorer did not answer. Retrying shortly.",
			kind: "paused",
			title: "Scanning paused",
		};
	}

	const newBlocksLeft = status.newBlocksLeft ?? 0;
	if (status.state === "backfilling" && newBlocksLeft > 0) {
		return {
			detail: withTimeLeft(`${blocks(newBlocksLeft)} left`, status.etaSeconds),
			kind: "progress",
			percent: status.percentage,
			title: "Checking new blocks",
		};
	}

	if (status.history) {
		const { done, total } = status.history;
		const checked = `${done.toLocaleString("en-US")} of ${blocks(total)} checked`;
		// Payments from before the gap are out of the balance until the search finds whether the
		// gap spent them: without a word, they look lost.
		const held = status.heldPayments ?? 0;
		const lead =
			held > 0
				? `New payments show up right away; ${held.toLocaleString("en-US")} earlier ${held === 1 ? "payment returns" : "payments return"} to the balance once the search ends.`
				: "New payments show up right away.";
		return {
			// Between runs the last run's rate still gives the time left; without one, say it resumes.
			detail:
				status.isScanning || status.etaSeconds
					? withTimeLeft(`${lead} ${checked}`, status.etaSeconds)
					: `${lead} ${checked} · continues shortly`,
			kind: "progress",
			percent: Math.min(99, Math.floor((done / Math.max(1, total)) * 100)),
			title: "Searching older payments",
		};
	}

	if (status.state === "synced") {
		return {
			detail: `Checked up to block #${status.currentHeight.toLocaleString("en-US")}`,
			kind: "done",
			title: "Private payments up to date",
		};
	}

	return null;
}
