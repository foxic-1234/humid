/**
 * The date a user gave for when a restored wallet was created (ms since epoch), as the background
 * accepts it from the popup: absent stays absent, a date ahead of now is now.
 */
export function toWalletCreatedAt(value: unknown, now = Date.now()): number | undefined {
	if (value === undefined || value === null) return undefined;
	if (typeof value !== "number" || !Number.isFinite(value) || value < 0) {
		throw new Error("Invalid wallet creation date.");
	}

	return Math.min(Math.trunc(value), now);
}

/** A `YYYY-MM` month input as the start of that month, local time; empty or malformed: none. */
export function walletCreatedAtFromMonth(value: string): number | undefined {
	const match = /^(\d{4})-(\d{2})$/.exec(value.trim());
	if (!match) return undefined;
	const month = Number(match[2]);
	if (month < 1 || month > 12) return undefined;

	return new Date(Number(match[1]), month - 1, 1).getTime();
}
