import type { SpTxInput } from "@humid/sp-core";

import type { LiquidChainRecord, LiquidNetworkKind } from "../chains/LiquidChainRecord";

/**
 * Build a safe Esplora `/api` base URL from the chain's `explorerUrl` setting.
 *
 * Defense-in-depth: rejects non-HTTP(S) schemes (`javascript:`, `data:`, etc.)
 * to prevent URL-based exfiltration even if a malicious chain config is injected.
 */
export function buildExplorerApi(chain: Pick<LiquidChainRecord, "id" | "settings">): string {
	const raw = chain.settings?.explorerUrl;
	if (!raw) {
		const backendUrl = chain.settings?.backend?.url;
		if (backendUrl && !chain.settings?.backend?.waterfalls) {
			try {
				const parsed = new URL(backendUrl.replace(/\/+$/, ""));
				if (parsed.protocol === "https:" || parsed.protocol === "http:") {
					return parsed.href.replace(/\/+$/, "");
				}
			} catch {
				// Fall through to throw below.
			}
		}
		throw new Error(`[sp-explorer] No explorer URL configured for chain ${chain.id}`);
	}
	try {
		const parsed = new URL(raw.replace(/\/+$/, ""));
		if (parsed.protocol !== "https:" && parsed.protocol !== "http:") {
			throw new Error(`Unsafe explorer URL scheme: ${parsed.protocol}`);
		}
		return `${parsed.href.replace(/\/+$/, "")}/api`;
	} catch (err) {
		throw new Error(`[sp-explorer] Invalid or unsafe explorer URL: ${err}`, { cause: err });
	}
}

/**
 * Timeout of one explorer request. A busy public Esplora queues requests for seconds; a request
 * cut short counts as a failure and halves the rate, so it must not be cut before a slow answer.
 */
export const EXPLORER_TIMEOUT_MS = 10_000;

export async function fetchWithTimeout(
	url: string,
	init?: RequestInit,
	timeoutMs = EXPLORER_TIMEOUT_MS,
): Promise<Response> {
	const controller = new AbortController();
	const timeoutId = setTimeout(() => controller.abort(), timeoutMs);
	try {
		return await fetch(url, {
			...init,
			signal: controller.signal,
		});
	} finally {
		clearTimeout(timeoutId);
	}
}

/**
 * Requests to one explorer in flight at once. Enough to reach the rate ceiling at a second or two
 * of latency, few enough not to burst: a burst is what a public Esplora punishes first.
 */
export const MAX_CONCURRENT_EXPLORER_REQUESTS = 16;
/** Longest pause after a 429 without a usable Retry-After. */
const MAX_RATE_LIMIT_COOLDOWN_MS = 30_000;
/** How long a server that answered 429, or kept failing, is passed over when a scan picks one. */
const RATE_LIMITED_AVOID_MS = 5 * 60_000;
/**
 * Failures in a row (dropped connections, timeouts, 5xx) before a server is passed over: a single
 * one happens on a healthy server too, and moving to a fallback that is down stalls the scan.
 */
const FAILURES_BEFORE_AVOID = 3;
/** How long a fallback that failed is passed over, unless a probe finds it answering sooner. */
const FALLBACK_FAILED_AVOID_MS = 30 * 60_000;
/**
 * A fallback passed over for failing is asked for the chain tip now and then, outside any scan:
 * one that answers is used again at once, so a passing failure or a change of network costs a
 * minute and not the half hour. The wait doubles with each probe left unanswered, and when a
 * server a probe brought back fails again within `FALLBACK_RELAPSE_MS`.
 */
const FALLBACK_PROBE_INTERVAL_MS = 60_000;
const MAX_FALLBACK_PROBE_INTERVAL_MS = 15 * 60_000;
const FALLBACK_RELAPSE_MS = 10 * 60_000;
const FALLBACK_PROBE_TIMEOUT_MS = 5000;
/**
 * Request starts per second to one server: a run starts slow and, every `RATE_STEP_UP_MS` the
 * server keeps answering, doubles its rate until the first failure and speeds up by one after it,
 * up to the ceiling; any failure halves it. The ceiling only shapes a burst: Blockstream answered
 * 20 a second cleanly and 30 with the odd 429, but what it limits is requests an hour (see
 * `HOURLY_REQUEST_BUDGETS`), which a burst at the ceiling spends in half a minute.
 */
export const INITIAL_EXPLORER_REQUESTS_PER_SECOND = 3;
export const MAX_EXPLORER_REQUESTS_PER_SECOND = 20;
const RATE_STEP_UP_MS = 10_000;
/**
 * Servers used when the primary one fails or its hour of requests is spent, which is where most of
 * a long scan is read from. liquid.network answers 15 requests a second cleanly for a minute, but
 * what it limits is a longer window: two scans at 6 to 7 a second each ended after some 1,400
 * requests (four minutes) in a few 429s, then timeouts, then no answer to that IP for over an
 * hour. The rate it keeps up for hours is not measured yet; the ceiling stays low until it is.
 */
const FALLBACK_EXPLORER_ORIGINS = new Set(["https://liquid.network"]);
export const FALLBACK_EXPLORER_REQUESTS_PER_SECOND = 1;

/**
 * Requests an hour the scanner allows itself on a server that caps them per IP. Without an API key
 * Blockstream answers 429 past 700 an hour (and 500,000 a month), with no Retry-After, and for
 * every path. The LWK wallet syncs through the same server from the same IP, so the scanner keeps
 * under half; the block windows in flight when its allowance runs out still finish, a hundred
 * requests or so. Measured with `scripts/explorerRateProbe.ts`.
 */
const HOURLY_REQUEST_BUDGETS = new Map<string, number>([["https://blockstream.info", 300]]);
const BUDGET_WINDOW_MS = 60 * 60_000;
/**
 * The share of a server's hourly budget a search of older blocks may use. The rest is kept for the
 * new blocks: a search with no other server to read from would spend the hour in half a minute,
 * and no payment would show until the next one.
 */
const HISTORY_BUDGET_SHARE = 0.5;
/** Requests are counted by the minute they started in. */
const BUDGET_BUCKET_MS = 60_000;
/**
 * How long a server with an hourly cap is left alone after a 429 without a Retry-After: its hour
 * is spent, by this wallet or by anything else behind the IP, and asking again only adds to it.
 * Blockstream answered again 44 minutes after a probe spent its hour at once.
 */
export const HOURLY_LIMIT_AVOID_MS = 60 * 60_000;
/** The request counts are saved for the next service worker at most this often. */
const BUDGET_PERSIST_INTERVAL_MS = 2000;

/** Thrown before any request when the run's only explorer has no requests left this hour. */
export class ExplorerBudgetError extends Error {
	constructor() {
		super("The block explorer's hourly request limit is reached; scanning resumes later.");
		this.name = "ExplorerBudgetError";
	}
}

/** Request slots, rate and rate-limit pause of one explorer server, keyed by origin. */
type ExplorerLimiter = {
	/** A scan picks another public explorer until then: set by a 429 or a failed connection. */
	avoidUntil: number;
	/** Requests an hour the scanner allows itself here; undefined without a cap. */
	budget?: number;
	/** The hour's allowance is spent until then: by the count below, or because a 429 said so. */
	budgetSpentUntil: number;
	ceiling: number;
	consecutiveFailures: number;
	consecutiveRateLimits: number;
	/** No request to this server starts before this time: set by a 429. */
	cooldownUntil: number;
	inFlight: number;
	/** When the rate last changed: it steps up only after a clean `RATE_STEP_UP_MS`. */
	lastRateChangeAt: number;
	lastPersistedAt: number;
	/** The next request may start at this time, at most `rate` a second. */
	nextStartAt: number;
	origin: string;
	/** Passed over for failing: the next probe may go out at this time; 0 otherwise. */
	probeAfter: number;
	/** A probe brought the server back at this time; 0 if none did. */
	probedBackAt: number;
	/** The wait before the next probe. */
	probeInterval: number;
	queue: Array<() => void>;
	rate: number;
	/** Doubling the rate on each step up: until the server's first failure. */
	slowStart: boolean;
	/** Requests started in the last hour as [minute start, count], oldest first; with a budget. */
	spent: Array<[number, number]>;
};

const explorerLimiters = new Map<string, ExplorerLimiter>();
/** Test-only: a fixed rate for every server instead of the adaptive one. */
let fixedRate: number | undefined;
/** Test-only: the hourly budget of the servers that have one. */
let testBudget: number | undefined;
/** Requests started since the service worker began, on every server. */
let requestsStarted = 0;

/**
 * Limiter state kept in `chrome.storage.session`, so a service worker woken by the next refresh
 * neither starts over at the initial rate nor forgets a server's pause or ban.
 */
const LIMITERS_SESSION_KEY = "humid_explorer_limiters";
/** A learned rate older than this is not trusted: the server's load may have changed since. */
const PERSISTED_RATE_TTL_MS = 30 * 60_000;

type PersistedLimiter = Pick<
	ExplorerLimiter,
	| "avoidUntil"
	| "budgetSpentUntil"
	| "cooldownUntil"
	| "probeAfter"
	| "probedBackAt"
	| "probeInterval"
	| "rate"
	| "slowStart"
	| "spent"
> & { savedAt: number };

export type SessionArea = {
	get: (key: string) => Promise<Record<string, unknown>>;
	set: (items: Record<string, unknown>) => Promise<void>;
};

/** `chrome.storage.session` where this context has it (an MV3 extension), else undefined. */
export function sessionArea(): SessionArea | undefined {
	return (globalThis as { chrome?: { storage?: { session?: SessionArea } } }).chrome?.storage
		?.session;
}

let persistedLimiters: Record<string, PersistedLimiter> = {};
let limitersRestored: Promise<void> | undefined;
let limitersRestoredDone = false;

/**
 * Read the persisted limiter states once per service worker; best effort. A scan awaits it before
 * it picks an explorer, so a server paused or banned before the worker slept stays passed over.
 */
export function restoreExplorerLimiters(): Promise<void> {
	return restoreLimiters();
}

function restoreLimiters(): Promise<void> {
	limitersRestored ??= (async () => {
		try {
			const stored = (await sessionArea()?.get(LIMITERS_SESSION_KEY))?.[LIMITERS_SESSION_KEY];
			if (stored && typeof stored === "object") {
				persistedLimiters = stored as Record<string, PersistedLimiter>;
			}
		} catch {
			// No persisted state: every server starts fresh.
		} finally {
			limitersRestoredDone = true;
		}
	})();
	return limitersRestored;
}

/** Save a server's limiter state for the next service worker; best effort. */
function persistLimiter(limiter: ExplorerLimiter): void {
	const area = sessionArea();
	if (!area) return;
	limiter.lastPersistedAt = Date.now();
	persistedLimiters[limiter.origin] = {
		avoidUntil: limiter.avoidUntil,
		budgetSpentUntil: limiter.budgetSpentUntil,
		cooldownUntil: limiter.cooldownUntil,
		probeAfter: limiter.probeAfter,
		probedBackAt: limiter.probedBackAt,
		probeInterval: limiter.probeInterval,
		rate: limiter.rate,
		savedAt: Date.now(),
		slowStart: limiter.slowStart,
		spent: limiter.spent,
	};
	area.set({ [LIMITERS_SESSION_KEY]: persistedLimiters }).catch(() => {});
}

function limiterFor(url: string): ExplorerLimiter {
	const origin = new URL(url).origin;
	let limiter = explorerLimiters.get(origin);
	if (!limiter) {
		const ceiling =
			fixedRate ??
			(FALLBACK_EXPLORER_ORIGINS.has(origin)
				? FALLBACK_EXPLORER_REQUESTS_PER_SECOND
				: MAX_EXPLORER_REQUESTS_PER_SECOND);
		limiter = {
			avoidUntil: 0,
			// A test's fixed rate also lifts the budgets, unless it sets one.
			budget: HOURLY_REQUEST_BUDGETS.has(origin)
				? (testBudget ?? (fixedRate === undefined ? HOURLY_REQUEST_BUDGETS.get(origin) : undefined))
				: undefined,
			budgetSpentUntil: 0,
			ceiling,
			consecutiveFailures: 0,
			consecutiveRateLimits: 0,
			cooldownUntil: 0,
			inFlight: 0,
			lastPersistedAt: 0,
			lastRateChangeAt: Date.now(),
			nextStartAt: 0,
			origin,
			probeAfter: 0,
			probedBackAt: 0,
			probeInterval: FALLBACK_PROBE_INTERVAL_MS,
			queue: [],
			rate: Math.min(fixedRate ?? INITIAL_EXPLORER_REQUESTS_PER_SECOND, ceiling),
			slowStart: true,
			spent: [],
		};
		const saved = persistedLimiters[origin];
		if (saved) {
			// Pauses and bans are absolute times: they hold whatever their age. So do the hour's
			// request counts, which `budgetUsed` drops as they age.
			limiter.avoidUntil = Number(saved.avoidUntil) || 0;
			limiter.cooldownUntil = Number(saved.cooldownUntil) || 0;
			limiter.budgetSpentUntil = Number(saved.budgetSpentUntil) || 0;
			limiter.probeAfter = Number(saved.probeAfter) || 0;
			limiter.probedBackAt = Number(saved.probedBackAt) || 0;
			limiter.probeInterval = Number(saved.probeInterval) || FALLBACK_PROBE_INTERVAL_MS;
			if (Array.isArray(saved.spent)) {
				limiter.spent = saved.spent
					.filter((entry) => Array.isArray(entry) && entry.length === 2)
					.map(([start, count]) => [Number(start), Number(count)] as [number, number])
					.filter(([start, count]) => Number.isFinite(start) && count > 0);
			}
			if (fixedRate === undefined && Date.now() - saved.savedAt < PERSISTED_RATE_TTL_MS) {
				limiter.rate = Math.min(ceiling, Math.max(1, Number(saved.rate) || limiter.rate));
				limiter.slowStart = saved.slowStart === true;
			}
		}
		explorerLimiters.set(origin, limiter);
	}
	return limiter;
}

/**
 * Test-only: forget every server's state, as a new service worker does (what `chrome.storage.session`
 * holds stays); optionally fix the rate (no ramp, no halving).
 */
export function resetExplorerLimiterForTesting(
	options: { hourlyBudget?: number; requestsPerSecond?: number } = {},
): void {
	explorerLimiters.clear();
	persistedLimiters = {};
	limitersRestored = undefined;
	limitersRestoredDone = false;
	fixedRate = options.requestsPerSecond;
	testBudget = options.hourlyBudget;
}

/** Requests started on the server in the last hour; forgets the older ones. */
function budgetUsed(limiter: ExplorerLimiter, now: number): number {
	const oldest = now - BUDGET_WINDOW_MS - BUDGET_BUCKET_MS;
	while (limiter.spent.length > 0 && limiter.spent[0]![0] <= oldest) {
		limiter.spent.shift();
	}
	return limiter.spent.reduce((sum, [, count]) => sum + count, 0);
}

/** The server's hour is spent until `until`: scans pick another explorer, or wait. */
function markBudgetSpent(limiter: ExplorerLimiter, until: number): void {
	limiter.budgetSpentUntil = Math.max(limiter.budgetSpentUntil, until);
	limiter.avoidUntil = Math.max(limiter.avoidUntil, until);
	persistLimiter(limiter);
}

/**
 * Count a request about to start against the server's hourly budget. Once the budget is used the
 * server counts as spent until half of it is free again: coming back for every request that ages
 * out would start a run for a handful of blocks.
 */
function countAgainstBudget(limiter: ExplorerLimiter): void {
	requestsStarted++;
	const { budget } = limiter;
	if (budget === undefined) return;
	const now = Date.now();
	const bucket = Math.floor(now / BUDGET_BUCKET_MS) * BUDGET_BUCKET_MS;
	const last = limiter.spent[limiter.spent.length - 1];
	if (last && last[0] === bucket) last[1]++;
	else limiter.spent.push([bucket, 1]);

	let used = budgetUsed(limiter, now);
	if (now >= limiter.budgetSpentUntil && used >= budget) {
		let until = now;
		for (const [start, count] of limiter.spent) {
			if (used <= budget / 2) break;
			used -= count;
			until = start + BUDGET_BUCKET_MS + BUDGET_WINDOW_MS;
		}
		markBudgetSpent(limiter, until);
	} else if (now - limiter.lastPersistedAt >= BUDGET_PERSIST_INTERVAL_MS) {
		persistLimiter(limiter);
	}
}

/**
 * Whether the scanner has used up the hour's requests on `api`'s server, or the server said so
 * with a 429. A scan then takes no further block window from it.
 */
export function explorerBudgetSpent(api: string): boolean {
	return Date.now() < limiterFor(api).budgetSpentUntil;
}

/**
 * Requests a search of older blocks may still send to `api`'s server this hour: no end of them on
 * a server without an hourly budget, else what is left of `HISTORY_BUDGET_SHARE` of the budget.
 */
export function explorerHistoryAllowance(api: string): number {
	const limiter = limiterFor(api);
	if (limiter.budget === undefined) return Infinity;
	const now = Date.now();
	if (now < limiter.budgetSpentUntil) return 0;
	return Math.max(0, Math.floor(limiter.budget * HISTORY_BUDGET_SHARE - budgetUsed(limiter, now)));
}

/**
 * The first of `apis` on a server without an hourly budget that is not being passed over, which
 * is where a search of older blocks reads from. One that answered 429 is left alone for its
 * minutes: liquid.network stopped answering an IP for over an hour after a scan that went on
 * through its 429s.
 */
export function uncappedExplorerApi(apis: string[]): string | undefined {
	const now = Date.now();
	return apis.find((api) => {
		const limiter = limiterFor(api);
		return limiter.budget === undefined && limiter.avoidUntil <= now;
	});
}

/** Requests started since the service worker began, on every explorer. */
export function explorerRequestsStarted(): number {
	return requestsStarted;
}

/**
 * Requests a second a search of older blocks can count on for hours: the rate ceilings of the
 * servers without an hourly budget that answer (a pause after a 429 passes in seconds); with none
 * of them, the search's share of the budgets. A burst on a budgeted server runs a hundred times
 * faster, for seconds.
 */
export function sustainedExplorerRequestRate(apis: string[]): number {
	const now = Date.now();
	let uncapped = 0;
	let capped = 0;
	for (const origin of new Set(apis.map((api) => new URL(api).origin))) {
		const limiter = limiterFor(origin);
		if (limiter.budget !== undefined) {
			capped += (limiter.budget * HISTORY_BUDGET_SHARE) / (BUDGET_WINDOW_MS / 1000);
		} else if (!awaitsProbe(origin, now)) {
			uncapped += limiter.ceiling;
		}
	}
	return uncapped > 0 ? uncapped : capped;
}

/** Test-only: the current request rate of the server `url` is on. */
export function explorerRateForTesting(url: string): number {
	return limiterFor(url).rate;
}

/**
 * The server answered: after a clean `RATE_STEP_UP_MS`, twice the rate while it has never failed,
 * else one more request a second.
 */
function rateUp(limiter: ExplorerLimiter): void {
	const now = Date.now();
	if (fixedRate !== undefined || limiter.rate >= limiter.ceiling) return;
	if (now - limiter.lastRateChangeAt < RATE_STEP_UP_MS) return;
	limiter.rate = Math.min(limiter.ceiling, limiter.slowStart ? limiter.rate * 2 : limiter.rate + 1);
	limiter.lastRateChangeAt = now;
	persistLimiter(limiter);
}

/**
 * Any failure halves the rate and ends the doubling: a hard ban comes as dropped connections or
 * timeouts, not as a 429, so every failure is taken as a warning.
 */
function rateDown(limiter: ExplorerLimiter): void {
	limiter.slowStart = false;
	if (fixedRate !== undefined) return;
	limiter.rate = Math.max(1, limiter.rate / 2);
	limiter.lastRateChangeAt = Date.now();
}

/**
 * A failure without a 429: slower at once, passed over after `FAILURES_BEFORE_AVOID` in a row. A
 * fallback is passed over at its first failure, and for long: it is there only for when the
 * primary fails, and one that cannot be reached (blocked in some networks) costs a timeout a
 * request.
 */
function failed(limiter: ExplorerLimiter): void {
	rateDown(limiter);
	limiter.consecutiveFailures++;
	if (FALLBACK_EXPLORER_ORIGINS.has(limiter.origin)) {
		const now = Date.now();
		// Requests in flight fail together: only the first of them sets the probe's wait.
		if (limiter.probeAfter === 0) {
			limiter.probeInterval =
				now - limiter.probedBackAt < FALLBACK_RELAPSE_MS
					? Math.min(limiter.probeInterval * 2, MAX_FALLBACK_PROBE_INTERVAL_MS)
					: FALLBACK_PROBE_INTERVAL_MS;
			limiter.probeAfter = now + limiter.probeInterval;
		}
		limiter.avoidUntil = now + FALLBACK_FAILED_AVOID_MS;
	} else if (limiter.consecutiveFailures >= FAILURES_BEFORE_AVOID) {
		limiter.avoidUntil = Date.now() + RATE_LIMITED_AVOID_MS;
	}
	persistLimiter(limiter);
}

/**
 * Ask each fallback passed over for failing, whose probe is due, for the chain tip: one that
 * answers is used again at once. A scan awaits this before it picks its explorers; the probe is
 * outside the scan's requests, so a server still down costs the scan nothing but the wait. While
 * no explorer of `apis` is usable the scan stands still, and the probe goes out a minute after the
 * last one however long its wait has grown.
 */
export async function probeUnreachableExplorers(apis: string[]): Promise<void> {
	if (!limitersRestoredDone) await restoreLimiters();
	await Promise.all(
		apis.map(async (api) => {
			const limiter = limiterFor(api);
			const now = Date.now();
			if (limiter.probeAfter === 0 || now >= limiter.avoidUntil) return;
			const standsStill = !apis.some((other) => limiterFor(other).avoidUntil <= now);
			const due = standsStill
				? Math.min(
						limiter.probeAfter,
						limiter.probeAfter - limiter.probeInterval + FALLBACK_PROBE_INTERVAL_MS,
					)
				: limiter.probeAfter;
			if (now < due) return;
			// Before the answer: another run starting meanwhile sends no second probe.
			limiter.probeAfter = now + limiter.probeInterval;
			let answered = false;
			try {
				const res = await fetchWithTimeout(
					`${api}/blocks/tip/height`,
					undefined,
					FALLBACK_PROBE_TIMEOUT_MS,
				);
				answered = res.ok && /^\d+$/.test((await res.text()).trim());
			} catch {
				// Still down.
			}
			if (answered) {
				limiter.avoidUntil = 0;
				limiter.consecutiveFailures = 0;
				limiter.probeAfter = 0;
				limiter.probedBackAt = Date.now();
			} else {
				limiter.probeInterval = Math.min(limiter.probeInterval * 2, MAX_FALLBACK_PROBE_INTERVAL_MS);
				limiter.probeAfter = Date.now() + limiter.probeInterval;
			}
			persistLimiter(limiter);
		}),
	);
}

/** Whether `api`'s server is passed over for failing and waits for a probe to bring it back. */
function awaitsProbe(api: string, now: number): boolean {
	const origin = new URL(api).origin;
	const state = explorerLimiters.get(origin) ?? persistedLimiters[origin];
	return state !== undefined && Number(state.probeAfter) > 0 && Number(state.avoidUntil) > now;
}

/** Whether a fallback of `apis` is passed over for failing: a long scan is then far slower. */
export function fallbackExplorerUnreachable(apis: string[]): boolean {
	const now = Date.now();
	return apis.some((api) => awaitsProbe(api, now));
}

const sleep = (ms: number) => new Promise((resolve) => setTimeout(resolve, ms));

/** Up to a second more, so wallets behind one IP that paused together do not resume together. */
const jitter = () => Math.random() * 1000;

/**
 * One request to a block explorer: per server at most `MAX_CONCURRENT_EXPLORER_REQUESTS` run at
 * once and the server's adaptive rate start a second; after a 429 every request to that server
 * waits out a shared pause (Retry-After, else doubling up to 30 s, plus jitter). A 429, or a few
 * failures in a row, also has scans pick another public explorer for a while.
 */
export async function fetchFromExplorer(
	url: string,
	init?: RequestInit,
	timeoutMs = EXPLORER_TIMEOUT_MS,
): Promise<Response> {
	if (!limitersRestoredDone) await restoreLimiters();
	const limiter = limiterFor(url);
	while (limiter.inFlight >= MAX_CONCURRENT_EXPLORER_REQUESTS) {
		await new Promise<void>((resolve) => limiter.queue.push(resolve));
	}
	limiter.inFlight++;
	try {
		const startAt = Math.max(limiter.cooldownUntil, limiter.nextStartAt, Date.now());
		limiter.nextStartAt = startAt + 1000 / limiter.rate;
		const wait = startAt - Date.now();
		if (wait > 0) await sleep(wait);
		countAgainstBudget(limiter);

		let res: Response;
		try {
			res = await fetchWithTimeout(url, init, timeoutMs);
		} catch (error) {
			failed(limiter);
			throw error;
		}
		if (res.status === 429) {
			rateDown(limiter);
			limiter.consecutiveRateLimits++;
			const retryAfter = Number.parseInt(res.headers.get("Retry-After") ?? "", 10);
			const timed = Number.isFinite(retryAfter) && retryAfter > 0;
			if (limiter.budget !== undefined && !timed) {
				// The hourly cap, not a burst: no pause of seconds outlasts it, so requests are not
				// held back to retry; the server is left alone instead.
				markBudgetSpent(limiter, Date.now() + HOURLY_LIMIT_AVOID_MS);
				return res;
			}
			const pause =
				(timed
					? Math.min(retryAfter * 1000, 2 * MAX_RATE_LIMIT_COOLDOWN_MS)
					: Math.min(1000 * 2 ** (limiter.consecutiveRateLimits - 1), MAX_RATE_LIMIT_COOLDOWN_MS)) +
				jitter();
			limiter.cooldownUntil = Math.max(limiter.cooldownUntil, Date.now() + pause);
			limiter.avoidUntil = Date.now() + Math.max(pause, RATE_LIMITED_AVOID_MS);
			// It answers: this pause is the server's own, which no probe lifts.
			limiter.probeAfter = 0;
			persistLimiter(limiter);
		} else if (res.status >= 500) {
			failed(limiter);
		} else {
			limiter.consecutiveFailures = 0;
			limiter.consecutiveRateLimits = 0;
			limiter.probeAfter = 0;
			rateUp(limiter);
		}
		return res;
	} finally {
		limiter.inFlight--;
		limiter.queue.shift()?.();
	}
}

/**
 * Public Esplora APIs per network. When the chain uses one of them, the scanner may use any:
 * block hashes are the same everywhere, and spreading the load keeps it under rate limits. A chain
 * with its own explorer (say, a self-hosted one) is only ever scanned through that one.
 */
const PUBLIC_EXPLORER_APIS: Partial<Record<LiquidNetworkKind, string[]>> = {
	mainnet: ["https://blockstream.info/liquid/api", "https://liquid.network/api"],
	testnet: [
		"https://blockstream.info/liquidtestnet/api",
		"https://liquid.network/liquidtestnet/api",
	],
};

/** The Esplora APIs a scan may use: the configured one first, then the other public ones. */
export function buildExplorerApis(chain: Pick<LiquidChainRecord, "id" | "settings">): string[] {
	const configured = buildExplorerApi(chain);
	const publicApis = PUBLIC_EXPLORER_APIS[chain.settings.network] ?? [];
	return publicApis.includes(configured)
		? [configured, ...publicApis.filter((api) => api !== configured)]
		: [configured];
}

/**
 * The first API whose server has not answered 429 in the last minutes, else the one passed over
 * the shortest. A run sticks to its pick; the request-level pause handles a 429 within it.
 */
export function pickExplorerApi(apis: string[]): string {
	return usableExplorerApis(apis)[0]!;
}

/**
 * Every API whose server has not answered 429 (or failed) in the last minutes, in the given order
 * (the chain's own explorer first, then fallbacks); if all have, the one passed over the shortest.
 * A fallback that does not answer is not that one while another server is left: a server whose
 * hour is spent says so at once, the fallback costs a timeout a request.
 */
export function usableExplorerApis(apis: string[]): string[] {
	const now = Date.now();
	const avoidedUntil = (api: string) => {
		const origin = new URL(api).origin;
		return (
			explorerLimiters.get(origin)?.avoidUntil ??
			(Number(persistedLimiters[origin]?.avoidUntil) || 0)
		);
	};
	const usable = apis.filter((api) => avoidedUntil(api) <= now);
	if (usable.length > 0) return usable;
	const answering = apis.filter((api) => !awaitsProbe(api, now));
	return [
		(answering.length > 0 ? answering : apis).reduce((best, api) =>
			avoidedUntil(api) < avoidedUntil(best) ? api : best,
		),
	];
}

export async function fetchWithRetryAndBackoff(
	url: string,
	init?: RequestInit,
	timeoutMs = EXPLORER_TIMEOUT_MS,
	maxRetries = 3,
): Promise<Response> {
	let attempt = 0;
	while (attempt <= maxRetries) {
		try {
			const res = await fetchFromExplorer(url, init, timeoutMs);
			if (res.status === 429) {
				attempt++;
				// An hour's cap does not lift within a retry.
				if (attempt > maxRetries || explorerBudgetSpent(url)) {
					return res;
				}
				// The next attempt waits out the pause this 429 set.
				continue;
			}
			return res;
		} catch (err) {
			attempt++;
			if (attempt > maxRetries) {
				throw err;
			}
			await new Promise((resolve) => setTimeout(resolve, 250 * attempt));
		}
	}
	throw new Error(`Failed to fetch ${url} after retries`);
}

/**
 * Fill `prevoutScriptPubKey` from Esplora for inputs whose parent transaction is not at hand.
 * Coinbase and peg-in inputs never need one.
 */
export async function resolveMissingPrevouts(vin: SpTxInput[], explorerApi: string): Promise<void> {
	const missing = vin.filter(
		(v) =>
			!v.isCoinbase &&
			!v.isPegin &&
			!v.prevoutScriptPubKey &&
			((v.witness?.length ?? 0) > 0 || (v.scriptsig?.length ?? 0) > 0),
	);
	if (missing.length === 0) return;

	const failed: string[] = [];
	await Promise.all(
		missing.map(async (input) => {
			try {
				const res = await fetchFromExplorer(`${explorerApi}/tx/${input.txid}`);
				const out = res.ok
					? ((await res.json()) as { vout?: { scriptpubkey?: string }[] }).vout?.[input.vout]
					: undefined;
				if (out?.scriptpubkey) {
					input.prevoutScriptPubKey = out.scriptpubkey;
					return;
				}
				failed.push(`${input.txid}:${input.vout} (status: ${res.status})`);
			} catch (err) {
				failed.push(
					`${input.txid}:${input.vout} (${err instanceof Error ? err.message : String(err)})`,
				);
			}
		}),
	);

	if (failed.length > 0) {
		throw new Error(
			`[sp-explorer] Failed to resolve required prevout(s) for input aggregation: ${failed.join(", ")}`,
		);
	}
}

/**
 * Whether an outpoint is spent, and by which transaction, as the explorer sees it.
 * Returns null when the explorer gave no usable answer (network error, non-2xx, malformed body).
 */
export async function fetchOutspend(
	explorerApi: string,
	txid: string,
	vout: number,
): Promise<{ spent: boolean; txid?: string } | null> {
	try {
		const res = await fetchFromExplorer(`${explorerApi}/tx/${txid}/outspend/${vout}`);
		if (!res.ok) return null;
		const body = (await res.json()) as { spent?: unknown; txid?: unknown };
		if (typeof body?.spent !== "boolean") return null;
		return { spent: body.spent, txid: typeof body.txid === "string" ? body.txid : undefined };
	} catch {
		return null;
	}
}

/**
 * Raw hex of a transaction the explorer knows (in a block or in its mempool). `notFound` is a
 * definite 404; null means the explorer gave no usable answer.
 *
 * Existence is proven by `/tx/{txid}/hex`, not by `/tx/{txid}/status`: Esplora answers the latter
 * with `{"confirmed":false}` and HTTP 200 even for a txid it has never seen.
 */
export async function fetchTxHex(
	explorerApi: string,
	txid: string,
): Promise<{ hex: string } | { notFound: true } | null> {
	try {
		const res = await fetchFromExplorer(`${explorerApi}/tx/${txid}/hex`);
		if (res.status === 404) return { notFound: true };
		if (!res.ok) return null;
		const hex = (await res.text()).trim().toLowerCase();
		return /^(?:[0-9a-f]{2})+$/.test(hex) ? { hex } : null;
	} catch {
		return null;
	}
}

/**
 * A scan error as the status card shows it: a timeout or a failed connection in plain words. With
 * the run's `apis`, a fallback that is down is named as such: the scan goes on without it.
 */
export function describeExplorerError(error: unknown, fallback: string, apis?: string[]): string {
	const timedOut =
		error instanceof Error && (error.name === "AbortError" || error.name === "TimeoutError");
	if ((timedOut || error instanceof TypeError) && apis && fallbackExplorerUnreachable(apis)) {
		const now = Date.now();
		// Without the fallback the scan lives on the main explorer's hourly allowance.
		return apis.some((api) => !awaitsProbe(api, now) && !explorerBudgetSpent(api))
			? "A backup block explorer is not answering; scanning continues through the main one, more slowly."
			: "A backup block explorer is not answering and the main one's hourly request limit is reached; scanning resumes when the limit resets.";
	}
	if (timedOut) {
		return "The block explorer did not answer in time; scanning resumes shortly.";
	}
	if (error instanceof TypeError) {
		return "The block explorer is unreachable; scanning resumes shortly.";
	}
	return error instanceof Error ? error.message : fallback;
}
