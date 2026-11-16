import { afterEach, beforeEach, describe, expect, it, setSystemTime } from "bun:test";

import { createLiquidChainRecord } from "../chains/createBuiltInLiquidChains";
import { LIQUID_TESTNET_CHAIN_ID } from "../domain/LiquidChain";
import {
	buildExplorerApis,
	describeExplorerError,
	explorerHistoryAllowance,
	explorerBudgetSpent,
	explorerRateForTesting,
	FALLBACK_EXPLORER_REQUESTS_PER_SECOND,
	fallbackExplorerUnreachable,
	fetchFromExplorer,
	fetchWithRetryAndBackoff,
	HOURLY_LIMIT_AVOID_MS,
	INITIAL_EXPLORER_REQUESTS_PER_SECOND,
	MAX_CONCURRENT_EXPLORER_REQUESTS,
	MAX_EXPLORER_REQUESTS_PER_SECOND,
	pickExplorerApi,
	probeUnreachableExplorers,
	resetExplorerLimiterForTesting,
	restoreExplorerLimiters,
	sustainedExplorerRequestRate,
	uncappedExplorerApi,
} from "./explorer";

describe("explorer request limiter", () => {
	const realFetch = globalThis.fetch;

	beforeEach(() => {
		resetExplorerLimiterForTesting({ requestsPerSecond: Infinity });
	});

	afterEach(() => {
		globalThis.fetch = realFetch;
		resetExplorerLimiterForTesting();
	});

	it("runs at most a few explorer requests at once", async () => {
		let inFlight = 0;
		let peak = 0;
		globalThis.fetch = (async () => {
			inFlight++;
			peak = Math.max(peak, inFlight);
			await new Promise((resolve) => setTimeout(resolve, 10));
			inFlight--;
			return new Response("ok");
		}) as unknown as typeof fetch;

		const responses = await Promise.all(
			Array.from({ length: 2 * MAX_CONCURRENT_EXPLORER_REQUESTS }, (_, i) =>
				fetchFromExplorer(`https://esplora.test/${i}`),
			),
		);

		expect(responses.every((r) => r.ok)).toBe(true);
		expect(peak).toBe(MAX_CONCURRENT_EXPLORER_REQUESTS);
	});

	it("starts at most a few requests a second on one server", async () => {
		resetExplorerLimiterForTesting({ requestsPerSecond: 10 });
		const sentAt: number[] = [];
		globalThis.fetch = (async () => {
			sentAt.push(Date.now());
			return new Response("ok");
		}) as unknown as typeof fetch;

		await Promise.all(
			Array.from({ length: 5 }, (_, i) => fetchFromExplorer(`https://esplora.test/${i}`)),
		);
		await fetchFromExplorer("https://other.test/0");

		// Five starts 100 ms apart on one server; another server is not held back by it.
		expect(sentAt[4]! - sentAt[0]!).toBeGreaterThanOrEqual(380);
		expect(sentAt[5]! - sentAt[4]!).toBeLessThan(100);
	});

	it("passes over a server only after it failed a few times in a row", async () => {
		globalThis.fetch = (async () => {
			throw new TypeError("fetch failed");
		}) as unknown as typeof fetch;
		const apis = ["https://slow.test/api", "https://fast.test/api"];
		const fail = () => expect(fetchFromExplorer(`${apis[0]}/blocks/tip/height`)).rejects.toThrow();

		// One dropped connection happens on a healthy server too.
		await fail();
		await fail();
		expect(pickExplorerApi(apis)).toBe(apis[0]!);

		await fail();
		expect(pickExplorerApi(apis)).toBe(apis[1]!);
	});

	it("passes over a fallback explorer at its first failure", async () => {
		globalThis.fetch = (async () => {
			throw new TypeError("fetch failed");
		}) as unknown as typeof fetch;
		const fallback = "https://liquid.network/liquidtestnet/api";
		const apis = [fallback, "https://blockstream.info/liquidtestnet/api"];

		// Unreachable from some networks: every request to it would wait out a timeout.
		await expect(fetchFromExplorer(`${fallback}/blocks/tip/height`)).rejects.toThrow();

		expect(pickExplorerApi(apis)).toBe(apis[1]!);
	});

	it("waits out Retry-After after a 429 before any further request", async () => {
		const sentAt: number[] = [];
		globalThis.fetch = (async () => {
			sentAt.push(Date.now());
			return sentAt.length === 1
				? new Response("slow down", { headers: { "Retry-After": "1" }, status: 429 })
				: new Response("ok");
		}) as unknown as typeof fetch;

		const res = await fetchWithRetryAndBackoff("https://esplora.test/blocks/tip/height");
		const other = await fetchFromExplorer("https://esplora.test/other");

		expect(res.status).toBe(200);
		expect(other.status).toBe(200);
		expect(sentAt[1]! - sentAt[0]!).toBeGreaterThanOrEqual(950);
	});
});

describe("explorer choice", () => {
	const realFetch = globalThis.fetch;
	const testnet = createLiquidChainRecord({ id: LIQUID_TESTNET_CHAIN_ID, name: "Liquid Testnet" });

	afterEach(() => {
		globalThis.fetch = realFetch;
		resetExplorerLimiterForTesting();
	});

	it("offers every public explorer for a chain on a public one", () => {
		expect(buildExplorerApis(testnet)).toEqual([
			"https://blockstream.info/liquidtestnet/api",
			"https://liquid.network/liquidtestnet/api",
		]);
	});

	it("keeps a chain with its own explorer on that one only", () => {
		const own = {
			...testnet,
			settings: { ...testnet.settings, explorerUrl: "https://esplora.me/" },
		};

		expect(buildExplorerApis(own)).toEqual(["https://esplora.me/api"]);
	});

	it("moves to the next explorer while the first pauses after a 429", async () => {
		const apis = buildExplorerApis(testnet);
		globalThis.fetch = (async () =>
			new Response("slow down", {
				headers: { "Retry-After": "60" },
				status: 429,
			})) as unknown as typeof fetch;

		expect(pickExplorerApi(apis)).toBe(apis[0]!);
		await fetchFromExplorer(`${apis[0]}/blocks/tip/height`);

		expect(pickExplorerApi(apis)).toBe(apis[1]!);
	});
});

describe("a fallback explorer that failed", () => {
	const realFetch = globalThis.fetch;
	const primary = "https://blockstream.info/liquidtestnet/api";
	const fallback = "https://liquid.network/liquidtestnet/api";
	const apis = [fallback, primary];
	const MINUTE = 60_000;
	/** What the fallback does: "down" drops the connection. */
	let answer: "down" | number;
	let probes = 0;

	beforeEach(() => {
		resetExplorerLimiterForTesting({ requestsPerSecond: Infinity });
		answer = "down";
		probes = 0;
		globalThis.fetch = (async (input: string) => {
			if (!input.startsWith(fallback)) return new Response("7", { status: 200 });
			probes++;
			if (answer === "down") throw new TypeError("fetch failed");
			return new Response(answer === 200 ? "2707940" : "slow down", {
				headers: answer === 429 ? { "Retry-After": "60" } : undefined,
				status: answer,
			});
		}) as unknown as typeof fetch;
	});

	afterEach(() => {
		globalThis.fetch = realFetch;
		setSystemTime();
		resetExplorerLimiterForTesting();
	});

	const later = (ms: number) => setSystemTime(new Date(Date.now() + ms));
	const request = () => fetchFromExplorer(`${fallback}/blocks/tip/height`);
	const failOnce = () => expect(request()).rejects.toThrow();

	it("is used again as soon as a probe finds it answering", async () => {
		await failOnce();
		expect(pickExplorerApi(apis)).toBe(primary);
		expect(fallbackExplorerUnreachable(apis)).toBe(true);

		// Not before its wait: the server gets no request meanwhile.
		probes = 0;
		later(MINUTE - 1000);
		await probeUnreachableExplorers(apis);
		expect(probes).toBe(0);

		answer = 200;
		later(2000);
		await probeUnreachableExplorers(apis);
		expect(probes).toBe(1);
		expect(pickExplorerApi(apis)).toBe(fallback);
		expect(fallbackExplorerUnreachable(apis)).toBe(false);
	});

	it("is probed less and less often while it stays down", async () => {
		await failOnce();
		probes = 0;
		const probeAfter = async (ms: number) => {
			later(ms);
			await probeUnreachableExplorers(apis);
			return probes;
		};

		expect(await probeAfter(MINUTE + 1)).toBe(1);
		// The wait doubled: two minutes from the probe that failed.
		expect(await probeAfter(MINUTE + 1)).toBe(1);
		expect(await probeAfter(MINUTE)).toBe(2);
		expect(await probeAfter(3 * MINUTE)).toBe(2);
		expect(await probeAfter(MINUTE + 1)).toBe(3);
		expect(pickExplorerApi(apis)).toBe(primary);
	});

	it("sends one probe when several runs start together", async () => {
		await failOnce();
		probes = 0;
		later(MINUTE + 1);

		await Promise.all([probeUnreachableExplorers(apis), probeUnreachableExplorers(apis)]);

		expect(probes).toBe(1);
	});

	it("waits longer for its probe when it fails again soon after one brought it back", async () => {
		await failOnce();
		answer = 200;
		later(MINUTE + 1);
		await probeUnreachableExplorers(apis);
		expect(pickExplorerApi(apis)).toBe(fallback);

		// It answers a probe and fails the scan: probing every minute would flap for hours.
		answer = "down";
		await failOnce();
		probes = 0;
		later(MINUTE + 1);
		await probeUnreachableExplorers(apis);
		expect(probes).toBe(0);
		later(MINUTE);
		await probeUnreachableExplorers(apis);
		expect(probes).toBe(1);
	});

	it("takes the failures of requests in flight as one", async () => {
		await Promise.all([failOnce(), failOnce(), failOnce()]);
		probes = 0;
		answer = 200;

		later(MINUTE + 1);
		await probeUnreachableExplorers(apis);

		expect(probes).toBe(1);
		expect(pickExplorerApi(apis)).toBe(fallback);
	});

	it("does not lift the pause of a server that answered 429", async () => {
		answer = 429;
		await request();
		expect(pickExplorerApi(apis)).toBe(primary);
		probes = 0;
		answer = 200;

		later(MINUTE / 2);
		await probeUnreachableExplorers(apis);

		expect(probes).toBe(0);
		expect(pickExplorerApi(apis)).toBe(primary);
		expect(fallbackExplorerUnreachable(apis)).toBe(false);
		// Older blocks are not read from it meanwhile: going on through a 429 is what gets an IP
		// shut out for an hour. The time left still counts on it: it is back in minutes.
		expect(uncappedExplorerApi(apis)).not.toBe(fallback);
		expect(sustainedExplorerRequestRate(apis)).toBeGreaterThan(1);

		later(5 * MINUTE);
		expect(pickExplorerApi(apis)).toBe(fallback);
		expect(uncappedExplorerApi(apis)).toBe(fallback);
	});

	it("does not take a page that is not the chain tip for an answer", async () => {
		await failOnce();
		globalThis.fetch = (async () =>
			new Response("<html>Sign in to this network</html>", {
				status: 200,
			})) as unknown as typeof fetch;

		later(MINUTE + 1);
		await probeUnreachableExplorers(apis);

		expect(pickExplorerApi(apis)).toBe(primary);
	});

	it("is named in a scan error while it is down, and not otherwise", async () => {
		const timeout = Object.assign(new Error("aborted"), { name: "AbortError" });
		expect(describeExplorerError(timeout, "failed", apis)).toBe(
			"The block explorer did not answer in time; scanning resumes shortly.",
		);

		await failOnce();

		expect(describeExplorerError(timeout, "failed", apis)).toBe(
			"A backup block explorer is not answering; scanning continues through the main one, more slowly.",
		);
		expect(describeExplorerError(new Error("Bad block"), "failed", apis)).toBe("Bad block");
	});

	it("is probed every minute while the scan has no other explorer to read from", async () => {
		resetExplorerLimiterForTesting({ hourlyBudget: 2, requestsPerSecond: Infinity });
		await failOnce();
		// Two probes unanswered: the wait is four minutes by now.
		later(MINUTE + 1);
		await probeUnreachableExplorers(apis);
		later(2 * MINUTE + 1);
		await probeUnreachableExplorers(apis);
		probes = 0;
		later(MINUTE + 1);
		await probeUnreachableExplorers(apis);
		expect(probes).toBe(0);

		await fetchFromExplorer(`${primary}/blocks/tip/height`);
		await fetchFromExplorer(`${primary}/blocks/tip/height`);
		expect(explorerBudgetSpent(primary)).toBe(true);
		answer = 200;
		await probeUnreachableExplorers(apis);

		expect(probes).toBe(1);
		expect(pickExplorerApi(apis)).toBe(fallback);
	});

	it("is not gone back to when the main explorer's hour is spent", async () => {
		resetExplorerLimiterForTesting({ hourlyBudget: 2, requestsPerSecond: Infinity });
		const timeout = Object.assign(new Error("aborted"), { name: "AbortError" });
		await failOnce();
		await fetchFromExplorer(`${primary}/blocks/tip/height`);
		await fetchFromExplorer(`${primary}/blocks/tip/height`);
		expect(explorerBudgetSpent(primary)).toBe(true);

		// Both are passed over: the one that answers says its hour is spent at once, the other
		// would cost a timeout a request.
		expect(pickExplorerApi(apis)).toBe(primary);
		expect(describeExplorerError(timeout, "failed", apis)).toBe(
			"A backup block explorer is not answering and the main one's hourly request limit is reached; scanning resumes when the limit resets.",
		);
	});

	describe("across service worker restarts", () => {
		const scope = globalThis as { chrome?: unknown };

		beforeEach(() => {
			const session: Record<string, unknown> = {};
			scope.chrome = {
				storage: {
					session: {
						get: async (key: string) => ({ [key]: structuredClone(session[key]) }),
						set: async (items: Record<string, unknown>) =>
							Object.assign(session, structuredClone(items)),
					},
				},
			};
		});

		afterEach(() => {
			delete scope.chrome;
		});

		it("still probes it, and uses it once it answers", async () => {
			await failOnce();
			resetExplorerLimiterForTesting({ requestsPerSecond: Infinity });
			await restoreExplorerLimiters();
			expect(fallbackExplorerUnreachable(apis)).toBe(true);
			expect(pickExplorerApi(apis)).toBe(primary);

			answer = 200;
			later(MINUTE + 1);
			await probeUnreachableExplorers(apis);

			expect(pickExplorerApi(apis)).toBe(fallback);
		});
	});
});

describe("hourly request budget", () => {
	const realFetch = globalThis.fetch;
	const budgeted = "https://blockstream.info/liquidtestnet/api";
	const fallback = "https://liquid.network/liquidtestnet/api";
	const apis = [budgeted, fallback];
	const options = { hourlyBudget: 10, requestsPerSecond: Infinity };
	let sent = 0;
	let status = 200;

	beforeEach(() => {
		resetExplorerLimiterForTesting(options);
		sent = 0;
		status = 200;
		globalThis.fetch = (async () => {
			sent++;
			return new Response("{}", { status });
		}) as unknown as typeof fetch;
	});

	afterEach(() => {
		globalThis.fetch = realFetch;
		setSystemTime();
		resetExplorerLimiterForTesting();
	});

	const later = (ms: number) => setSystemTime(new Date(Date.now() + ms));
	const spend = async (api: string, count: number) => {
		for (let i = 0; i < count; i++) await fetchFromExplorer(`${api}/blocks/tip/height`);
	};

	it("leaves a server once its hour of requests is used, until half of them are free", async () => {
		await spend(budgeted, 5);
		later(10 * 60_000);
		await spend(budgeted, 4);
		expect(explorerBudgetSpent(budgeted)).toBe(false);
		expect(pickExplorerApi(apis)).toBe(budgeted);

		await spend(budgeted, 1);
		expect(explorerBudgetSpent(budgeted)).toBe(true);
		expect(pickExplorerApi(apis)).toBe(fallback);

		// The first five requests age out an hour after they were made, ten minutes before the rest.
		later(49 * 60_000);
		expect(pickExplorerApi(apis)).toBe(fallback);
		later(3 * 60_000);
		expect(explorerBudgetSpent(budgeted)).toBe(false);
		expect(pickExplorerApi(apis)).toBe(budgeted);
	});

	it("leaves half of a server's hour to the new blocks when older ones are searched", async () => {
		await spend(budgeted, 3);
		expect(explorerHistoryAllowance(budgeted)).toBe(2);

		await spend(budgeted, 3);
		expect(explorerHistoryAllowance(budgeted)).toBe(0);
		// The new blocks still have the other half.
		expect(explorerBudgetSpent(budgeted)).toBe(false);
		expect(pickExplorerApi(apis)).toBe(budgeted);

		// A server without a cap has no share to keep.
		await spend(fallback, 20);
		expect(explorerHistoryAllowance(fallback)).toBe(Infinity);
	});

	it("sets no budget on a server that has no hourly cap", async () => {
		await spend("https://esplora.test/api", 30);

		expect(explorerBudgetSpent("https://esplora.test/api")).toBe(false);
	});

	it("takes a 429 without Retry-After as the hour spent: no retry, and an hour away", async () => {
		status = 429;

		const res = await fetchWithRetryAndBackoff(`${budgeted}/blocks/tip/height`);

		expect(res.status).toBe(429);
		expect(sent).toBe(1);
		expect(pickExplorerApi(apis)).toBe(fallback);
		later(HOURLY_LIMIT_AVOID_MS - 60_000);
		expect(pickExplorerApi(apis)).toBe(fallback);
		later(2 * 60_000);
		expect(pickExplorerApi(apis)).toBe(budgeted);
	});

	it("counts what the explorers keep up for hours, not a burst", async () => {
		// The fallback at this test's fixed rate, the budgeted server at ten requests an hour.
		resetExplorerLimiterForTesting({ hourlyBudget: 10, requestsPerSecond: 2 });
		// Older blocks are read from the server without a cap while it answers.
		expect(sustainedExplorerRequestRate(apis)).toBeCloseTo(2, 6);
		expect(uncappedExplorerApi(apis)).toBe(fallback);

		globalThis.fetch = (async () => {
			throw new TypeError("fetch failed");
		}) as unknown as typeof fetch;
		await expect(fetchFromExplorer(`${fallback}/blocks/tip/height`)).rejects.toThrow();

		// Without it, the search's share of the budgeted server's hour.
		expect(sustainedExplorerRequestRate(apis)).toBeCloseTo(5 / 3600, 6);
		expect(uncappedExplorerApi(apis)).toBeUndefined();
	});

	it("keeps the hour's count across service worker restarts", async () => {
		const scope = globalThis as { chrome?: unknown };
		const session: Record<string, unknown> = {};
		scope.chrome = {
			storage: {
				session: {
					get: async (key: string) => ({ [key]: structuredClone(session[key]) }),
					set: async (items: Record<string, unknown>) =>
						Object.assign(session, structuredClone(items)),
				},
			},
		};
		try {
			await spend(budgeted, 6);
			// Counts are saved every couple of seconds, not on every request.
			later(3000);
			await spend(budgeted, 1);

			resetExplorerLimiterForTesting(options);
			await restoreExplorerLimiters();
			await spend(budgeted, 2);
			expect(explorerBudgetSpent(budgeted)).toBe(false);
			await spend(budgeted, 1);
			expect(explorerBudgetSpent(budgeted)).toBe(true);

			resetExplorerLimiterForTesting(options);
			await restoreExplorerLimiters();
			expect(explorerBudgetSpent(budgeted)).toBe(true);
			expect(pickExplorerApi(apis)).toBe(fallback);
		} finally {
			delete scope.chrome;
		}
	});
});

describe("adaptive explorer rate", () => {
	const realFetch = globalThis.fetch;
	const url = "https://esplora.test/blocks/tip/height";
	let status = 200;

	beforeEach(() => {
		resetExplorerLimiterForTesting();
		status = 200;
		globalThis.fetch = (async () =>
			status === 0
				? Promise.reject(new TypeError("fetch failed"))
				: new Response("ok", { status })) as unknown as typeof fetch;
	});

	afterEach(() => {
		globalThis.fetch = realFetch;
		setSystemTime();
		resetExplorerLimiterForTesting();
	});

	const later = (ms: number) => setSystemTime(new Date(Date.now() + ms));

	it("starts slow and doubles a step while the server answers, up to the ceiling", async () => {
		expect(explorerRateForTesting(url)).toBe(INITIAL_EXPLORER_REQUESTS_PER_SECOND);

		await fetchFromExplorer(url);
		expect(explorerRateForTesting(url)).toBe(INITIAL_EXPLORER_REQUESTS_PER_SECOND);

		const rates: number[] = [];
		for (let step = 0; step < 4; step++) {
			later(10_001);
			await fetchFromExplorer(url);
			rates.push(explorerRateForTesting(url));
		}
		expect(rates).toEqual([
			INITIAL_EXPLORER_REQUESTS_PER_SECOND * 2,
			INITIAL_EXPLORER_REQUESTS_PER_SECOND * 4,
			MAX_EXPLORER_REQUESTS_PER_SECOND,
			MAX_EXPLORER_REQUESTS_PER_SECOND,
		]);
	});

	it("speeds up by one a step once the server has failed", async () => {
		for (let step = 0; step < 3; step++) {
			later(10_001);
			await fetchFromExplorer(url);
		}
		status = 503;
		later(1001);
		await fetchFromExplorer(url);
		const halved = explorerRateForTesting(url);

		status = 200;
		later(10_001);
		await fetchFromExplorer(url);
		later(10_001);
		await fetchFromExplorer(url);

		expect(explorerRateForTesting(url)).toBe(halved + 2);
	});

	describe("across service worker restarts", () => {
		let session: Record<string, unknown>;
		const scope = globalThis as { chrome?: unknown };

		beforeEach(() => {
			session = {};
			scope.chrome = {
				storage: {
					session: {
						get: async (key: string) => ({ [key]: structuredClone(session[key]) }),
						set: async (items: Record<string, unknown>) =>
							Object.assign(session, structuredClone(items)),
					},
				},
			};
		});

		afterEach(() => {
			delete scope.chrome;
		});

		it("keeps the learned rate for a while, then starts over", async () => {
			for (let step = 0; step < 2; step++) {
				later(10_001);
				await fetchFromExplorer(url);
			}
			const learned = explorerRateForTesting(url);
			expect(learned).toBeGreaterThan(INITIAL_EXPLORER_REQUESTS_PER_SECOND);

			resetExplorerLimiterForTesting();
			await restoreExplorerLimiters();
			expect(explorerRateForTesting(url)).toBe(learned);

			later(31 * 60_000);
			resetExplorerLimiterForTesting();
			await restoreExplorerLimiters();
			expect(explorerRateForTesting(url)).toBe(INITIAL_EXPLORER_REQUESTS_PER_SECOND);
		});

		it("keeps passing over a server that answered 429", async () => {
			const primary = "https://esplora.test/api";
			const other = "https://other.test/api";
			globalThis.fetch = (async () =>
				new Response("slow down", {
					headers: { "Retry-After": "60" },
					status: 429,
				})) as unknown as typeof fetch;
			await fetchFromExplorer(`${primary}/blocks/tip/height`);
			expect(pickExplorerApi([primary, other])).toBe(other);

			resetExplorerLimiterForTesting();
			await restoreExplorerLimiters();

			expect(pickExplorerApi([primary, other])).toBe(other);
		});
	});

	it("halves on a 5xx and on a dropped connection, not below one", async () => {
		for (let step = 0; step < 5; step++) {
			later(10_001);
			await fetchFromExplorer(url);
		}
		const before = explorerRateForTesting(url);

		// Each request a second later on the fake clock, so the rate itself never makes the test wait.
		status = 503;
		later(1001);
		await fetchFromExplorer(url);
		expect(explorerRateForTesting(url)).toBe(before / 2);

		status = 0;
		later(1001);
		await expect(fetchFromExplorer(url)).rejects.toThrow();
		expect(explorerRateForTesting(url)).toBe(before / 4);

		for (let n = 0; n < 6; n++) {
			later(1001);
			await fetchFromExplorer(url).catch(() => undefined);
		}
		expect(explorerRateForTesting(url)).toBe(1);
	});

	it("keeps the fallback explorer under its own ceiling", async () => {
		const fallback = "https://liquid.network/liquidtestnet/api/blocks/tip/height";
		for (let step = 0; step < 10; step++) {
			later(10_001);
			await fetchFromExplorer(fallback);
		}

		expect(explorerRateForTesting(fallback)).toBe(FALLBACK_EXPLORER_REQUESTS_PER_SECOND);
	});
});
