import {
	Alert02Icon,
	CheckmarkCircle02Icon,
	RefreshIcon,
	Search01Icon,
} from "@hugeicons/core-free-icons";
import { HugeiconsIcon } from "@hugeicons/react";
import { useQuery } from "@tanstack/react-query";

import { accountsClient } from "@/core/accounts/application/accounts-rpc/client";
import type { ChainRecord } from "@/core/chains/application/ChainRecord";
import { cn } from "@/theme/utils.ts";
import { UiButton } from "@/ui/UiButton/base";

import { describeScanStatus, type ScanStatusView } from "./scanStatusView";

/** While blocks are being checked the card follows closely; otherwise a slow poll is enough. */
const ACTIVE_POLL_MS = 3_000;
const IDLE_POLL_MS = 20_000;

/**
 * Silent Payments scanning on the home screen: whether private payments are up to date, how far a
 * scan has come and how long it has left, or why it is paused. Shares its query with
 * the chain settings, so both show the same status.
 */
export function LiquidScanStatus({
	chain,
	isRetrying = false,
	onRetry,
}: {
	chain: ChainRecord;
	isRetrying?: boolean;
	onRetry: () => void;
}) {
	const { data } = useQuery({
		queryFn: () => accountsClient.getSilentPaymentScanStatus({ chainId: chain.id }),
		queryKey: ["silentPaymentScanStatus", chain.id],
		refetchInterval: (query) =>
			query.state.data?.isScanning || query.state.data?.state === "backfilling"
				? ACTIVE_POLL_MS
				: IDLE_POLL_MS,
	});

	const view = data ? describeScanStatus(data) : null;
	if (!view) return null;

	return <LiquidScanStatusCard isRetrying={isRetrying} onRetry={onRetry} view={view} />;
}

/** The card itself, for one view of the status; without `onRetry` a paused scan has no button. */
export function LiquidScanStatusCard({
	isRetrying = false,
	onRetry,
	view,
}: {
	isRetrying?: boolean;
	onRetry?: () => void;
	view: ScanStatusView;
}) {
	if (view.kind === "done") {
		return (
			<div
				aria-live="polite"
				className="text-muted-foreground flex items-center justify-center gap-1.5 text-xs"
			>
				<HugeiconsIcon icon={CheckmarkCircle02Icon} className="size-3.5 text-emerald-500" />
				<span className="text-foreground/80">{view.title}</span>
				<span aria-hidden>·</span>
				<span>{view.detail}</span>
			</div>
		);
	}

	const tone = {
		paused: "border-amber-500/30 bg-amber-500/10",
		progress: "border-border bg-muted/40",
	}[view.kind];
	const icon = view.kind === "progress" ? Search01Icon : Alert02Icon;

	return (
		<div aria-live="polite" className={cn("flex flex-col gap-2.5 rounded-xl border p-3", tone)}>
			<div className="flex items-start gap-2.5">
				<HugeiconsIcon
					icon={icon}
					className={cn(
						"mt-0.5 size-4 shrink-0",
						view.kind === "progress" ? "text-primary" : "text-amber-500",
					)}
				/>
				<div className="flex min-w-0 flex-1 flex-col gap-0.5">
					<p className="text-sm font-medium">{view.title}</p>
					<p className="text-muted-foreground text-xs leading-relaxed">{view.detail}</p>
				</div>
				{view.kind === "progress" ? (
					<span className="text-muted-foreground font-mono text-xs tabular-nums">
						{view.percent}%
					</span>
				) : null}
			</div>

			{view.kind === "progress" ? (
				// The percentage above reads it out; the bar only draws it.
				<div aria-hidden className="bg-muted h-1.5 w-full overflow-hidden rounded-full">
					<div
						className="bg-primary h-full rounded-full transition-[width] duration-500"
						style={{ width: `${Math.max(3, view.percent)}%` }}
					/>
				</div>
			) : null}

			{view.kind === "paused" && onRetry ? (
				<UiButton
					className="self-start"
					disabled={isRetrying}
					onClick={onRetry}
					size="xs"
					type="button"
					variant="outline"
				>
					<HugeiconsIcon icon={RefreshIcon} className={cn(isRetrying && "animate-spin")} />
					Retry now
				</UiButton>
			) : null}
		</div>
	);
}
