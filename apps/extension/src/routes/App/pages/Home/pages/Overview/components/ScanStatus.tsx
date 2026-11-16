import { chainGroupUis } from "@/routes/App/chainGroupUis";
import { useHome } from "@/routes/App/pages/Home/HomeContext";
import { usePortfolioRefresh } from "@/routes/App/pages/Home/HomeContext/hooks/usePortfolioRefresh";

/**
 * The selected chain's wallet scanning status under the balance, when its chain group scans: retry
 * force-syncs the account, which restarts a paused scan.
 */
export function ScanStatus() {
	const { accountGroup, chain } = useHome();
	const { isRefreshing, refresh } = usePortfolioRefresh({
		accountGroupId: accountGroup.id,
		chainId: chain.id,
	});
	const ChainScanStatus = chainGroupUis[chain.chainGroupId]?.ScanStatus;
	if (!ChainScanStatus) return null;

	return (
		<ChainScanStatus
			chain={chain}
			isRetrying={isRefreshing}
			onRetry={() => {
				if (!isRefreshing) refresh();
			}}
		/>
	);
}
