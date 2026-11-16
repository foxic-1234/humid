import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";

import { accountsClient } from "@/core/accounts/application/accounts-rpc/client";

/** All label lists, whatever their account and chain: what a label change invalidates. */
const SILENT_PAYMENT_LABELS_QUERY_KEY = ["silentPaymentLabels"] as const;

/**
 * The selected account's BIP-352 labels on `chainId`, plus create and rename. A change refetches
 * every label list, so the Receive screen and the chain settings stay in step.
 */
export function useSilentPaymentLabels(chainId: string, accountGroupId?: string) {
	const queryClient = useQueryClient();
	const query = useQuery({
		queryFn: () => accountsClient.listSilentPaymentLabels({ chainId }),
		queryKey: [...SILENT_PAYMENT_LABELS_QUERY_KEY, chainId, accountGroupId ?? "selected"],
	});

	const invalidate = () =>
		queryClient.invalidateQueries({ queryKey: SILENT_PAYMENT_LABELS_QUERY_KEY });

	const createMutation = useMutation({
		mutationFn: (name: string) => accountsClient.createSilentPaymentLabel({ chainId, name }),
		onSuccess: invalidate,
	});

	const renameMutation = useMutation({
		mutationFn: (input: { index: number; name: string }) =>
			accountsClient.renameSilentPaymentLabel({ chainId, ...input }),
		onSuccess: invalidate,
	});

	return {
		create: createMutation,
		labels: query.data?.labels ?? [],
		query,
		rename: renameMutation,
	};
}
