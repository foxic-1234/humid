import {
	WALLET_RPC_ERROR_REASONS,
	WalletRpcResourceUnavailableError,
	WalletRpcUserRejectedError,
} from "@/core/wallet-rpc/errors";
import type { WalletRpcBaseContext } from "@/core/wallet-rpc/types";

import type { ConfirmationPolicy } from "./ConfirmationPolicy";

export type WalletMethodInput<TParams, TContext, TReview> = {
	context: TContext;
	params: TParams;
	review: TReview;
};

export type CreateWalletMethodInput<
	TParams,
	TContext extends WalletRpcBaseContext,
	TReview,
	TResult,
> = {
	confirmation: ConfirmationPolicy<TParams, TContext, TReview>;
	/**
	 * Releases what `review` acquired (e.g. wipes an account's private keys) once the call ends:
	 * after `execute`, a rejected confirmation, or any error past `review`.
	 */
	dispose?: (review: TReview) => void;
	execute: (input: WalletMethodInput<TParams, TContext, TReview>) => Promise<TResult> | TResult;
	id: string;
	parse: (params: unknown) => TParams;
	review: (input: { context: TContext; params: TParams }) => Promise<TReview> | TReview;
};

export type WalletMethod<TContext extends WalletRpcBaseContext, TResult> = ((
	params: unknown,
	context: TContext,
) => Promise<TResult>) & {
	id: string;
};

export function createWalletMethod<
	TParams,
	TContext extends WalletRpcBaseContext,
	TReview,
	TResult,
>({
	confirmation,
	dispose,
	execute,
	id,
	parse,
	review,
}: CreateWalletMethodInput<TParams, TContext, TReview, TResult>): WalletMethod<TContext, TResult> {
	const handler = async (params: unknown, context: TContext): Promise<TResult> => {
		const parsedParams = parse(params);

		const reviewed = await review({ context, params: parsedParams });

		try {
			if (!context.authorization.isGranted(id)) {
				if (!context.confirm) {
					throw new WalletRpcResourceUnavailableError(
						"Wallet method requires a confirmation surface.",
						undefined,
						WALLET_RPC_ERROR_REASONS.CONFIRMATION_UNAVAILABLE,
					);
				}

				const confirmed = await context.confirm({
					...(await confirmation({ context, params: parsedParams, review: reviewed })),
					method: id,
					requester: context.requester,
				});

				if (!confirmed) {
					throw new WalletRpcUserRejectedError();
				}
			}

			return await execute({ context, params: parsedParams, review: reviewed });
		} finally {
			dispose?.(reviewed);
		}
	};

	return Object.assign(handler, { id });
}
