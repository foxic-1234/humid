import type { KeySourceId } from "@/core/accounts/application/account-registry/model/identifiers";
import type { KeyManagerState } from "@/core/key-manager/types";
import {
	WALLET_RPC_ERROR_REASONS,
	WalletRpcResourceUnavailableError,
} from "@/core/wallet-rpc/errors";

export function getLocalRootSeedMaterial(state: KeyManagerState): string {
	const keySource = Object.values(state.accountModel.keySources).find(
		(record) => record.kind === "local-root" && record.material.kind === "seed",
	);
	const secretMaterial = keySource ? state.secretMaterials[keySource.id] : undefined;

	if (!secretMaterial || secretMaterial.kind !== "seed") {
		throw new WalletRpcResourceUnavailableError(
			"No local-root seed key source is available for Liquid.",
			undefined,
			WALLET_RPC_ERROR_REASONS.MISSING_LOCAL_ROOT_KEYRING,
		);
	}

	return secretMaterial.value;
}

export function getSeedMaterialForKeySource(
	state: KeyManagerState,
	keySourceId: KeySourceId,
): string {
	const secretMaterial = state.secretMaterials[keySourceId];

	if (!secretMaterial || (secretMaterial.kind !== "seed" && secretMaterial.kind !== "mnemonic")) {
		throw new WalletRpcResourceUnavailableError(
			"No seed key source is available for the selected account.",
			undefined,
			WALLET_RPC_ERROR_REASONS.MISSING_LOCAL_ROOT_KEYRING,
		);
	}

	return secretMaterial.value;
}

/**
 * Whether the wallet's seed was restored from a recovery phrase rather than generated here: a
 * restored wallet may have received payments before this install.
 */
export function isRestoredKeySource(state: KeyManagerState, keySourceId?: KeySourceId): boolean {
	const keySource = findKeySource(state, keySourceId);

	return keySource?.kind === "imported-mnemonic" || keySource?.metadata?.source === "imported";
}

/**
 * When the user says a restored wallet was created (ms since epoch), if they said: its first
 * Silent Payments scan starts no later than that.
 */
export function getWalletCreatedAt(
	state: KeyManagerState,
	keySourceId?: KeySourceId,
): number | undefined {
	if (!isRestoredKeySource(state, keySourceId)) return undefined;
	const value = findKeySource(state, keySourceId)?.metadata?.walletCreatedAt;

	return typeof value === "number" && Number.isFinite(value) && value >= 0 ? value : undefined;
}

function findKeySource(state: KeyManagerState, keySourceId?: KeySourceId) {
	return keySourceId
		? state.accountModel.keySources[keySourceId]
		: Object.values(state.accountModel.keySources).find((record) => record.kind === "local-root");
}
