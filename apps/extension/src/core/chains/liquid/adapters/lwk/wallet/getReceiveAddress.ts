import { bytesToHex } from "@noble/hashes/utils.js";

import type { LiquidWalletAccount } from "../../../application/backends/LiquidWalletBackend";
import { getLwkImplementation } from "./getLwkImplementation";

const SIGNING_ADDRESS_INDEX = 0;

export function getWalletAddress(
	account: LiquidWalletAccount,
	index: number,
): { address: string; unconfidential: string } {
	const result = getLwkImplementation(account).wollet.address(index);
	const address = result.address();

	return { address: address.toString(), unconfidential: address.toUnconfidential().toString() };
}

export function getWalletReceiveAddress(account: LiquidWalletAccount): {
	address: string;
	index: number;
} {
	const implementation = getLwkImplementation(account);
	const result = implementation.wollet.address();

	return { address: result.address().toString(), index: result.index() };
}

export function getWalletSigningAddress(account: LiquidWalletAccount): {
	address: string;
	index: number;
	unconfidential: string;
} {
	const implementation = getLwkImplementation(account);
	const result = implementation.wollet.address(SIGNING_ADDRESS_INDEX);
	const address = result.address();

	return {
		address: address.toString(),
		index: result.index(),
		unconfidential: address.toUnconfidential().toString(),
	};
}

/**
 * The wallet's static Silent Payment address (B_scan, B_spend).
 * Returns the base static SP address without labels.
 */
export function getWalletSilentPaymentAddress(account: LiquidWalletAccount): {
	address: string;
	scanPublicKey: string;
	spendPublicKey: string;
} {
	if (account.silentPaymentAddress && account.silentPaymentKeys) {
		return {
			address: account.silentPaymentAddress,
			scanPublicKey: bytesToHex(account.silentPaymentKeys.scanKey.publicKey),
			spendPublicKey: bytesToHex(account.silentPaymentKeys.spendKey.publicKey),
		};
	}

	throw new Error("Silent Payment keys are not initialized for this account");
}
