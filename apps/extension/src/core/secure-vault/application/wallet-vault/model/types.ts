export type WalletVaultStatus = {
	accountCount?: number;
	hasVault: boolean;
	isUnlocked: boolean;
	keyringCount?: number;
	createdAt?: number;
	updatedAt?: number;
};

export type WalletVaultCreateInput = {
	passphrase: string;
	seedMaterial: string;
	/** "imported" when the phrase was restored, so the wallet scans for past payments. */
	source?: "generated" | "imported";
	/** For a restored phrase: when the user says the wallet was created (ms since epoch). */
	walletCreatedAt?: number;
};

export type WalletVaultUnlockInput = {
	passphrase: string;
};
