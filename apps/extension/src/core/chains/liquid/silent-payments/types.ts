/** ELIP-352 types of the extension; the core ones live in @humid/sp-core. */
export type { SilentPaymentRecipientKeys } from "@humid/sp-core";

/**
 * ELIP-352 Silent Payment output data.
 * The output is a confidential Liquid Taproot output, blinded to BK_k = bk_k·G,
 * where bk_k is derived from the BIP-352 shared secret S.
 */
export type LiquidSpOutputData = {
	blindingKeyHex: string; // bk_k 32-byte hex scalar (ELIP-352)
	blindingPublicKey: Uint8Array; // 33 bytes compressed BK_k = bk_k·G
	confidentialAddress: string; // standard Liquid Blech32 confidential address (tlq1p... / lq1p...)
	destinationScriptPubKey: Uint8Array; // standard Taproot 0x51 0x20 <P_x>
	ephemeralPublicKey: Uint8Array; // 33 bytes compressed A
	k: number; // BIP-352 per-recipient output counter (0, 1, ...)
	oneTimePoint: Uint8Array; // 33 bytes compressed P_k
	taprootPublicKey: Uint8Array; // 32 bytes x-only P_k
	tweakHex: string; // 32-byte hex output tweak t_k
};
