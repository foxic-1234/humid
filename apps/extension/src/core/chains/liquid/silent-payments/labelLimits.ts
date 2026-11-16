// Limits of BIP-352 labels, shared by the background and the popup without pulling in the
// key handling of `labels.ts`.

/** The wallet scans for at most 100 labels, the change label m = 0 among them. */
export const MAX_SILENT_PAYMENT_LABELS = 99;
export const MAX_SILENT_PAYMENT_LABEL_NAME_LENGTH = 40;

/** BIP-352 change label m = 0: always matched, never shown as a user label. */
export const SP_CHANGE_LABEL_INDICES: readonly number[] = [0];
