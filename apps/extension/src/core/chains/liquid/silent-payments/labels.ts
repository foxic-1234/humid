import { deriveLabeledSilentPaymentAddress } from "@humid/sp-core";

import type { LiquidChainRecord } from "../chains/LiquidChainRecord";
import {
	MAX_SILENT_PAYMENT_LABEL_NAME_LENGTH,
	MAX_SILENT_PAYMENT_LABELS,
	SP_CHANGE_LABEL_INDICES,
} from "./labelLimits";
import {
	getSilentPaymentLabels,
	type SilentPaymentLabel,
	updateSilentPaymentLabels,
} from "./store";
import type { SilentPaymentRecipientKeys } from "./types";

const MAX_LABEL_INDEX = 0x7fffffff;

function normalizeLabelName(name: string): string {
	const trimmed = name.trim();
	if (trimmed.length === 0) {
		throw new Error("Label name cannot be empty");
	}
	if (trimmed.length > MAX_SILENT_PAYMENT_LABEL_NAME_LENGTH) {
		throw new Error(
			`Label name cannot be longer than ${MAX_SILENT_PAYMENT_LABEL_NAME_LENGTH} characters`,
		);
	}
	return trimmed;
}

function labelAddress(
	chain: LiquidChainRecord,
	recipientKeys: SilentPaymentRecipientKeys,
	index: number,
): string {
	return deriveLabeledSilentPaymentAddress(recipientKeys, index, chain.settings.network).address;
}

/** Create the next label m after the highest one the account has, and store it. */
export async function createSilentPaymentLabel(options: {
	chain: LiquidChainRecord;
	name: string;
	recipientKeys: SilentPaymentRecipientKeys;
	silentPaymentAddress: string;
}): Promise<SilentPaymentLabel> {
	const { chain, recipientKeys, silentPaymentAddress } = options;
	const name = normalizeLabelName(options.name);
	let created: SilentPaymentLabel | undefined;

	await updateSilentPaymentLabels(chain.id, silentPaymentAddress, (labels) => {
		const known = labels.map((label) => label.index);
		const userLabelCount = new Set(known.filter((m) => !SP_CHANGE_LABEL_INDICES.includes(m))).size;
		if (userLabelCount >= MAX_SILENT_PAYMENT_LABELS) {
			throw new Error(`An account can have at most ${MAX_SILENT_PAYMENT_LABELS} labels`);
		}
		const index = Math.max(0, ...known) + 1;
		if (index > MAX_LABEL_INDEX) {
			throw new Error("No label index is left for this account");
		}

		created = {
			address: labelAddress(chain, recipientKeys, index),
			createdAt: Date.now(),
			index,
			name,
		};
		return [...labels, created];
	});

	return created!;
}

export async function renameSilentPaymentLabel(options: {
	chainId: string;
	index: number;
	name: string;
	silentPaymentAddress: string;
}): Promise<SilentPaymentLabel> {
	const name = normalizeLabelName(options.name);
	let renamed: SilentPaymentLabel | undefined;

	await updateSilentPaymentLabels(options.chainId, options.silentPaymentAddress, (labels) =>
		labels.map((label) => {
			if (label.index !== options.index) return label;
			renamed = { ...label, name };
			return renamed;
		}),
	);

	if (!renamed) {
		throw new Error(`Unknown label ${options.index}`);
	}
	return renamed;
}

/**
 * Keep labels that payments arrived on but this wallet does not know, as
 * after a restore from the seed: their payments are the account's, so they get a placeholder name
 * the user can change.
 */
export async function adoptSilentPaymentLabels(options: {
	chain: LiquidChainRecord;
	labelIndices: readonly number[];
	recipientKeys: SilentPaymentRecipientKeys;
	silentPaymentAddress: string;
}): Promise<void> {
	const { chain, recipientKeys, silentPaymentAddress } = options;
	const isUserLabel = (m: number) =>
		Number.isInteger(m) && m > 0 && m <= MAX_LABEL_INDEX && !SP_CHANGE_LABEL_INDICES.includes(m);

	const local = new Set(
		(await getSilentPaymentLabels(chain.id, silentPaymentAddress)).map((label) => label.index),
	);
	if (options.labelIndices.every((m) => !isUserLabel(m) || local.has(m))) return;

	await updateSilentPaymentLabels(chain.id, silentPaymentAddress, (labels) => {
		const known = new Set(labels.map((label) => label.index));
		const adopted = [...new Set(options.labelIndices)]
			.filter((m) => isUserLabel(m) && !known.has(m))
			.map((index) => ({
				address: labelAddress(chain, recipientKeys, index),
				createdAt: Date.now(),
				index,
				name: `Label ${index}`,
			}));
		return [...labels, ...adopted];
	});
}
