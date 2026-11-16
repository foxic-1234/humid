import { useState } from "react";

import { useSilentPaymentLabels } from "@/core/chains/liquid/presentation/useSilentPaymentLabels";
import { MAX_SILENT_PAYMENT_LABEL_NAME_LENGTH } from "@/core/chains/liquid/silent-payments/labelLimits";
import { UiButton } from "@/ui/UiButton/base";
import { UiField, UiFieldDescription, UiFieldLabel } from "@/ui/UiField";
import { UiInput } from "@/ui/UiInput/base";

function errorText(error: unknown, fallback: string): string {
	return error instanceof Error ? error.message : fallback;
}

/** One label: its name, saved when the field loses focus or on Enter, and its address. */
function LabelRow({
	address,
	index,
	name,
	onRename,
}: {
	address: string;
	index: number;
	name: string;
	onRename: (name: string) => void;
}) {
	const [draft, setDraft] = useState(name);
	const save = () => {
		const next = draft.trim();
		if (next && next !== name) onRename(next);
		else setDraft(name);
	};

	return (
		<li className="flex flex-col gap-1">
			<div className="flex items-center gap-2">
				<span className="text-muted-foreground w-8 shrink-0 font-mono text-[11px]">#{index}</span>
				<UiInput
					aria-label={`Name of label ${index}`}
					className="text-xs"
					maxLength={MAX_SILENT_PAYMENT_LABEL_NAME_LENGTH}
					onBlur={save}
					onChange={(event) => setDraft(event.target.value)}
					onKeyDown={(event) => {
						if (event.key === "Enter") event.currentTarget.blur();
					}}
					value={draft}
				/>
			</div>
			<p className="text-muted-foreground truncate pl-10 font-mono text-[10px]" title={address}>
				{address}
			</p>
		</li>
	);
}

/**
 * The account's BIP-352 labels on this network: separate SP addresses of the same account whose
 * payments are marked with the label's name. Created here or on the Receive screen. A label cannot
 * be deleted: its address may already be out there, and payments to it must still be found.
 */
export function SilentPaymentLabelsField({ chainId }: { chainId: string }) {
	const { create, labels, query, rename } = useSilentPaymentLabels(chainId);
	const [name, setName] = useState("");

	// A chain being added has no account on it yet.
	if (!query.isSuccess) return null;

	return (
		<UiField>
			<UiFieldLabel htmlFor="sp-new-label">Labels</UiFieldLabel>

			{labels.length > 0 ? (
				<ul className="flex flex-col gap-2.5">
					{labels.map((label) => (
						<LabelRow
							key={label.index}
							address={label.address}
							index={label.index}
							name={label.name}
							onRename={(next) => rename.mutate({ index: label.index, name: next })}
						/>
					))}
				</ul>
			) : null}

			<form
				className="flex items-center gap-2"
				onSubmit={(event) => {
					event.preventDefault();
					create.mutate(name, { onSuccess: () => setName("") });
				}}
			>
				<UiInput
					id="sp-new-label"
					className="text-xs"
					maxLength={MAX_SILENT_PAYMENT_LABEL_NAME_LENGTH}
					onChange={(event) => setName(event.target.value)}
					placeholder="New label, e.g. Donations"
					value={name}
				/>
				<UiButton
					disabled={create.isPending || !name.trim()}
					size="sm"
					type="submit"
					variant="outline"
				>
					{create.isPending ? "Creating…" : "Create"}
				</UiButton>
			</form>

			{create.isError ? (
				<p className="text-destructive text-xs">
					{errorText(create.error, "Could not create the label.")}
				</p>
			) : null}
			{rename.isError ? (
				<p className="text-destructive text-xs">
					{errorText(rename.error, "Could not rename the label.")}
				</p>
			) : null}

			<UiFieldDescription>
				Separate Silent Payment addresses of the selected account on this network. Payments to a
				label are marked with its name, which never leaves the wallet.
			</UiFieldDescription>
		</UiField>
	);
}
