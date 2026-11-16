import {
	Add01Icon,
	ArrowLeft01Icon,
	CheckmarkCircle02Icon,
	Copy01Icon,
	InformationCircleIcon,
} from "@hugeicons/core-free-icons";
import { HugeiconsIcon } from "@hugeicons/react";
import { Link } from "@tanstack/react-router";
import { useState } from "react";
import QRCode from "react-qr-code";

import { useSilentPaymentLabels } from "@/core/chains/liquid/presentation/useSilentPaymentLabels";
import { MAX_SILENT_PAYMENT_LABEL_NAME_LENGTH } from "@/core/chains/liquid/silent-payments/labelLimits";
import { cn } from "@/theme/utils.ts";
import { UiButton, UiButtonVariants } from "@/ui/UiButton/base";
import { UiCopyButton } from "@/ui/UiCopyButton";
import { UiInput } from "@/ui/UiInput/base";
import { UiScrollArea } from "@/ui/UiScrollArea";
import {
	UiSelect,
	UiSelectContent,
	UiSelectItem,
	UiSelectTrigger,
	UiSelectValue,
} from "@/ui/UiSelect/base";
import { UiTabs, UiTabsContent, UiTabsList, UiTabsTrigger } from "@/ui/UiTabs/base";
import { UiTooltip, UiTooltipContent, UiTooltipProvider, UiTooltipTrigger } from "@/ui/UiTooltip";

const CONFIDENTIAL_TAB = "confidential";
const UNCONFIDENTIAL_TAB = "unconfidential";
const SILENT_PAYMENTS_TAB = "silent-payments";

function LabelWithHint({ hint, label }: { hint: string; label: string }) {
	return (
		<div className="flex items-center justify-center gap-1.5">
			<span className="text-muted-foreground text-xs font-semibold tracking-wide uppercase">
				{label}
			</span>
			<UiTooltip>
				<UiTooltipTrigger
					aria-label={`What ${label.toLowerCase()} is for`}
					className="text-muted-foreground hover:text-foreground rounded-full transition-colors"
				>
					<HugeiconsIcon icon={InformationCircleIcon} size={14} />
				</UiTooltipTrigger>
				<UiTooltipContent>{hint}</UiTooltipContent>
			</UiTooltip>
		</div>
	);
}

function AddressPanel({ address, hint, label }: { address: string; hint: string; label: string }) {
	return (
		<div className="flex flex-col items-center gap-4">
			<LabelWithHint hint={hint} label={label} />

			<div className="rounded-xl border bg-white p-3">
				<QRCode value={address} size={176} bgColor="#ffffff" fgColor="#000000" />
			</div>

			<p className="text-muted-foreground max-w-full font-mono text-xs break-all">{address}</p>

			<UiCopyButton
				className={cn(UiButtonVariants({ variant: "outline", size: "lg" }), "w-full")}
				value={address}
			>
				{(copied) => (
					<>
						<HugeiconsIcon icon={copied ? CheckmarkCircle02Icon : Copy01Icon} size={18} />
						{copied ? "Copied" : "Copy address"}
					</>
				)}
			</UiCopyButton>
		</div>
	);
}

/** A value that is not an address: shown as text, with the same label and hint treatment. */
function ValueRow({ hint, label, value }: { hint: string; label: string; value: string }) {
	return (
		<div className="border-border/60 flex w-full flex-col items-center gap-2 border-t pt-4">
			<LabelWithHint hint={hint} label={label} />
			<p className="text-muted-foreground max-w-full font-mono text-xs break-all">{value}</p>
			<UiCopyButton
				className={cn(UiButtonVariants({ variant: "ghost", size: "sm" }))}
				value={value}
			>
				{(copied) => (
					<>
						<HugeiconsIcon icon={copied ? CheckmarkCircle02Icon : Copy01Icon} size={14} />
						{copied ? "Copied" : "Copy key"}
					</>
				)}
			</UiCopyButton>
		</div>
	);
}

const MAIN_ADDRESS = "main";

/**
 * Which SP address to show: the account's own, or one of its labels (BIP-352), each a separate
 * address that pays the same account and tells its payments apart.
 */
function SilentPaymentLabelPicker({
	accountGroupId,
	chainId,
	onChange,
	value,
}: {
	accountGroupId?: string;
	chainId: string;
	onChange: (value: string) => void;
	value: string;
}) {
	const { create, labels } = useSilentPaymentLabels(chainId, accountGroupId);
	const [isAdding, setIsAdding] = useState(false);
	const [name, setName] = useState("");

	const items: Record<string, string> = { [MAIN_ADDRESS]: "Main address" };
	for (const label of labels) items[String(label.index)] = label.name;

	const submit = () => {
		create.mutate(name, {
			onSuccess: (label) => {
				onChange(String(label.index));
				setName("");
				setIsAdding(false);
			},
		});
	};

	return (
		<div className="flex w-full flex-col gap-2">
			<div className="flex w-full items-center gap-2">
				<UiSelect items={items} value={value} onValueChange={(next) => onChange(String(next))}>
					<UiSelectTrigger aria-label="Silent Payment address" className="min-w-0 flex-1">
						<UiSelectValue />
					</UiSelectTrigger>
					<UiSelectContent>
						{Object.entries(items).map(([key, title]) => (
							<UiSelectItem key={key} value={key}>
								{title}
							</UiSelectItem>
						))}
					</UiSelectContent>
				</UiSelect>
				<UiButton
					aria-label="New label"
					onClick={() => setIsAdding((open) => !open)}
					size="sm"
					type="button"
					variant="outline"
				>
					<HugeiconsIcon icon={Add01Icon} size={14} />
					Label
				</UiButton>
			</div>

			{isAdding ? (
				<form
					className="flex w-full flex-col gap-1.5 text-left"
					onSubmit={(event) => {
						event.preventDefault();
						submit();
					}}
				>
					<div className="flex items-center gap-2">
						<UiInput
							aria-label="Label name"
							maxLength={MAX_SILENT_PAYMENT_LABEL_NAME_LENGTH}
							onChange={(event) => setName(event.target.value)}
							placeholder="e.g. Donations"
							value={name}
						/>
						<UiButton disabled={create.isPending || !name.trim()} size="sm" type="submit">
							{create.isPending ? "Creating…" : "Create"}
						</UiButton>
					</div>
					<p className="text-muted-foreground text-[11px]">
						A separate address for the same account: payments to it are marked with this name, which
						never leaves the wallet.
					</p>
					{create.isError ? (
						<p className="text-destructive text-xs">
							{create.error instanceof Error ? create.error.message : "Could not create the label."}
						</p>
					) : null}
				</form>
			) : null}
		</div>
	);
}

/** Silent Payments panel with BIP-352 label selection and creation. */
function SilentPaymentsPanel({
	accountGroupId,
	baseAddress,
	chainId,
	scanPublicKey,
	spendPublicKey,
}: {
	accountGroupId?: string;
	baseAddress: string;
	chainId: string;
	scanPublicKey?: string;
	spendPublicKey?: string;
}) {
	const { labels } = useSilentPaymentLabels(chainId, accountGroupId);
	const [selected, setSelected] = useState(MAIN_ADDRESS);
	const selectedLabel = labels.find((label) => String(label.index) === selected);

	const staticHint =
		"Reusable static Silent Payment address (BIP-352). Senders generate a unique one-time Taproot stealth key for each payment, preventing address reuse while keeping amounts and asset IDs fully confidential.";
	const labelHint =
		"A labeled Silent Payment address (BIP-352) of the same account. Payments to it arrive in the same balance, marked with the label's name.";

	return (
		<div className="flex w-full flex-col items-center gap-4">
			<SilentPaymentLabelPicker
				accountGroupId={accountGroupId}
				chainId={chainId}
				onChange={setSelected}
				value={selectedLabel ? selected : MAIN_ADDRESS}
			/>

			{selectedLabel ? (
				<AddressPanel
					address={selectedLabel.address}
					hint={labelHint}
					label={`Label: ${selectedLabel.name}`}
				/>
			) : (
				<AddressPanel
					address={baseAddress}
					hint={staticHint}
					label="Liquid Silent Payment Address"
				/>
			)}

			{scanPublicKey ? (
				<ValueRow
					hint="Scan public key (Bscan). Senders derive the ECDH shared secret from it; the one-time output key and the output's blinding key both follow from that secret."
					label="Scan Public Key (Bscan)"
					value={scanPublicKey}
				/>
			) : null}

			{spendPublicKey ? (
				<ValueRow
					hint="Spend public key (Bspend) used to derive one-time stealth Taproot spending private keys."
					label="Spend Public Key (Bspend)"
					value={spendPublicKey}
				/>
			) : null}
		</div>
	);
}

export function ReceiveView({
	address,
	accountGroupId,
	accountName,
	scanPublicKey,
	chainId,
	chainName,
	silentPaymentAddress,
	spendPublicKey,
	unconfidential,
}: {
	address: string;
	accountGroupId?: string;
	accountName: string;
	scanPublicKey?: string;
	chainId: string;
	chainName: string;
	silentPaymentAddress?: string;
	spendPublicKey?: string;
	unconfidential: string;
}) {
	return (
		<UiTooltipProvider>
			<div className="flex size-full min-h-0 flex-col overflow-hidden">
				<header className="border-border/60 flex shrink-0 items-center gap-2 border-b px-2 py-2.5">
					<Link
						to="/app"
						aria-label="Back"
						className="text-muted-foreground hover:bg-accent hover:text-foreground rounded-md p-1.5 transition-colors"
					>
						<HugeiconsIcon icon={ArrowLeft01Icon} size={18} />
					</Link>
					<p className="text-sm font-semibold">Receive</p>
				</header>

				<UiScrollArea className="min-h-0 flex-1">
					<div className="flex flex-col items-center gap-5 px-5 py-6 text-center">
						<p className="text-muted-foreground text-sm">
							{accountName} · {chainName}
						</p>

						<UiTabs defaultValue={CONFIDENTIAL_TAB} className="w-full">
							<UiTabsList className="grid w-full grid-cols-3">
								<UiTabsTrigger value={CONFIDENTIAL_TAB}>Confidential</UiTabsTrigger>
								<UiTabsTrigger value={UNCONFIDENTIAL_TAB}>Explicit</UiTabsTrigger>
								<UiTabsTrigger value={SILENT_PAYMENTS_TAB}>Silent</UiTabsTrigger>
							</UiTabsList>

							<UiTabsContent value={CONFIDENTIAL_TAB} className="mt-5">
								<AddressPanel
									address={address}
									hint="Blinded, and derived one further along the descriptor each time you look. Amounts and assets paid to it are readable only with this wallet's blinding key."
									label="Confidential address"
								/>
							</UiTabsContent>

							<UiTabsContent value={SILENT_PAYMENTS_TAB} className="mt-5">
								{silentPaymentAddress ? (
									<SilentPaymentsPanel
										accountGroupId={accountGroupId}
										baseAddress={silentPaymentAddress}
										chainId={chainId}
										scanPublicKey={scanPublicKey}
										spendPublicKey={spendPublicKey}
									/>
								) : (
									<p className="text-muted-foreground py-8 text-xs">
										Silent Payments address is not available for this account.
									</p>
								)}
							</UiTabsContent>

							<UiTabsContent value={UNCONFIDENTIAL_TAB} className="mt-5">
								<AddressPanel
									address={unconfidential}
									hint="The same wallet address, unblinded, and fixed at the first index of the external chain. Contract actions are funded from here and return their change here; amounts paid to it are public."
									label="Unconfidential address"
								/>
							</UiTabsContent>
						</UiTabs>
					</div>
				</UiScrollArea>
			</div>
		</UiTooltipProvider>
	);
}
