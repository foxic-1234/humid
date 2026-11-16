import { useState } from "react";

import { UiButton } from "@/ui/UiButton/base";
import {
	UiSelect,
	UiSelectContent,
	UiSelectItem,
	UiSelectTrigger,
	UiSelectValue,
} from "@/ui/UiSelect/base";

const MONTHS: Record<string, string> = {
	"01": "January",
	"02": "February",
	"03": "March",
	"04": "April",
	"05": "May",
	"06": "June",
	"07": "July",
	"08": "August",
	"09": "September",
	"10": "October",
	"11": "November",
	"12": "December",
};

/** The Liquid Network launched in 2018: no wallet holds Liquid payments from before. */
const FIRST_YEAR = 2018;

/**
 * When a restored wallet was created, as a `YYYY-MM` month (empty until both are picked).
 * Optional: its first Silent Payments scan starts before that month, so payments received
 * earlier are found. Two selects rather than a month input, whose picker follows the OS locale.
 */
export function WalletCreatedField({
	disabled,
	id,
	onChange,
	value,
}: {
	disabled?: boolean;
	id: string;
	onChange: (value: string) => void;
	value: string;
}) {
	const [initialYear = "", initialMonth = ""] = value.split("-");
	const [year, setYear] = useState(initialYear);
	const [month, setMonth] = useState(initialMonth);

	const now = new Date();
	const currentYear = now.getFullYear();
	const years = Array.from({ length: currentYear - FIRST_YEAR + 1 }, (_, i) =>
		String(currentYear - i),
	);
	const isFutureMonth = (y: string, m: string) =>
		Number(y) === currentYear && Number(m) > now.getMonth() + 1;

	const update = (nextYear: string, nextMonth: string) => {
		const keptMonth = isFutureMonth(nextYear, nextMonth) ? "" : nextMonth;
		setYear(nextYear);
		setMonth(keptMonth);
		onChange(nextYear && keptMonth ? `${nextYear}-${keptMonth}` : "");
	};

	const descriptionId = `${id}-description`;

	return (
		<div className="flex flex-col gap-1.5">
			<div className="flex items-center justify-between gap-2">
				<label className="text-sm font-medium" htmlFor={id}>
					Wallet created <span className="text-muted-foreground font-normal">(optional)</span>
				</label>
				{year || month ? (
					<UiButton
						disabled={disabled}
						onClick={() => update("", "")}
						size="xs"
						type="button"
						variant="ghost"
					>
						Clear
					</UiButton>
				) : null}
			</div>
			<div className="flex gap-2">
				<UiSelect
					disabled={disabled}
					items={MONTHS}
					onValueChange={(next) => update(year, String(next ?? ""))}
					value={month || null}
				>
					<UiSelectTrigger aria-describedby={descriptionId} className="h-9 flex-1" id={id}>
						<UiSelectValue placeholder="Month" />
					</UiSelectTrigger>
					<UiSelectContent>
						{Object.entries(MONTHS).map(([key, label]) => (
							<UiSelectItem key={key} disabled={isFutureMonth(year, key)} value={key}>
								{label}
							</UiSelectItem>
						))}
					</UiSelectContent>
				</UiSelect>
				<UiSelect
					disabled={disabled}
					onValueChange={(next) => update(String(next ?? ""), month)}
					value={year || null}
				>
					<UiSelectTrigger aria-label="Year" className="h-9 w-28">
						<UiSelectValue placeholder="Year" />
					</UiSelectTrigger>
					<UiSelectContent>
						{years.map((y) => (
							<UiSelectItem key={y} value={y}>
								{y}
							</UiSelectItem>
						))}
					</UiSelectContent>
				</UiSelect>
			</div>
			<span id={descriptionId} className="text-muted-foreground text-xs leading-5">
				Payments received since this month are found. Not sure? Pick an earlier one, or leave it
				empty to look back from your first transaction (30 days without one).
			</span>
		</div>
	);
}
