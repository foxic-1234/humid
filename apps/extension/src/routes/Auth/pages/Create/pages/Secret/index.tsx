import { useNavigate } from "@tanstack/react-router";

import { UiTabs, UiTabsContent, UiTabsList, UiTabsTrigger } from "@/ui/UiTabs/base";

import { type SeedSource, useAuthCreateContext } from "../../index";
import { CreateSeedTab } from "./components/CreateSeedTab";
import { ImportSeedTab } from "./components/ImportSeedTab";

const SEED_TABS = [
	{ Content: CreateSeedTab, label: "Create new", source: "generated", value: "create" },
	{ Content: ImportSeedTab, label: "Import", source: "imported", value: "import" },
] as const;

export function AuthCreateSecretPage() {
	const navigate = useNavigate();
	const { setSeedMaterial } = useAuthCreateContext();

	const handleComplete = (mnemonic: string, source: SeedSource, walletCreatedAt?: number) => {
		setSeedMaterial(mnemonic, source, walletCreatedAt);
		void navigate({ to: "/auth/create/password" });
	};

	return (
		<main className="flex size-full flex-col gap-5 overflow-y-auto p-5">
			<div className="flex flex-col gap-2">
				<p className="text-muted-foreground text-xs font-medium tracking-normal uppercase">
					Create · Step 1 of 2
				</p>
				<h1 className="cn-font-heading text-2xl leading-tight font-semibold">Recovery phrase</h1>
			</div>

			<UiTabs defaultValue="create" className="flex-1">
				<UiTabsList className="w-full">
					{SEED_TABS.map((tab) => (
						<UiTabsTrigger key={tab.value} value={tab.value}>
							{tab.label}
						</UiTabsTrigger>
					))}
				</UiTabsList>

				{SEED_TABS.map(({ Content, source, value }) => (
					<UiTabsContent key={value} value={value} className="mt-4">
						<Content
							onComplete={(mnemonic, walletCreatedAt?: number) =>
								handleComplete(mnemonic, source, walletCreatedAt)
							}
						/>
					</UiTabsContent>
				))}
			</UiTabs>
		</main>
	);
}
