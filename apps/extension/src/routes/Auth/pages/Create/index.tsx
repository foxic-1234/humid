import { Outlet } from "@tanstack/react-router";
import { createContext, type ReactNode, useContext, useMemo, useState } from "react";

/** Whether the recovery phrase was generated here or restored (imported). */
export type SeedSource = "generated" | "imported";

type AuthCreateContextValue = {
	seedMaterial: string;
	seedSource: SeedSource;
	setSeedMaterial: (
		seedMaterial: string,
		seedSource?: SeedSource,
		walletCreatedAt?: number,
	) => void;
	/** For a restored phrase: when the user says the wallet was created (ms since epoch). */
	walletCreatedAt?: number;
};

const AuthCreateContext = createContext<AuthCreateContextValue | null>(null);

export function useAuthCreateContext() {
	const context = useContext(AuthCreateContext);

	if (!context) {
		throw new Error("useAuthCreateContext must be used within AuthCreateLayout.");
	}

	return context;
}

export function AuthCreateProvider({
	children,
	initialSeedMaterial = "",
}: {
	children: ReactNode;
	initialSeedMaterial?: string;
}) {
	const [seed, setSeed] = useState<{
		material: string;
		source: SeedSource;
		walletCreatedAt?: number;
	}>({
		material: initialSeedMaterial,
		source: "generated",
	});
	const value = useMemo<AuthCreateContextValue>(
		() => ({
			seedMaterial: seed.material,
			seedSource: seed.source,
			setSeedMaterial: (material, source = "generated", walletCreatedAt) =>
				setSeed({ material, source, walletCreatedAt }),
			walletCreatedAt: seed.walletCreatedAt,
		}),
		[seed],
	);

	return <AuthCreateContext.Provider value={value}>{children}</AuthCreateContext.Provider>;
}

export function AuthCreateLayout() {
	return (
		<AuthCreateProvider>
			<Outlet />
		</AuthCreateProvider>
	);
}
