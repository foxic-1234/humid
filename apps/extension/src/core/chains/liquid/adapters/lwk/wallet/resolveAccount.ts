import { deriveSilentPaymentKeysFromSeed } from "@humid/sp-core";

import {
	WALLET_RPC_ERROR_REASONS,
	WalletRpcResourceUnavailableError,
} from "@/core/wallet-rpc/errors";

import { createLiquidAccountRegistry } from "../../../accounts/createLiquidAccountRegistry";
import type {
	LiquidWalletAccount,
	ResolveLiquidWalletAccountInput,
} from "../../../application/backends/LiquidWalletBackend";
import { isLiquidMainnetChain } from "../../../chains/LiquidChainRecord";
import { toLiquidAssetId } from "../../../domain/validation";
import { createLwkBlockchainClient } from "../createLwkBlockchainClient";
import { createLwkMnemonicFromSeedMaterial } from "../createLwkMnemonic";
import { createLwkNetwork } from "../createLwkNetwork";
import { getLocalRootSeedMaterial, getSeedMaterialForKeySource } from "../getLocalRootSeedMaterial";
import { loadLwkWasm } from "../loadLwkWasm";

/**
 * The key origin of a single-key descriptor, e.g. `[5abf90c6/84'/1'/0']` →
 * `{ fingerprint: 0x5abf90c6, path: "m/84'/1'/0'" }`.
 */
export function descriptorKeyOrigin(descriptor: string): { fingerprint: number; path: string } {
	const match = /\[([0-9a-f]{8})((?:\/\d+['h]?)+)\]/i.exec(descriptor);
	if (!match) {
		throw new Error("The wallet descriptor has no key origin");
	}
	return { fingerprint: Number.parseInt(match[1], 16), path: `m${match[2].replace(/h/g, "'")}` };
}

export async function createLwkLiquidAccount(
	input: ResolveLiquidWalletAccountInput,
): Promise<LiquidWalletAccount> {
	const seedMaterial = input.keySourceId
		? getSeedMaterialForKeySource(input.keyManagerState, input.keySourceId)
		: getLocalRootSeedMaterial(input.keyManagerState);
	const lwk = await loadLwkWasm();
	const network = createLwkNetwork(lwk, input.chain);
	const blockchainClient = createLwkBlockchainClient(lwk, input.chain, network);
	const masterMnemonic = createLwkMnemonicFromSeedMaterial(lwk, seedMaterial);

	try {
		const masterSigner = new lwk.Signer(masterMnemonic, network);
		const accountGroupIndex = input.accountGroupIndex ?? 0;
		const activeMnemonic =
			accountGroupIndex === 0
				? masterMnemonic
				: masterSigner.derive_bip85_mnemonic(accountGroupIndex, 12);
		const signer = accountGroupIndex === 0 ? masterSigner : new lwk.Signer(activeMnemonic, network);
		const descriptor = signer.wpkhSlip77Descriptor();
		const wollet = new lwk.Wollet(network, descriptor);
		const dwid = wollet.dwid();
		const rawPolicyAssetId = network.policyAsset().toString();
		const policyAssetId = toLiquidAssetId(input.chain.id, rawPolicyAssetId);
		const accountIdentifier = `${input.chain.id}:${dwid}` as const;

		const activeMnemonicStr = activeMnemonic.toString();
		// Free intermediate WASM mnemonics and signers that are not retained in implementation
		if (accountGroupIndex !== 0) {
			masterSigner.free();
			activeMnemonic.free();
		}
		masterMnemonic.free();

		// ELIP-352: coin type 1776' and `lqsp` on mainnet, 1' and `tlqsp` on testnet and regtest.
		const spNetwork = isLiquidMainnetChain(input.chain) ? "mainnet" : "testnet";

		const { HDKey } = await import("@scure/bip32");
		const { mnemonicToSeedSync } = await import("@scure/bip39");

		let seed: Uint8Array | undefined;
		let masterHD: InstanceType<typeof HDKey> | undefined;
		let spKeys: ReturnType<typeof deriveSilentPaymentKeysFromSeed>;
		let accountHD: InstanceType<typeof HDKey>;

		try {
			seed = mnemonicToSeedSync(activeMnemonicStr);
			// ELIP-352: derive silent payment keys from seed using account 0 on the active mnemonic.
			// In Humid, each account group (accountGroupIndex >= 1) is already an isolated wallet
			// with its own BIP-85 child mnemonic (activeMnemonic). Deriving at account index 0
			// aligns with BIP-84 (m/84'/.../0') and LWK descriptor derivation, ensuring that any
			// standard third-party ELIP-352 wallet importing the account's mnemonic recovers
			// all silent payment transactions at account 0 without double derivation.
			spKeys = deriveSilentPaymentKeysFromSeed(seed, spNetwork, 0);
			masterHD = HDKey.fromMasterSeed(seed);
			// Input keys come from the same account path LWK's descriptor uses, read from its key
			// origin rather than assumed; the fingerprint proves the descriptor is this seed's.
			const origin = descriptorKeyOrigin(descriptor.toString());
			if (masterHD.fingerprint !== origin.fingerprint) {
				throw new Error("The wallet descriptor's key origin does not belong to this seed");
			}
			accountHD = masterHD.derive(origin.path);
		} finally {
			// Securely wipe raw seed bytes and master HD extended private key immediately
			// after account-level derivation is complete.
			if (seed) {
				seed.fill(0);
			}
			if (masterHD) {
				masterHD.wipePrivateData();
			}
		}

		const deriveInputKey = (isInternal: boolean, wildcardIndex: number) => {
			const branch = isInternal ? 1 : 0;
			const branchNode = accountHD.deriveChild(branch);
			const child = branchNode.deriveChild(wildcardIndex);
			// The branch node holds a private key too; only the child's key is handed out (and the
			// caller zeroizes it).
			branchNode.wipePrivateData();
			if (!child.privateKey || !child.publicKey) {
				throw new Error(`Failed to derive child key at branch ${branch}, index ${wildcardIndex}`);
			}
			return {
				privateKey: child.privateKey,
				publicKey: child.publicKey,
			};
		};

		const wipePrivateData = () => {
			if (spKeys?.scanKey?.privateKey) {
				spKeys.scanKey.privateKey.fill(0);
			}
			if (spKeys?.spendKey?.privateKey) {
				spKeys.spendKey.privateKey.fill(0);
			}
			accountHD?.wipePrivateData();
		};

		if (input.updateKeyManagerState) {
			const accountRegistry = createLiquidAccountRegistry();

			await input.updateKeyManagerState((state) => {
				const ensured = accountRegistry.ensureDescriptorWalletAccount({
					accountGroupId: input.accountGroupId,
					accountModel: state.accountModel,
					chainId: input.chain.id,
					context: {
						dwid,
						policyAssetId,
						rawPolicyAssetId,
					},
				});

				return {
					...state,
					accountModel: ensured.accountModel,
				};
			});
		}

		return {
			accountGroupId: input.accountGroupId,
			accountGroupIndex,
			accountIdentifier,
			...(input.keySourceId === undefined ? {} : { keySourceId: input.keySourceId }),
			chain: input.chain,
			chainId: input.chain.id,
			descriptor: descriptor.toString(),
			dwid,
			implementation: {
				blockchainClient,
				deriveInputKey,
				network,
				signer,
				wollet,
			},
			policyAssetId,
			rawPolicyAssetId,
			silentPaymentAddress: spKeys.address,
			silentPaymentKeys: spKeys,
			wipePrivateData,
		};
	} catch (error) {
		console.error("[liquid] Failed to derive the Liquid account", error);

		const cause = error instanceof Error ? error.message : String(error);

		throw new WalletRpcResourceUnavailableError(
			`Could not derive a Liquid software wallet from the local root keyring: ${cause}`,
			undefined,
			WALLET_RPC_ERROR_REASONS.WALLET_DERIVATION_FAILED,
		);
	}
}
