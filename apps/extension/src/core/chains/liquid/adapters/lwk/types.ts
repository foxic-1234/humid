import type { LwkNetwork } from "./createLwkNetwork";
import type { LwkWasmModule } from "./loadLwkWasm";

export type LwkLiquidAccountImplementation = {
	blockchainClient: InstanceType<LwkWasmModule["EsploraClient"]>;
	deriveInputKey?: (
		isInternal: boolean,
		wildcardIndex: number,
	) => {
		privateKey: Uint8Array;
		publicKey: Uint8Array;
	};
	network: LwkNetwork;
	signer: InstanceType<LwkWasmModule["Signer"]>;
	wollet: InstanceType<LwkWasmModule["Wollet"]>;
};
