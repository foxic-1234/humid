import type { Meta, StoryObj } from "@storybook/react-vite";

import { LiquidScanStatusCard } from "./LiquidScanStatus";

const meta = {
	title: "Chains/Liquid/LiquidScanStatus",
	component: LiquidScanStatusCard,
	render: (args) => (
		<div className="flex w-[360px] flex-col p-5">
			<LiquidScanStatusCard {...args} />
		</div>
	),
	args: {
		onRetry: () => {},
		view: {
			detail: "Checked up to block #2,681,973",
			kind: "done",
			title: "Private payments up to date",
		},
	},
} satisfies Meta<typeof LiquidScanStatusCard>;

export default meta;

type Story = StoryObj<typeof meta>;

/** Every block up to the tip is checked: a quiet line under the balance. */
export const UpToDate: Story = {};

/** A catch-up of the blocks mined since the wallet was last open. */
export const CheckingNewBlocks: Story = {
	args: {
		view: {
			detail: "12 blocks left · less than a minute left",
			kind: "progress",
			percent: 60,
			title: "Checking new blocks",
		},
	},
};

/** A restored wallet: the newest blocks are done, the history is searched newest first. */
export const SearchingHistory: Story = {
	args: {
		view: {
			detail: "New payments show up right away. 405 of 70,688 blocks checked · about 25 min left",
			kind: "progress",
			percent: 0,
			title: "Searching older payments",
		},
	},
};

/** The explorer failed; a retry follows, or the user retries now. */
export const Paused: Story = {
	args: {
		view: {
			detail: "The block explorer is limiting requests; scanning resumes shortly.",
			kind: "paused",
			title: "Scanning paused",
		},
	},
};
