import type { Meta, StoryObj } from '@storybook/react-vite'
import { PasskeysCard } from './PasskeysCard'
import {
  credentials,
  phoneCredential,
  platformCredential,
  securityKeyCredential,
} from './stories/fixtures'
import { estivaId, estivaIdParameters } from './stories/harness'

/**
 * The devices that can sign in as you.
 *
 * Takes its credentials as a prop, so every case here is real data rather than
 * a stubbed request — including the ones that need hardware to reach honestly.
 */
const meta = {
  title: 'Account/PasskeysCard',
  component: PasskeysCard,
  decorators: estivaId,
  parameters: {
    ...estivaIdParameters,
    layout: 'padded',
  },
  args: { onChange: () => {} },
} satisfies Meta<typeof PasskeysCard>

export default meta
type Story = StoryObj<typeof meta>

/** Three devices of different kinds — the shape of a settled account. */
export const Several: Story = {
  args: { credentials },
}

/** Right after enrolling: one passkey, never yet used to sign in. */
export const JustEnrolled: Story = {
  args: { credentials: [{ ...platformCredential, lastUsedAt: null, nickname: null }] },
}

/**
 * A single passkey, which is the case where removing it must not be offered
 * casually — it is the only way in.
 */
export const OnlyOne: Story = {
  args: { credentials: [platformCredential] },
}

/** A hardware key: no nickname, single-device, not backed up, never used. */
export const SecurityKey: Story = {
  args: { credentials: [securityKeyCredential] },
}

/** Synced from a phone — backed up, hybrid transport. */
export const Phone: Story = {
  args: { credentials: [phoneCredential] },
}

/**
 * No passkeys at all.
 *
 * Unreachable through the app — enrolment mints one — but reachable by revoking
 * the last, so the empty state is worth having a design for.
 */
export const None: Story = {
  args: { credentials: [] },
}
