import type { Meta, StoryObj } from '@storybook/react-vite'
import { SecurityCard } from './SecurityCard'
import { securityEvents } from './stories/fixtures'
import { estivaId, estivaIdParameters } from './stories/harness'

/**
 * What has happened to your access — the answer to "was that me?".
 *
 * Not the admin audit view scoped to one person: this is the smaller question
 * with the larger audience, and the server sends an allowlist of actions rather
 * than everything filtered.
 */
const meta = {
  title: 'Account/SecurityCard',
  component: SecurityCard,
  decorators: estivaId,
  parameters: {
    ...estivaIdParameters,
    layout: 'padded',
  },
} satisfies Meta<typeof SecurityCard>

export default meta
type Story = StoryObj<typeof meta>

/**
 * The case worth designing for: a recovery link **somebody else** issued.
 *
 * `bySomeoneElse` is the one distinction this screen exists to draw — "a passkey
 * was added" is unremarkable when you added it and is the whole story when an
 * admin did.
 */
export const Activity: Story = {
  parameters: { api: { '/me/security-events': { events: securityEvents } } },
}

/** Nothing an admin touched — every line is your own doing. */
export const OnlyYourOwn: Story = {
  parameters: {
    api: { '/me/security-events': { events: securityEvents.filter((e) => !e.bySomeoneElse) } },
  },
}

/** A brand new account: enrolled, signed in once, nothing else. */
export const Empty: Story = {
  parameters: { api: { '/me/security-events': { events: [] } } },
}

/**
 * **Renders nothing, by design.** Never a spinner in a card that is not the
 * reason anybody opened the page — so while the request is in flight the card
 * is simply absent, and the page must not reserve space for it.
 */
export const Loading: Story = {
  parameters: { api: { '/me/security-events': 'pending' } },
}

/** Also nothing: a failed load is silent rather than an error card. */
export const Failed: Story = {
  parameters: {
    api: { '/me/security-events': { status: 500, body: { error: { code: 'internal' } } } },
  },
}
