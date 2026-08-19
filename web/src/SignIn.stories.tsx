import type { Meta, StoryObj } from '@storybook/react-vite'
import { SignIn } from './SignIn'
import { estivaId, estivaIdParameters } from './stories/harness'

/**
 * The only screen somebody sees before they have an identity.
 *
 * It has three jobs, chosen from the address bar: sign in, enrol from an
 * invite, or recover an account. There is no route to the last two except a
 * link, so each story sets the query string that produces its screen —
 * `parameters.search` — and answers the lookup that follows from fixtures.
 *
 * Nothing here invokes an authenticator. Pressing the button in a story starts a
 * WebAuthn ceremony the browser will refuse; the states worth designing are the
 * ones before and around it.
 */
const INVITE = 'inv_74gTpBjJXmclqOJQJj7sgdCYMiYXbiA2iavYUBEc'
const RECOVERY = 'rec_9fQ2LmT4vXsA7bKp1ZrN6yEwCu3HdJgV'

const meta = {
  title: 'Entry/SignIn',
  component: SignIn,
  decorators: estivaId,
  parameters: {
    ...estivaIdParameters,
    layout: 'centered',
  },
  args: { onSignedIn: () => {} },
} satisfies Meta<typeof SignIn>

export default meta
type Story = StoryObj<typeof meta>

/**
 * The default: one button, and a line saying accounts are created by invitation.
 *
 * No email field on purpose — login is usernameless, so the authenticator offers
 * whatever discoverable credential it holds for this origin and the person types
 * nothing at all.
 */
export const SignInDefault: Story = {
  name: 'Sign in',
}

/** Looking the invite up, before it is known whether it is any good. */
export const LoadingInvite: Story = {
  parameters: { search: `?invite=${INVITE}`, api: { [`/invites/${INVITE}`]: 'pending' } },
}

/**
 * Enrolment — the screen a new colleague actually lands on.
 *
 * The email is shown, never typed: it comes from the invite, and a link that let
 * you choose your own address would not be an invitation to anything.
 */
export const Enrol: Story = {
  parameters: {
    search: `?invite=${INVITE}`,
    api: {
      [`/invites/${INVITE}`]: {
        valid: true,
        email: 'ravi@estiva.app',
        displayName: 'Ravi Chandra',
        handle: 'ravi',
      },
    },
  },
}

/** An invite with no name or handle set — only the address is fixed. */
export const EnrolMinimal: Story = {
  parameters: {
    search: `?invite=${INVITE}`,
    api: {
      [`/invites/${INVITE}`]: {
        valid: true,
        email: 'newcomer@estiva.app',
        displayName: null,
        handle: null,
      },
    },
  },
}

/**
 * Expired. Invites last 168 hours, and the reason is in the body — the endpoint
 * answers `404` for expired, consumed and unknown alike so nobody can probe it
 * for which tokens exist.
 */
export const InviteExpired: Story = {
  parameters: {
    search: `?invite=${INVITE}`,
    api: { [`/invites/${INVITE}`]: { status: 404, body: { valid: false, reason: 'expired' } } },
  },
}

/** Already used — which means somebody enrolled, so the answer is to sign in. */
export const InviteConsumed: Story = {
  parameters: {
    search: `?invite=${INVITE}`,
    api: { [`/invites/${INVITE}`]: { status: 404, body: { valid: false, reason: 'consumed' } } },
  },
}

/** A mistyped or invented token. */
export const InviteUnknown: Story = {
  parameters: {
    search: `?invite=${INVITE}`,
    api: { [`/invites/${INVITE}`]: { status: 404, body: { valid: false, reason: 'unknown' } } },
  },
}

/** Resolving a recovery link. */
export const LoadingRecovery: Story = {
  parameters: { search: `?recover=${RECOVERY}`, api: { [`/recovery/${RECOVERY}`]: 'pending' } },
}

/**
 * Recovery: whose account this link opens, before anybody touches an
 * authenticator.
 *
 * Mechanically identical to an admin taking over an account — which is exactly
 * why `SecurityCard` reports it to the person it happened to.
 */
export const Recover: Story = {
  parameters: {
    search: `?recover=${RECOVERY}`,
    api: {
      [`/recovery/${RECOVERY}`]: {
        ok: true,
        recovery: {
          email: 'katerina@estiva.app',
          displayName: 'Katerina',
          expiresAt: '2026-08-25T17:23:05.196Z',
        },
      },
    },
  },
}

/** A recovery link that has run out. */
export const RecoveryExpired: Story = {
  parameters: {
    search: `?recover=${RECOVERY}`,
    api: { [`/recovery/${RECOVERY}`]: { status: 404, body: { ok: false, reason: 'expired' } } },
  },
}

/** Already spent — the new passkey exists, so this link must not work twice. */
export const RecoveryConsumed: Story = {
  parameters: {
    search: `?recover=${RECOVERY}`,
    api: { [`/recovery/${RECOVERY}`]: { status: 404, body: { ok: false, reason: 'consumed' } } },
  },
}
