import type { Meta, StoryObj } from '@storybook/react-vite'
import { App } from './App'
import {
  AUDIT_ACTIONS,
  auditEntries,
  credentials,
  me,
  people,
  profile,
  securityEvents,
} from './stories/fixtures'
import { estivaId, estivaIdParameters } from './stories/harness'

/**
 * The pages, whole.
 *
 * The card stories cover each surface on its own, which is where the detail
 * gets designed - but several things exist only at page level and were
 * therefore invisible: the "Visible only inside Estiva" panel, the page header
 * and its actions, the admin navigation, and how three cards sit together down
 * a column. `App` routes on `location.pathname`, so each story declares the
 * path its page lives at.
 */
const account = {
  '/me': me,
  '/me/profile': profile,
  '/me/credentials': { credentials },
  '/me/security-events': { events: securityEvents },
}

const meta = {
  title: 'Pages/App',
  component: App,
  decorators: estivaId,
  parameters: {
    ...estivaIdParameters,
    layout: 'fullscreen',
    path: '/',
    api: account,
  },
} satisfies Meta<typeof App>

export default meta
type Story = StoryObj<typeof meta>

/**
 * Your account: the public profile, the private panel, passkeys, and recent
 * activity, in the order they appear.
 */
export const Account: Story = {}

/** The same page for somebody who is not an admin - no Admin action in the header. */
export const AccountAsMember: Story = {
  parameters: { api: { ...account, '/me': { ...me, role: 'member' } } },
}

/** A profile the relay has not taken: the panel says so rather than looking published. */
export const AccountNotPublished: Story = {
  parameters: {
    api: { ...account, '/me/profile': { ...profile, handle: null, nip05: null } },
  },
}

/** Before anything has loaded. */
export const Loading: Story = {
  parameters: { api: { ...account, '/me': 'pending' } },
}

/** No session: the whole app is the sign-in screen. */
export const SignedOut: Story = {
  parameters: {
    api: {
      ...account,
      '/me': { status: 401, body: { error: { code: 'unauthenticated', message: 'No session.' } } },
    },
  },
}

/** The service reachable but unwell. */
export const Failed: Story = {
  parameters: {
    api: {
      ...account,
      '/me': { status: 500, body: { error: { code: 'internal', message: 'Something broke.' } } },
    },
  },
}

// --- The admin half ----------------------------------------------------------

/** The directory, with the page header and navigation the card story cannot show. */
export const AdminDirectory: Story = {
  parameters: {
    path: '/admin',
    api: { ...account, '/admin/people': { people, admissionUnknownReason: null } },
  },
}

/** The audit log at its own route. */
export const AdminHistory: Story = {
  parameters: {
    path: '/admin/history',
    api: {
      ...account,
      '/admin/audit': { entries: auditEntries, nextBefore: null, actions: AUDIT_ACTIONS },
    },
  },
}

/** One person, reached from the directory. */
export const AdminPersonPage: Story = {
  parameters: {
    path: '/admin/usr_01HQ8ZK4',
    api: {
      ...account,
      '/admin/people/usr_01HQ8ZK4': {
        person: people.find((p) => p.id === 'usr_01HQ8ZK4') ?? people[0],
        credentials,
        admissionUnknownReason: null,
      },
    },
  },
}

/**
 * A member who typed the URL.
 *
 * Told plainly rather than shown an empty screen - and the real check is on the
 * server, which refuses `/admin/people` regardless of what this renders.
 */
export const AdminAsMember: Story = {
  parameters: {
    path: '/admin',
    api: { ...account, '/me': { ...me, role: 'member' } },
  },
}
