import type { Meta, StoryObj } from '@storybook/react-vite'
import { AdminPeople, AdminPerson } from './AdminPeople'
import { credentials, people, peopleAdmissionUnknown } from './stories/fixtures'
import { estivaId, estivaIdParameters } from './stories/harness'

/**
 * Who is in this workspace, and is any of them half set up.
 *
 * The console answers a different question from the account screens, and its
 * whole value is the awkward rows — an invite nobody accepted, somebody stuck
 * mid-enrolment, a member the relay never admitted. The fixtures are chosen to
 * show each of those rather than a plausible-looking healthy team.
 */
const meta = {
  title: 'Admin/People',
  component: AdminPeople,
  decorators: estivaId,
  parameters: {
    ...estivaIdParameters,
    layout: 'padded',
    api: { '/admin/people': { people, admissionUnknownReason: null } },
  },
  args: { onOpen: () => {} },
} satisfies Meta<typeof AdminPeople>

export default meta
type Story = StoryObj<typeof meta>

/** Every row type at once: users, invites, role identities, and the operator. */
export const Directory: Story = {}

/** A workspace on day one — one admin, nobody else yet. */
export const JustTheFounder: Story = {
  parameters: {
    api: { '/admin/people': { people: people.slice(0, 1), admissionUnknownReason: null } },
  },
}

export const Loading: Story = {
  parameters: { api: { '/admin/people': 'pending' } },
}

export const Failed: Story = {
  parameters: {
    api: {
      '/admin/people': {
        status: 500,
        body: { error: { code: 'internal', message: 'The directory could not be read.' } },
      },
    },
  },
}

/**
 * Not an admin.
 *
 * The console is reachable by URL, so the refusal is a screen rather than a
 * redirect — telling somebody what happened beats bouncing them somewhere else.
 */
export const Forbidden: Story = {
  parameters: {
    api: {
      '/admin/people': {
        status: 403,
        body: { error: { code: 'forbidden', message: 'Only an administrator can see this.' } },
      },
    },
  },
}

// --- Admission could not be read ---------------------------------------------
//
// Five reasons, arriving once beside the list rather than on every row. Before
// they existed a grey chip meant four different things — including "somebody
// offboarded the operator and disabled admission for everyone", which is how
// that went unnoticed on production.

/** No relay configured, so admission is not a question this workspace can answer. */
export const AdmissionRelayNotConfigured: Story = {
  parameters: {
    api: {
      '/admin/people': {
        people: peopleAdmissionUnknown,
        admissionUnknownReason: 'relay-not-configured',
      },
    },
  },
}

export const AdmissionOperatorNotConfigured: Story = {
  parameters: {
    api: {
      '/admin/people': {
        people: peopleAdmissionUnknown,
        admissionUnknownReason: 'operator-not-configured',
      },
    },
  },
}

/** The one that hides in plain sight: the operator identity was offboarded. */
export const AdmissionOperatorInactive: Story = {
  parameters: {
    api: {
      '/admin/people': {
        people: peopleAdmissionUnknown,
        admissionUnknownReason: 'operator-inactive',
      },
    },
  },
}

export const AdmissionForbidden: Story = {
  parameters: {
    api: {
      '/admin/people': { people: peopleAdmissionUnknown, admissionUnknownReason: 'forbidden' },
    },
  },
}

export const AdmissionUnreachable: Story = {
  parameters: {
    api: {
      '/admin/people': { people: peopleAdmissionUnknown, admissionUnknownReason: 'unreachable' },
    },
  },
}

// --- One person ---------------------------------------------------------------

type DetailStory = StoryObj<typeof AdminPerson>

const detail = (id: string, extra: Record<string, unknown> = {}): Record<string, unknown> => {
  const found = people.find((p) => p.id === id) ?? people[0]
  return { person: found, credentials, admissionUnknownReason: null, ...extra }
}

/**
 * A settled member: passkeys, a handle, admitted to the relay.
 *
 * Rendered through `AdminPerson` rather than the list, since the two are
 * separate screens sharing one module.
 */
export const PersonDetail: DetailStory = {
  render: (args) => <AdminPerson {...args} />,
  args: { id: 'usr_01HQ8ZK4', onBack: () => {} },
  parameters: { api: { '/admin/people/usr_01HQ8ZK4': detail('usr_01HQ8ZK4') } },
}

/** Stuck mid-enrolment: invite accepted, no passkey, nothing to admit. */
export const PersonEnrolling: DetailStory = {
  render: (args) => <AdminPerson {...args} />,
  args: { id: 'usr_01HQ8ZK6', onBack: () => {} },
  parameters: {
    api: { '/admin/people/usr_01HQ8ZK6': detail('usr_01HQ8ZK6', { credentials: [] }) },
  },
}

/**
 * The operator identity.
 *
 * Offboarding this one disables admission for the whole workspace, which is why
 * the row is marked rather than looking like any other service identity.
 */
export const PersonOperator: DetailStory = {
  render: (args) => <AdminPerson {...args} />,
  args: { id: 'rol_01HQ8ZM1', onBack: () => {} },
  parameters: {
    api: { '/admin/people/rol_01HQ8ZM1': detail('rol_01HQ8ZM1', { credentials: [] }) },
  },
}

/** Already offboarded — the actions available here are the reinstate half. */
export const PersonOffboarded: DetailStory = {
  render: (args) => <AdminPerson {...args} />,
  args: { id: 'usr_01HQ8ZK8', onBack: () => {} },
  parameters: {
    api: { '/admin/people/usr_01HQ8ZK8': detail('usr_01HQ8ZK8', { credentials: [] }) },
  },
}

export const PersonLoading: DetailStory = {
  render: (args) => <AdminPerson {...args} />,
  args: { id: 'usr_01HQ8ZK4', onBack: () => {} },
  parameters: { api: { '/admin/people/usr_01HQ8ZK4': 'pending' } },
}

export const PersonNotFound: DetailStory = {
  render: (args) => <AdminPerson {...args} />,
  args: { id: 'usr_missing', onBack: () => {} },
  parameters: {
    api: {
      '/admin/people/usr_missing': {
        status: 404,
        body: { error: { code: 'not_found', message: 'No such person.' } },
      },
    },
  },
}
