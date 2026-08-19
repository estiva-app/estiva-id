import type { Meta, StoryObj } from '@storybook/react-vite'
import { AuditLog } from './AuditLog'
import { AUDIT_ACTIONS, auditEntries } from './stories/fixtures'
import { estivaId, estivaIdParameters } from './stories/harness'

/**
 * The admin console's answer to "what has happened here".
 *
 * Every actor type and outcome is styled apart, so the fixtures deliberately mix
 * people, apps and the system, and success with refusal and error.
 */
const meta = {
  title: 'Admin/AuditLog',
  component: AuditLog,
  decorators: estivaId,
  parameters: {
    ...estivaIdParameters,
    layout: 'padded',
    api: {
      '/admin/audit': { entries: auditEntries, nextBefore: null, actions: AUDIT_ACTIONS },
    },
  },
} satisfies Meta<typeof AuditLog>

export default meta
type Story = StoryObj<typeof meta>

/** A full page: users, apps and the system, with a refusal and an error among them. */
export const Ready: Story = {}

/**
 * More to load.
 *
 * `nextBefore` is what puts the button there; paging is by cursor rather than
 * offset, so the control only appears when the server says there is a next page.
 */
export const MorePages: Story = {
  parameters: {
    api: {
      '/admin/audit': {
        entries: auditEntries,
        nextBefore: auditEntries[auditEntries.length - 1]?.occurredAt ?? null,
        actions: AUDIT_ACTIONS,
      },
    },
  },
}

/**
 * The compact rendering, used where the log is embedded under one person rather
 * than standing on its own.
 */
export const Compact: Story = {
  args: { compact: true, person: 'usr_01HQ8ZK3' },
}

/** A filter that matches nothing, and a workspace where nothing has happened yet. */
export const Empty: Story = {
  parameters: {
    api: { '/admin/audit': { entries: [], nextBefore: null, actions: AUDIT_ACTIONS } },
  },
}

/** The log itself failing — an admin screen that cannot answer its one question. */
export const Failed: Story = {
  parameters: {
    api: {
      '/admin/audit': {
        status: 500,
        body: { error: { code: 'internal', message: 'The audit log could not be read.' } },
      },
    },
  },
}

/** Waiting on the first page. */
export const Loading: Story = {
  parameters: { api: { '/admin/audit': 'pending' } },
}
