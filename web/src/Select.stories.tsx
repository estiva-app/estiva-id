import type { Meta, StoryObj } from '@storybook/react-vite'
import { useState } from 'react'
import { Select } from './Select'
import { estivaId, estivaIdParameters } from './stories/harness'

/**
 * The dropdown, drawn by this app rather than by the operating system.
 *
 * Open one: the menu is Peek's - white surface, `--border-default` outline, 8px
 * radius, `--shadow-lg`, 36px rows that fill on hover. The trigger is the same
 * control as the text inputs it sits beside.
 *
 * Worth exercising with the keyboard, since that is what replacing a native
 * control puts at risk: arrows move, Home and End jump, Enter and Space pick,
 * Escape closes and returns focus to the trigger.
 */
const ROLES = [
  { value: 'member', label: 'Member' },
  { value: 'admin', label: 'Admin' },
]

const meta = {
  title: 'Primitives/Select',
  component: Select,
  decorators: estivaId,
  parameters: { ...estivaIdParameters, layout: 'centered' },
  // Required props, so the stories below can be pure `render`.
  args: { value: 'member', onChange: () => {}, options: ROLES, ariaLabel: 'Example' },
} satisfies Meta<typeof Select>

export default meta
type Story = StoryObj<typeof meta>

/** Controlled, so the tick and the trigger label follow what you pick. */
function Demo({
  options,
  initial = '',
}: { options: { value: string; label: string }[]; initial?: string }) {
  const [value, setValue] = useState(initial)
  return <Select value={value} onChange={setValue} options={options} ariaLabel="Example" />
}

/** Two options - the role picker on the invite form. */
export const Short: Story = {
  render: () => <Demo options={ROLES} initial="member" />,
}

/** The audit filter: one catch-all and a list the server supplied. */
export const Long: Story = {
  render: () => (
    <Demo
      initial=""
      options={[
        { value: '', label: 'Everything' },
        { value: 'session.create', label: 'signed in' },
        { value: 'authorize.issue', label: 'authorised an app' },
        { value: 'authorize.probe', label: 'probed for a session' },
        { value: 'invite.create', label: 'invited somebody' },
        { value: 'user.offboard', label: 'offboarded somebody' },
        { value: 'profile.publish', label: 'published a profile' },
        { value: 'passkey.register', label: 'added a passkey' },
        { value: 'passkey.revoke', label: 'removed a passkey' },
      ]}
    />
  ),
}

/**
 * Longer labels than the trigger is wide.
 *
 * The trigger truncates rather than growing, so a row of controls keeps its
 * shape; the menu sizes to the trigger and its rows do not wrap.
 */
export const LongLabels: Story = {
  render: () => (
    <Demo
      initial="a"
      options={[
        { value: 'a', label: 'Everything that has ever happened in this workspace' },
        { value: 'b', label: 'Only the things an administrator did' },
      ]}
    />
  ),
}

/** Unavailable, using the same disabled treatment as every other control. */
export const Disabled: Story = {
  render: () => (
    <Select value="member" onChange={() => {}} options={ROLES} disabled ariaLabel="Example" />
  ),
}
