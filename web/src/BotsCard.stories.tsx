import type { Meta, StoryObj } from '@storybook/react-vite'
import { BotsCard } from './BotsCard'
import { estivaId, estivaIdParameters } from './stories/harness'

/**
 * The bots you made for yourself (PEEK-164).
 *
 * Takes its list as a prop, so the states below are real data rather than a
 * stubbed request. The one state this cannot reach honestly is the one that
 * matters most — a secret shown once — because it exists only after a real
 * `POST /me/bots` and is deliberately kept nowhere. That is the design rather
 * than a gap in the story: a secret a story could render is a secret something
 * stored.
 */
const meta = {
  title: 'Account/BotsCard',
  component: BotsCard,
  decorators: estivaId,
  parameters: {
    ...estivaIdParameters,
    layout: 'padded',
  },
  args: { onChange: () => {} },
} satisfies Meta<typeof BotsCard>

export default meta
type Story = StoryObj<typeof meta>

/**
 * Nobody has made one yet — what a person sees the first time.
 *
 * The note above the field is doing the work here: it says the bot cannot
 * write, and that it stops when they do, *before* they decide whether to make
 * one. Both are enforced on the server; saying so here is what stops somebody
 * discovering the first one in a failed write and the second never.
 */
export const NoneYet: Story = {
  args: { bots: [], limit: 5 },
}

/**
 * A couple already made.
 *
 * The names are composed rather than chosen, which is why they all carry
 * "steered by" — a bot renders exactly like a colleague in a Peek conversation
 * (PEEK-171), so a self-chosen "Support" would be one careless moment from a
 * message nobody can attribute.
 */
export const AFew: Story = {
  args: {
    bots: [
      { id: '1', displayName: 'Laptop (steered by Katerina Kelepouri)' },
      { id: '2', displayName: 'Desktop (steered by Katerina Kelepouri)' },
    ],
    limit: 5,
  },
}

/**
 * At the limit, so the form is gone rather than present and failing.
 *
 * Five because each bot mints a relay member and an identity somebody has to
 * offboard later. Refusing after the fact would be a round trip to be told no,
 * under a button that looked available.
 */
export const AtTheLimit: Story = {
  args: {
    bots: Array.from({ length: 5 }, (_, index) => ({
      id: String(index),
      displayName: `Bot ${index + 1} (steered by Katerina Kelepouri)`,
    })),
    limit: 5,
  },
}

/**
 * One bot, from somebody whose name is long enough to push the composed name
 * past a comfortable width.
 *
 * Worth having as its own case: the name is built from two strings this card
 * does not control, so the first place it can look wrong is a real account.
 */
export const LongName: Story = {
  args: {
    bots: [
      {
        id: '1',
        displayName: 'Research assistant for the migration (steered by Katerina Kelepouri)',
      },
    ],
    limit: 5,
  },
}
