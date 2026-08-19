import type { Meta, StoryObj } from '@storybook/react-vite'
import { ProfileCard } from './ProfileCard'
import { emptyProfile, profile, profileWithPicture } from './stories/fixtures'
import { estivaId, estivaIdParameters } from './stories/harness'

/**
 * How you appear, everywhere in the suite.
 *
 * Estiva ID is the sole publisher of profiles — an app that could publish one
 * could undo that ownership — so this card is the only place a name or avatar
 * is set, and what it saves reaches Peek and Ship through the relay rather than
 * through either app.
 *
 * The card takes the profile as a prop and holds the save outcome in its own
 * state, so **press Save to reach the outcome states**; each story below wires
 * `PUT /me/profile` to a different answer.
 */
const meta = {
  title: 'Account/ProfileCard',
  component: ProfileCard,
  decorators: estivaId,
  parameters: {
    ...estivaIdParameters,
    layout: 'padded',
    api: { '/me/profile': { profile, published: true, eventId: 'ev_01HQ' } },
  },
  args: { profile, onSaved: () => {} },
} satisfies Meta<typeof ProfileCard>

export default meta
type Story = StoryObj<typeof meta>

/** A settled profile: name, handle, and a `nip05` the relay has accepted. */
export const Filled: Story = {}

/**
 * A picture set.
 *
 * The one state the empty card cannot show: the avatar renders at Peek's crop,
 * **Replace** and **Remove** appear in place of "Choose a picture", and the hint
 * becomes the stored URL - long, mono, and wrapping, which is the part worth
 * checking.
 */
export const WithPicture: Story = {
  args: { profile: profileWithPicture },
}

/**
 * Claimed but never filled in — the state every account passes through between
 * enrolling and its first save, and where the empty-field styling has to hold.
 */
export const Empty: Story = {
  args: { profile: emptyProfile },
}

/** A name but no handle yet, so there is nothing for `nip05` to be built from. */
export const NoHandle: Story = {
  args: { profile: { ...profile, handle: null, nip05: null } },
}

/**
 * Saved, but the relay did not take it.
 *
 * The distinction the `published` flag exists for: the row committed, so a
 * reload shows the new name, while everyone else still sees the old one. Press
 * **Save** to see it.
 */
export const SavedButNotPublished: Story = {
  parameters: {
    api: {
      '/me/profile': {
        profile,
        published: false,
        eventId: null,
        publishError: 'The relay refused the profile: not a member of this community.',
      },
    },
  },
}

/**
 * A handle somebody else already holds. Press **Save**.
 *
 * Handles are org-wide and appear in everyone's `nip05`, so a collision is a
 * refusal rather than a suggestion.
 */
export const HandleTaken: Story = {
  args: { profile: { ...profile, handle: 'jan' } },
  parameters: {
    api: {
      '/me/profile': {
        status: 409,
        body: {
          error: {
            code: 'conflict',
            message: 'That handle is already taken.',
            detail: { field: 'handle' },
          },
        },
      },
    },
  },
}

/** The save itself failing. Press **Save**. */
export const SaveFailed: Story = {
  parameters: {
    api: {
      '/me/profile': {
        status: 500,
        body: { error: { code: 'internal', message: 'Could not save your profile.' } },
      },
    },
  },
}

/** In flight, and held there: press **Save** and the request never resolves. */
export const Saving: Story = {
  parameters: { api: { '/me/profile': 'pending' } },
}
