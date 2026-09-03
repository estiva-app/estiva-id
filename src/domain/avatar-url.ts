/**
 * Where a stored avatar is served from (SHA-22).
 *
 * Its own module because both sides of the round trip need it and they already
 * point at each other: `avatar.ts` publishes through `profile.ts`, so
 * `profile.ts` cannot import `avatar.ts` back. Nothing here touches the
 * database or the relay, which also makes the mapping testable on its own.
 */
import { config } from '../config.js'
import { parseBlobPath } from '../nostr/blossom.js'

/** Where {@link avatarDisplayUrl} points and where the route is mounted — one constant, so they cannot drift. */
export const AVATAR_PATH = '/avatar'

/**
 * The path a browser can actually load a stored picture from.
 *
 * The hash survives into the new URL, so this rewrites *where* the bytes are
 * fetched without giving up what PEEK-32 bought: `picture` is still content
 * addressed, still the same string for everyone, and still resolvable to the
 * relay blob by anyone holding the URL — including an app we did not write,
 * which needs only to know that the last path segment is a Blossom hash.
 *
 * Only a relay media URL is rewritten. A `picture` that already points here is
 * returned unchanged so the mapping is idempotent, and anything else — a URL
 * somebody set by hand, an empty profile — is passed through untouched rather
 * than being second-guessed.
 */
export function avatarDisplayUrl(picture: string | null | undefined): string | null {
  if (!picture) return null

  const relay = config().RELAY_BRIDGE_URL
  if (!relay || !picture.startsWith(`${relay}/media/`)) return picture

  const segment = picture.slice(`${relay}/media/`.length)
  return parseBlobPath(segment)
    ? `${config().ISSUER_URL.replace(/\/+$/, '')}${AVATAR_PATH}/${segment}`
    : picture
}
