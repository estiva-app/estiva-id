/**
 * SHA-22: the mapping from where a picture is stored to where it is served.
 *
 * Database-free by construction — that is why the mapping is its own module.
 * The cases that matter are the ones that must *not* be rewritten: this runs
 * over `picture` for every identity on every publish, and a mapping that
 * mangles a value it does not understand would corrupt a published `kind:0`.
 */
import { beforeAll, describe, expect, it } from 'vitest'
import { AVATAR_PATH, avatarDisplayUrl } from './avatar-url.js'

const RELAY = 'https://relay.test'
const ISSUER = 'https://id.test'
const SHA = 'a'.repeat(64)

beforeAll(async () => {
  process.env.RELAY_BRIDGE_URL = RELAY
  process.env.ISSUER_URL = ISSUER
  process.env.COMMUNITY_HOST = 'estiva.test'
  const { resetConfigForTests } = await import('../config.js')
  resetConfigForTests()
})

describe('a relay media URL', () => {
  it('is served from here instead', () => {
    expect(avatarDisplayUrl(`${RELAY}/media/${SHA}.jpg`)).toBe(`${ISSUER}${AVATAR_PATH}/${SHA}.jpg`)
  })

  it('keeps the hash, so the relay blob stays derivable from what we publish', () => {
    expect(avatarDisplayUrl(`${RELAY}/media/${SHA}.png`)).toContain(SHA)
  })

  it('carries a thumbnail through unchanged in shape', () => {
    expect(avatarDisplayUrl(`${RELAY}/media/${SHA}.thumb.jpg`)).toBe(
      `${ISSUER}${AVATAR_PATH}/${SHA}.thumb.jpg`,
    )
  })

  it('is idempotent — mapping an already-mapped URL changes nothing', () => {
    const once = avatarDisplayUrl(`${RELAY}/media/${SHA}.jpg`)
    expect(avatarDisplayUrl(once)).toBe(once)
  })
})

describe('anything else', () => {
  it.each([
    ['an empty profile', null],
    ['an undefined picture', undefined],
    ['an empty string', ''],
  ])('leaves %s as nothing', (_label, picture) => {
    expect(avatarDisplayUrl(picture)).toBeNull()
  })

  it.each([
    ['a URL somebody set by hand', 'https://example.test/me.jpg'],
    ['another relay', `https://other.test/media/${SHA}.jpg`],
    ['a media path that is not a blob', `${RELAY}/media/portrait.jpg`],
    ['a media path with traversal in it', `${RELAY}/media/../events`],
    ['the relay root', RELAY],
  ])('passes %s through untouched', (_label, picture) => {
    expect(avatarDisplayUrl(picture)).toBe(picture)
  })
})
