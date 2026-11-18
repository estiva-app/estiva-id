/**
 * An error's own wording, as each browser words the errors that quote what a
 * person wrote, with the planted text gone and our code's own words kept.
 */
import { describe, expect, it } from 'vitest'
import { readBrowser, readScreen, scrubMessage } from './error-reports.js'

describe('scrubMessage', () => {
  it.each([
    // Chrome, a decrypted message that is not JSON
    [
      `Unexpected token 'p', "planted secret" is not valid JSON`,
      'Unexpected token … is not valid JSON',
    ],
    // Chrome, JSON with quotes inside the quoted input
    [
      `Unexpected token 'x', "{"planted":x}" is not valid JSON`,
      'Unexpected token … is not valid JSON',
    ],
    // Safari
    [
      `JSON Parse error: Unexpected identifier "planted"`,
      'JSON Parse error: Unexpected identifier …',
    ],
    // Firefox's URL error names its input without quotes
    [
      'URL constructor: planted secret is not a valid URL.',
      'URL constructor: … is not a valid URL.',
    ],
    // An unpaired quote: everything after it goes
    [
      `Cannot read properties of undefined (reading 'planted`,
      'Cannot read properties of undefined (reading …',
    ],
    // Addresses and ids, unquoted
    ['failed at https://peek.estiva.app/t/planted-thing now', 'failed at <url> now'],
    ['mail planted@example.com bounced', 'mail <address> bounced'],
    ['no event npub1plantedq9z8x7c6v5b4n3m2', 'no event <id>'],
    [`missing ${'a1'.repeat(32)}`, 'missing <id>'],
  ])('%s', (raw, expected) => {
    expect(scrubMessage(raw)).toBe(expected)
    expect(scrubMessage(raw)).not.toContain('planted')
  })

  it("keeps our code's own words, long names included", () => {
    expect(scrubMessage('useLiveTopicSubscription is not a function')).toBe(
      'useLiveTopicSubscription is not a function',
    )
  })

  it('caps a long message at 200 characters', () => {
    expect(scrubMessage('word '.repeat(100)).length).toBe(200)
  })

  it('is empty for anything that is not text', () => {
    expect(scrubMessage({ toString: () => 'planted' })).toBe('')
  })
})

describe('readScreen', () => {
  it.each(['/', '/app/desk', '/app/teams/:id/chat', '/:word/:ref'])(
    'keeps the pattern %s',
    (pattern) => {
      expect(readScreen(pattern)).toBe(pattern)
    },
  )

  it.each([
    '/t/quality-catch-it-5a1c',
    '/app/teams/6f1b5cce',
    '/app/desk?q=planted',
    'app/desk',
    '/app/teams/Planted',
  ])('refuses %s, which is an address, not a pattern', (raw) => {
    expect(readScreen(raw)).toBeUndefined()
  })
})

describe('readBrowser', () => {
  it.each([
    [
      'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36 Edg/131.0.0.0',
      { name: 'Edge', version: '131' },
    ],
    [
      'Mozilla/5.0 (X11; Linux x86_64; rv:133.0) Gecko/20100101 Firefox/133.0',
      { name: 'Firefox', version: '133' },
    ],
    [
      'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/18.1 Safari/605.1.15',
      { name: 'Safari', version: '18' },
    ],
    [
      'Mozilla/5.0 (iPhone; CPU iPhone OS 18_1 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/18.1 Mobile/15E148 Safari/604.1',
      { name: 'Safari', version: '18' },
    ],
    ['curl/8.5.0', { name: 'Other' }],
  ])('%s', (ua, expected) => {
    expect(readBrowser(ua)).toEqual(expected)
  })
})
