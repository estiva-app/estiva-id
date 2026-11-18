/**
 * An error's own wording, cleaned of what a person may have written (PROD-2).
 *
 * Pure, with no server import, so Estiva ID's own pages (`web/`) clean an
 * error's wording with the same rules before it leaves the browser, and this
 * server cleans it again on arrival (PROD-4).
 */

const MAX_MESSAGE = 200

const QUOTES = /["'`‘’“”«»]/

/**
 * An error's own wording with what may have been written by a person removed:
 * everything from the first quote mark to the last (an unpaired one to the
 * end), web and mail addresses, Nostr bech32 ids, and any run of 16 or more
 * letters and digits with a digit in it (keys, event ids, tokens). Firefox's URL error names its
 * input without quotes, so it keeps only its own words.
 */
export function scrubMessage(raw: unknown): string {
  if (typeof raw !== 'string') return ''
  // The whole wording is cleaned, never a cut of it: the rules below read its end.
  let text = raw.replace(/\p{Cc}+/gu, ' ')

  // An apostrophe inside a word (Firefox's "can't access property") is wording, not a quote.
  const isQuote = (i: number) =>
    QUOTES.test(text[i] as string) &&
    !(/\p{L}/u.test(text[i - 1] ?? '') && /\p{L}/u.test(text[i + 1] ?? ''))
  let first = -1
  for (let i = 0; i < text.length; i++) {
    if (isQuote(i)) {
      first = i
      break
    }
  }
  if (first >= 0) {
    let last = -1
    for (let i = text.length - 1; i > first; i--) {
      if (isQuote(i)) {
        last = i
        break
      }
    }
    text = `${text.slice(0, first)}…${last > first ? text.slice(last + 1) : ''}`
  }

  text = text
    // Wordings that name their input without quotes keep only their own words.
    // Firefox: "URL constructor: X is …", "Window.fetch: X is …"; the API's name is kept.
    .replace(
      /^(?:(URL constructor|[A-Z][A-Za-z]*\.[A-Za-z]+): )?.* is not a valid URL\.?$/s,
      (_all, api: string | undefined) =>
        api ? `${api}: … is not a valid URL.` : '… is not a valid URL.',
    )
    .replace(/\b(Failed to parse URL from|Invalid regular expression:|Invalid URL:)\s.*$/s, '$1 …')
    .replace(
      /^Cannot convert .* to an? (BigInt|Symbol|number|string|object|primitive value)\b.*$/s,
      'Cannot convert … to a $1',
    )
    // A web address runs to the end: one with a space in it would leave the rest behind.
    // Starts only where a run of scheme letters does: from every dot of `a.a.a…` it cost the square of the length.
    .replace(/(?<![a-z0-9+.-])[a-z0-9+.-]*:\/\/.*$/is, '<url>')
    // Starts only where a word does, and no part of it spans an @: `\S+@\S+` tried from every
    // letter of a long word costs the square of its length (614 ms at 32 KB, on the one thread).
    .replace(/(?<!\S)[^\s@]*@\S*\.\S*/g, '<address>')
    .replace(/\b(npub|nsec|note|nevent|naddr|nprofile|nrelay)1[0-9a-z]+/gi, '<id>')
    // A key, event id or token has digits; a long code name (`useLiveTopicSubscription`) has none.
    .replace(/[A-Za-z0-9+/=_-]{16,}/g, (run) => (/\d/.test(run) ? '<id>' : run))
    .replace(/\s+/g, ' ')
    .trim()

  return text.length > MAX_MESSAGE ? `${text.slice(0, MAX_MESSAGE - 1)}…` : text
}
