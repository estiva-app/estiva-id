/**
 * PEEK-72 — one human, one pubkey, one profile. Checked, not asserted.
 *
 *   ID_BASE=https://id.estiva.app RP_ID=estiva.app \
 *     RELAY_URL=https://estiva.estiva.app npx tsx scripts/verify-identity.ts
 *
 * Run by hand after each stage. Not CI: it creates a real identity and publishes
 * real events to a real relay.
 *
 * ## Why this exists
 *
 * Identity bugs are silent. There is no error — just two plausible-looking rows
 * and a colleague who quietly appears twice. Every property below is one that
 * breaks without anything failing:
 *
 *   * a profile that saves but never reaches the relay
 *   * a handle whose domain disagrees with `communities.host`, which Buzz
 *     *discards* rather than rejecting
 *   * a rename that publishes a second `kind:0` instead of replacing the first
 *   * a withdrawn handle that keeps resolving — a leaver keeping their badge
 *
 * ## The admission step, and why it is not automated here
 *
 * The relay runs closed (`BUZZ_REQUIRE_RELAY_MEMBERSHIP=true`), so a freshly
 * minted pubkey cannot publish until it is admitted. This script prints the
 * command and waits rather than doing it: Buzz owns admission and Estiva ID
 * only observes it (PEEK-36). A verification script that quietly granted itself
 * membership would be testing a path nobody else uses.
 *
 * ## Not covered yet
 *
 * Offboarding (step 6 of the ticket). `offboardUser` exists in the domain layer
 * with no HTTP route, so this script cannot reach it — that arrives with the
 * admin surface, PEEK-66. `src/domain/offboarding.test.ts` covers the behaviour
 * against a database in the meantime.
 *
 * The single-writer assertion is narrower than the ticket's wording for a
 * reason. "Neither app authored a `kind:0`" cannot be attributed for a synthetic
 * identity no app has ever heard of, so what is checked instead is the property
 * that would actually break: **exactly one** `kind:0` exists for this pubkey.
 * Two writers produce two, and a replaceable event that failed to replace
 * produces two.
 */
import { randomUUID } from 'node:crypto'
import { createHash } from 'node:crypto'
import type { SignedEvent, UnsignedEvent } from '../src/nostr/event.js'
import { verifyEvent } from '../src/nostr/keys.js'
import { SoftwareAuthenticator } from '../src/test/authenticator.js'

const ID_BASE = (process.env.ID_BASE ?? 'http://localhost:8787').replace(/\/+$/, '')
const RP_ID = process.env.RP_ID ?? 'localhost'
const RELAY_URL = (process.env.RELAY_URL ?? 'http://localhost:3000').replace(/\/+$/, '')
const EMAIL = process.env.EMAIL ?? `peek72-${Date.now()}@invalid.test`
/** How long to wait for the pubkey to be admitted, in seconds. */
const ADMIT_TIMEOUT = Number(process.env.ADMIT_TIMEOUT ?? 300)

const out = (line = '') => process.stdout.write(`${line}\n`)
const sha256Hex = (input: string) => createHash('sha256').update(input, 'utf8').digest('hex')
const sleep = (ms: number) => new Promise((resolve) => setTimeout(resolve, ms))

let failures = 0
function check(label: string, passed: boolean, detail?: string): void {
  out(`  ${passed ? 'ok  ' : 'FAIL'}  ${label}${detail ? `  — ${detail}` : ''}`)
  if (!passed) failures += 1
}

// --- Estiva ID ---------------------------------------------------------------

interface Session {
  pubkey: string
  cookie: string
  /** Per-app tokens, minted on demand. */
  tokens: Map<string, string>
}

async function idFetch(path: string, init: RequestInit = {}): Promise<Response> {
  return fetch(`${ID_BASE}${path}`, {
    ...init,
    headers: {
      ...(init.body ? { 'content-type': 'application/json' } : {}),
      ...init.headers,
    },
  })
}

async function idJson<T>(path: string, init: RequestInit = {}): Promise<T> {
  const response = await idFetch(path, init)
  const text = await response.text()
  if (!response.ok) throw new Error(`${path} ${response.status}: ${text.slice(0, 300)}`)
  return JSON.parse(text) as T
}

/**
 * A genuine WebAuthn registration, driven by the same software authenticator the
 * tests use — real CBOR attestation, COSE keys and DER signatures.
 *
 * The passkey lives only in this process. The account survives it and is then
 * unreachable, which is fine for verification and useless as an identity.
 */
async function register(): Promise<Session> {
  const device = new SoftwareAuthenticator({ rpId: RP_ID, origin: ID_BASE })

  const options = await idJson<{ challenge: string }>('/auth/register/options', {
    method: 'POST',
    body: JSON.stringify({ email: EMAIL, displayName: 'PEEK-72 probe' }),
  })

  const response = await idFetch('/auth/register/verify', {
    method: 'POST',
    body: JSON.stringify(device.register(options.challenge)),
  })
  if (!response.ok) throw new Error(`register/verify: ${await response.text()}`)
  const { pubkey } = (await response.json()) as { pubkey: string }

  const cookie = (response.headers.get('set-cookie') ?? '').split(';')[0] as string
  if (!cookie) throw new Error('no session cookie returned')

  return { pubkey, cookie, tokens: new Map() }
}

/** Tokens are audience-bound and short-lived, so they are minted per app, lazily. */
async function tokenFor(session: Session, clientId: string): Promise<string> {
  const held = session.tokens.get(clientId)
  if (held) return held
  const { access_token } = await idJson<{ access_token: string }>('/token', {
    method: 'POST',
    headers: { cookie: session.cookie },
    body: JSON.stringify({ clientId }),
  })
  session.tokens.set(clientId, access_token)
  return access_token
}

interface ProfileResponse {
  profile: { displayName: string | null; handle: string | null; nip05: string | null }
  published: boolean
  eventId: string | null
  publishError?: string | null
}

const saveProfile = (session: Session, update: Record<string, unknown>) =>
  idJson<ProfileResponse>('/me/profile', {
    method: 'PUT',
    headers: { cookie: session.cookie },
    body: JSON.stringify(update),
  })

/** The one path an app is never allowed: signing a profile. */
async function signViaEstivaId(token: string, event: UnsignedEvent): Promise<SignedEvent> {
  const { event: signed } = await idJson<{ event: SignedEvent }>('/sign', {
    method: 'POST',
    headers: { authorization: `Bearer ${token}` },
    body: JSON.stringify({
      event: {
        kind: event.kind,
        created_at: event.created_at,
        tags: event.tags,
        content: event.content,
      },
    }),
  })
  return signed
}

// --- Relay -------------------------------------------------------------------

/**
 * NIP-98 header, itself signed by Estiva ID.
 *
 * The `nonce` is load-bearing: the relay records each auth event id in a replay
 * set and `created_at` has one-second resolution, so two identical requests in
 * the same second would collide and the second would be refused.
 */
async function authHeader(
  token: string,
  pubkey: string,
  url: string,
  body: string,
): Promise<string> {
  const signed = await signViaEstivaId(token, {
    pubkey,
    created_at: Math.floor(Date.now() / 1000),
    kind: 27235,
    tags: [
      ['u', url],
      ['method', 'POST'],
      ['nonce', randomUUID()],
      ['payload', sha256Hex(body)],
    ],
    content: '',
  })
  return `Nostr ${Buffer.from(JSON.stringify(signed), 'utf8').toString('base64')}`
}

async function relayPost(
  session: Session,
  token: string,
  path: string,
  payload: unknown,
): Promise<{ status: number; text: string }> {
  const url = `${RELAY_URL}${path}`
  const body = JSON.stringify(payload)
  const response = await fetch(url, {
    method: 'POST',
    headers: {
      'content-type': 'application/json',
      authorization: await authHeader(token, session.pubkey, url, body),
    },
    body,
  })
  return { status: response.status, text: await response.text() }
}

async function query(session: Session, token: string, filters: unknown[]): Promise<SignedEvent[]> {
  const { status, text } = await relayPost(session, token, '/query', filters)
  if (status < 200 || status >= 300) throw new Error(`query ${status}: ${text.slice(0, 200)}`)
  const parsed = JSON.parse(text)
  return Array.isArray(parsed) ? (parsed as SignedEvent[]) : []
}

/** Public, unauthenticated — the same lookup any other client performs. */
async function resolveHandle(handle: string): Promise<string | undefined> {
  const response = await fetch(
    `${RELAY_URL}/.well-known/nostr.json?name=${encodeURIComponent(handle)}`,
  )
  if (!response.ok) return undefined
  const { names } = (await response.json()) as { names: Record<string, string> }
  return names[handle]
}

/**
 * Block until the pubkey can act on the relay.
 *
 * Membership is checked by attempting a real authenticated read rather than by
 * asking a status endpoint, because the thing that matters is whether the relay
 * will serve this pubkey — not what any other system believes about it.
 */
async function waitForAdmission(session: Session, token: string): Promise<boolean> {
  const deadline = Date.now() + ADMIT_TIMEOUT * 1000
  let announced = false

  while (Date.now() < deadline) {
    const { status } = await relayPost(session, token, '/query', [{ kinds: [0], limit: 1 }])
    if (status >= 200 && status < 300) return true

    if (!announced) {
      announced = true
      out()
      out('  This pubkey is not a relay member yet, and the relay runs closed.')
      out('  On the box:')
      out()
      out(`    buzz-admin add-member --pubkey ${session.pubkey}`)
      out()
      out(`  Waiting up to ${ADMIT_TIMEOUT}s…`)
    }
    await sleep(5000)
  }
  return false
}

// --- The proof ---------------------------------------------------------------

async function main(): Promise<void> {
  out(`identity service  ${ID_BASE}`)
  out(`relay             ${RELAY_URL}`)
  out(`email             ${EMAIL}`)
  out()

  const session = await register()
  out(`registered  ${session.pubkey}`)

  // Minted early: admission polling needs it, and a token that expires mid-run
  // would look like a membership failure.
  const peekToken = await tokenFor(session, 'estiva-peek')

  if (!(await waitForAdmission(session, peekToken))) {
    out()
    out('  Never admitted. Nothing below can be checked — stopping.')
    process.exitCode = 1
    return
  }

  const handle = `peek72-${Date.now().toString(36)}`
  const picture = 'https://example.test/probe.png'

  out()
  out('--- one profile, published once ---')

  const saved = await saveProfile(session, {
    displayName: 'PEEK-72 probe',
    picture,
    handle,
  })
  check('the profile published', saved.published, saved.publishError ?? undefined)
  check('an event id came back', Boolean(saved.eventId))
  check(
    'nip05 was assembled from handle + community host',
    saved.profile.nip05?.startsWith(`${handle}@`) ?? false,
    saved.profile.nip05 ?? 'none',
  )

  // Replaceable events are replaced on ingest, but a relay that failed to
  // replace, or a second writer, both show up as more than one.
  const profiles = await query(session, peekToken, [{ kinds: [0], authors: [session.pubkey] }])
  check(
    'exactly one kind:0 exists for this pubkey',
    profiles.length === 1,
    `found ${profiles.length}`,
  )

  const profileEvent = profiles[0]
  if (profileEvent) {
    const content = JSON.parse(profileEvent.content) as Record<string, string>
    check('its signature verifies', verifyEvent(profileEvent))
    check('it carries display_name', content.display_name === 'PEEK-72 probe')
    check('it carries name as well', content.name === 'PEEK-72 probe')
    check('it carries picture', content.picture === picture)
    check('it carries nip05', content.nip05 === saved.profile.nip05)
  }

  // The end-to-end one: this only resolves if the handle's domain matched
  // `communities.host` exactly. A mismatch is discarded silently, so a published
  // profile is not evidence on its own.
  check(
    'the relay resolves the handle to this pubkey',
    (await resolveHandle(handle)) === session.pubkey,
  )

  out()
  out('--- one human, one pubkey ---')

  const channel = randomUUID()
  await relayPost(
    session,
    peekToken,
    '/events',
    await signViaEstivaId(peekToken, {
      pubkey: session.pubkey,
      created_at: Math.floor(Date.now() / 1000),
      kind: 9007,
      tags: [
        ['h', channel],
        ['name', 'PEEK-72 probe'],
        ['visibility', 'open'],
        ['channel_type', 'stream'],
      ],
      content: '',
    }),
  )

  const asPeek = await signViaEstivaId(peekToken, {
    pubkey: session.pubkey,
    created_at: Math.floor(Date.now() / 1000),
    kind: 9,
    tags: [['h', channel]],
    content: 'Written as Estiva Peek.',
  })
  const peekPublish = await relayPost(session, peekToken, '/events', asPeek)
  check('Peek published a message', peekPublish.status === 200, peekPublish.text.slice(0, 80))

  const shipToken = await tokenFor(session, 'linear-lite')
  const asShip = await signViaEstivaId(shipToken, {
    pubkey: session.pubkey,
    created_at: Math.floor(Date.now() / 1000),
    kind: 30851,
    tags: [
      ['h', channel],
      ['d', randomUUID()],
      ['title', 'Written as Estiva Ship'],
    ],
    content: 'Two apps, one person.',
  })
  const shipPublish = await relayPost(session, shipToken, '/events', asShip)
  check('Ship published an issue', shipPublish.status === 200, shipPublish.text.slice(0, 80))

  check('both events carry the same pubkey', asPeek.pubkey === asShip.pubkey)
  check('and it is the profile’s pubkey', asPeek.pubkey === session.pubkey)

  out()
  out('--- a rename reaches both apps ---')

  const renamed = await saveProfile(session, { displayName: 'PEEK-72 renamed' })
  check('the rename published', renamed.published, renamed.publishError ?? undefined)

  const afterRename = await query(session, peekToken, [{ kinds: [0], authors: [session.pubkey] }])
  check(
    'still exactly one kind:0 — replaced, not accumulated',
    afterRename.length === 1,
    `found ${afterRename.length}`,
  )
  const renamedContent = afterRename[0]
    ? (JSON.parse(afterRename[0].content) as Record<string, string>)
    : {}
  check('the relay shows the new name', renamedContent.display_name === 'PEEK-72 renamed')
  check(
    'the handle survived a rename that did not mention it',
    renamedContent.nip05 === saved.profile.nip05,
  )

  out()
  out('--- withdrawing a handle actually withdraws it ---')

  // The offboarding primitive. Measured behaviour, pinned here against the live
  // relay because it is the difference between a leaver losing their badge and
  // keeping it — and because Buzz's sync behaviour here is undocumented.
  const cleared = await saveProfile(session, { handle: null })
  check('the withdrawal published', cleared.published, cleared.publishError ?? undefined)
  check('the profile reports no handle', cleared.profile.handle === null)
  check('the relay stops resolving it', (await resolveHandle(handle)) === undefined)

  out()
  out('--- not covered ---')
  out('  offboarding — needs an HTTP route for offboardUser (PEEK-66)')
  out('  Ship still publishes its own kind:0 from a per-browser key (PEEK-48)')

  out()
  out(failures === 0 ? `PASS — ${session.pubkey}` : `FAIL — ${failures} check(s) failed`)
  if (failures > 0) process.exitCode = 1
}

await main()
