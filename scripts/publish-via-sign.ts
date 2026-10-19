/**
 * PEEK-28 — publish to the relay as a user, holding no secret key.
 *
 *   ID_BASE=https://id.estiva.app RP_ID=estiva.app \
 *   RELAY_URL=https://estiva.estiva.app CLIENT_ID=estiva-peek \
 *     npx tsx scripts/publish-via-sign.ts
 *
 * ## The claim
 *
 * Everything the relay accepts here was signed by Estiva ID. This process holds
 * a passkey (to authenticate) and a JWT (to call `/sign`) — and **never the
 * Nostr secret key**, which does not leave the identity service. That is the
 * whole point of the seam: Stage 4 can re-point it at a local signer and this
 * script would not change.
 *
 * Both events on the wire go through `/sign`:
 *
 *   1. the content itself — a channel, then a message in it
 *   2. the NIP-98 `kind:27235` that authenticates the HTTP request carrying it
 *
 * The second is easy to miss. Buzz's bridge authenticates with NIP-98, so
 * without it an app can hold a perfectly signed event and still be unable to
 * publish. Signing content but not auth would leave the seam half-built.
 *
 * ## Preconditions
 *
 * The relay runs closed, so the user's pubkey must already be a member:
 *
 *   buzz-admin add-member --pubkey <pubkey>
 */
import { randomUUID } from 'node:crypto'
import { createHash } from 'node:crypto'
import type { SignedEvent, UnsignedEvent } from '../src/nostr/event.js'
import { verifyEvent } from '../src/nostr/keys.js'
import { SoftwareAuthenticator } from '../src/test/authenticator.js'
import { signIn } from './sign-in.js'

const ID_BASE = process.env.ID_BASE ?? 'http://localhost:8787'
const RP_ID = process.env.RP_ID ?? 'localhost'
const RELAY_URL = (process.env.RELAY_URL ?? 'http://localhost:3000').replace(/\/+$/, '')
const CLIENT_ID = process.env.CLIENT_ID ?? 'estiva-peek'
const EMAIL = process.env.EMAIL ?? `peek28-${Date.now()}@invalid.test`

const out = (line: string) => process.stdout.write(`${line}\n`)
const sha256Hex = (input: string) => createHash('sha256').update(input, 'utf8').digest('hex')

async function idPost(path: string, body: unknown, headers: Record<string, string> = {}) {
  return fetch(`${ID_BASE}${path}`, {
    method: 'POST',
    headers: { 'content-type': 'application/json', ...headers },
    body: JSON.stringify(body),
  })
}

/**
 * Register and obtain a token. No Nostr key is created or seen here.
 *
 * `ESTIVA_TOKEN` + `ESTIVA_PUBKEY` skip registration, which is what makes this
 * runnable against a closed relay: membership is granted to a pubkey, and a
 * pubkey invented mid-run cannot already be a member. Register first, admit,
 * then publish with the identity you were given.
 */
async function authenticate(): Promise<{ pubkey: string; token: string }> {
  const existingToken = process.env.ESTIVA_TOKEN
  const existingPubkey = process.env.ESTIVA_PUBKEY
  if (existingToken && existingPubkey) {
    return { pubkey: existingPubkey, token: existingToken }
  }

  const device = new SoftwareAuthenticator({ rpId: RP_ID, origin: ID_BASE })

  const options = (await (
    await idPost('/auth/register/options', { email: EMAIL, displayName: 'PEEK-28 proof' })
  ).json()) as { challenge: string }

  const verifyResponse = await idPost('/auth/register/verify', device.register(options.challenge))
  if (!verifyResponse.ok) throw new Error(`register: ${await verifyResponse.text()}`)
  const { pubkey } = (await verifyResponse.json()) as { pubkey: string }

  const cookie = (verifyResponse.headers.get('set-cookie') ?? '').split(';')[0] as string
  const { access_token } = await signIn(ID_BASE, cookie, CLIENT_ID)

  return { pubkey, token: access_token }
}

/** The only way this script can produce a signature. */
async function signViaEstivaId(token: string, event: UnsignedEvent): Promise<SignedEvent> {
  const response = await idPost(
    '/sign',
    {
      event: {
        kind: event.kind,
        created_at: event.created_at,
        tags: event.tags,
        content: event.content,
      },
    },
    { authorization: `Bearer ${token}` },
  )
  if (!response.ok) throw new Error(`sign kind:${event.kind} — ${await response.text()}`)
  return ((await response.json()) as { event: SignedEvent }).event
}

/**
 * NIP-98 header, with its own kind:27235 signed by Estiva ID.
 *
 * `nonce` is not decoration: the relay records each auth event id in a replay
 * set, and `created_at` has one-second resolution — two identical requests in
 * the same second would otherwise produce a byte-identical event and the second
 * would be rejected.
 */
async function authHeader(
  token: string,
  pubkey: string,
  url: string,
  body: string,
): Promise<string> {
  const unsigned: UnsignedEvent = {
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
  }
  const signed = await signViaEstivaId(token, unsigned)
  return `Nostr ${Buffer.from(JSON.stringify(signed), 'utf8').toString('base64')}`
}

async function relayPost(token: string, pubkey: string, path: string, payload: unknown) {
  const url = `${RELAY_URL}${path}`
  const body = JSON.stringify(payload)
  const response = await fetch(url, {
    method: 'POST',
    headers: {
      'content-type': 'application/json',
      authorization: await authHeader(token, pubkey, url, body),
    },
    body,
  })
  return { status: response.status, text: await response.text() }
}

async function main(): Promise<void> {
  out(`identity service  ${ID_BASE}`)
  out(`relay             ${RELAY_URL}\n`)

  const { pubkey, token } = await authenticate()
  out(`registered  ${pubkey}`)
  out('this process holds a passkey and a JWT — no Nostr secret key\n')

  const channel = randomUUID()
  const now = () => Math.floor(Date.now() / 1000)

  // Ordering is enforced: a channel-scoped event into a channel the relay does
  // not know is rejected as a membership problem, which looks like permissions
  // and is really a missing container.
  const createChannel = await signViaEstivaId(token, {
    pubkey,
    created_at: now(),
    kind: 9007,
    tags: [
      ['h', channel],
      ['name', 'PEEK-28 proof'],
      ['visibility', 'open'],
      ['channel_type', 'stream'],
    ],
    content: '',
  })
  out(`signed kind:9007 by Estiva ID    id ${createChannel.id.slice(0, 16)}…`)
  const created = await relayPost(token, pubkey, '/events', createChannel)
  out(`  relay: ${created.status} ${created.text.slice(0, 90)}`)

  const message = await signViaEstivaId(token, {
    pubkey,
    created_at: now(),
    kind: 9,
    tags: [['h', channel]],
    content: 'Published without ever holding the key.',
  })
  out(`signed kind:9    by Estiva ID    id ${message.id.slice(0, 16)}…`)
  const published = await relayPost(token, pubkey, '/events', message)
  out(`  relay: ${published.status} ${published.text.slice(0, 90)}\n`)

  // Read it back the way any other client would.
  const read = await relayPost(token, pubkey, '/query', [{ ids: [message.id] }])
  const events = JSON.parse(read.text) as SignedEvent[]
  const found = events.find((e) => e.id === message.id)

  out('--- verdict ---')
  out(`  relay returned the event:      ${found ? 'yes' : 'NO'}`)
  if (found) {
    out(`  author is our pubkey:          ${found.pubkey === pubkey ? 'yes' : 'NO'}`)
    out(`  signature verifies:            ${verifyEvent(found) ? 'yes' : 'NO'}`)
    out(`  content survived round trip:   ${found.content === message.content ? 'yes' : 'NO'}`)
  }
  out(`\n  pubkey ${pubkey}`)
}

await main()
