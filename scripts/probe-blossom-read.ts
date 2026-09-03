/**
 * Does our BUD-11 *read* token satisfy a live relay? (SHA-22)
 *
 *   RELAY_BRIDGE_URL=https://estiva.estiva.app COMMUNITY_HOST=estiva.estiva.app \
 *     pnpm exec tsx scripts/probe-blossom-read.ts
 *
 * The sibling of `probe-blossom.ts`, for the verb that broke every avatar in
 * the suite. Same reason for existing: the rules are in Buzz's source and
 * nowhere else, and the whole avatar proxy rests on one assumption — that a
 * kind:24242 `t=get` event of the shape `blossom.ts` mints is the credential
 * `GET /media/*` is asking for. If that is wrong, the proxy 403s in production
 * with a green test suite behind it.
 *
 * ## What it can prove without being admitted
 *
 * The same asymmetry the upload probe leans on: **401 for anything wrong with
 * the auth event, 403 only when the event was fine and the pubkey is not a
 * member**. A key nobody has admitted therefore reads cleanly on the token
 * itself. Nothing is written, and no real blob is touched.
 *
 * ## The control that is the bug
 *
 * The first row sends no `Authorization` at all — what an `<img>` sends. A 401
 * there is the defect: it is the state in which no browser can display an
 * avatar however the workspace is configured. It is also the negative control
 * that separates "reads are gated" from "this endpoint refuses everything", so
 * it is worth a row of its own rather than a sentence in a ticket.
 *
 * **A pass here is not a working avatar.** It proves the token is right up to
 * the membership gate. Serving bytes needs the operator key admitted, which is
 * what `readAvatar` signs with.
 */
import { randomBytes } from 'node:crypto'
import { Resolver } from 'node:dns/promises'
import { request as httpsRequest } from 'node:https'
import { config } from '../src/config.js'
import { buildAuthEvent } from '../src/nostr/blossom.js'

/** Public resolver and a direct HTTPS call — see the note in `probe-blossom.ts`. */
const resolver = new Resolver()
resolver.setServers(['1.1.1.1', '8.8.8.8'])

interface Reply {
  status: number
  body: string
}

async function get(target: URL, headers: Record<string, string>): Promise<Reply> {
  const [address] = await resolver.resolve4(target.hostname)
  if (!address) throw new Error(`No A record for ${target.hostname}`)

  return new Promise((resolve, reject) => {
    const req = httpsRequest(
      {
        host: address,
        servername: target.hostname,
        path: target.pathname,
        method: 'GET',
        headers: { ...headers, host: target.hostname },
      },
      (res) => {
        const chunks: Buffer[] = []
        res.on('data', (chunk: Buffer) => chunks.push(chunk))
        res.on('end', () =>
          resolve({ status: res.statusCode ?? 0, body: Buffer.concat(chunks).toString('utf8') }),
        )
      },
    )
    req.on('error', reject)
    req.end()
  })
}

const out = (line = '') => process.stdout.write(`${line}\n`)

const cfg = config()
if (!cfg.RELAY_BRIDGE_URL || !cfg.COMMUNITY_HOST) {
  process.stderr.write('Set RELAY_BRIDGE_URL and COMMUNITY_HOST.\n')
  process.exit(2)
}

const secretKey = randomBytes(32)
/*
  A hash of nothing in particular. The membership check runs before the blob is
  looked up, so a key that is not a member never learns whether it exists —
  which is what lets this probe run against production without naming anybody's
  actual picture.
*/
const digest = 'c'.repeat(64)
const url = `${cfg.RELAY_BRIDGE_URL}/media/${digest}.jpg`

type Tags = string[][]

async function attempt(
  label: string,
  mutate: ((event: Record<string, unknown>) => void) | 'no-header',
) {
  let headers: Record<string, string> = {}
  if (mutate !== 'no-header') {
    const event = buildAuthEvent('get', {
      secretKey,
      sha256Hex: digest,
      host: cfg.COMMUNITY_HOST,
    }) as unknown as Record<string, unknown>
    mutate(event)
    headers = {
      authorization: `Nostr ${Buffer.from(JSON.stringify(event), 'utf8').toString('base64')}`,
    }
  }

  const response = await get(new URL(url), headers)
  const body = response.body.slice(0, 90).replace(/\s+/g, ' ')
  out(`  ${String(response.status).padEnd(5)}${label.padEnd(38)}${body}`)
  return response.status
}

out(`\nGET ${url}`)
out('Reading with a key nobody has admitted.')
out('  401 = auth event rejected   403 = auth event fine, membership refused\n')

const browser = await attempt('no Authorization — what an <img> sends', 'no-header')
const valid = await attempt('as built (expect 403)', () => {})

const broken: number[] = []
broken.push(
  await attempt('kind 27235, not 24242', (e) => {
    e.kind = 27235
  }),
)
broken.push(
  await attempt('t tag "upload", not "get"', (e) => {
    e.tags = (e.tags as Tags).map((t) => (t[0] === 't' ? ['t', 'upload'] : t))
  }),
)
broken.push(
  await attempt('no expiration tag', (e) => {
    e.tags = (e.tags as Tags).filter((t) => t[0] !== 'expiration')
  }),
)
broken.push(
  await attempt('empty content', (e) => {
    e.content = ''
  }),
)
broken.push(
  await attempt('neither x nor server in scope', (e) => {
    e.tags = (e.tags as Tags).filter((t) => t[0] !== 'x' && t[0] !== 'server')
  }),
)
broken.push(
  await attempt('server tag for another host', (e) => {
    e.tags = (e.tags as Tags).map((t) =>
      t[0] === 'server' ? ['server', 'somewhere.else.test'] : t,
    )
  }),
)

const controlsHeld = broken.every((status) => status === 401)
const passed = browser === 401 && valid === 403 && controlsHeld

out()
out(
  browser === 401
    ? 'Reads ARE gated — an unauthenticated GET is 401. This is SHA-22.'
    : `An unauthenticated GET returned ${browser}. Reads are no longer gated; the proxy is unnecessary.`,
)
out(
  passed
    ? 'PASS — the t=get token satisfies every check Buzz makes; only membership stopped it.'
    : `FAIL — valid token returned ${valid} (want 403); broken ones returned ${broken.join(', ')} (want 401 each).`,
)
process.exit(passed ? 0 : 1)
