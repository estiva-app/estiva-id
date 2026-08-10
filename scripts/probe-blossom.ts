/**
 * Does our BUD-11 auth event actually satisfy a live relay? (PEEK-32)
 *
 *   RELAY_BRIDGE_URL=https://estiva.estiva.app COMMUNITY_HOST=estiva.estiva.app \
 *     pnpm exec tsx scripts/probe-blossom.ts
 *
 * Kept in the repo for the same reason `estiva-ship/scripts/probe-nip05.ts` is:
 * Buzz's media auth is undocumented outside its own source, this is cheap to
 * re-run, and if the rules ever change this is what notices.
 *
 * ## Why it can prove anything without being admitted
 *
 * Buzz answers **401 for anything wrong with the auth event** and **403 only
 * when the event was fine but the pubkey is not a relay member**
 * (`crates/buzz-media/src/error.rs`). Both checks run *before* the body is
 * consumed. So a freshly generated, never-admitted key gives a clean read on the
 * auth event itself, and nothing is stored either way.
 *
 * The negative controls are the point. A 403 from the valid event means nothing
 * unless the deliberately broken ones come back 401 — otherwise the endpoint
 * might be refusing everything the same way.
 *
 * **A pass here is not a passing upload.** It proves the client is correct up to
 * the membership gate. Storing a blob needs an operator to run
 * `buzz-admin add-member --pubkey <hex>` for a key this service holds.
 */
import { randomBytes } from 'node:crypto'
import { Resolver } from 'node:dns/promises'
import { request as httpsRequest } from 'node:https'
import { sha256 } from '@noble/hashes/sha256'
import { bytesToHex } from '@noble/hashes/utils'
import { config } from '../src/config.js'
import { buildUploadAuthEvent } from '../src/nostr/blossom.js'

/**
 * Resolve through a public resolver, and speak HTTPS directly.
 *
 * WSL's stub resolver intermittently returns NXDOMAIN for `estiva.estiva.app`
 * while the record is perfectly healthy publicly, and `fetch` cannot be pointed
 * at another resolver — `dns.setServers` only affects `dns.resolve*`, not the
 * `getaddrinfo` path `fetch` takes. So this does its own lookup and hands the
 * address to `node:https`, which still sends the real hostname as SNI and in
 * `Host`, so the relay resolves its tenant exactly as it would for anyone else.
 *
 * A local networking quirk should not be able to look like a relay outage.
 */
const resolver = new Resolver()
resolver.setServers(['1.1.1.1', '8.8.8.8'])

interface Reply {
  status: number
  body: string
}

async function put(target: URL, headers: Record<string, string>, body: Uint8Array): Promise<Reply> {
  const [address] = await resolver.resolve4(target.hostname)
  if (!address) throw new Error(`No A record for ${target.hostname}`)

  return new Promise((resolve, reject) => {
    const req = httpsRequest(
      {
        host: address,
        servername: target.hostname,
        path: target.pathname,
        method: 'PUT',
        headers: { ...headers, host: target.hostname, 'content-length': String(body.byteLength) },
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
    req.end(body)
  })
}

/** A real 1x1 PNG, so MIME sniffing has something valid to accept. */
const PNG = Buffer.from(
  'iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAYAAAAfFcSJAAAADUlEQVR42mP8z8BQDwAEhQGAhKmMIQAAAABJRU5ErkJggg==',
  'base64',
)

/** Same convention as the other scripts here: stdout, not a logger. */
const out = (line = '') => process.stdout.write(`${line}\n`)

const cfg = config()
if (!cfg.RELAY_BRIDGE_URL || !cfg.COMMUNITY_HOST) {
  process.stderr.write('Set RELAY_BRIDGE_URL and COMMUNITY_HOST.\n')
  process.exit(2)
}

const secretKey = randomBytes(32)
const digest = bytesToHex(sha256(new Uint8Array(PNG)))
const url = `${cfg.RELAY_BRIDGE_URL}/media/upload`

type Tags = string[][]

async function attempt(label: string, mutate: (event: Record<string, unknown>) => void) {
  const event = buildUploadAuthEvent({
    secretKey,
    sha256Hex: digest,
    host: cfg.COMMUNITY_HOST,
  }) as unknown as Record<string, unknown>
  mutate(event)

  const response = await put(
    new URL(url),
    {
      'content-type': 'image/png',
      'x-sha-256': digest,
      authorization: `Nostr ${Buffer.from(JSON.stringify(event), 'utf8').toString('base64')}`,
    },
    new Uint8Array(PNG),
  )
  const body = response.body.slice(0, 90).replace(/\s+/g, ' ')
  out(`  ${String(response.status).padEnd(5)}${label.padEnd(36)}${body}`)
  return response.status
}

out(`\nPUT ${url}`)
out('Uploading a 1x1 PNG signed by a key nobody has admitted.')
out('  401 = auth event rejected   403 = auth event fine, membership refused\n')

const valid = await attempt('as built (expect 403)', () => {})

const broken: number[] = []
broken.push(
  await attempt('kind 27235, not 24242', (e) => {
    e.kind = 27235
  }),
)
broken.push(
  await attempt('t tag "get", not "upload"', (e) => {
    e.tags = (e.tags as Tags).map((t) => (t[0] === 't' ? ['t', 'get'] : t))
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
  await attempt('x tag not matching the body', (e) => {
    e.tags = (e.tags as Tags).map((t) => (t[0] === 'x' ? ['x', 'f'.repeat(64)] : t))
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
const passed = valid === 403 && controlsHeld

out(
  passed
    ? '\nPASS — the auth event satisfies every BUD-11 check; only membership stopped it.'
    : `\nFAIL — valid event returned ${valid} (want 403); broken events returned ${broken.join(', ')} (want 401 each).`,
)
process.exit(passed ? 0 : 1)
