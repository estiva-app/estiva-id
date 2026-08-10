/**
 * The private directory (PEEK-30).
 *
 * Two channels, keyed the same way. A person's public face is a `kind:0` on the
 * relay — `display_name`, `picture`, `nip05` — readable by anyone, including
 * apps we did not write. Their **email is not there and never will be**: a
 * private contact address on a shared relay is unretractable, and Nostr's slot
 * for a public identifier is `nip05`, not email.
 *
 * So "show me a colleague's name, email and avatar" is answered from two places
 * joined on the pubkey: the avatar and name from the relay, the email from here.
 * That is what makes the requirement work without the leak.
 *
 * ## Who may ask
 *
 * A bearer token, which means an app acting for a signed-in person. Not the
 * session cookie: the callers are on other origins, which is the whole reason
 * `/token` exists.
 *
 * The token's subject must still be an **active** identity. Tokens live 600s and
 * a leaver holds one until it expires, so re-checking here is what stops the
 * directory being readable for ten minutes after somebody is offboarded.
 *
 * ## Lookup, never listing
 *
 * There is no endpoint that returns everybody. A caller has to know the pubkey
 * it is asking about, which it does because it read it off an event it could
 * already see. A token scoped to one app is therefore not a way to export the
 * staff list — that view exists, for admins, at `/admin/people`.
 */
import { Hono } from 'hono'
import { z } from 'zod'
import { lookupContacts } from '../../domain/directory.js'
import { verifyToken } from '../../domain/jwt.js'
import { findSignerByPubkey } from '../../domain/keys.js'
import { badRequest, forbidden, notFound, unauthenticated } from '../../errors.js'
import type { AppEnv } from '../app.js'
import { allowOrigin, preflight } from '../cors.js'

const HEX64 = /^[0-9a-f]{64}$/

/**
 * A cap, because the body is attacker-influenced and the query is an `IN` list.
 * A thread with more than this many distinct authors on one screen is not a
 * case worth optimising for; the caller pages.
 */
const MAX_LOOKUP = 200

const lookupSchema = z.object({
  pubkeys: z.array(z.string().regex(HEX64, 'expected 64 lowercase hex characters')).max(MAX_LOOKUP),
})

function bearerToken(header: string | undefined): string {
  if (!header?.startsWith('Bearer ')) throw unauthenticated('Expected a Bearer token')
  const token = header.slice('Bearer '.length).trim()
  if (!token) throw unauthenticated('Empty Bearer token')
  return token
}

/**
 * Resolve the caller, and refuse anyone who is no longer active.
 *
 * The app is authenticated by the token's audience, but nothing about the *app*
 * decides this — a directory read is made on behalf of a person, and it is that
 * person's standing that matters.
 */
async function requireActiveCaller(authorization: string | undefined): Promise<string> {
  const { pubkey } = await verifyToken(bearerToken(authorization))
  const caller = await findSignerByPubkey(pubkey)
  if (!caller || caller.userStatus !== 'active') {
    throw forbidden('That identity is no longer active')
  }
  return pubkey
}

export function directoryRoutes(): Hono<AppEnv> {
  const routes = new Hono<AppEnv>()

  // Preflighted because of the Authorization header — a browser sends OPTIONS
  // before any request carrying one. Without this the app sees a CORS failure
  // and no request ever reaches the handler, which is precisely the shape of
  // the PEEK-90 bug and precisely what in-process tests cannot catch.
  routes.options('/directory/lookup', preflight('POST, OPTIONS', 'authorization, content-type'))
  routes.options('/directory/:pubkey', preflight('GET, OPTIONS', 'authorization'))

  /** Several at once — what an app rendering a thread actually needs. */
  routes.post('/directory/lookup', async (c) => {
    await allowOrigin(c)
    await requireActiveCaller(c.req.header('authorization'))

    const parsed = lookupSchema.safeParse(await c.req.json().catch(() => null))
    if (!parsed.success) {
      throw badRequest(`Expected { pubkeys: string[] }, at most ${MAX_LOOKUP}`, {
        issues: parsed.error.issues.map((issue) => ({
          path: issue.path.join('.'),
          message: issue.message,
        })),
      })
    }

    // Unknown pubkeys are absent rather than null entries: the caller asked
    // about keys, and the answer is the people among them.
    return c.json({ contacts: await lookupContacts(parsed.data.pubkeys) })
  })

  /** One, for the common case of opening a single person. */
  routes.get('/directory/:pubkey', async (c) => {
    await allowOrigin(c)
    await requireActiveCaller(c.req.header('authorization'))

    const pubkey = c.req.param('pubkey')
    if (!HEX64.test(pubkey)) throw badRequest('Expected a 64-character lowercase hex pubkey')

    const [contact] = await lookupContacts([pubkey])
    if (!contact) throw notFound('Nobody here has that pubkey')
    return c.json(contact)
  })

  return routes
}
