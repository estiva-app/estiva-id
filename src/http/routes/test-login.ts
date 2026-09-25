/**
 * `POST /auth/test-login` — a test account signs in with nobody present (PER-22).
 *
 *     { email, secret }  →  Set-Cookie: estiva_id_session=…
 *                           { pubkey, session_token, cookie_name, expires_at }
 *
 * The result is an **ordinary session**, not a delegated one: a test account is
 * the person it plays, so it reaches exactly what any member reaches. The token
 * is in the body as well as the cookie because a harness that is not a browser
 * — a script reading the relay — has no cookie jar to put it in.
 *
 * Only a test account can hold a secret (see the migration), so this route
 * cannot become a passwordless way into a real person's account. Every refusal
 * is the same 401 to the caller; which one it was goes to the audit log.
 */
import { Hono } from 'hono'
import { setCookie } from 'hono/cookie'
import { z } from 'zod'
import { config } from '../../config.js'
import { recordAudit } from '../../domain/audit.js'
import { getActivePubkey } from '../../domain/keys.js'
import { SESSION_COOKIE, createSession } from '../../domain/sessions.js'
import { authenticateTestAccount } from '../../domain/test-accounts.js'
import { badRequest, rateLimited, unauthenticated } from '../../errors.js'
import type { AppEnv } from '../app.js'
import { createRateLimiter } from '../rate-limit.js'

const schema = z.object({ email: z.string().email(), secret: z.string().min(1) })

/**
 * Ten a minute per account. A harness signs in once per run; a secret is 256
 * random bits, so this bounds noise rather than guessing.
 */
const limiter = createRateLimiter(10, 60_000)

/** Test seam — see `rate-limit.ts`. Not reachable over HTTP. */
export const resetTestLoginRateLimitForTests = () => limiter.reset()

export function testLoginRoutes(): Hono<AppEnv> {
  const routes = new Hono<AppEnv>()

  routes.post('/auth/test-login', async (c) => {
    const cfg = config()
    const parsed = schema.safeParse(await c.req.json().catch(() => null))
    if (!parsed.success) throw badRequest('Expected { email, secret }')

    const budget = limiter.check(parsed.data.email.toLowerCase())
    if (!budget.allowed) {
      c.header('retry-after', String(budget.retryAfterSeconds))
      throw rateLimited('Too many sign-in attempts', {
        retryAfterSeconds: budget.retryAfterSeconds,
      })
    }

    const result = await authenticateTestAccount(parsed.data.email, parsed.data.secret)
    if (!result.ok) {
      await recordAudit({
        actorType: 'user',
        actorUserId: result.userId,
        action: 'session.create',
        outcome: 'refused',
        detail: { method: 'test_credential', reason: result.reason },
        requestId: c.get('requestId'),
      })
      throw unauthenticated('invalid_credentials')
    }

    const [pubkey, session] = await Promise.all([
      getActivePubkey(result.userId),
      createSession({ userId: result.userId, userAgent: c.req.header('user-agent') }),
    ])

    await recordAudit({
      actorType: 'user',
      actorUserId: result.userId,
      action: 'session.create',
      outcome: 'success',
      subjectPubkey: pubkey,
      detail: { method: 'test_credential' },
      requestId: c.get('requestId'),
    })

    setCookie(c, SESSION_COOKIE, session.token, {
      httpOnly: true,
      sameSite: 'Lax',
      secure: cfg.NODE_ENV === 'production',
      path: '/',
      maxAge: cfg.SESSION_TTL_SECONDS,
    })
    return c.json({
      pubkey,
      session_token: session.token,
      cookie_name: SESSION_COOKIE,
      expires_at: session.expiresAt.toISOString(),
    })
  })

  return routes
}
