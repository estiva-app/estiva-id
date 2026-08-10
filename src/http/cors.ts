/**
 * CORS, for the endpoints an app on another origin has to call.
 *
 * Two rules, and the second is the whole safety argument:
 *
 * 1. **The allowlist is the registered redirect URIs**, not a second setting.
 *    One list that cannot drift out of step with the one `/authorize` enforces.
 * 2. **`Access-Control-Allow-Credentials` is never sent.** Without it a browser
 *    will neither attach the session cookie cross-origin nor expose a response
 *    to a credentialed request — so cookie-authenticated routes stay
 *    same-origin-only while bearer-authenticated ones work from anywhere
 *    registered. Every route here authenticates with something the caller
 *    already holds and sends explicitly: a code and a PKCE verifier, or a
 *    bearer token. No ambient authority is being shared.
 *
 * This started inside `routes/tokens.ts` as "CORS for /token, and only for
 * /token". The private directory (PEEK-30) is the second endpoint a browser app
 * calls cross-origin, so it moves here rather than being copied — two
 * implementations of a security boundary is one implementation and one liability.
 *
 * **In-process tests cannot check any of this.** Nothing enforces CORS when you
 * call a Hono app in the same process, which is how PEEK-90 shipped asserting
 * the code grant needed no CORS with green tests and a feature that could not
 * work. Anything added here is verified in a browser, across two origins.
 */
import type { Context } from 'hono'
import { isRegisteredRedirectOrigin } from '../domain/authorization.js'
import type { AppEnv } from './app.js'

/**
 * Echo the caller's origin when it is registered.
 *
 * Returns whether it was allowed, so a preflight can refuse outright while an
 * actual request simply proceeds without the header — a same-origin request
 * sends no `Origin` and needs none.
 */
export async function allowOrigin(c: Context<AppEnv>): Promise<boolean> {
  const origin = c.req.header('origin')
  if (!origin || !(await isRegisteredRedirectOrigin(origin))) return false

  c.header('access-control-allow-origin', origin)
  // The response varies by Origin, so a cache must not serve one origin's
  // answer to another.
  c.header('vary', 'Origin')
  return true
}

/**
 * A preflight handler for one route.
 *
 * `403` rather than `204` for an unregistered origin: there is nothing to
 * preflight, and answering successfully would imply the request that follows
 * would be allowed.
 */
export function preflight(methods: string, headers: string) {
  return async (c: Context<AppEnv>) => {
    if (!(await allowOrigin(c))) return c.body(null, 403)
    c.header('access-control-allow-methods', methods)
    c.header('access-control-allow-headers', headers)
    c.header('access-control-max-age', '600')
    return c.body(null, 204)
  }
}
