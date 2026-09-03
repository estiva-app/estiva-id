/**
 * Serving a stored profile picture (SHA-22).
 *
 * `GET /avatar/<sha256>.<ext>` — the URL published as `picture`, and the only
 * one a browser can load. `domain/avatar.ts` carries the argument for why the
 * bytes come through this service at all; what is decided here is the envelope.
 *
 * **Unauthenticated, on purpose.** The caller is an `<img>` on `peek.estiva.app`
 * or `ship.estiva.app`: it sends no `Authorization`, and under `SameSite` it
 * sends no session cookie cross-site either. Requiring either would refuse
 * every real request. What replaces per-viewer authorisation is the narrowing
 * in `readAvatar` — a hash is served only while it is somebody's current
 * `picture`, so this is not a door onto the media store.
 *
 * **No CORS headers, also on purpose.** An `<img>` without `crossorigin` is not
 * a CORS request; adding the headers would suggest a guarantee this route does
 * not make and cannot test in process (see `http/cors.ts`).
 *
 * **`public`, not `private`.** Buzz answers `private, max-age=31536000,
 * immutable` because it is serving an authenticated response. This response is
 * not authenticated and the content is addressed by its own hash, so it is
 * cacheable by anything in the path — which is the point, since the alternative
 * is every avatar in every app costing this service a signed relay round trip
 * on every render.
 */
import { Hono } from 'hono'
import { AVATAR_PATH, readAvatar } from '../../domain/avatar.js'
import { AppError, notFound } from '../../errors.js'
import type { AppEnv } from '../app.js'

/** A year, `immutable`. Safe at any length: the URL names the bytes. */
const CACHE_CONTROL = 'public, max-age=31536000, immutable'

export function avatarRoutes(): Hono<AppEnv> {
  const routes = new Hono<AppEnv>()

  routes.get(`${AVATAR_PATH}/:file`, async (c) => {
    const result = await readAvatar(c.req.param('file'))

    if (!result.ok) {
      /*
        Both of these are this deployment's own configuration, not a missing
        picture: `no_operator` is `RELAY_OPERATOR_USER_ID` unset, and
        `not_admitted` is that key never having been admitted to the relay.
        They get their own status and their own log line because answering
        `404` would send whoever is looking straight past the actual fault,
        which is the failure mode PEEK-96 spent a day on.
      */
      if (result.reason === 'no_operator' || result.reason === 'not_admitted') {
        c.get('log').error({ reason: result.reason }, 'avatar read refused by the relay')
        throw new AppError('internal', 'This deployment cannot read its own media store', {
          reason: result.reason,
        })
      }
      if (result.reason === 'refused' || result.reason === 'unreachable') {
        c.get('log').warn({ reason: result.reason }, 'avatar read failed')
        throw new AppError('internal', 'Could not read that picture', { reason: result.reason })
      }
      // `not_an_avatar` and `not_found` collapse together: a hash nobody
      // references and a hash the store does not hold are the same answer, so
      // this cannot be used to test whether particular bytes exist.
      throw notFound('No such picture')
    }

    c.header('cache-control', CACHE_CONTROL)
    c.header('content-type', result.contentType)
    if (result.contentLength) c.header('content-length', result.contentLength)
    // The relay sniffs the real type on upload and the set of accepted types
    // holds no document format, but a store that serves bytes to an `<img>`
    // should still say it means the type it declared.
    c.header('x-content-type-options', 'nosniff')

    return result.body ? c.body(result.body) : c.body(null)
  })

  return routes
}
