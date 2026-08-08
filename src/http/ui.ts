/**
 * Serving the account UI (PEEK-68).
 *
 * Mounted only when a build exists. In development Vite serves the UI on its
 * own port and proxies here, so this path is never taken; in production the
 * bundle sits in `dist-web` and this is what hands it out.
 *
 * The mount is conditional rather than unconditional-and-404 because it decides
 * what this origin serves. A deployment with no UI build should answer as the
 * API-only service it is, not as a broken web app.
 */
import { existsSync } from 'node:fs'
import { readFile } from 'node:fs/promises'
import { dirname, join, normalize } from 'node:path'
import { fileURLToPath } from 'node:url'
import { serveStatic } from '@hono/node-server/serve-static'
import type { Hono } from 'hono'
import type { AppEnv } from './app.js'

/** `dist/http/ui.js` → repo root → `dist-web`. */
const UI_ROOT = join(dirname(fileURLToPath(import.meta.url)), '../../dist-web')

export function uiIsBuilt(): boolean {
  return existsSync(join(UI_ROOT, 'index.html'))
}

/**
 * Serve `dist-web`, falling back to `index.html` for client-side routes.
 *
 * The fallback is restricted to GET requests that actually want HTML. Without
 * that, a typo in an API path answers `200` with the app shell instead of a
 * JSON `404`, and a client parsing the response gets a syntax error rather than
 * the error the service meant to send.
 */
export function mountUi(app: Hono<AppEnv>): void {
  app.use(
    '/assets/*',
    serveStatic({
      root: relativeToCwd(UI_ROOT),
      // Hashed filenames, so this is safe and makes reloads free.
      onFound: (_path, c) => c.header('cache-control', 'public, max-age=31536000, immutable'),
    }),
  )

  app.get('*', async (c, next) => {
    if (!c.req.header('accept')?.includes('text/html')) return next()

    const html = await readFile(join(UI_ROOT, 'index.html'), 'utf8')
    // The shell names the user's own account; a cached copy served to the next
    // person would be the wrong shell, and it is one small file.
    c.header('cache-control', 'no-store')
    return c.html(html)
  })
}

/**
 * `serveStatic` resolves `root` relative to the process working directory, not
 * to this module. The container runs from `/app` and `dist-web` sits there, so
 * this is a plain relative path in practice — computed rather than hardcoded so
 * a different working directory does not silently serve nothing.
 */
function relativeToCwd(absolute: string): string {
  const cwd = normalize(process.cwd())
  return absolute.startsWith(cwd) ? normalize(absolute.slice(cwd.length + 1)) : absolute
}
