/**
 * The account UI (PEEK-68).
 *
 * `web/` is a plain directory of this package rather than a workspace member.
 * One `package.json`, one lockfile, one `node_modules` — the repo was a single
 * package and adding a workspace to hold one page would restructure the Docker
 * build for no gain.
 *
 * In development Vite serves the UI and proxies the API to the Hono process, so
 * the browser sees a single origin. That matters more here than in most apps:
 * the session cookie is host-only and WebAuthn assertions are checked against
 * `RP_ORIGINS`, so a UI on a different origin would fail authentication in ways
 * that look like bugs in the passkey code.
 */
import { execSync } from 'node:child_process'
import react from '@vitejs/plugin-react'
import { defineConfig } from 'vite'

/**
 * The commit the pages are built from, for their error reports (PROD-4): the
 * image build's `RELEASE` (as `GITHUB_SHA`), or this checkout's HEAD.
 */
function release(): string {
  if (process.env.GITHUB_SHA && process.env.GITHUB_SHA !== 'unknown') return process.env.GITHUB_SHA
  try {
    return execSync('git rev-parse HEAD', {
      encoding: 'utf8',
      stdio: ['ignore', 'pipe', 'ignore'],
    }).trim()
  } catch {
    return 'unknown'
  }
}

/** Everything the Hono app owns. Anything else is the SPA's. */
const API_PREFIXES = [
  '/auth',
  '/me',
  '/token',
  '/sign',
  '/report',
  '/healthz',
  '/readyz',
  '/.well-known',
]

export default defineConfig({
  root: 'web',
  plugins: [react()],
  define: {
    'import.meta.env.VITE_ID_RELEASE': JSON.stringify(release()),
  },
  build: {
    // Served beside the bundle so Sentry turns a report's frames into readable
    // code (PROD-4). The repo is public, so they show nothing new.
    sourcemap: true,
    // Beside `dist/`, not inside it: `dist/` is the compiled service and the
    // Dockerfile copies it wholesale. Keeping the two apart means the runtime
    // image can take the server without the UI, or the UI without rebuilding
    // the server.
    outDir: '../dist-web',
    emptyOutDir: true,
  },
  server: {
    port: 5173,
    proxy: Object.fromEntries(
      API_PREFIXES.map((prefix) => [
        prefix,
        { target: 'http://localhost:8787', changeOrigin: false },
      ]),
    ),
  },
})
