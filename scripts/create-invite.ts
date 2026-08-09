/**
 * Mint an invite from the box — including the very first one.
 *
 *   EMAIL=jan@example.com ROLE=admin npx tsx scripts/create-invite.ts
 *
 * ## Why a script exists at all
 *
 * Registration requires an invite (PEEK-65), and an invite requires an admin.
 * On a fresh deployment there is no admin, so without this there is no way in
 * — for anybody, including you.
 *
 * The alternatives were worse. "First registration becomes admin" is a race on
 * a public origin: `id.estiva.app` is reachable by anyone, and whoever hits it
 * first owns the workspace. A bootstrap token in the environment is the same
 * secret as shell access with an extra copy to leak. Requiring shell access is
 * the honest expression of "only the operator may create the first identity",
 * and it is how the relay's own owner key was bootstrapped.
 *
 * After the first admin exists, prefer `POST /invites` — this stays for
 * recovery, for the day the only admin loses their passkey.
 */
import { config } from '../src/config.js'
import { closePool } from '../src/db/pool.js'
import { INVITE_TTL_HOURS, anyAdminExists, createInvite } from '../src/domain/invites.js'
import { findUserByEmail } from '../src/domain/users.js'

const EMAIL = process.env.EMAIL ?? ''
const ROLE = (process.env.ROLE ?? 'member') as 'admin' | 'member'
const DISPLAY_NAME = process.env.DISPLAY_NAME
const HANDLE = process.env.HANDLE?.toLowerCase()

const out = (line = '') => process.stdout.write(`${line}\n`)

async function main(): Promise<void> {
  if (!/^[^@\s]+@[^@\s]+$/.test(EMAIL)) {
    throw new Error('EMAIL is required, e.g. EMAIL=jan@example.com')
  }
  if (ROLE !== 'admin' && ROLE !== 'member') {
    throw new Error("ROLE must be 'admin' or 'member'")
  }

  const existing = await findUserByEmail(EMAIL)
  if (existing) throw new Error(`${EMAIL} already exists — no invite needed`)

  const bootstrapping = !(await anyAdminExists())
  if (bootstrapping && ROLE !== 'admin') {
    // Minting a member invite into an empty workspace produces somebody who can
    // sign in and invite nobody, and no way to fix it without running this
    // again. Refusing is kinder than the support conversation.
    throw new Error('No admin exists yet. The first invite must be ROLE=admin.')
  }

  const invite = await createInvite({
    email: EMAIL,
    displayName: DISPLAY_NAME,
    handle: HANDLE,
    role: ROLE,
    // No admin to attribute a bootstrap invite to, which is exactly why the
    // column is nullable.
    createdBy: null,
  })

  out(bootstrapping ? '\nBootstrapping — this is the first identity.\n' : '')
  out(`email      ${invite.email}`)
  out(`role       ${invite.role}`)
  if (invite.handle) out(`handle     ${invite.handle}`)
  out(`expires    ${invite.expiresAt.toISOString()}  (${INVITE_TTL_HOURS}h)`)
  out()
  out(`${config().ISSUER_URL}/?invite=${invite.token}`)
  out()
  out('Shown once — only its hash is stored. Send it over a private channel;')
  out('anyone holding this link can enrol as that email.')

  if (bootstrapping) {
    out()
    out('Note: enrolling creates the identity but not relay access. The relay')
    out('runs closed, so publishing a profile also needs, on the box:')
    out('  docker exec buzz-prod-relay-1 buzz-admin add-member --pubkey <hex>')
  }
}

try {
  await main()
} catch (error) {
  process.stderr.write(`${(error as Error).message}\n`)
  process.exitCode = 1
} finally {
  await closePool()
}
