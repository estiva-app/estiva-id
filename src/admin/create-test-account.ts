/**
 * Create a test account, or rotate its secret (PER-22).
 *
 *   EMAIL=qa-1@estiva.app DISPLAY_NAME="QA-1" HANDLE=qa-1 pnpm test-account
 *   EMAIL=qa-1@estiva.app ROTATE=1 pnpm test-account
 *
 * A test account is an ordinary member everywhere but here — no bot flag, no
 * marker on the relay — and signs in with `POST /auth/test-login` and the secret
 * this prints. Creation runs enrolment's steps without the passkey: a custodied
 * key, admission to the relay, then the profile.
 *
 * A script rather than a console button, like `create-invite.ts`: a credential
 * that skips a passkey should take shell access to mint.
 *
 * On the box:
 *
 *   docker compose run --rm -T -e EMAIL=qa-1@estiva.app -e DISPLAY_NAME=QA-1 \
 *     -e HANDLE=qa-1 estiva-id node dist/admin/create-test-account.js
 */
import { config } from '../config.js'
import { closePool } from '../db/pool.js'
import { createTestAccount, issueTestSecret } from '../domain/test-accounts.js'
import { findUserByEmail } from '../domain/users.js'

const EMAIL = process.env.EMAIL ?? ''
const DISPLAY_NAME = process.env.DISPLAY_NAME ?? ''
const HANDLE = process.env.HANDLE?.toLowerCase()
const ROTATE = process.env.ROTATE === '1'

const out = (line = '') => process.stdout.write(`${line}\n`)

async function main(): Promise<void> {
  if (!/^[^@\s]+@[^@\s]+$/.test(EMAIL)) throw new Error('EMAIL is required')

  if (ROTATE) {
    const existing = await findUserByEmail(EMAIL)
    if (!existing) throw new Error(`${EMAIL} does not exist`)
    // Refused by the schema for anybody who is not a test account.
    const secret = await issueTestSecret(existing.id)
    out(`rotated    ${EMAIL}`)
    out(`secret     ${secret}`)
    out()
    out('Shown once. The previous secret no longer works.')
    return
  }

  if (!DISPLAY_NAME) throw new Error('DISPLAY_NAME is required')
  const created = await createTestAccount({
    email: EMAIL,
    displayName: DISPLAY_NAME,
    handle: HANDLE,
  })

  out(`email      ${EMAIL}`)
  out(`pubkey     ${created.pubkey}`)
  out(`admitted   ${created.admitted}`)
  out(`profile    ${created.published}`)
  out(`secret     ${created.secret}`)
  out()
  out(`Sign in:   POST ${config().ISSUER_URL}/auth/test-login { email, secret }`)
  out('Shown once — only its hash is stored.')
}

try {
  await main()
} catch (error) {
  process.stderr.write(`${(error as Error).message}\n`)
  process.exitCode = 1
} finally {
  await closePool()
}
