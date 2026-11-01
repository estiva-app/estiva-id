/**
 * App credentials — the rows PEEK-71's policy lives in.
 *
 * Stage 1 has no client secret. The user's token is audience-bound to one app,
 * so the audience *is* the app's identity on a `/sign` call, and the policy row
 * is a ceiling on what that token can do. A secret would add nothing a browser
 * app could actually keep.
 */
import { queryOne } from '../db/pool.js'
import type { AppPolicy } from './policy.js'

interface AppRow {
  client_id: string
  name: string
  allowed_kinds: number[]
  nip98_url_prefixes: string[]
  relay_auth_urls: string[]
  status: 'active' | 'disabled'
}

export async function findAppPolicy(clientId: string): Promise<AppPolicy | undefined> {
  const row = await queryOne<AppRow>(
    `select client_id, name, allowed_kinds, nip98_url_prefixes, relay_auth_urls, status
       from app_credentials where client_id = $1`,
    [clientId],
  )
  if (!row) return undefined
  return {
    clientId: row.client_id,
    name: row.name,
    allowedKinds: row.allowed_kinds,
    nip98UrlPrefixes: row.nip98_url_prefixes,
    relayAuthUrls: row.relay_auth_urls,
    status: row.status,
  }
}
