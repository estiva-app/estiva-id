import { unauthenticated } from '../errors.js'

/** The token from an `Authorization: Bearer <token>` header, or a 401. */
export function bearerToken(header: string | undefined): string {
  if (!header?.startsWith('Bearer ')) throw unauthenticated('Expected a Bearer token')
  const token = header.slice('Bearer '.length).trim()
  if (!token) throw unauthenticated('Empty Bearer token')
  return token
}
