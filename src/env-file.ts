/**
 * Load `.env` for local development, using Node's built-in loader.
 *
 * Values already present in the real environment win, so this is inert in CI
 * and in production — where configuration arrives from the platform and a
 * stray `.env` on disk must never silently override it.
 */
import { existsSync } from 'node:fs'
import { resolve } from 'node:path'

export function loadEnvFile(path = resolve(process.cwd(), '.env')): void {
  if (!existsSync(path)) return
  process.loadEnvFile(path)
}
