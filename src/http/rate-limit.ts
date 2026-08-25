/**
 * A fixed-window rate limiter, in process memory.
 *
 * Built for CRO-1's `/nip44` endpoints, which is the first place in this
 * service where a *quantity* of successful calls is itself the risk. Everything
 * else here is gated on whether a caller may do a thing at all; a decryption
 * endpoint is gated on that plus how fast, because a token that leaked has a
 * ten-minute life and the difference between reading one blob and enumerating
 * every blob a person has is throughput.
 *
 * **In process memory, deliberately, and this is the limitation to know.**
 * Estiva ID runs as one container on one box (`operations/PRODUCTION.md`), so a
 * per-process counter is a per-deployment counter today and the honest simple
 * thing. It is not that under two replicas: each would keep its own window and
 * the effective limit would be N times the number here. Anything that scales
 * this service out has to move the counter to Postgres or Redis first, and a
 * comment is the wrong place to discover that — hence {@link RATE_LIMIT_SCOPE}.
 *
 * Counters are also lost on restart, which is the safe direction: a deploy
 * forgives, it does not lock anybody out.
 */

/**
 * What one counter covers. Read this before adding a replica.
 *
 * Exported so a test can assert the scope rather than infer it, and so grep for
 * "rate limit" from an ops question lands somewhere that answers it.
 */
export const RATE_LIMIT_SCOPE = 'per-process' as const

interface Window {
  count: number
  resetAtMs: number
}

export interface RateLimitResult {
  allowed: boolean
  /** Seconds until the window resets. For a `Retry-After` header. */
  retryAfterSeconds: number
}

export interface RateLimiter {
  check(key: string): RateLimitResult
  /** Test seam — drop every window so one test's calls cannot fail the next's. */
  reset(): void
}

/**
 * `limit` requests per `windowMs`, keyed by whatever the caller passes.
 *
 * Fixed window rather than sliding: a burst can straddle a boundary and reach
 * 2×limit briefly, which is a known and acceptable property here. A sliding
 * window costs a per-key array of timestamps, and the thing being bounded is an
 * enumeration over minutes, not a burst over one second.
 */
export function createRateLimiter(limit: number, windowMs: number): RateLimiter {
  const windows = new Map<string, Window>()

  return {
    check(key: string): RateLimitResult {
      const now = Date.now()
      const existing = windows.get(key)

      if (!existing || existing.resetAtMs <= now) {
        windows.set(key, { count: 1, resetAtMs: now + windowMs })
        // Expired windows are only cleared when their own key is next seen, so
        // a key that is never used again would leak one small object. Sweep on
        // write, cheaply, rather than holding a timer that keeps the process
        // alive — the map is bounded by active (app, user) pairs regardless.
        if (windows.size > 1000) {
          for (const [candidate, window] of windows) {
            if (window.resetAtMs <= now) windows.delete(candidate)
          }
        }
        return { allowed: true, retryAfterSeconds: 0 }
      }

      const retryAfterSeconds = Math.max(1, Math.ceil((existing.resetAtMs - now) / 1000))
      if (existing.count >= limit) return { allowed: false, retryAfterSeconds }

      existing.count += 1
      return { allowed: true, retryAfterSeconds }
    },

    reset() {
      windows.clear()
    },
  }
}
