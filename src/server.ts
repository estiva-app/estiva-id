/**
 * Process entrypoint: validate config, bind, and shut down cleanly.
 */
import { serve } from '@hono/node-server'
import { config } from './config.js'
import { closePool } from './db/pool.js'
import { reportServerError } from './domain/server-errors.js'
import { createApp } from './http/app.js'
import { logger } from './logger.js'

const cfg = config()
const app = createApp()

const server = serve({ fetch: app.fetch, port: cfg.PORT }, (info) => {
  logger.info({ port: info.port, issuer: cfg.ISSUER_URL, env: cfg.NODE_ENV }, 'estiva-id listening')
})

async function shutdown(signal: string): Promise<void> {
  logger.info({ signal }, 'shutting down')
  server.close()
  await closePool()
  process.exit(0)
}

process.on('SIGTERM', () => void shutdown('SIGTERM'))
process.on('SIGINT', () => void shutdown('SIGINT'))

/**
 * An error nothing caught still ends the process, as Node's default does, so
 * the container restarts clean; it is reported first (PROD-6), waiting at most
 * a few seconds for Sentry.
 */
function fatal(how: 'unhandled-rejection' | 'uncaught-exception') {
  return (error: unknown) => {
    logger.fatal({ err: error }, how)
    const report = reportServerError(error, { how }, logger)
    const timeout = new Promise((resolve) => setTimeout(resolve, 3_000).unref())
    void Promise.race([report, timeout]).finally(() => process.exit(1))
  }
}

process.on('unhandledRejection', fatal('unhandled-rejection'))
process.on('uncaughtException', fatal('uncaught-exception'))
