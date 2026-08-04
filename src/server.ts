/**
 * Process entrypoint: validate config, bind, and shut down cleanly.
 */
import { serve } from '@hono/node-server'
import { config } from './config.js'
import { closePool } from './db/pool.js'
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
