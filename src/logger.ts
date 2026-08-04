/**
 * Structured logging.
 *
 * The project brief calls out that failure must be *loud*: after Stage 2 no app
 * can sign locally, so an outage here stops publishing everywhere. Logs are
 * JSON in production so that is greppable and alertable rather than decorative.
 */
import { pino } from 'pino'
import { config } from './config.js'

const cfg = config()

export const logger = pino({
  level: cfg.LOG_LEVEL,
  base: { service: 'estiva-id' },
  redact: {
    paths: [
      'req.headers.authorization',
      'req.headers.cookie',
      'res.headers["set-cookie"]',
      '*.secretKey',
      '*.secretKeyHex',
      '*.kek',
    ],
    censor: '[redacted]',
  },
  transport:
    cfg.NODE_ENV === 'development'
      ? { target: 'pino-pretty', options: { colorize: true, translateTime: 'HH:MM:ss' } }
      : undefined,
})

export type Logger = typeof logger
