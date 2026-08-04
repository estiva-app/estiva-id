/**
 * One error shape for the whole service.
 *
 * Callers of `/sign` are other apps, and they need to distinguish "your token
 * expired" from "this app may not sign that kind" without parsing prose. Every
 * failure therefore carries a stable machine-readable `code`.
 */

export type ErrorCode =
  | 'bad_request'
  | 'unauthenticated'
  | 'forbidden'
  | 'not_found'
  | 'conflict'
  | 'policy_violation'
  | 'internal'

const STATUS_BY_CODE: Record<ErrorCode, number> = {
  bad_request: 400,
  unauthenticated: 401,
  forbidden: 403,
  not_found: 404,
  conflict: 409,
  policy_violation: 422,
  internal: 500,
}

export class AppError extends Error {
  readonly code: ErrorCode
  readonly status: number
  /** Safe to return to the caller. Never put key material or PII in here. */
  readonly detail: Record<string, unknown> | undefined

  constructor(code: ErrorCode, message: string, detail?: Record<string, unknown>) {
    super(message)
    this.name = 'AppError'
    this.code = code
    this.status = STATUS_BY_CODE[code]
    this.detail = detail
  }
}

export const badRequest = (message: string, detail?: Record<string, unknown>) =>
  new AppError('bad_request', message, detail)

export const unauthenticated = (message = 'Authentication required') =>
  new AppError('unauthenticated', message)

export const forbidden = (message: string, detail?: Record<string, unknown>) =>
  new AppError('forbidden', message, detail)

export const notFound = (message = 'Not found') => new AppError('not_found', message)

export const conflict = (message: string, detail?: Record<string, unknown>) =>
  new AppError('conflict', message, detail)

/** A `/sign` request that was well-formed but refused by app policy (PEEK-71). */
export const policyViolation = (message: string, detail?: Record<string, unknown>) =>
  new AppError('policy_violation', message, detail)

export interface ErrorBody {
  error: { code: ErrorCode; message: string; detail?: Record<string, unknown> }
}

export function toErrorBody(error: AppError): ErrorBody {
  return {
    error: {
      code: error.code,
      message: error.message,
      ...(error.detail ? { detail: error.detail } : {}),
    },
  }
}
