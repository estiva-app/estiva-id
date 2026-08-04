/**
 * A software WebAuthn authenticator, for tests.
 *
 * PEEK-26's acceptance is behavioural — *"a person can register, sign in from a
 * second device, and list/revoke their own credentials"* — so the tests drive
 * real ceremonies rather than mocking the verifier. That means producing the
 * bytes a real authenticator produces: CBOR attestation objects, COSE public
 * keys, and DER ECDSA signatures over `authData || sha256(clientDataJSON)`.
 *
 * Test-only. Nothing here is imported by the service.
 */
import { createHash, createSign, generateKeyPairSync, randomBytes } from 'node:crypto'

// --- Minimal CBOR encoder (only the types an attestation object needs) ------

function head(major: number, length: number): Buffer {
  if (length < 24) return Buffer.from([(major << 5) | length])
  if (length < 0x100) return Buffer.from([(major << 5) | 24, length])
  if (length < 0x10000) {
    const buf = Buffer.alloc(3)
    buf[0] = (major << 5) | 25
    buf.writeUInt16BE(length, 1)
    return buf
  }
  const buf = Buffer.alloc(5)
  buf[0] = (major << 5) | 26
  buf.writeUInt32BE(length, 1)
  return buf
}

type CborValue = number | string | Buffer | Map<number | string, CborValue>

function cbor(value: CborValue): Buffer {
  if (typeof value === 'number') {
    return value >= 0 ? head(0, value) : head(1, -1 - value)
  }
  if (typeof value === 'string') {
    const bytes = Buffer.from(value, 'utf8')
    return Buffer.concat([head(3, bytes.length), bytes])
  }
  if (Buffer.isBuffer(value)) {
    return Buffer.concat([head(2, value.length), value])
  }
  const parts = [head(5, value.size)]
  for (const [key, entry] of value) {
    parts.push(cbor(typeof key === 'number' ? key : key), cbor(entry))
  }
  return Buffer.concat(parts)
}

// --- Authenticator ---------------------------------------------------------

const b64url = (buf: Buffer): string => buf.toString('base64url')

export interface SoftwareAuthenticatorOptions {
  rpId: string
  origin: string
}

export class SoftwareAuthenticator {
  readonly credentialId: Buffer
  private readonly privateKey
  private readonly cosePublicKey: Buffer
  private signCount = 0

  constructor(private readonly options: SoftwareAuthenticatorOptions) {
    this.credentialId = randomBytes(32)

    const { privateKey, publicKey } = generateKeyPairSync('ec', { namedCurve: 'P-256' })
    this.privateKey = privateKey

    const jwk = publicKey.export({ format: 'jwk' })
    const x = Buffer.from(jwk.x as string, 'base64url')
    const y = Buffer.from(jwk.y as string, 'base64url')

    // COSE_Key for ES256: kty=EC2(2), alg=ES256(-7), crv=P-256(1), x, y.
    this.cosePublicKey = cbor(
      new Map<number, CborValue>([
        [1, 2],
        [3, -7],
        [-1, 1],
        [-2, x],
        [-3, y],
      ]),
    )
  }

  get credentialIdB64(): string {
    return b64url(this.credentialId)
  }

  private clientData(type: 'webauthn.create' | 'webauthn.get', challenge: string): Buffer {
    return Buffer.from(
      JSON.stringify({ type, challenge, origin: this.options.origin, crossOrigin: false }),
      'utf8',
    )
  }

  private authData(flags: number, includeAttestedData: boolean): Buffer {
    const rpIdHash = createHash('sha256').update(this.options.rpId, 'utf8').digest()
    const counter = Buffer.alloc(4)
    counter.writeUInt32BE(this.signCount)

    const base = Buffer.concat([rpIdHash, Buffer.from([flags]), counter])
    if (!includeAttestedData) return base

    const credIdLength = Buffer.alloc(2)
    credIdLength.writeUInt16BE(this.credentialId.length)
    return Buffer.concat([
      base,
      Buffer.alloc(16), // AAGUID — all zeros, as platform authenticators report
      credIdLength,
      this.credentialId,
      this.cosePublicKey,
    ])
  }

  /** UP | UV | AT — user present, user verified, attested credential data. */
  register(challenge: string) {
    const clientDataJSON = this.clientData('webauthn.create', challenge)
    const attestationObject = cbor(
      new Map<string, CborValue>([
        ['fmt', 'none'],
        ['attStmt', new Map()],
        ['authData', this.authData(0x45, true)],
      ]),
    )

    return {
      id: this.credentialIdB64,
      rawId: this.credentialIdB64,
      type: 'public-key' as const,
      clientExtensionResults: {},
      response: {
        clientDataJSON: b64url(clientDataJSON),
        attestationObject: b64url(attestationObject),
        transports: ['internal' as const],
      },
    }
  }

  /** UP | UV. Increments the signature counter, as a real authenticator does. */
  authenticate(challenge: string, userHandle?: string) {
    this.signCount += 1
    const clientDataJSON = this.clientData('webauthn.get', challenge)
    const authData = this.authData(0x05, false)

    const signature = createSign('sha256')
      .update(Buffer.concat([authData, createHash('sha256').update(clientDataJSON).digest()]))
      .sign(this.privateKey)

    return {
      id: this.credentialIdB64,
      rawId: this.credentialIdB64,
      type: 'public-key' as const,
      clientExtensionResults: {},
      response: {
        clientDataJSON: b64url(clientDataJSON),
        authenticatorData: b64url(authData),
        signature: b64url(signature),
        ...(userHandle ? { userHandle: b64url(Buffer.from(userHandle, 'utf8')) } : {}),
      },
    }
  }

  /** Replay the previous counter value — how a cloned authenticator behaves. */
  freezeCounter(): void {
    this.signCount -= 1
  }
}
