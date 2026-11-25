import { createHash, generateKeyPairSync, randomBytes, sign, type KeyObject } from 'node:crypto'

/**
 * A software authenticator for tests: it makes and answers WebAuthn requests the way a browser and a platform
 * authenticator would, with a made-up key kept in memory. Only what the plugin's own checks read is built.
 */

const b64 = (b: Uint8Array | Buffer) => Buffer.from(b).toString('base64url')
const sha256 = (b: Uint8Array | Buffer | string) => createHash('sha256').update(b).digest()

// A small CBOR writer: unsigned and negative integers, byte strings, text strings and maps.
function head(major: number, n: number): Buffer {
  if (n < 24) return Buffer.from([(major << 5) | n])
  if (n < 256) return Buffer.from([(major << 5) | 24, n])
  return Buffer.from([(major << 5) | 25, n >> 8, n & 255])
}
type Cbor = number | string | Uint8Array | Map<number | string, Cbor>
function cbor(v: Cbor): Buffer {
  if (typeof v === 'number') return v >= 0 ? head(0, v) : head(1, -1 - v)
  if (typeof v === 'string') return Buffer.concat([head(3, Buffer.byteLength(v)), Buffer.from(v)])
  if (v instanceof Uint8Array) return Buffer.concat([head(2, v.length), Buffer.from(v)])
  return Buffer.concat([head(5, v.size), ...[...v].flatMap(([k, x]) => [cbor(k), cbor(x)])])
}

export type Cred = { id: Buffer; key: KeyObject; publicKey: KeyObject; rpID: string; userHandle: Buffer | null; counter: number }

export type Knobs = {
  /** Origin the page claims. Default: the first the caller passes. */
  origin?: string
  /** Report no user verification (a bare tap). */
  noUv?: boolean
  /** Sign with a different key than the one registered. */
  wrongKey?: KeyObject
  /** The counter to report. Default: counts up by one. */
  counter?: number
  /** Leave out the user handle. */
  noHandle?: boolean
  /** Report this user handle instead. */
  handle?: Buffer
  /** Answer a different challenge than the one asked. */
  challenge?: string
  /** Answer for another site. */
  rpID?: string
  /** What to put in the type field of the client data. */
  type?: string
}

export class VirtualAuthenticator {
  creds: Cred[] = []

  /** `navigator.credentials.create` for options from `generateRegistrationOptions`. */
  create(options: { challenge: string; rp: { id?: string }; user: { id: string }; excludeCredentials?: { id: string }[] }, origin: string, knobs: Knobs = {}) {
    const rpID = knobs.rpID ?? options.rp.id!
    if ((options.excludeCredentials ?? []).some((c) => this.creds.some((x) => b64(x.id) === c.id && x.rpID === rpID))) throw new Error('InvalidStateError')
    const { privateKey, publicKey } = generateKeyPairSync('ec', { namedCurve: 'P-256' })
    const id = randomBytes(32)
    const jwk = publicKey.export({ format: 'jwk' }) as { x: string; y: string }
    const cose = cbor(new Map<number, Cbor>([[1, 2], [3, -7], [-1, 1], [-2, Buffer.from(jwk.x, 'base64url')], [-3, Buffer.from(jwk.y, 'base64url')]]))
    const flags = knobs.noUv ? 0x41 : 0x45
    const authData = Buffer.concat([sha256(rpID), Buffer.from([flags]), Buffer.alloc(4), Buffer.alloc(16), Buffer.from([0, id.length]), id, cose])
    const clientData = Buffer.from(JSON.stringify({ type: knobs.type ?? 'webauthn.create', challenge: knobs.challenge ?? options.challenge, origin: knobs.origin ?? origin, crossOrigin: false }))
    const attestationObject = cbor(new Map<string, Cbor>([['fmt', 'none'], ['attStmt', new Map()], ['authData', authData]]))
    this.creds.push({ id, key: privateKey, publicKey, rpID: options.rp.id!, userHandle: Buffer.from(options.user.id, 'base64url'), counter: 0 })
    return {
      id: b64(id),
      rawId: b64(id),
      type: 'public-key' as const,
      response: { clientDataJSON: b64(clientData), attestationObject: b64(attestationObject), transports: ['internal'] },
      clientExtensionResults: {},
      authenticatorAttachment: 'platform' as const,
    }
  }

  /** `navigator.credentials.get`. With no allowed list it picks a passkey for the site, as a discoverable sign-in does. */
  get(options: { challenge: string; rpId?: string; allowCredentials?: { id: string }[] }, origin: string, knobs: Knobs = {}, which?: Cred) {
    const rpID = options.rpId!
    const cred = which ?? this.creds.find((c) => c.rpID === rpID && (!options.allowCredentials?.length || options.allowCredentials.some((a) => a.id === b64(c.id))))
    if (!cred) throw new Error('NotAllowedError')
    cred.counter = knobs.counter ?? cred.counter + 1
    const authData = Buffer.concat([sha256(knobs.rpID ?? rpID), Buffer.from([knobs.noUv ? 0x01 : 0x05]), Buffer.from([(cred.counter >> 24) & 255, (cred.counter >> 16) & 255, (cred.counter >> 8) & 255, cred.counter & 255])])
    const clientData = Buffer.from(JSON.stringify({ type: knobs.type ?? 'webauthn.get', challenge: knobs.challenge ?? options.challenge, origin: knobs.origin ?? origin, crossOrigin: false }))
    const signature = sign('sha256', Buffer.concat([authData, sha256(clientData)]), knobs.wrongKey ?? cred.key)
    const handle = knobs.handle ?? cred.userHandle
    return {
      id: b64(cred.id),
      rawId: b64(cred.id),
      type: 'public-key' as const,
      response: { clientDataJSON: b64(clientData), authenticatorData: b64(authData), signature: b64(signature), ...(knobs.noHandle || !handle ? {} : { userHandle: b64(handle) }) },
      clientExtensionResults: {},
      authenticatorAttachment: 'platform' as const,
    }
  }
}
