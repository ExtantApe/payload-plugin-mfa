import { mongooseAdapter } from '@payloadcms/db-mongodb'
import { MongoMemoryReplSet } from 'mongodb-memory-server'
import { buildConfig, createLocalReq, getPayload, type Endpoint, type Payload, type PayloadRequest } from 'payload'
import { afterAll, beforeAll, describe, expect, it } from 'vitest'

import {
  allowEnrollment,
  beginPasskey as beginRaw,
  codeFor,
  confirm,
  finishPasskey,
  hasPasskeys,
  listPasskeys,
  mfa,
  passkeyProofOptions as proofOptionsRaw,
  passkeySignIn as signInRaw,
  passkeySignInOptions as signInOptionsRaw,
  removePasskey as removeRaw,
  renamePasskey,
  resetFor,
  signIn,
  start,
  statusFor,
  turnOff,
  type MfaEvent,
  type Proof,
} from '../src/index.js'
import { MFA_TRUSTED, optionsOf } from '../src/core.js'
import { VirtualAuthenticator, type Knobs } from './authenticator.js'

/** A made-up site with passkeys on. Staff must have a second step; members may. Everything is in memory. */
type U = { id: string; email: string; role: string }
const SECRET = 'a-made-up-app-secret-for-tests-only-0123456789'
const PW = 'correct-horse-battery'
const RP = 'example.test'
const ORIGIN = 'https://example.test'
let payload: Payload
let mongo: MongoMemoryReplSet
const events: MfaEvent[] = []
const hookLog: string[] = []
let n = 0

const make = async (role = 'member') => (await payload.create({ collection: 'users', data: { email: `${role}-${++n}@example.invalid`, password: PW, role } as never })) as unknown as U
const reqWith = async (headers: Record<string, string> = {}) => {
  const req = (await createLocalReq({}, payload)) as PayloadRequest
  ;(req as { headers: Headers }).headers = new Headers(headers)
  return req
}
const ip = (address: string) => reqWith({ 'x-test-ip': address })
// Most tests don't care which address they come from, so each call gets its own. A call with no address at all
// shares one limited bucket, and the limits tests call the plugin directly to prove that.
let addresses = 0
const fresh = () => ip(`10.${Math.floor(++addresses / 250)}.${addresses % 250}.7`)
const beginPasskey = async (p: Payload, a: Parameters<typeof beginRaw>[1]) => beginRaw(p, { ...a, req: a.req ?? (await fresh()) })
const passkeyProofOptions = async (p: Payload, a: Parameters<typeof proofOptionsRaw>[1]) => proofOptionsRaw(p, { ...a, req: a.req ?? (await fresh()) })
const removePasskey = async (p: Payload, a: Parameters<typeof removeRaw>[1]) => removeRaw(p, { ...a, req: a.req ?? (await fresh()) })
const passkeySignInOptions = async (p: Payload, a: { req?: PayloadRequest } = {}) => signInOptionsRaw(p, { req: a.req ?? (await fresh()) })
const passkeySignIn = async (p: Payload, a: { token: unknown; response: unknown; req?: PayloadRequest }) => signInRaw(p, { ...a, req: a.req ?? (await fresh()) })

/** Adds a passkey to an account the way a person's device would. Returns the device and the saved passkey. */
async function addPasskey(u: U, name = 'Test laptop', device = new VirtualAuthenticator(), proof?: Proof) {
  const { token, options } = await beginPasskey(payload, { userId: u.id, proof })
  const saved = await finishPasskey(payload, { userId: u.id, token, response: device.create(options as never, ORIGIN), name })
  return { device, saved }
}
/** Signs in with whatever the device holds for the site. */
async function viaPasskey(device: VirtualAuthenticator, knobs: Knobs = {}, req?: PayloadRequest) {
  const { token, options } = await passkeySignInOptions(payload, { req })
  return passkeySignIn(payload, { token, response: device.get(options as never, ORIGIN, knobs), req })
}
const reasonOf = async (p: Promise<unknown>) => {
  try {
    await p
    return 'ok'
  } catch (error) {
    return (error as { reason?: string }).reason ?? (error as { mfa?: string }).mfa ?? (error as Error).message
  }
}
const whoIs = async (token: string) => (await payload.auth({ headers: new Headers({ Authorization: `JWT ${token}` }) })).user as { id: string } | null
const sessionsOf = async (u: U) => ((await payload.findByID({ collection: 'users', id: u.id, overrideAccess: true, showHiddenFields: true, depth: 0 })) as unknown as { sessions?: unknown[] }).sessions?.length ?? 0
const count = async (slug: string) => (await payload.count({ collection: slug as never, overrideAccess: true })).totalDocs
const enrolApp = async (u: U) => {
  const { key } = await start(payload, { userId: u.id })
  const { recoveryCodes } = await confirm(payload, { userId: u.id, code: codeFor(key) })
  return { key, recoveryCodes }
}
const refresh = async (user: Record<string, unknown>) => {
  const hooks = payload.collections.users!.config.hooks.beforeOperation ?? []
  const req = (await createLocalReq({ user: { ...user, collection: 'users' } as never }, payload)) as PayloadRequest
  for (const h of hooks) await h({ operation: 'refresh', req, args: {} as never, collection: payload.collections.users!.config, context: {} } as never)
}

beforeAll(async () => {
  mongo = await MongoMemoryReplSet.create({ replSet: { count: 1, storageEngine: 'wiredTiger' } })
  const config = await buildConfig({
    secret: SECRET,
    telemetry: false,
    typescript: { autoGenerate: false },
    db: mongooseAdapter({ url: mongo.getUri('passkeys'), ensureIndexes: true }),
    collections: [
      {
        slug: 'users',
        trash: true,
        auth: { maxLoginAttempts: 5, lockTime: 600_000 },
        access: { read: () => true, update: () => true },
        fields: [{ name: 'role', type: 'text' }],
        hooks: {
          beforeLogin: [({ user }) => void hookLog.push(`before:${String((user as { email?: string }).email)}`), ({ user }) => {
            if (String((user as { email?: string }).email).startsWith('blocked-')) throw new Error('a site rule says no')
          }],
          afterLogin: [({ user }) => void hookLog.push(`after:${String((user as { email?: string }).email)}`)],
          // The operation hooks Payload's own login runs. They also run for other operations, so each one looks for `login`.
          beforeOperation: [
            ({ operation, args }) => {
              if (operation !== 'login') return
              const email = String((args as { data?: { email?: string } }).data?.email)
              hookLog.push(`beforeOperation:${email}`)
              if (email.startsWith('opblocked-')) throw new Error('a site rule says no, before the sign-in')
            },
          ],
          afterOperation: [
            ({ operation, req }) => {
              if (operation !== 'login') return undefined as never
              const email = String((req.user as { email?: string } | null)?.email)
              hookLog.push(`afterOperation:${email}`)
              if (email.startsWith('afterblocked-')) throw new Error('a site rule says no, after the sign-in')
              return undefined as never
            },
          ],
          // Payload reads the signed-in user through the read pipeline. This hook refuses it only for the plugin's own trusted request.
          afterRead: [
            ({ doc, context }) => {
              if (context[MFA_TRUSTED] && String((doc as { email?: string }).email).startsWith('banned-')) throw new Error('a site rule hides this account')
              return doc
            },
          ],
        },
      },
    ],
    plugins: [
      mfa({
        requiredFor: ({ user }) => (user as unknown as U).role === 'staff',
        issuer: 'Test site',
        clientAddress: (req) => req.headers?.get?.('x-test-ip') ?? null,
        onEvent: (e) => void events.push({ ...e, req: undefined }),
        endpoint: true,
        limits: { code: 50 },
        passkeys: { rpID: RP, rpName: 'Test site', origins: [ORIGIN], maxPerAccount: 3 },
      }),
    ],
  })
  payload = await getPayload({ config })
}, 120_000)

afterAll(async () => {
  await payload?.destroy?.()
  await mongo?.stop()
})

describe('setup', () => {
  const base = { secret: SECRET, collections: [{ slug: 'users', auth: true, fields: [] }] }
  const build = (passkeys: unknown) => () => mfa({ passkeys: passkeys as never })(base as never)
  it('refuses a site address that could let a passkey work somewhere else', () => {
    expect(build({ rpID: RP, origins: [ORIGIN] })).not.toThrow()
    expect(build({ rpID: RP, origins: [] })).toThrow(/origins/)
    expect(build({ rpID: 'https://example.test', origins: [ORIGIN] })).toThrow(/rpID/)
    expect(build({ rpID: RP, origins: ['http://example.test'] })).toThrow(/https/)
    expect(build({ rpID: RP, origins: ['https://example.test/'] })).toThrow(/trailing|path/)
    expect(build({ rpID: RP, origins: ['https://evil.test'] })).toThrow(/outside/)
    expect(build({ rpID: RP, origins: ['https://notexample.test'] })).toThrow(/outside/)
    expect(build({ rpID: 'localhost', origins: ['http://localhost:3000'] })).not.toThrow()
    expect(build({ rpID: RP, origins: [ORIGIN], maxPerAccount: 0 })).toThrow(/maxPerAccount/)
  })
  it('refuses to start when a limit could switch the limiter off', () => {
    const limits = (l: unknown) => () => mfa({ limits: l as never })(base as never)
    expect(limits({ code: 5, emailCode: 3, passkey: 10, windowMinutes: 15 })).not.toThrow()
    expect(limits({ code: 1, emailCode: 1, passkey: 1, windowMinutes: 1 })).not.toThrow()
    for (const key of ['code', 'emailCode', 'passkey', 'windowMinutes'])
      for (const bad of [0, -1, 0.5, 1.5, Number.NaN, Infinity, -Infinity, '5'])
        expect(limits({ [key]: bad }), `${key}=${String(bad)}`).toThrow(new RegExp(key))
  })
  it('adds no passkey collections when passkeys are off, and refuses every call', async () => {
    const out = mfa()(base as never) as { collections: { slug: string }[] }
    expect(out.collections.map((c) => c.slug).sort()).toEqual(['mfa-attempts', 'mfa-state', 'users'])
  })
})

describe('adding passkeys', () => {
  it('registers a discoverable passkey that needs the person’s own check, under a name, and lists it without keys', async () => {
    const u = await make()
    const device = new VirtualAuthenticator()
    const { token, options } = await beginPasskey(payload, { userId: u.id })
    expect(options.authenticatorSelection).toMatchObject({ residentKey: 'required', userVerification: 'required' })
    expect(options.attestation).toBe('none')
    expect(options.rp).toMatchObject({ id: RP, name: 'Test site' })
    // The stored handle is not the database id.
    expect(Buffer.from(options.user.id, 'base64url').toString()).not.toContain(String(u.id))
    const saved = await finishPasskey(payload, { userId: u.id, token, response: device.create(options as never, ORIGIN), name: '  Work   laptop ' })
    expect(saved).toMatchObject({ name: 'Work laptop', lastUsedAt: null })
    const list = await listPasskeys(payload, u.id)
    expect(list).toHaveLength(1)
    expect(JSON.stringify(list)).not.toMatch(/publicKey|credentialId/)
    expect(await hasPasskeys(payload, u.id)).toBe(true)
  })

  it('needs a name, and refuses an empty, long, control-character or repeated one', async () => {
    const u = await make()
    await addPasskey(u, 'Phone')
    for (const bad of ['', '   ', 'x'.repeat(61), 'bad\u0007name', 42 as never, 'phone']) {
      const { token, options } = await beginPasskey(payload, { userId: u.id, proof: undefined }).catch(() => ({ token: '', options: null as never }))
      if (!options) continue
      const device = new VirtualAuthenticator()
      expect(await reasonOf(finishPasskey(payload, { userId: u.id, token, response: device.create(options as never, ORIGIN), name: bad }))).toBe('badName')
    }
    expect(await listPasskeys(payload, u.id)).toHaveLength(1)
  })

  it('keeps several, each with its own name, up to the limit, and won’t take the same device twice', async () => {
    const u = await make()
    const { device } = await addPasskey(u, 'One')
    // Once a passkey exists, adding another needs a fresh check: here, the first passkey itself.
    const proofFrom = async () => {
      const p = await passkeyProofOptions(payload, { userId: u.id })
      return { passkey: { token: p.token, response: device.get(p.options as never, ORIGIN) } } satisfies Proof
    }
    await addPasskey(u, 'Two', undefined, await proofFrom())
    await addPasskey(u, 'Three', undefined, await proofFrom())
    expect((await listPasskeys(payload, u.id)).map((p) => p.name)).toEqual(['One', 'Two', 'Three'])
    expect(await reasonOf(beginPasskey(payload, { userId: u.id, proof: await proofFrom() }))).toBe('tooManyPasskeys')
  })

  it('refuses the same passkey twice, even when the browser is made to try', async () => {
    const u = await make()
    const { device } = await addPasskey(u, 'One')
    const p = await passkeyProofOptions(payload, { userId: u.id })
    const { options } = await beginPasskey(payload, { userId: u.id, proof: { passkey: { token: p.token, response: device.get(p.options as never, ORIGIN) } } })
    // The device would refuse (the account lists it as excluded)...
    expect(options.excludeCredentials).toHaveLength(1)
    expect(() => device.create(options as never, ORIGIN)).toThrow('InvalidStateError')
  })

  it('refuses a registration with the wrong origin, site, challenge, type or no user check, and uses the challenge up', async () => {
    const u = await make()
    const attempt = async (knobs: Knobs) => {
      const { token, options } = await beginPasskey(payload, { userId: u.id })
      return reasonOf(finishPasskey(payload, { userId: u.id, token, response: new VirtualAuthenticator().create(options as never, ORIGIN, knobs), name: `n${++n}` }))
    }
    expect(await attempt({ origin: 'https://evil.test' })).toBe('wrongPasskey')
    expect(await attempt({ rpID: 'evil.test' })).toBe('wrongPasskey')
    expect(await attempt({ challenge: 'AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA' })).toBe('wrongPasskey')
    expect(await attempt({ type: 'webauthn.get' })).toBe('wrongPasskey')
    expect(await attempt({ noUv: true })).toBe('wrongPasskey')
    expect(await listPasskeys(payload, u.id)).toHaveLength(0)
    // A challenge works once.
    const { token, options } = await beginPasskey(payload, { userId: u.id })
    const response = new VirtualAuthenticator().create(options as never, ORIGIN)
    expect(await reasonOf(finishPasskey(payload, { userId: u.id, token, response, name: 'First' }))).toBe('ok')
    expect(await reasonOf(finishPasskey(payload, { userId: u.id, token, response, name: 'Again' }))).toBe('wrongPasskey')
  })

  it('refuses a registration challenge made for someone else, or used as a sign-in or a check', async () => {
    const a = await make()
    const b = await make()
    const { token, options } = await beginPasskey(payload, { userId: a.id })
    const response = new VirtualAuthenticator().create(options as never, ORIGIN)
    expect(await reasonOf(finishPasskey(payload, { userId: b.id, token, response, name: 'Theirs' }))).toBe('wrongPasskey')
    // The challenge is gone once tried, even by the wrong account.
    expect(await reasonOf(finishPasskey(payload, { userId: a.id, token, response, name: 'Mine' }))).toBe('wrongPasskey')
    const signin = await passkeySignInOptions(payload)
    expect(await reasonOf(finishPasskey(payload, { userId: a.id, token: signin.token, response: new VirtualAuthenticator().create(options as never, ORIGIN), name: 'Sneaky' }))).toBe('wrongPasskey')
    expect(await listPasskeys(payload, a.id)).toHaveLength(0)
    expect(await listPasskeys(payload, b.id)).toHaveLength(0)
  })

  it('needs a fresh check to add a passkey once the account has an app or a passkey, and none when it has neither', async () => {
    const u = await make()
    await expect(beginPasskey(payload, { userId: u.id })).resolves.toBeTruthy() // nothing yet: the site checked the password
    const { key, recoveryCodes } = await enrolApp(u)
    expect(await reasonOf(beginPasskey(payload, { userId: u.id }))).toBe('needsCode')
    expect(await reasonOf(beginPasskey(payload, { userId: u.id, proof: { code: '000000' } }))).toBe('wrongCode')
    expect(await reasonOf(beginPasskey(payload, { userId: u.id, proof: { code: '' } }))).toBe('needsCode')
    expect(await reasonOf(beginPasskey(payload, { userId: u.id, proof: { code: codeFor(key, Date.now() + 30_000) } }))).toBe('ok')
    // The same app code can't prove twice, but a recovery code does, once.
    expect(await reasonOf(beginPasskey(payload, { userId: u.id, proof: { code: codeFor(key, Date.now() + 30_000) } }))).toBe('wrongCode')
    expect(await reasonOf(beginPasskey(payload, { userId: u.id, proof: { code: recoveryCodes[0]! } }))).toBe('ok')
    expect(await reasonOf(beginPasskey(payload, { userId: u.id, proof: { code: recoveryCodes[0]! } }))).toBe('wrongCode')
  })

  it('refuses an emailed code as the fresh check, and a malformed proof', async () => {
    const u = await make()
    await enrolApp(u)
    for (const proof of [{ code: '12345678' }, 'yes', 7, { passkey: 'x' }, { passkey: { token: 'x'.repeat(30), response: {} } }, {}] as never[])
      expect(['needsCode', 'wrongCode', 'wrongPasskey']).toContain(await reasonOf(beginPasskey(payload, { userId: u.id, proof })))
  })

  it('renames a passkey, only on the account that owns it, and not to a name already used', async () => {
    const a = await make()
    const b = await make()
    const { saved } = await addPasskey(a, 'Old name')
    await renamePasskey(payload, { userId: a.id, id: saved.id, name: 'New name' })
    expect((await listPasskeys(payload, a.id))[0]!.name).toBe('New name')
    expect(await reasonOf(renamePasskey(payload, { userId: b.id, id: saved.id, name: 'Mine now' }))).toBe('notFound')
    expect((await listPasskeys(payload, a.id))[0]!.name).toBe('New name')
    expect(await reasonOf(renamePasskey(payload, { userId: a.id, id: saved.id, name: '' }))).toBe('badName')
  })
})

describe('signing in with a passkey', () => {
  it('signs in with the passkey alone, no password and no code, and the session works', async () => {
    const u = await make()
    const { device } = await addPasskey(u)
    const before = await sessionsOf(u)
    const r = await viaPasskey(device)
    expect(r.user.id).toBe(u.id)
    expect((await whoIs(r.token))?.id).toBe(u.id)
    expect(await sessionsOf(u)).toBe(before + 1)
    expect((await listPasskeys(payload, u.id))[0]!.lastUsedAt).toBeTruthy()
  })

  it('signs in an account that has the app on, with no code, and the app still works as the fallback', async () => {
    const u = await make()
    const { key, recoveryCodes } = await enrolApp(u)
    const { device } = await addPasskey(u, 'Phone', undefined, { code: recoveryCodes[0]! })
    expect((await whoIs((await viaPasskey(device)).token))?.id).toBe(u.id)
    // The password alone still needs a code; the app's code and a recovery code still sign in.
    expect(await reasonOf(signIn(payload, { email: u.email, password: PW }))).toBe('needed')
    expect(await reasonOf(signIn(payload, { email: u.email, password: PW, code: codeFor(key, Date.now() + 30_000) }))).toBe('ok')
    expect(await reasonOf(signIn(payload, { email: u.email, password: PW, code: recoveryCodes[1]! }))).toBe('ok')
    expect(await reasonOf(signIn(payload, { email: u.email, password: PW, code: recoveryCodes[1]! }))).toBe('wrong')
  })

  it('works for an account that must have a second step and never set up an app, and keeps working on refresh and on every request', async () => {
    const staff = await make('staff')
    // Staff can't enrol anything with a bare password: the window is how they set up their first passkey.
    expect(await reasonOf(signIn(payload, { email: staff.email, password: PW }))).toBe('enroll')
    await allowEnrollment(payload, { userId: staff.id })
    const { device } = await addPasskey(staff)
    const r = await viaPasskey(device)
    const sid = ((await payload.findByID({ collection: 'users', id: staff.id, overrideAccess: true, showHiddenFields: true, depth: 0 })) as unknown as { sessions: { id: string }[] }).sessions.at(-1)!.id
    // End the window: only the passkey's session is left to count.
    const doc = (await payload.find({ collection: 'mfa-state' as never, where: { user: { equals: staff.id } }, overrideAccess: true })).docs[0] as { id: string }
    await payload.db.updateOne({ collection: 'mfa-state', where: { id: { equals: doc.id } } as never, data: { enrollUntil: null }, returning: false })
    expect((await whoIs(r.token))?.id).toBe(staff.id)
    await expect(refresh({ ...staff, _sid: sid })).resolves.toBeUndefined()
    // Password sign-in is still refused: the passkey wasn't shown.
    expect(await reasonOf(signIn(payload, { email: staff.email, password: PW }))).toBe('enroll')
  })

  it('stops counting a passkey session for a required account once its last passkey is gone', async () => {
    const staff = await make('staff')
    await allowEnrollment(payload, { userId: staff.id })
    const { device, saved } = await addPasskey(staff)
    const r = await viaPasskey(device)
    const sid = ((await payload.findByID({ collection: 'users', id: staff.id, overrideAccess: true, showHiddenFields: true, depth: 0 })) as unknown as { sessions: { id: string }[] }).sessions.at(-1)!.id
    const doc = (await payload.find({ collection: 'mfa-state' as never, where: { user: { equals: staff.id } }, overrideAccess: true })).docs[0] as { id: string }
    await payload.db.updateOne({ collection: 'mfa-state', where: { id: { equals: doc.id } } as never, data: { enrollUntil: null }, returning: false })
    expect((await whoIs(r.token))?.id).toBe(staff.id)
    const p = await passkeyProofOptions(payload, { userId: staff.id })
    await removePasskey(payload, { userId: staff.id, id: saved.id, proof: { passkey: { token: p.token, response: device.get(p.options as never, ORIGIN) } } })
    expect(await whoIs(r.token)).toBeNull()
    await expect(refresh({ ...staff, _sid: sid })).rejects.toThrow()
  })

  it('runs the site’s own login hooks, and one that refuses leaves no session behind', async () => {
    const u = await make()
    const { device } = await addPasskey(u)
    hookLog.length = 0
    await viaPasskey(device)
    expect(hookLog.filter((h) => !h.includes('Operation'))).toEqual([`before:${u.email}`, `after:${u.email}`])
    const blocked = await payload.create({ collection: 'users', data: { email: `blocked-${++n}@example.invalid`, password: PW } as never }) as unknown as U
    const { device: d2 } = await addPasskey(blocked)
    const before = await sessionsOf(blocked)
    expect(await reasonOf(viaPasskey(d2))).toBe('wrongPasskey')
    expect(await sessionsOf(blocked)).toBe(before)
  })

  it('runs every step of Payload’s own login: operation hooks, the read pipeline and the failed-attempt count', async () => {
    const u = await make()
    const { device } = await addPasskey(u)
    await payload.db.updateOne({ collection: 'users', where: { id: { equals: u.id } } as never, data: { loginAttempts: 3 }, returning: false })
    hookLog.length = 0
    await viaPasskey(device)
    // The same order a password login uses, with the operation hooks around the login hooks.
    expect(hookLog).toEqual([`beforeOperation:${u.email}`, `before:${u.email}`, `after:${u.email}`, `afterOperation:${u.email}`])
    const after = (await payload.findByID({ collection: 'users', id: u.id, overrideAccess: true, showHiddenFields: true, depth: 0 })) as unknown as { loginAttempts?: number }
    expect(after.loginAttempts).toBe(0)
    // A beforeOperation hook that throws stops the sign-in before any session exists.
    const early = (await payload.create({ collection: 'users', data: { email: `opblocked-${++n}@example.invalid`, password: PW } as never })) as unknown as U
    const e = await addPasskey(early)
    expect(await reasonOf(viaPasskey(e.device))).toBe('wrongPasskey')
    expect(await sessionsOf(early)).toBe(0)
    // So does an afterOperation hook that throws, even though the session and token already exist: it is rolled back.
    const late = (await payload.create({ collection: 'users', data: { email: `afterblocked-${++n}@example.invalid`, password: PW } as never })) as unknown as U
    const l = await addPasskey(late)
    expect(await reasonOf(viaPasskey(l.device))).toBe('wrongPasskey')
    expect(await sessionsOf(late)).toBe(0)
    // So does a read rule that hides the account (the account would otherwise have been signed in).
    const hidden = (await payload.create({ collection: 'users', data: { email: `banned-${++n}@example.invalid`, password: PW } as never })) as unknown as U
    const h = await addPasskey(hidden)
    expect(await reasonOf(viaPasskey(h.device))).toBe('wrongPasskey')
    expect(await sessionsOf(hidden)).toBe(0)
  })

  it('refuses a soft-deleted (trashed) account, and signs it in again once it is restored', async () => {
    const u = await make()
    const { device } = await addPasskey(u)
    await payload.db.updateOne({ collection: 'users', where: { id: { equals: u.id } } as never, data: { deletedAt: new Date().toISOString() }, returning: false })
    expect(await reasonOf(viaPasskey(device))).toBe('wrongPasskey')
    const trashed = (await payload.findByID({ collection: 'users', id: u.id, trash: true, overrideAccess: true, showHiddenFields: true, depth: 0 })) as unknown as { sessions?: unknown[] }
    expect(trashed.sessions?.length ?? 0).toBe(0)
    await payload.db.updateOne({ collection: 'users', where: { id: { equals: u.id } } as never, data: { deletedAt: null }, returning: false })
    expect(await reasonOf(viaPasskey(device))).toBe('ok')
  })

  it('lets only one of two answers at the same counter through, however they interleave', async () => {
    const u = await make()
    const { device } = await addPasskey(u)
    // Two fresh checks (a passkey proof, which needs no session) answered at the same counter.
    const one = await passkeyProofOptions(payload, { userId: u.id })
    const two = await passkeyProofOptions(payload, { userId: u.id })
    const a = device.get(one.options as never, ORIGIN, { counter: 1 })
    const b = device.get(two.options as never, ORIGIN, { counter: 1 })
    // Hold both answers just before they move the counter, so each has been checked against the same stored count.
    const db = payload.db as unknown as { updateOne: (args: { collection: string }) => Promise<unknown> }
    const real = db.updateOne
    let waiting = 0
    let release: () => void = () => undefined
    const both = new Promise<void>((resolve) => {
      release = resolve
    })
    db.updateOne = function (this: unknown, args: { collection: string }) {
      if (args.collection !== 'mfa-passkeys') return real.call(this, args)
      waiting++
      if (waiting >= 2) release()
      return Promise.race([both, new Promise((r) => setTimeout(r, 5000))]).then(() => real.call(this, args))
    }
    let results: string[]
    try {
      results = await Promise.all([reasonOf(beginPasskey(payload, { userId: u.id, proof: { passkey: { token: one.token, response: a } } })), reasonOf(beginPasskey(payload, { userId: u.id, proof: { passkey: { token: two.token, response: b } } }))])
    } finally {
      db.updateOne = real
    }
    expect(waiting).toBe(2)
    expect(results.filter((r) => r === 'ok')).toHaveLength(1)
    expect(results.filter((r) => r === 'wrongPasskey')).toHaveLength(1)
  })

  it('refuses a locked account', async () => {
    const u = await make()
    const { device } = await addPasskey(u)
    await payload.db.updateOne({ collection: 'users', where: { id: { equals: u.id } } as never, data: { lockUntil: new Date(Date.now() + 600_000).toISOString() }, returning: false })
    expect(await reasonOf(viaPasskey(device))).toBe('wrongPasskey')
    await payload.db.updateOne({ collection: 'users', where: { id: { equals: u.id } } as never, data: { lockUntil: null }, returning: false })
    expect(await reasonOf(viaPasskey(device))).toBe('ok')
  })

  it('refuses everything that isn’t a clean assertion, the same way each time', async () => {
    const u = await make()
    const { device } = await addPasskey(u)
    const other = new VirtualAuthenticator()
    const bad: [string, Knobs][] = [
      ['another origin', { origin: 'https://evil.test' }],
      ['another site', { rpID: 'evil.test' }],
      ['no user check', { noUv: true }],
      ['another challenge', { challenge: 'AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA' }],
      ['the wrong key', { wrongKey: other.create({ challenge: 'x', rp: { id: RP }, user: { id: 'AA' } }, ORIGIN) && other.creds[0]!.key }],
      ['no user handle', { noHandle: true }],
      ['another account’s handle', { handle: Buffer.from('someone-else-entirely') }],
      ['a create type', { type: 'webauthn.create' }],
    ]
    for (const [label, knobs] of bad) expect(await reasonOf(viaPasskey(device, knobs)), label).toBe('wrongPasskey')
    // None of that locked or changed anything: a clean one works.
    expect(await reasonOf(viaPasskey(device))).toBe('ok')
  })

  it('refuses a passkey the plugin doesn’t know, and one whose account has since been deleted', async () => {
    const stranger = new VirtualAuthenticator()
    const u = await make()
    const { options } = await beginPasskey(payload, { userId: u.id })
    stranger.create(options as never, ORIGIN)
    expect(await reasonOf(viaPasskey(stranger))).toBe('wrongPasskey')
    const { device } = await addPasskey(u, 'Gone soon')
    await payload.delete({ collection: 'users', id: u.id, overrideAccess: true })
    expect(await reasonOf(viaPasskey(device))).toBe('wrongPasskey')
  })

  it('uses a challenge once, so a recorded answer can’t be replayed, and uses it up even when the answer is bad', async () => {
    const u = await make()
    const { device } = await addPasskey(u)
    const { token, options } = await passkeySignInOptions(payload)
    const response = device.get(options as never, ORIGIN)
    expect(await reasonOf(passkeySignIn(payload, { token, response }))).toBe('ok')
    expect(await reasonOf(passkeySignIn(payload, { token, response }))).toBe('wrongPasskey')
    const second = await passkeySignInOptions(payload)
    expect(await reasonOf(passkeySignIn(payload, { token: second.token, response: device.get(second.options as never, ORIGIN, { noUv: true }) }))).toBe('wrongPasskey')
    expect(await reasonOf(passkeySignIn(payload, { token: second.token, response: device.get(second.options as never, ORIGIN) }))).toBe('wrongPasskey')
  })

  it('lets only one of two answers to the same challenge in', async () => {
    const u = await make()
    const { device } = await addPasskey(u)
    const { token, options } = await passkeySignInOptions(payload)
    const response = device.get(options as never, ORIGIN)
    const results = await Promise.all(Array.from({ length: 6 }, () => reasonOf(passkeySignIn(payload, { token, response }))))
    expect(results.filter((r) => r === 'ok')).toHaveLength(1)
  })

  it('refuses an expired challenge and one made for another purpose', async () => {
    const u = await make()
    const { device } = await addPasskey(u)
    const { token, options } = await passkeySignInOptions(payload)
    await payload.db.updateMany?.({ collection: 'mfa-challenges', where: {} as never, data: { expiresAt: new Date(Date.now() - 1000).toISOString() }, returning: false } as never)
    expect(await reasonOf(passkeySignIn(payload, { token, response: device.get(options as never, ORIGIN) }))).toBe('wrongPasskey')
    const proof = await passkeyProofOptions(payload, { userId: u.id })
    expect(await reasonOf(passkeySignIn(payload, { token: proof.token, response: device.get(proof.options as never, ORIGIN) }))).toBe('wrongPasskey')
    expect(await reasonOf(passkeySignIn(payload, { token: 'nonsense', response: {} }))).toBe('wrongPasskey')
    expect(await reasonOf(passkeySignIn(payload, { token: undefined, response: null }))).toBe('wrongPasskey')
  })

  it('refuses a counter that goes backwards (a cloned authenticator), and counts that stay at zero work', async () => {
    const u = await make()
    const { device } = await addPasskey(u)
    expect(await reasonOf(viaPasskey(device))).toBe('ok') // 1
    expect(await reasonOf(viaPasskey(device))).toBe('ok') // 2
    expect(await reasonOf(viaPasskey(device, { counter: 1 }))).toBe('wrongPasskey')
    expect(await reasonOf(viaPasskey(device, { counter: 2 }))).toBe('wrongPasskey')
    expect(await reasonOf(viaPasskey(device, { counter: 3 }))).toBe('ok')
    // Synced passkeys report 0 every time.
    const v = await make()
    const { device: synced } = await addPasskey(v)
    expect(await reasonOf(viaPasskey(synced, { counter: 0 }))).toBe('ok')
    expect(await reasonOf(viaPasskey(synced, { counter: 0 }))).toBe('ok')
  })

  it('never says which part failed: unknown and known accounts get the same answer', async () => {
    const u = await make()
    const { device } = await addPasskey(u)
    const a = await passkeySignInOptions(payload)
    const stranger = new VirtualAuthenticator()
    stranger.create({ challenge: 'x', rp: { id: RP }, user: { id: 'AA' } }, ORIGIN)
    const unknown = await passkeySignIn(payload, { token: a.token, response: stranger.get(a.options as never, ORIGIN) }).catch((e) => e)
    const b = await passkeySignInOptions(payload)
    const known = await passkeySignIn(payload, { token: b.token, response: device.get(b.options as never, ORIGIN, { noUv: true }) }).catch((e) => e)
    expect(unknown.message).toBe(known.message)
    expect(unknown.reason).toBe(known.reason)
  })
})

describe('challenge guards', () => {
  const countOf = async (u: U) => (await listPasskeys(payload, u.id)).length
  /** An assertion a device makes over a challenge it was handed, with everything else about it correct. */
  const answerFor = (device: VirtualAuthenticator, challenge: string) => device.get({ challenge, rpId: RP }, ORIGIN)

  it('purpose: a challenge made for one job can’t do another, even when everything else about the answer is right', async () => {
    const u = await make()
    const { device } = await addPasskey(u)
    // A proof challenge used to sign in.
    const proofOpts = await passkeyProofOptions(payload, { userId: u.id })
    expect(await reasonOf(passkeySignIn(payload, { token: proofOpts.token, response: answerFor(device, proofOpts.options.challenge) }))).toBe('wrongPasskey')
    // A proof challenge answered for its own job works: it starts a registration.
    const again = await passkeyProofOptions(payload, { userId: u.id })
    const extra = new VirtualAuthenticator()
    const ok = await beginPasskey(payload, { userId: u.id, proof: { passkey: { token: again.token, response: answerFor(device, again.options.challenge) } } })
    // A registration challenge answered with a sign-in: the browser's answer is a good assertion over the registration challenge.
    expect(await reasonOf(passkeySignIn(payload, { token: ok.token, response: answerFor(device, ok.options.challenge) }))).toBe('wrongPasskey')
    // A sign-in challenge used to register: a good registration over the sign-in challenge.
    const signin = await passkeySignInOptions(payload)
    const before = await countOf(u)
    const created = extra.create({ challenge: signin.options.challenge, rp: { id: RP }, user: { id: Buffer.from('x').toString('base64url') } }, ORIGIN)
    expect(await reasonOf(finishPasskey(payload, { userId: u.id, token: signin.token, response: created, name: 'Wrong job' }))).toBe('wrongPasskey')
    // A proof challenge used to register, for the very same account.
    const proof2 = await passkeyProofOptions(payload, { userId: u.id })
    const created2 = extra.create({ challenge: proof2.options.challenge, rp: { id: RP }, user: { id: Buffer.from('y').toString('base64url') } }, ORIGIN)
    expect(await reasonOf(finishPasskey(payload, { userId: u.id, token: proof2.token, response: created2, name: 'Wrong job' }))).toBe('wrongPasskey')
    expect(await countOf(u)).toBe(before)
    // Refusing it used the challenge up: the right job can't use it afterwards either.
    expect(await reasonOf(removePasskey(payload, { userId: u.id, id: (await listPasskeys(payload, u.id))[0]!.id, proof: { passkey: { token: proof2.token, response: answerFor(device, proof2.options.challenge) } } }))).toBe('wrongPasskey')
  })

  it('owner: a challenge made for one account can’t be used by another, even when everything else about the answer is right', async () => {
    const a = await make()
    const b = await make()
    const da = (await addPasskey(a, 'A device')).device
    const db = (await addPasskey(b, 'B device')).device
    // A's proof challenge, answered by B's own device for B: B's credential and B's account are right; only the owner is wrong.
    const pa = await passkeyProofOptions(payload, { userId: a.id })
    const [bOnly] = await listPasskeys(payload, b.id)
    expect(await reasonOf(removePasskey(payload, { userId: b.id, id: bOnly!.id, proof: { passkey: { token: pa.token, response: answerFor(db, pa.options.challenge) } } }))).toBe('wrongPasskey')
    expect(await countOf(b)).toBe(1)
    // A's registration challenge, finished as B with a good registration from a new device.
    const reg = await beginPasskey(payload, { userId: a.id, proof: await (async () => { const p = await passkeyProofOptions(payload, { userId: a.id }); return { passkey: { token: p.token, response: answerFor(da, p.options.challenge) } } })() })
    const fresh2 = new VirtualAuthenticator()
    const created = fresh2.create({ challenge: reg.options.challenge, rp: { id: RP }, user: { id: reg.options.user.id } }, ORIGIN)
    expect(await reasonOf(finishPasskey(payload, { userId: b.id, token: reg.token, response: created, name: 'Not mine' }))).toBe('wrongPasskey')
    expect(await countOf(b)).toBe(1)
    // The owner's own challenge was used up by the refusal; a new one works for its owner.
    const again = await beginPasskey(payload, { userId: a.id, proof: await (async () => { const p = await passkeyProofOptions(payload, { userId: a.id }); return { passkey: { token: p.token, response: answerFor(da, p.options.challenge) } } })() })
    const fine = new VirtualAuthenticator().create({ challenge: again.options.challenge, rp: { id: RP }, user: { id: again.options.user.id } }, ORIGIN)
    expect(await reasonOf(finishPasskey(payload, { userId: a.id, token: again.token, response: fine, name: 'Fine' }))).toBe('ok')
  })
})

describe('removing passkeys', () => {
  it('needs a fresh check every time, and takes an app code, a recovery code or a passkey', async () => {
    const u = await make()
    const { key, recoveryCodes } = await enrolApp(u)
    const first = await addPasskey(u, 'One', undefined, { code: recoveryCodes[0]! })
    const second = await addPasskey(u, 'Two', undefined, { code: recoveryCodes[1]! })
    const third = await addPasskey(u, 'Three', undefined, { code: recoveryCodes[2]! })
    expect(await reasonOf(removePasskey(payload, { userId: u.id, id: first.saved.id }))).toBe('needsCode')
    expect(await reasonOf(removePasskey(payload, { userId: u.id, id: first.saved.id, proof: { code: '000000' } }))).toBe('wrongCode')
    expect(await listPasskeys(payload, u.id)).toHaveLength(3)
    expect(await reasonOf(removePasskey(payload, { userId: u.id, id: first.saved.id, proof: { code: codeFor(key, Date.now() + 30_000) } }))).toBe('ok')
    expect(await reasonOf(removePasskey(payload, { userId: u.id, id: second.saved.id, proof: { code: recoveryCodes[3]! } }))).toBe('ok')
    const p = await passkeyProofOptions(payload, { userId: u.id })
    expect(await reasonOf(removePasskey(payload, { userId: u.id, id: third.saved.id, proof: { passkey: { token: p.token, response: third.device.get(p.options as never, ORIGIN) } } }))).toBe('ok')
    expect(await listPasskeys(payload, u.id)).toHaveLength(0)
    // A removed passkey signs nobody in.
    expect(await reasonOf(viaPasskey(first.device))).toBe('wrongPasskey')
  })

  it('refuses a passkey proof from another account, a reused one, and a proof that isn’t a passkey check', async () => {
    const a = await make()
    const b = await make()
    const mine = await addPasskey(a, 'Mine')
    const theirs = await addPasskey(b, 'Theirs')
    const pb = await passkeyProofOptions(payload, { userId: b.id })
    // B's device, B's challenge, offered for A's passkey.
    expect(await reasonOf(removePasskey(payload, { userId: a.id, id: mine.saved.id, proof: { passkey: { token: pb.token, response: theirs.device.get(pb.options as never, ORIGIN) } } }))).toBe('wrongPasskey')
    // A sign-in challenge isn't a proof.
    const s = await passkeySignInOptions(payload)
    expect(await reasonOf(removePasskey(payload, { userId: a.id, id: mine.saved.id, proof: { passkey: { token: s.token, response: mine.device.get(s.options as never, ORIGIN) } } }))).toBe('wrongPasskey')
    // A used proof can't be used again.
    const pa = await passkeyProofOptions(payload, { userId: a.id })
    const answer = mine.device.get(pa.options as never, ORIGIN)
    await removePasskey(payload, { userId: a.id, id: (await addPasskey(a, 'Spare', undefined, { passkey: { token: pa.token, response: answer } })).saved.id, proof: undefined }).catch(() => undefined)
    expect(await reasonOf(removePasskey(payload, { userId: a.id, id: mine.saved.id, proof: { passkey: { token: pa.token, response: answer } } }))).toBe('wrongPasskey')
    expect(await listPasskeys(payload, a.id)).toHaveLength(2)
    // Another account can't remove it, with or without a proof of its own.
    expect(await reasonOf(removePasskey(payload, { userId: b.id, id: mine.saved.id, proof: { code: '123456' } }))).toBe('notFound')
  })

  it('has no proof to ask for when a passkey proof is wanted from an account with none', async () => {
    const u = await make()
    expect(await reasonOf(passkeyProofOptions(payload, { userId: u.id }))).toBe('notOn')
  })
})

describe('limits', () => {
  it('stops after 10 tries on one account in a window, the good one included', async () => {
    const u = await make()
    const { device } = await addPasskey(u)
    for (let i = 0; i < 10; i++) expect(await reasonOf(viaPasskey(device, { noUv: true }))).toBe('wrongPasskey')
    expect(await reasonOf(viaPasskey(device))).toBe('wrongPasskey')
    expect(events.some((e) => e.type === 'too-many-tries' && e.user === String(u.id) && e.detail?.what === 'passkey')).toBe(true)
  })

  it('limits per address, and the account limit ignores which address asked', async () => {
    const a = await make()
    const b = await make()
    const da = (await addPasskey(a)).device
    const db = (await addPasskey(b)).device
    // 10 bad tries from one address, spread over two accounts, then even a good one from that address is refused.
    for (let i = 0; i < 5; i++) await reasonOf(viaPasskey(da, { noUv: true }, await ip('203.0.113.9')))
    for (let i = 0; i < 5; i++) await reasonOf(viaPasskey(db, { noUv: true }, await ip('203.0.113.9')))
    expect(await reasonOf(viaPasskey(da, {}, await ip('203.0.113.9')))).not.toBe('ok')
    // The sign-in itself is limited too, not just asking for a challenge.
    events.length = 0
    const fresh = await passkeySignInOptions(payload, { req: await ip('203.0.113.77') })
    expect(await reasonOf(passkeySignIn(payload, { token: fresh.token, response: da.get(fresh.options as never, ORIGIN), req: await ip('203.0.113.9') }))).toBe('wrongPasskey')
    expect(events.some((e) => e.type === 'passkey-refused' && e.detail?.why === 'address-limit')).toBe(true)
    expect(await reasonOf(viaPasskey(db, {}, await ip('203.0.113.10')))).toBe('ok')
    // Account a has had 5 of its 10 (the rest were refused by address first); five more from new addresses use them up.
    for (let i = 0; i < 5; i++) await reasonOf(viaPasskey(da, { noUv: true }, await ip(`198.51.100.${i}`)))
    expect(await reasonOf(viaPasskey(da, {}, await ip('198.51.100.77')))).toBe('wrongPasskey')
  })

  it('limits how many sign-in challenges one address can ask for', async () => {
    const req = await ip('203.0.113.50')
    let refused = 0
    for (let i = 0; i < 40; i++) if ((await reasonOf(passkeySignInOptions(payload, { req }))) === 'tooMany') refused++
    expect(refused).toBeGreaterThan(0)
    expect(await reasonOf(passkeySignInOptions(payload, { req: await ip('203.0.113.51') }))).toBe('ok')
  })

  it('still limits when no address is known: one shared bucket, so nobody can guess without limit', async () => {
    const noAddress = await reqWith()
    // Asking for challenges, from a call with no request at all and from one whose request carries no address.
    const asked: string[] = []
    for (let i = 0; i < 10; i++) asked.push(await reasonOf(i % 2 ? signInOptionsRaw(payload, { req: noAddress }) : signInOptionsRaw(payload)))
    expect(asked.every((r) => r === 'ok')).toBe(true)
    expect(await reasonOf(signInOptionsRaw(payload))).toBe('tooMany')
    expect(await reasonOf(signInOptionsRaw(payload, { req: noAddress }))).toBe('tooMany')
    // Signing in, too: ten tries, then the eleventh is refused by the limit, whatever it carries.
    events.length = 0
    for (let i = 0; i < 10; i++) await reasonOf(signInRaw(payload, { token: 'x', response: {}, ...(i % 2 ? { req: noAddress } : {}) }))
    expect(events.some((e) => e.type === 'too-many-tries' && e.detail?.what === 'passkey')).toBe(false)
    expect(await reasonOf(signInRaw(payload, { token: 'x', response: {} }))).toBe('wrongPasskey')
    expect(events.some((e) => e.type === 'too-many-tries' && e.detail?.what === 'passkey')).toBe(true)
    expect(events.some((e) => e.type === 'passkey-refused' && e.detail?.why === 'address-limit')).toBe(true)
    // An address that is known has its own bucket and still works.
    expect(await reasonOf(passkeySignInOptions(payload))).toBe('ok')
  })

  it('uses one try from the shared bucket for a good sign-in with no address, not two', async () => {
    const o = optionsOf(payload) as { limit?: (a: { kind: string; key: string }) => boolean }
    const u = await make()
    const { device } = await addPasskey(u)
    const seen: string[] = []
    try {
      o.limit = ({ kind, key }) => {
        seen.push(`${kind}|${key}`)
        return true
      }
      const { token, options } = await signInOptionsRaw(payload)
      seen.length = 0
      await signInRaw(payload, { token, response: device.get(options as never, ORIGIN) })
    } finally {
      delete o.limit
    }
    expect(seen.filter((k) => k.endsWith('address:unknown'))).toEqual(['passkey-address|address:unknown'])
    expect(seen.filter((k) => k.includes('account:'))).toHaveLength(1)
  })

  it('hands a site’s own limiter the shared key when no address is known', async () => {
    const o = optionsOf(payload) as { limit?: (a: { kind: string; key: string }) => boolean }
    const seen: string[] = []
    try {
      o.limit = ({ kind, key }) => {
        seen.push(`${kind}|${key}`)
        return !key.endsWith('unknown')
      }
      expect(await reasonOf(signInOptionsRaw(payload))).toBe('tooMany')
      expect(seen).toContain('passkeyOptions-address|address:unknown')
      expect(await reasonOf(signInOptionsRaw(payload, { req: await ip('192.0.2.200') }))).toBe('ok')
    } finally {
      delete o.limit
    }
  })

  it('refuses when the limiter fails, and when a site limiter says no', async () => {
    const o = optionsOf(payload) as { limit?: unknown }
    const u = await make()
    const { device } = await addPasskey(u)
    try {
      o.limit = () => {
        throw new Error('limiter down')
      }
      expect(await reasonOf(viaPasskey(device))).not.toBe('ok')
      o.limit = () => false
      expect(await reasonOf(viaPasskey(device))).not.toBe('ok')
      o.limit = () => true
    } finally {
      delete o.limit
    }
    expect(await reasonOf(viaPasskey(device))).toBe('ok')
  })
})

describe('resets, status and events', () => {
  it('removes an account’s passkeys when a maintainer resets it, unless told to keep them', async () => {
    const a = await make()
    const b = await make()
    const da = (await addPasskey(a)).device
    await addPasskey(b)
    await resetFor(payload, a.id, { actor: 'maintainer-1' })
    expect(await listPasskeys(payload, a.id)).toHaveLength(0)
    expect(await reasonOf(viaPasskey(da))).toBe('wrongPasskey')
    await resetFor(payload, b.id, { keepPasskeys: true })
    expect(await listPasskeys(payload, b.id)).toHaveLength(1)
    expect(events.find((e) => e.type === 'reset' && e.user === String(a.id))?.detail?.passkeysRemoved).toBe(1)
  })

  it('leaves the app alone when a passkey is removed, and passkeys alone when the app is turned off', async () => {
    const u = await make()
    const { key, recoveryCodes } = await enrolApp(u)
    const { saved } = await addPasskey(u, 'Phone', undefined, { code: recoveryCodes[0]! })
    await removePasskey(payload, { userId: u.id, id: saved.id, proof: { code: codeFor(key, Date.now() + 30_000) } })
    expect((await statusFor(payload, u.id)).on).toBe(true)
    const again = await addPasskey(u, 'Tablet', undefined, { code: recoveryCodes[1]! })
    await turnOff(payload, { userId: u.id, code: recoveryCodes[2]! })
    expect(await listPasskeys(payload, u.id)).toHaveLength(1)
    expect(await reasonOf(viaPasskey(again.device))).toBe('ok')
  })

  it('records every change and refusal in events, with no key, challenge, credential or name in them', async () => {
    events.length = 0
    const u = await make()
    const { device, saved } = await addPasskey(u, 'Secret Name Here')
    await viaPasskey(device)
    await reasonOf(viaPasskey(device, { noUv: true }))
    await renamePasskey(payload, { userId: u.id, id: saved.id, name: 'Other Secret Name' })
    const p = await passkeyProofOptions(payload, { userId: u.id })
    await removePasskey(payload, { userId: u.id, id: saved.id, proof: { passkey: { token: p.token, response: device.get(p.options as never, ORIGIN) } } })
    const mine = events.filter((e) => e.user === String(u.id)).map((e) => e.type)
    expect(mine).toEqual(expect.arrayContaining(['passkey-added', 'passkey-signed-in', 'passkey-refused', 'passkey-renamed', 'passkey-removed']))
    const text = JSON.stringify(events)
    for (const secret of ['Secret Name Here', 'Other Secret Name', device.creds[0]!.id.toString('base64url'), 'publicKey', 'challenge']) expect(text).not.toContain(secret)
  })

  it('answers every passkey call with a plain refusal when passkeys are off', async () => {
    const o = optionsOf(payload) as { passkeyConfig: unknown }
    const kept = o.passkeyConfig
    o.passkeyConfig = null
    try {
      const u = await make()
      expect(await reasonOf(passkeySignInOptions(payload))).toBe('passkeysOff')
      expect(await reasonOf(passkeySignIn(payload, { token: 'x', response: {} }))).toBe('passkeysOff')
      expect(await reasonOf(beginPasskey(payload, { userId: u.id }))).toBe('passkeysOff')
      expect(await hasPasskeys(payload, u.id)).toBe(false)
    } finally {
      o.passkeyConfig = kept
    }
  })
})

describe('the passkey endpoints', () => {
  const find = (path: string) => (payload.collections.users!.config.endpoints as Endpoint[]).find((e) => e.path === path)!
  const post = async (path: string, body: unknown, headers: Record<string, string> = {}) => {
    const req = await reqWith({ 'content-type': 'application/json', ...headers })
    ;(req as unknown as { json: () => Promise<unknown> }).json = async () => body
    return find(path).handler(req)
  }

  it('signs in over HTTP with a cookie, and answers every failure alike', async () => {
    const u = await make()
    const { device } = await addPasskey(u)
    const opened = (await (await post('/mfa/passkey/options', {}, { 'x-test-ip': '192.0.2.1' })).json()) as any
    expect(opened.ok).toBe(true)
    const ok = await post('/mfa/passkey/sign-in', { token: opened.token, response: device.get(opened.options, ORIGIN) }, { 'x-test-ip': '192.0.2.1' })
    expect(ok.status).toBe(200)
    expect(ok.headers.get('set-cookie')).toMatch(/payload-token=/)
    const second = (await (await post('/mfa/passkey/options', {}, { 'x-test-ip': '192.0.2.1' })).json()) as any
    const bad = await post('/mfa/passkey/sign-in', { token: second.token, response: device.get(second.options, ORIGIN, { noUv: true }) }, { 'x-test-ip': '192.0.2.1' })
    const junk = await post('/mfa/passkey/sign-in', { token: 'x', response: 7 })
    const none = await post('/mfa/passkey/sign-in', undefined)
    for (const r of [bad, junk, none]) {
      expect(r.status).toBe(401)
      expect(r.headers.get('set-cookie')).toBeNull()
    }
    expect(await bad.json()).toEqual(await junk.json())
  })

  it('is not there unless the site turns the endpoints on', () => {
    const slugs = (payload.collections.users!.config.endpoints as Endpoint[]).map((e) => e.path)
    expect(slugs).toEqual(expect.arrayContaining(['/mfa/passkey/options', '/mfa/passkey/sign-in', '/mfa/login']))
  })
})

describe('what is stored', () => {
  it('keeps passkeys and challenges out of reach of every request, and keeps no secret in a passkey record', async () => {
    for (const slug of ['mfa-passkeys', 'mfa-challenges']) {
      const access = payload.collections[slug as never]!.config.access as unknown as Record<string, (a: unknown) => boolean>
      for (const op of ['read', 'create', 'update', 'delete']) expect(access[op]!({})).toBe(false)
    }
    const u = await make()
    await addPasskey(u)
    const doc = (await payload.find({ collection: 'mfa-passkeys' as never, where: { user: { equals: u.id } }, overrideAccess: true })).docs[0] as Record<string, unknown>
    expect(Object.keys(doc).sort()).toEqual(expect.arrayContaining(['credentialId', 'publicKey', 'counter', 'name', 'user']))
    // Challenges are cleaned out as new ones arrive.
    await payload.db.updateMany?.({ collection: 'mfa-challenges', where: {} as never, data: { expiresAt: new Date(Date.now() - 1000).toISOString() }, returning: false } as never)
    await passkeySignInOptions(payload)
    expect(await count('mfa-challenges')).toBe(1)
  })
})
