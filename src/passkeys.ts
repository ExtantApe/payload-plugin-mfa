import { createHash, randomBytes } from 'node:crypto'

import {
  generateAuthenticationOptions,
  generateRegistrationOptions,
  verifyAuthenticationResponse,
  verifyRegistrationResponse,
  type AuthenticationResponseJSON,
  type AuthenticatorTransport,
  type PublicKeyCredentialCreationOptionsJSON,
  type PublicKeyCredentialRequestOptionsJSON,
  type RegistrationResponseJSON,
} from '@simplewebauthn/server'
import { checkLoginPermission, commitTransaction, createLocalReq, getFieldsToSign, initTransaction, jwtSign, killTransaction, type Payload, type PayloadRequest } from 'payload'
import { addSessionToUser } from 'payload/shared'

import { acceptCode, allowed, emit, hasUnmovedState, isOnState, keysOf, loadState, loadUser, MFA_TRUSTED, MfaRefused, optionsOf, saveIfUnchanged, withSession } from './core.js'
import { mac, same } from './crypto.js'
import type { MfaUser, Resolved } from './types.js'

/**
 * Passkeys (WebAuthn), ADR 0002. Every credential is a discoverable one that needs the person's own check on the
 * device (a fingerprint, face or PIN). A passkey signs a person in by itself; nothing here reads a password or a code.
 */

const MINUTE = 60_000
const REFUSED = 'That passkey didn’t work.'

type Config = NonNullable<Resolved['passkeyConfig']>
const configOf = (payload: Payload): { o: Resolved; c: Config } => {
  const o = optionsOf(payload)
  if (!o.passkeyConfig) throw new MfaRefused('passkeysOff', 'Passkeys aren’t turned on for this site.')
  return { o, c: o.passkeyConfig }
}

/** A passkey a person added, as the plugin keeps it. The public key is not secret; nothing can sign in without the device. */
type StoredPasskey = {
  id: string
  user: string
  credentialId: string
  publicKey: string
  counter: number
  transports: string[]
  name: string
  deviceType: string
  backedUp: boolean
  addedAt: string
  lastUsedAt: string | null
}

/** What a site shows in a list of an account's passkeys. */
export type PasskeySummary = { id: string; name: string; addedAt: string; lastUsedAt: string | null; deviceType: string; backedUp: boolean }

/** A fresh check: a current app or recovery code, or a passkey used just now (from `passkeyProofOptions`). */
export type Proof = { code: string } | { passkey: { token: string; response: unknown } }

const toStored = (doc: Record<string, unknown>): StoredPasskey => ({
  id: String(doc.id),
  user: String(doc.user),
  credentialId: String(doc.credentialId),
  publicKey: String(doc.publicKey),
  counter: Number(doc.counter ?? 0),
  transports: Array.isArray(doc.transports) ? (doc.transports as string[]) : [],
  name: String(doc.name ?? ''),
  deviceType: String(doc.deviceType ?? ''),
  backedUp: Boolean(doc.backedUp),
  addedAt: doc.addedAt ? new Date(doc.addedAt as string).toISOString() : '',
  lastUsedAt: doc.lastUsedAt ? new Date(doc.lastUsedAt as string).toISOString() : null,
})

const summary = (p: StoredPasskey): PasskeySummary => ({ id: p.id, name: p.name, addedAt: p.addedAt, lastUsedAt: p.lastUsedAt, deviceType: p.deviceType, backedUp: p.backedUp })

async function passkeysOf(payload: Payload, userId: string | number): Promise<StoredPasskey[]> {
  const o = optionsOf(payload)
  const docs = (await payload.find({ collection: o.passkeyStore as never, where: { user: { equals: String(userId) } }, sort: 'addedAt', limit: 100, depth: 0, overrideAccess: true, pagination: false })).docs
  return (docs as unknown as Record<string, unknown>[]).map(toStored)
}

async function passkeyByCredential(payload: Payload, credentialId: string): Promise<StoredPasskey | null> {
  const o = optionsOf(payload)
  const doc = (await payload.find({ collection: o.passkeyStore as never, where: { credentialId: { equals: credentialId } }, limit: 1, depth: 0, overrideAccess: true, pagination: false })).docs[0]
  return doc ? toStored(doc as unknown as Record<string, unknown>) : null
}

/** Whether an account has at least one passkey. One small read. */
export async function hasPasskeys(payload: Payload, userId: string | number, req?: PayloadRequest): Promise<boolean> {
  const o = optionsOf(payload)
  if (!o.passkeyConfig) return false
  const { totalDocs } = await payload.count({ collection: o.passkeyStore as never, where: { user: { equals: String(userId) } }, overrideAccess: true, ...(req ? { req } : {}) })
  return totalDocs > 0
}

/** The account's id as the authenticator stores it: a keyed hash, so the stored value says nothing about the database. */
const handleFor = (payload: Payload, userId: string | number) => mac(keysOf(payload), `passkey-handle|${String(userId)}`)
const handleBytes = (payload: Payload, userId: string | number) => new Uint8Array(Buffer.from(handleFor(payload, userId), 'hex'))
const handleText = (payload: Payload, userId: string | number) => Buffer.from(handleFor(payload, userId), 'hex').toString('base64url')

// ------------------------------------------------------------------------------------------------
// Challenges: random, stored once, used once, short-lived, and tied to what they were made for.

type Kind = 'signin' | 'register' | 'proof'
const tokenHash = (payload: Payload, token: string) => createHash('sha256').update(`${payload.secret}|mfa-challenge|${token}`).digest('hex')

async function issueChallenge(payload: Payload, kind: Kind, userId: string | number | null, challenge: string): Promise<string> {
  const { o, c } = configOf(payload)
  const now = Date.now()
  // Old challenges go as new ones arrive, so unused ones can't pile up.
  await payload.db.deleteMany({ collection: o.challenges, where: { expiresAt: { less_than: new Date(now).toISOString() } } as never }).catch((err: unknown) => payload.logger.warn({ err, msg: 'mfa: old passkey challenges weren’t cleared; they will be next time' }))
  const token = randomBytes(32).toString('base64url')
  await payload.db.create({ collection: o.challenges, data: { tokenHash: tokenHash(payload, token), kind, user: userId === null ? null : String(userId), challenge, expiresAt: new Date(now + c.challengeMinutes * MINUTE).toISOString() } })
  return token
}

/** Deletes the challenge in one database step and returns its text, or null when it's unknown, used, expired, or for something else. */
async function consumeChallenge(payload: Payload, token: unknown, kind: Kind, userId: string | number | null): Promise<string | null> {
  const o = optionsOf(payload)
  if (typeof token !== 'string' || token.length < 20 || token.length > 100) return null
  const doc = (await payload.db.deleteOne({ collection: o.challenges, where: { and: [{ tokenHash: { equals: tokenHash(payload, token) } }, { expiresAt: { greater_than: new Date().toISOString() } }] } as never })) as Record<string, unknown> | null
  if (!doc || doc.kind !== kind) return null
  if ((userId === null ? null : String(userId)) !== (doc.user ?? null)) return null
  return String(doc.challenge)
}

const isObject = (v: unknown): v is Record<string, unknown> => typeof v === 'object' && v !== null && !Array.isArray(v)

// ------------------------------------------------------------------------------------------------
// Sign in

/** Starts a passkey sign-in: a challenge, and the options for the browser's `startAuthentication`. No account is named. */
export async function passkeySignInOptions(payload: Payload, args: { req?: PayloadRequest } = {}): Promise<{ token: string; options: PublicKeyCredentialRequestOptionsJSON }> {
  const { c } = configOf(payload)
  if (!(await allowed(payload, 'passkeyOptions', null, args.req))) {
    await emit(payload, { type: 'too-many-tries', user: '', req: args.req, detail: { what: 'passkey-options' } })
    throw new MfaRefused('tooMany', 'Too many tries. Please wait a few minutes.')
  }
  // No allowed list: the device offers the passkeys it holds for this site, so nobody types an email address.
  const options = await generateAuthenticationOptions({ rpID: c.rpID, userVerification: 'required', allowCredentials: [] })
  return { token: await issueChallenge(payload, 'signin', null, options.challenge), options }
}

export type PasskeySignInResult = { token: string; exp: number; sid: string | undefined; user: { id: string | number; email?: string | null } }

const refuseSignIn = async (payload: Payload, req: PayloadRequest | undefined, user: string, why: string): Promise<never> => {
  await emit(payload, { type: 'passkey-refused', user, req, detail: { why } }).catch(() => undefined)
  throw new MfaRefused('wrongPasskey', REFUSED)
}

/** Checks one assertion against the account's stored passkey, and moves its counter. Returns the passkey, or null for any problem. */
async function checkAssertion(payload: Payload, c: Config, args: { challenge: string; response: unknown; expectUser: string | number | null; needHandle: boolean }): Promise<StoredPasskey | null> {
  const o = optionsOf(payload)
  const r = args.response
  if (!isObject(r) || typeof r.id !== 'string' || !isObject(r.response)) return null
  const stored = await passkeyByCredential(payload, r.id)
  if (!stored) return null
  if (args.expectUser !== null && stored.user !== String(args.expectUser)) return null
  // The stored handle must be the one the device reports. A discoverable sign-in has to carry it.
  const handle = r.response.userHandle
  const hasHandle = typeof handle === 'string' && handle !== ''
  if (hasHandle ? !same(handle, handleText(payload, stored.user)) : args.needHandle || (handle !== undefined && handle !== null && handle !== '')) return null
  let verified
  try {
    verified = await verifyAuthenticationResponse({
      response: r as unknown as AuthenticationResponseJSON,
      expectedChallenge: args.challenge,
      expectedOrigin: c.origins,
      expectedRPID: c.rpID,
      requireUserVerification: true,
      credential: { id: stored.credentialId, publicKey: new Uint8Array(Buffer.from(stored.publicKey, 'base64url')), counter: stored.counter, transports: stored.transports as AuthenticatorTransport[] },
    })
  } catch {
    return null
  }
  if (!verified.verified) return null
  // The counter moves only if nobody else moved it first (a cloned authenticator or a race fails closed).
  const done = await payload.db.updateOne({
    collection: o.passkeyStore,
    where: { and: [{ id: { equals: stored.id } }, { counter: { equals: stored.counter } }] } as never,
    data: { counter: verified.authenticationInfo.newCounter, lastUsedAt: new Date().toISOString(), backedUp: verified.authenticationInfo.credentialBackedUp },
  })
  return done === null || done === undefined ? null : { ...stored, counter: verified.authenticationInfo.newCounter }
}

/**
 * Signs in with a passkey alone: no password and no code. It checks the signature, the challenge, the origin, the
 * site and the person's own check on the device, then starts a session the way Payload's `login` does (its
 * session record, its token and its login hooks), so the rest of Payload sees an ordinary sign-in. Every problem
 * gives the same refusal, `MfaRefused` with reason `wrongPasskey`. The site sets the cookie from `token`.
 */
export async function passkeySignIn(payload: Payload, args: { token: unknown; response: unknown; req?: PayloadRequest }): Promise<PasskeySignInResult> {
  const { o, c } = configOf(payload)
  const req = args.req
  // Per address first (when the site gives `clientAddress`), so guessing can't be spread over accounts.
  if (!(await allowed(payload, 'passkey', null, req))) {
    await emit(payload, { type: 'too-many-tries', user: '', req, detail: { what: 'passkey' } })
    return refuseSignIn(payload, req, '', 'address-limit')
  }
  const challenge = await consumeChallenge(payload, args.token, 'signin', null).catch(() => null)
  if (!challenge) return refuseSignIn(payload, req, '', 'challenge')
  const credentialId = isObject(args.response) && typeof args.response.id === 'string' ? args.response.id : null
  const known = credentialId ? await passkeyByCredential(payload, credentialId).catch(() => null) : null
  if (!known) return refuseSignIn(payload, req, '', 'unknown-passkey')
  // Every try for an account counts, good or bad, so a stolen device can't be tried without end.
  if (!(await allowed(payload, 'passkey', known.user, req))) {
    await emit(payload, { type: 'too-many-tries', user: known.user, req, detail: { what: 'passkey' } })
    return refuseSignIn(payload, req, known.user, 'account-limit')
  }
  let stored: StoredPasskey | null
  try {
    stored = await checkAssertion(payload, c, { challenge, response: args.response, expectUser: null, needHandle: true })
  } catch (error) {
    payload.logger.error({ err: error, msg: 'mfa: a passkey check failed, so it was refused' })
    stored = null
  }
  if (!stored) return refuseSignIn(payload, req, known.user, 'not-verified')
  try {
    const result = await startSession(payload, o, stored.user, req)
    await emit(payload, { type: 'passkey-signed-in', user: stored.user, req, detail: { passkey: stored.id } })
    return result
  } catch (error) {
    payload.logger.error({ err: error, msg: 'mfa: a passkey sign-in could not start a session, so it was refused' })
    return refuseSignIn(payload, req, stored.user, 'session')
  }
}

/** The part of Payload's `login` that follows a good password: session, token and login hooks, with the sign-in marked as vouched for. */
async function startSession(payload: Payload, o: Resolved, userId: string, incoming: PayloadRequest | undefined): Promise<PasskeySignInResult> {
  const collection = payload.collections[o.users as never]
  if (!collection) throw new Error('no auth collection')
  const config = collection.config
  if (config.auth.disableLocalStrategy) throw new Error('local strategy is off')
  if (o.legacyUserField && (await hasUnmovedState(payload, o, userId))) throw new Error('state not moved')
  const req = (await createLocalReq({ context: { [MFA_TRUSTED]: true }, ...(incoming?.headers ? { req: { headers: incoming.headers } } : {}) } as never, payload)) as PayloadRequest
  const shouldCommit = await initTransaction(req)
  try {
    const raw = (await payload.db.findOne({ collection: o.users, where: { id: { equals: userId } } as never, req })) as (Record<string, unknown> & { id: string | number; email?: string }) | null
    if (!raw) throw new Error('no account')
    delete raw._id
    delete raw.__v
    // The same checks `login` makes after a good password: locked, not yet verified.
    checkLoginPermission({ req, user: raw as never })
    if (config.auth.verify && raw._verified === false) throw new Error('email not verified')
    const user = raw as Record<string, unknown> & { id: string | number; email?: string }
    user.collection = o.users
    user._strategy = 'local-jwt'
    const { sid } = await addSessionToUser({ collectionConfig: config, payload, req, user: user as never })
    // Record the session as verified, or a required account's first refresh would end it.
    for (let i = 0; ; i++) {
      const loaded = await loadState(payload, userId, req)
      if (await saveIfUnchanged(payload, userId, loaded, withSession(loaded.state, user as unknown as MfaUser, sid, new Date().toISOString()), req)) break
      if (i >= 2) throw new Error('could not record the session')
    }
    const fieldsToSign = getFieldsToSign({ collectionConfig: config, email: String(user.email ?? ''), user: user as never, ...(sid ? { sid } : {}) })
    let hooked: unknown = user
    for (const hook of config.hooks?.beforeLogin ?? []) hooked = (await hook({ collection: config, context: req.context, req, user: hooked as never })) || hooked
    const { exp, token } = await jwtSign({ fieldsToSign, secret: payload.secret, tokenExpiration: config.auth.tokenExpiration })
    req.user = hooked as never
    for (const hook of config.hooks?.afterLogin ?? []) hooked = (await hook({ collection: config, context: req.context, req, token, user: hooked as never })) || hooked
    if (shouldCommit) await commitTransaction(req)
    return { token, exp, sid, user: { id: user.id, email: user.email ?? null } }
  } catch (error) {
    await killTransaction(req)
    throw error
  }
}

// ------------------------------------------------------------------------------------------------
// A fresh check, for adding and removing passkeys

/** Starts a fresh check with a passkey the person already has: a challenge tied to this account. */
export async function passkeyProofOptions(payload: Payload, args: { userId: string | number; req?: PayloadRequest }): Promise<{ token: string; options: PublicKeyCredentialRequestOptionsJSON }> {
  const { c } = configOf(payload)
  const mine = await passkeysOf(payload, args.userId)
  if (!mine.length) throw new MfaRefused('notOn', 'This account has no passkey.')
  if (!(await allowed(payload, 'passkeyOptions', null, args.req))) throw new MfaRefused('tooMany', 'Too many tries. Please wait a few minutes.')
  const options = await generateAuthenticationOptions({ rpID: c.rpID, userVerification: 'required', allowCredentials: mine.map((p) => ({ id: p.credentialId, transports: p.transports as AuthenticatorTransport[] })) })
  return { token: await issueChallenge(payload, 'proof', args.userId, options.challenge), options }
}

/**
 * The fresh check for changing what signs an account in: a current app or recovery code (an emailed code is not
 * enough, it only proves the mailbox), or a passkey used just now. Limited per account, each code used once. An
 * account with no app and no passkey has nothing to prove with, so it passes with no proof; the site has checked
 * its password.
 */
async function requireProof(payload: Payload, c: Config, args: { userId: string | number; proof?: Proof; req?: PayloadRequest }): Promise<void> {
  const user = await loadUser(payload, args.userId, args.req)
  if (!user) throw new MfaRefused('notFound', 'That account wasn’t found.')
  const loaded = await loadState(payload, user.id, args.req)
  const state = loaded.state
  const mine = await passkeysOf(payload, user.id)
  if (!isOnState(state) && !mine.length) return
  const proof = args.proof
  if (!isObject(proof)) throw new MfaRefused('needsCode', 'Confirm with your authenticator app, a recovery code or a passkey first.')
  if ('code' in proof) {
    if (typeof proof.code !== 'string' || !proof.code.trim()) throw new MfaRefused('needsCode', 'Enter a code from your app, or a recovery code.')
    if (!isOnState(state)) throw new MfaRefused('wrongCode', 'Enter a code from your app, or a recovery code.')
    if (!(await allowed(payload, 'code', user.id, args.req))) throw new MfaRefused('tooMany', 'Too many tries. Please wait a few minutes.')
    const accepted = acceptCode(keysOf(payload), state, proof.code)
    if (!accepted || accepted.used === 'email') throw new MfaRefused('wrongCode', 'Enter a code from your app, or a recovery code.')
    if (!(await saveIfUnchanged(payload, user.id, loaded, accepted.next, args.req))) throw new MfaRefused('busy', 'Something changed at the same moment. Please try again.')
    return
  }
  const pk = (proof as { passkey?: unknown }).passkey
  if (!isObject(pk)) throw new MfaRefused('needsCode', 'Confirm with your authenticator app, a recovery code or a passkey first.')
  if (!(await allowed(payload, 'passkey', user.id, args.req))) {
    await emit(payload, { type: 'too-many-tries', user: String(user.id), req: args.req, detail: { what: 'passkey' } })
    throw new MfaRefused('tooMany', 'Too many tries. Please wait a few minutes.')
  }
  const challenge = await consumeChallenge(payload, pk.token, 'proof', user.id)
  const ok = challenge ? await checkAssertion(payload, c, { challenge, response: pk.response, expectUser: user.id, needHandle: false }).catch(() => null) : null
  if (!ok) {
    await emit(payload, { type: 'passkey-refused', user: String(user.id), req: args.req, detail: { why: 'proof' } })
    throw new MfaRefused('wrongPasskey', REFUSED)
  }
}

// ------------------------------------------------------------------------------------------------
// Managing passkeys. Server-only: the site checks the password first, as it does for `start`.

const cleanName = (name: unknown): string => {
  const n = typeof name === 'string' ? name.normalize('NFC').replace(/\s+/g, ' ').trim() : ''
  // eslint-disable-next-line no-control-regex
  if (!n || n.length > 60 || /[\u0000-\u001f\u007f]/.test(n)) throw new MfaRefused('badName', 'Give the passkey a name of up to 60 characters, such as Work laptop.')
  return n
}

/** An account's passkeys, for its security page. Never the keys. */
export async function listPasskeys(payload: Payload, userId: string | number): Promise<PasskeySummary[]> {
  configOf(payload)
  return (await passkeysOf(payload, userId)).map(summary)
}

/**
 * Starts adding a passkey. When the account already has an app or a passkey, a fresh check comes with it (`proof`),
 * so a session alone can't add a device. When it has neither, the site has checked the password. Returns the
 * options for the browser's `startRegistration`.
 */
export async function beginPasskey(payload: Payload, args: { userId: string | number; proof?: Proof; req?: PayloadRequest }): Promise<{ token: string; options: PublicKeyCredentialCreationOptionsJSON }> {
  const { c } = configOf(payload)
  const user = await loadUser(payload, args.userId, args.req)
  if (!user) throw new MfaRefused('notFound', 'That account wasn’t found.')
  const mine = await passkeysOf(payload, user.id)
  if (mine.length >= c.maxPerAccount) throw new MfaRefused('tooManyPasskeys', `An account can have up to ${c.maxPerAccount} passkeys. Remove one first.`)
  await requireProof(payload, c, { userId: user.id, proof: args.proof, req: args.req })
  const options = await generateRegistrationOptions({
    rpName: c.rpName,
    rpID: c.rpID,
    userName: String(user.email ?? user.id),
    userID: handleBytes(payload, user.id),
    attestationType: 'none',
    excludeCredentials: mine.map((p) => ({ id: p.credentialId, transports: p.transports as AuthenticatorTransport[] })),
    authenticatorSelection: { residentKey: 'required', userVerification: 'required' },
  })
  return { token: await issueChallenge(payload, 'register', user.id, options.challenge), options }
}

/** Finishes adding a passkey: checks the browser's answer and keeps the public key under the name the person gave. */
export async function finishPasskey(payload: Payload, args: { userId: string | number; token: unknown; response: unknown; name: unknown; req?: PayloadRequest }): Promise<PasskeySummary> {
  const { o, c } = configOf(payload)
  const name = cleanName(args.name)
  const user = await loadUser(payload, args.userId, args.req)
  if (!user) throw new MfaRefused('notFound', 'That account wasn’t found.')
  const challenge = await consumeChallenge(payload, args.token, 'register', user.id)
  if (!challenge || !isObject(args.response)) throw new MfaRefused('wrongPasskey', REFUSED)
  const mine = await passkeysOf(payload, user.id)
  if (mine.length >= c.maxPerAccount) throw new MfaRefused('tooManyPasskeys', `An account can have up to ${c.maxPerAccount} passkeys. Remove one first.`)
  if (mine.some((p) => p.name.toLowerCase() === name.toLowerCase())) throw new MfaRefused('badName', 'Another passkey already has that name.')
  let info
  try {
    const verified = await verifyRegistrationResponse({ response: args.response as unknown as RegistrationResponseJSON, expectedChallenge: challenge, expectedOrigin: c.origins, expectedRPID: c.rpID, requireUserVerification: true })
    if (!verified.verified || !verified.registrationInfo) throw new Error('not verified')
    info = verified.registrationInfo
  } catch (error) {
    payload.logger.warn({ err: error, msg: 'mfa: a passkey registration was refused' })
    await emit(payload, { type: 'passkey-refused', user: String(user.id), req: args.req, detail: { why: 'registration' } })
    throw new MfaRefused('wrongPasskey', REFUSED)
  }
  const now = new Date().toISOString()
  let created: Record<string, unknown>
  try {
    created = (await payload.db.create({
      collection: o.passkeyStore,
      data: {
        user: String(user.id),
        credentialId: info.credential.id,
        publicKey: Buffer.from(info.credential.publicKey).toString('base64url'),
        counter: info.credential.counter,
        transports: info.credential.transports ?? [],
        name,
        deviceType: info.credentialDeviceType,
        backedUp: info.credentialBackedUp,
        addedAt: now,
        lastUsedAt: null,
      },
    })) as Record<string, unknown>
  } catch (error) {
    // The same passkey can't be added twice, to this account or another.
    payload.logger.warn({ err: error, msg: 'mfa: a passkey could not be saved (it may already be registered)' })
    throw new MfaRefused('wrongPasskey', REFUSED)
  }
  await emit(payload, { type: 'passkey-added', user: String(user.id), req: args.req, detail: { passkey: String(created.id) } })
  return summary(toStored({ ...created, user: String(user.id) }))
}

/** Renames a passkey. A label only, so no fresh check. The name must be new on this account. */
export async function renamePasskey(payload: Payload, args: { userId: string | number; id: string; name: unknown; req?: PayloadRequest }): Promise<void> {
  const { o } = configOf(payload)
  const name = cleanName(args.name)
  const mine = await passkeysOf(payload, args.userId)
  const target = mine.find((p) => p.id === String(args.id))
  if (!target) throw new MfaRefused('notFound', 'That passkey wasn’t found.')
  if (mine.some((p) => p.id !== target.id && p.name.toLowerCase() === name.toLowerCase())) throw new MfaRefused('badName', 'Another passkey already has that name.')
  await payload.db.updateOne({ collection: o.passkeyStore, where: { and: [{ id: { equals: target.id } }, { user: { equals: String(args.userId) } }] } as never, data: { name }, returning: false })
  await emit(payload, { type: 'passkey-renamed', user: String(args.userId), req: args.req, detail: { passkey: target.id } })
}

/**
 * Removes a passkey. Needs a fresh check (`proof`): an app or recovery code, or a passkey used just now. Sessions the
 * passkey started stay open (end them with `resetFor` if the device was lost), but an account that must have
 * two-step stops counting them as verified once its last passkey is gone.
 */
export async function removePasskey(payload: Payload, args: { userId: string | number; id: string; proof?: Proof; req?: PayloadRequest }): Promise<void> {
  const { o, c } = configOf(payload)
  const mine = await passkeysOf(payload, args.userId)
  const target = mine.find((p) => p.id === String(args.id))
  if (!target) throw new MfaRefused('notFound', 'That passkey wasn’t found.')
  // The account has this passkey, so it has something to prove with, and `requireProof` demands it.
  await requireProof(payload, c, { userId: args.userId, proof: args.proof, req: args.req })
  await payload.db.deleteOne({ collection: o.passkeyStore, where: { and: [{ id: { equals: target.id } }, { user: { equals: String(args.userId) } }] } as never, returning: false })
  await emit(payload, { type: 'passkey-removed', user: String(args.userId), req: args.req, detail: { passkey: target.id } })
}

/** Removes every passkey an account has (a maintainer's reset). Returns how many. */
export async function removeAllPasskeys(payload: Payload, userId: string | number, req?: PayloadRequest): Promise<number> {
  const o = optionsOf(payload)
  if (!o.passkeyConfig) return 0
  const n = (await passkeysOf(payload, userId)).length
  if (n) await payload.db.deleteMany({ collection: o.passkeyStore, where: { user: { equals: String(userId) } } as never, ...(req ? { req } : {}) })
  return n
}
