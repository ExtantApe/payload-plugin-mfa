# ADR 0002: Passkeys

Status: proposed, 2026-11-25, with the code in the same pull request. Follows an owner decision of 2026-11-25: "Replaces password and code (Recommended)". ADR 0001 left passkeys for 0.2.

## Context

A passkey is a key pair on the person's device, unlocked by their fingerprint, face or PIN. Signing in with one proves two things at once: they hold the device and they are the person who unlocks it. So a passkey signs a person in by itself. It replaces the password and the code. The authenticator app and the recovery codes stay as the fallback for people who have no passkey, or lose their device.

The plugin stays off by default. A site that doesn't set `passkeys` gets no new collections, no new endpoints and the same behavior as 0.1.

## Library

`@simplewebauthn/server` 14.1.0, pinned exactly like `otpauth`. Checked 2026-11-25:

- npm registry: version 14.1.0 is `latest`, last modified 2026-11-06, MIT, Node `>=22` (this plugin's own floor), source at github.com/MasterKale/SimpleWebAuthn, a single maintainer.
- It is the library most Node WebAuthn servers use, it targets WebAuthn Level 2/3 (user verification, discoverable credentials, `none` attestation) and it checks the signature, origin, RP ID hash, challenge, flags and counter for us.
- The alternative, writing the CBOR and COSE parsing ourselves, is where mistakes happen. Not worth it.
- Risk: a single-maintainer dependency. It's one package, pinned, and the code that touches it is in one file (`src/passkeys.ts`), so replacing it is a small job.

The tests don't depend on the library's own helpers. They use a software authenticator written for the test suite (`test/authenticator.ts`) that makes real attestation and assertion bytes with Node's crypto, so the library is checked against an independent implementation.

## Decisions

1. **Discoverable credentials only.** Registration asks for `residentKey: 'required'` and `userVerification: 'required'`, attestation `none`. Sign-in sends no allowed list, so the device offers the passkeys it holds for the site and nobody types an email address. The server checks user verification itself too (`requireUserVerification: true`), so a bare tap is refused even if a browser skips the prompt.
2. **The site's domain is fixed in config.** `passkeys: { rpID, rpName?, origins, maxPerAccount?, challengeMinutes? }`. The plugin refuses to start if an origin isn't `https` (or `http` on localhost), has a path, or sits outside the `rpID`. A response from any other origin or site is refused.
3. **Storage.** One document per passkey in `mfa-passkeys` (account id, credential id, public key, counter, transports, name, device type, backed-up flag, dates). Access is false for every operation, like `mfa-state`. The public key isn't secret, but nothing needs to read it over the API. Passkeys are not kept on the account or in `mfa-state`, so Payload's own sign-in can't write old state back over them.
4. **Several passkeys per account, each with a name.** Up to `maxPerAccount` (default 10). A name is required, 1 to 60 characters, no control characters, unique on the account without regard to case. The same credential can't be added twice, to one account or two (unique index, plus `excludeCredentials` so the device refuses first). `listPasskeys` returns names and dates, never keys. `renamePasskey` is a label change and needs only the signed-in session, as the site decides.
5. **The account handle is a keyed hash,** not the database id. The authenticator stores it as the user handle. A discoverable sign-in must carry it and it must match the account that owns the credential, checked in constant time.
6. **Challenges.** 32 random bytes handed to the browser as an opaque token. The plugin keeps only a hash of the token, the challenge, its purpose (`signin`, `register` or `proof`), the account it was made for (if any) and an expiry (default 5 minutes). It is consumed in one atomic delete before anything else is checked, so a replay, a parallel duplicate, a wrong-purpose use and a use by another account all fail, and a bad answer still uses the challenge up. Expired challenges are deleted as new ones are made.
7. **Sign-in starts a normal Payload session.** `passkeySignIn` verifies the answer, then does what `login` does after a good password: the lock and verified-email checks, `addSessionToUser`, `getFieldsToSign`, the collection's `beforeLogin` hooks, `jwtSign`, the `afterLogin` hooks, all in one transaction that rolls back on any failure. The request carries `MFA_TRUSTED`, so this plugin's own `beforeLogin` lets it through while the site's other hooks still run, and a hook that throws still stops the sign-in with no session left behind. The result is `{ token, exp, sid, user: { id, email } }`; the site sets the cookie (the optional endpoint does it).
8. **The session counts as verified.** It is recorded in `mfa-state` against its session id like a code would be. The refresh check and the per-request check for a required account accept it as the second step while the account still has a passkey, and only within the remembered window. Remove the last passkey and such a session stops counting. Password-only sessions of an account that has a passkey but no app still follow `requiredFor` as before: a passkey on file doesn't make a bare password enough, and doesn't make it less.
9. **Fresh check to change what signs in.** Adding a passkey (when the account has an app or a passkey) and removing one both need a `proof`: a current app code or a recovery code (not an emailed one, which only proves the mailbox), or a passkey used just now (`passkeyProofOptions`, a `proof` challenge tied to the account). Each code is used once, as elsewhere. An account with neither an app nor a passkey has nothing to prove with, so the site's own password check stands in, as it does for `start`. Removing the last passkey is allowed; the password and the app are still there.
10. **Recovery codes still work.** Nothing here touches them. An account with a passkey and the app signs in with the password and an app or recovery code exactly as before. `turnOff` and `newRecoveryCodesFor` leave passkeys alone, and removing a passkey leaves the app alone.
11. **A maintainer's reset removes the account's passkeys** (a lost phone may hold one) unless `keepPasskeys: true`. It already signs the account out everywhere.
12. **Rate limits, keyed inside, same limiter.**
    - Every sign-in try that names a known credential counts against that account (`passkey`, default 10 per 15 minutes, good tries included, so a stolen device can't be tried forever), and every proof does too.
    - With `clientAddress`, each sign-in try and each challenge request also counts against the address, so guessing can't be spread over accounts.
    - The site's `limit` adapter gets the new kinds (`passkey`, `passkey-address`, `passkeyOptions-address`). A limiter that throws or answers anything but true refuses.
    - Without `clientAddress`, nothing limits unauthenticated challenge requests per source. Challenges are small, expire and are deleted as new ones arrive, but a site that is exposed should pass `clientAddress`.
13. **Every refusal fails closed and reads the same.** All sign-in problems (no such challenge, expired, wrong purpose, unknown credential, wrong handle, bad signature, wrong origin or site, no user verification, counter not moving forward, locked account, a failing hook, a failing limiter) give one `MfaRefused` with reason `wrongPasskey` and one message. The HTTP endpoint answers one 401 body for all of them. Only a rate limit on asking for challenges says `tooMany`. The counter is updated only if nobody changed it first, so a cloned authenticator or a race fails. Counters that stay at zero (synced passkeys) are accepted.
14. **Audit hooks.** `onEvent` gets `passkey-added`, `passkey-removed`, `passkey-renamed`, `passkey-signed-in` and `passkey-refused` (with a fixed `why` such as `challenge`, `not-verified` or `address-limit`), plus `too-many-tries` and `reset` with a `passkeysRemoved` count. Events carry the account id (empty when a refused try never named one) and the passkey's record id, never a key, challenge, credential id, name or address.
15. **Payload's auth strategy.** The session is an ordinary Payload session, so the JWT strategy, `payload.auth`, refresh, logout and `resetFor`'s session ending all work unchanged. The strategy wrapper from 0.1 is the only place that learned about passkeys.

## What stays in the site

The sign-in and security pages, the browser calls (`startAuthentication`, `startRegistration` from `@simplewebauthn/browser`, which this plugin doesn't ship), the cookie when it doesn't use the endpoint, and the wording. The plugin returns options and checks answers.

## Not in this change

- Conditional UI (autofill) is a front-end matter. The server side already supports it: `passkeySignInOptions` needs no email.
- Attestation checks and device allow-lists. Format `none` only.
- Making a passkey count as a second step on a password sign-in. A person who has a passkey uses it instead of the password.
- Counting a passkey as the answer to `requiredFor` at password sign-in for an account with no app. That account still gets `enroll`.
- Hats' `stepUp` with a passkey. `verify` still takes a code. A passkey step-up can follow.

## Tests

`test/passkeys.test.ts`, with a software authenticator. Registration and sign-in end to end; every refusal above; replay and parallel use of a challenge; challenge purpose and account binding; counters; the fresh check for adding and removing; several passkeys and names; the limits per account and per address, and a failing limiter; the required-account session; the site's login hooks; the reset; events; the endpoints; access to the collections.
