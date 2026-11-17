# Changelog

## Unreleased

- `moveLegacyState` no longer loses an old secret when the account already has a state record without one. Such a record appears between deploy and move (a password reset that blocks emailed codes, or a setup never confirmed), and the move used to count it as moved and remove the old group, silently turning two-step off. Now the old secret, enabled date and last step are merged into the record, the record's own fields (an email-code block and its date, a pending setup) stay, and the old group is removed only after the merge is written. Recovery codes are never copied into an existing record.
- A secret-less record that shows a deliberate clear is not merged. `turnOff` now writes a new `turnedOffAt` date, and `resetFor` already writes `resetAt` and `enrollUntil`; any of these, or an enabled date, recovery codes, a last step or a verified date, leaves the old field in place and lists the account in the new `needsReview` result. A started setup and an email-code block are the only markers that still merge, because neither revokes the old factor. Found in review of this change by the plugin's owner side.
- A record that already has a secret keeps it; if the old one differs, the account's id is listed in `differentSecret` and the old group is still removed. The result gains `merged`, `differentSecret` and `needsReview`.
- The state collection gains a `turnedOffAt` date field. Found by a Security Analyst read of the first site, 2026-11-15 (Captive Origins K5009).

Tested: 4 new tests (50 in all), on in-memory MongoDB with made-up accounts only, not a copy of any site's data: null and empty-secret records with a pending setup and an email block are merged (secret, enabled date, last step; email block and pending kept; no recovery codes; old group gone; two-step on; sign-in works; rerun is a no-op); a record left by `turnOff` and one left by `resetFor` are not merged, keep the old field, no secret and no recovery, and are listed in `needsReview` (also on a rerun); same and different secrets are kept and the different one reported; an account with no record moves as before. Not tested: a real site database, a merge write that loses a race, or a mutation check of the new guard.

## 0.1.0 (2026-11-13)

Published as 0.1.0 together with the first version below. 0.1.1 was never released on its own.

- `onEvent` gets a copy of the request without the entered code, the remember value, the headers (cookies, tokens and the client address) or the body. The raw request used to reach it, so a site logging `event.req` could have stored a code (found by the 2026-11-10 test self-audit). `payload` and the translation helpers stay on the copy but aren't enumerable, so a logger walking it never reaches the app's secret. The actor of an event is `event.user`: during a sign-in, `req.user` is whoever the request already had.

- `statusFor(payload, userId)`: `{ on, since, recoveryLeft }` for the person's security page, so a site doesn't read the state collection itself.
- `resetFor(payload, userId, { enrollHours, actor, endSessions })`: a maintainer's reset without a code. It goes through the version-checked write, clears the account's limiter tries, signs the account out everywhere by default (and refuses any session made before the reset, even one a racing sign-in wrote back), opens an enrollment window and sends a `reset` event naming the actor. Both are server-only, with no endpoint. Asked for while wiring it into the first site.

- Every signed-in request now reads the account's two-step state once, whether or not the site has a `requiredFor` rule, so a reset can end sessions that a racing sign-in wrote back.

Tested: 5 new tests (29 in all), including a reset racing a write that would keep the old secret, and old sessions written back after a reset (refused at request and at refresh). A security read approved 85b901f and found the session race in da6bfe2; both are fixed here. A mutation check shows each part of the reset fails one of the reset's own tests when removed: the cleared secret and recovery codes, the version guard, the cleared tries, ending sessions, the kept email-code block, and both window bounds. Not yet used on a site.

### First version

First version, as `payload-plugin-mfa` (renamed from payload-plugin-two-step by the owner, 2026-11-10), extracted from the first site's own two-step sign-in, with the decisions in `docs/adr/0001-design.md` (including the pre-publish read): factors, use-once codes with a race guard, per-account limits with keys built inside, the required rule at sign-in, refresh and every request, per-session expiry, remembered browsers, email codes blocked after a reset, step-up `verify`, and the login endpoint.

- The state lives in its own `two-step-state` collection, not on the account, so Payload's sign-in can't write old state back (found by the pre-publish read). `moveLegacyState` moves state kept on the account, run once as a script; until then those accounts can't sign in.
- The built-in limiter records each try before counting it, so tries at once can't outrun it.
- The key comes from the raw app secret, as the first site derives it.
- Tries older than the window are deleted as new ones arrive.

Tested: 24 tests. Replay, the race guard, per-account limiting, the failing rule and the limiter under 40 tries at once were each checked to fail when the protection is removed. Not yet used on a site, and no screens of its own.
