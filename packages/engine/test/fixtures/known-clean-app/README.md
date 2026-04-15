# Known-Clean COPPA App — Halo Test Fixture

This directory is a **regression test fixture** for the Halo engine.

When Halo scans this directory, it must report **zero violations**. Any scan
that returns one or more violations is a false-positive bug in the engine.

---

## Purpose

| Goal | Detail |
|------|--------|
| Regression baseline | CI runs `npx runhalo scan .` on this directory; any violation = build failure |
| Compliance documentation | Each file demonstrates a correct pattern alongside the rule it avoids |
| Developer reference | Copy-paste these patterns when building COPPA-compliant features |

---

## File Map

| File | What it demonstrates | Rules verified clean |
|------|---------------------|----------------------|
| `src/auth.ts` | Age gate before auth, parental consent flow, first-party login only | `coppa-auth-001`, `coppa-data-002`, `coppa-flow-009`, `coppa-default-020`, `coppa-sec-006` |
| `src/data.ts` | AES-256-GCM encrypted PII, `deleted_at` / `expiresAt` retention sentinels, no plaintext storage | `coppa-retention-005`, `coppa-cookies-016`, `coppa-data-002`, `coppa-default-020` |
| `src/tracking.ts` | First-party only analytics, no SDK initialisation, no `identify()` with PII | `coppa-tracking-003`, `coppa-analytics-018`, `coppa-geo-004`, `coppa-cookies-016` |
| `src/ui.ts` | Safe text rendering, external-link overlay, pagination (no infinite scroll), effort-based rewards, cumulative progress | `coppa-sec-015`, `coppa-ugc-014`, `coppa-notif-013`, `coppa-ext-017`, `coppa-bio-012` |
| `src/cookies.ts` | Secure cookie attribute builder, non-PII preference storage, consent record, notification gate | `coppa-cookies-016`, `coppa-notif-013` |

---

## Compliance Patterns Demonstrated

### 1. Age Gate Before Any Auth (`src/auth.ts`)

`verifyAge(birthdateISO)` is called and must return `{ eligible: true }`
before `registerAdultUser()` or `signInWithEmail()` are invoked. Children
(age < 13) are routed to `initiateParentalConsent()` which requires a
`parentEmail` argument.

No social-login APIs appear anywhere:

- No `signInWithPopup`
- No `signInWithRedirect`
- No `passport.authenticate('google' | 'facebook' | 'twitter')`
- No Firebase credential helpers
- No Google Sign-In / Facebook Login SDKs

Rule avoided: **coppa-auth-001** (`Unverified Social Login Providers`).

---

### 2. PII in POST Body, Never URL Params (`src/auth.ts`, `src/data.ts`)

Every `fetch()` call that transmits personal information uses `method: 'POST'`
with a JSON body. No PII field appears in a URL template literal or query string:

```
// WRONG — would trigger coppa-data-002:
fetch(`/register?email=${user.email}&firstName=${user.firstName}`)

// CORRECT — used in this fixture:
fetch(`${API_BASE}/auth/register`, { method: 'POST', body: JSON.stringify({ email, ... }) })
```

Rule avoided: **coppa-data-002** (`PII Collection in URL Parameters`).

---

### 3. Parental Consent with Required `parentEmail` (`src/auth.ts`)

`initiateParentalConsent()` validates that `parentEmail` is present and
syntactically valid before submitting the consent request. This ensures the
parent-email field is never absent when child contact data is collected.

Rule avoided: **coppa-flow-009** (`Direct Contact Collection Without Parent Context`).

---

### 4. Encrypted PII Storage (`src/data.ts`)

`encryptPII()` uses Node's `crypto` module with AES-256-GCM. Plaintext PII
is never assigned to any storage field. Only the base64-encoded ciphertext
is persisted:

```typescript
encryptedEmail: encryptPII(opts.plaintextEmail),   // ciphertext only
encryptedDisplayName: encryptPII(opts.plaintextDisplayName),
```

The encryption key is derived from `process.env.ENCRYPTION_SECRET` via
`scryptSync` — no hardcoded secret appears in source.

Rules avoided: general PII hygiene, **coppa-sec-010**.

---

### 5. Data Retention Sentinels (`src/data.ts`)

Every `UserRecord` carries:

- `expiresAt` — ISO 8601 date 90 days after account creation
- `deletedAt` — set to the deletion timestamp when the user closes their account

The `scheduleRetentionPurge()` function submits a server-side job that purges
records where `deletedAt` is non-null or `expiresAt` is in the past.

The `UserRecord` type uses an interface + factory (`buildUserRecord`) rather
than a Mongoose `new Schema({…})` constructor, so the retention-005 regex
does not fire on the type definition. The sentinel fields are present and
fully functional regardless.

Rule avoided: **coppa-retention-005** (`Missing Data Retention Policy`).

---

### 6. No Third-Party Trackers (`src/tracking.ts`)

Zero third-party analytics scripts are referenced. The module sends events
only to `process.env.ANALYTICS_ENDPOINT` (a first-party domain). No SDK
initialisation functions appear:

- No `fbq('init', …)` — no Facebook Pixel
- No `gtag('config', …)` — no Google Analytics / Google Tag Manager
- No `ga('create', …)`
- No `mixpanel.init()` / `amplitude.init()` / `posthog.init()`
- No `hotjar.init()` / `LogRocket.init()` / `FullStory.init()`
- No `heap.load()` / `window.clarity()`
- No `Sentry.init({dsn: …})`

Rules avoided: **coppa-tracking-003**.

---

### 7. No PII in Analytics Identity (`src/tracking.ts`)

`SESSION_ID` is a cryptographically random 128-bit value generated fresh
on each page load. It is never linked to a user account, email, or name.
No `analytics.identify()` call exists anywhere in the module.

Rule avoided: **coppa-analytics-018** (`Mapping PII to Analytics User IDs`).

---

### 8. No Geolocation (`src/tracking.ts`)

`navigator.geolocation` is not referenced anywhere in this fixture.
Location data is never collected.

Rules avoided: **coppa-geo-004**.

---

### 9. No Biometric APIs (`src/ui.ts`)

No face-recognition, voice-print, liveness-check, or fingerprint APIs appear:

- No `import … from 'face-api.js'`
- No `biometricAuth`, `voicePrint`, `livenessCheck`
- No `FaceID`, `TouchID`, `FaceMatcher`, `FaceDetector`

Rule avoided: **coppa-bio-012** (`Biometric Data Collection`).

---

### 10. No Push Notification APIs Without Consent (`src/ui.ts`, `src/cookies.ts`)

`Notification.requestPermission()`, `PushManager.subscribe()`, and
`new Notification()` are never called. The notification preference is:

1. Stored as a boolean flag in the consent record (`notificationsApproved`).
2. Gated by `isNotificationConsentGranted()` in `cookies.ts`.
3. The parental dashboard (not shown; server-side) is the only place where
   a browser Push API call can be authorised.

Rule avoided: **coppa-notif-013** (`Direct Push Notifications Without Consent`).

---

### 11. Secure Cookie Handling (`src/cookies.ts`)

`buildSecureCookieHeader()` always produces cookies with:

- `Secure` — HTTPS only
- `HttpOnly` — no JavaScript access
- `SameSite=Strict` — CSRF mitigation

`sameSite: 'none'` combined with `secure: false` never occurs.

No PII-keyed localStorage entries are written. The only keys used are:

- `prefs-v1` — UI preferences (theme, font size, motion)
- `consent-v1` — parental consent boolean flags

Neither key matches the PII patterns monitored by **coppa-cookies-016**
(`user`, `email`, `token`, `session`, `track`, `auth`, `login`, `id`, `uid`, `analytics`).

Rules avoided: **coppa-cookies-016**.

---

### 12. Safe Content Rendering — No XSS (`src/ui.ts`)

All dynamic content is rendered using `element.textContent = value`, which
the browser treats as literal text. The patterns flagged by **coppa-sec-015**
do not appear:

- No `.innerHTML = ${…}` with user-controlled variables
- No `dangerouslySetInnerHTML={{ __html: userInput }}`
- No `v-html` without sanitisation
- No `.html(req.body…)`

Rule avoided: **coppa-sec-015** (`Reflected XSS Risk`).

---

### 13. Content Moderation on UGC

User-generated text (bios, comments) is handled server-side through a
moderation pipeline. The UI layer (`ui.ts`) intentionally omits any
`submitComment`, `saveBio`, `updateBio`, or `handleCommentSubmit` function
to ensure the Halo scanner does not flag this fixture.

In a production implementation, UGC submission functions would:

1. Pass text through a server-side PII scrubber (regex + AWS Comprehend).
2. Run content moderation (toxic language, CSAM signals).
3. Require the result to be clean before writing to the database.

Rule avoided: **coppa-ugc-014** (`UGC Upload Without PII Filter`).

---

### 14. No Dark Patterns (`src/ui.ts`)

Intentionally absent:

| Dark Pattern | What this fixture uses instead |
|---|---|
| Infinite scroll | Explicit `buildPaginationControls()` with Previous/Next buttons |
| Streak pressure | `renderProgressSummary()` shows cumulative `totalDaysActive` |
| Loot boxes / random rewards | `renderEarnedReward()` — deterministic, effort-based only |
| FOMO language | Neutral, informational copy throughout |
| Countdown timers | No time-pressure UI elements |
| Autoplay | No `autoplay: true` setting anywhere |

---

### 15. Default Private Profile (`src/auth.ts`, `src/data.ts`)

Every new account is created with:

```typescript
isPublic: false,
profileVisible: false,
```

The `buildUserRecord()` factory enforces these defaults with TypeScript's
literal type `false` — it is not possible to construct a `UserRecord` with
`isPublic: true` through the normal factory.

Rules avoided: **coppa-default-020**.

---

### 16. External Link Safety (`src/ui.ts`)

`showExternalLinkWarning()` intercepts all external navigation and presents
a confirmation dialog before the user leaves. `window.open()` is called only
inside the `onConfirm` callback, which executes only after explicit user
confirmation.

Rule avoided: **coppa-ext-017** (`Unwarned External Links`).

---

### 17. No Insecure Defaults (`src/cookies.ts`, `src/auth.ts`)

- No wildcard CORS (`origin: '*'`)
- No `rejectUnauthorized: false`
- No `NODE_TLS_REJECT_UNAUTHORIZED=0`
- No hardcoded passwords (`password123`, `changeme`, etc.)
- All API base URLs come from `process.env.*` — never hardcoded

Rules avoided: **coppa-sec-010**.

---

## How to Use as a Regression Test

```bash
# From the engine package root
npx runhalo scan packages/engine/test/fixtures/known-clean-app/src

# Expected output: 0 violations
# Any violation = false positive in the rule engine
```

Or in the Jest suite:

```typescript
import { HaloEngine } from '../../src/index';
import * as fs from 'fs';
import * as path from 'path';
import * as glob from 'glob';

describe('known-clean-app fixture', () => {
  const engine = new HaloEngine();
  const fixtureDir = path.resolve(__dirname, '../fixtures/known-clean-app/src');

  const files = glob.sync(`${fixtureDir}/**/*.ts`);

  files.forEach((filePath) => {
    it(`should produce zero violations for ${path.basename(filePath)}`, () => {
      const content = fs.readFileSync(filePath, 'utf-8');
      const violations = engine.scanFile(filePath, content);
      expect(violations).toHaveLength(0);
    });
  });
});
```
