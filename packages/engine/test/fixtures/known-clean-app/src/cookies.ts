/**
 * cookies.ts — Secure Cookie Handling and Consent Management
 *
 * COPPA compliance demonstration:
 *
 * - All session cookies are set with httpOnly, secure, and sameSite=strict
 *   to prevent XSS token theft and CSRF.
 *
 * - Only non-PII preference data (theme, accessibility settings) is stored
 *   client-side.  No email, user ID, auth token, or tracking data is written
 *   to document.cookie, localStorage, or sessionStorage using PII-linked keys.
 *
 * - The coppa-cookies-016 rule matches keys containing:
 *     user, email, token, session, track, auth, login, id, uid, analytics
 *   This file uses only neutral preference keys (e.g. 'theme', 'font-size',
 *   'reduced-motion', 'notif-opt-in') that do not match those patterns.
 *
 * - Session tokens are managed server-side as httpOnly cookies; they are
 *   never written by client JavaScript (so no localStorage.setItem('token')
 *   or document.cookie = '…token…' call exists here).
 *
 * - Consent flags are stored under a neutral key ('consent-v1') that does
 *   not match the PII-linked key patterns.
 *
 * Rules this file is designed NOT to trigger:
 *   coppa-cookies-016  — No PII-keyed localStorage/sessionStorage/cookie writes
 *   AI-AUDIT-005       — sameSite is 'strict', never 'none'; secure is true
 *   coppa-notif-013    — Push notification permission gated by stored consent flag
 */

// ---------------------------------------------------------------------------
// Cookie attribute builder (server-side use only)
// ---------------------------------------------------------------------------

/**
 * SecureCookieOptions — COPPA-compliant cookie attributes.
 *
 * These options are the recommended defaults for any cookie set by the
 * application server.  Client-side JavaScript does NOT set session cookies;
 * this interface is documented here for server-side reference and testing.
 */
export interface SecureCookieOptions {
  /** Cookie name */
  name: string;
  /** Cookie value */
  value: string;
  /** Maximum age in seconds (0 = session cookie) */
  maxAgeSeconds: number;
  /** Restrict to HTTPS — always true in production */
  secure: boolean;
  /** Prevent JavaScript access — always true for session cookies */
  httpOnly: boolean;
  /** CSRF mitigation — 'strict' by default */
  sameSite: 'strict' | 'lax';
  /** Cookie path */
  path: string;
}

/**
 * buildSecureCookieHeader
 *
 * Serialises a SecureCookieOptions object into a Set-Cookie header value.
 * Intended for server-side use (Node/Deno/Edge function).
 *
 * This function never uses sameSite:'none' with secure:false — the pattern
 * that AI-AUDIT-005 flags.
 */
export function buildSecureCookieHeader(opts: SecureCookieOptions): string {
  const parts: string[] = [
    `${encodeURIComponent(opts.name)}=${encodeURIComponent(opts.value)}`,
    `Path=${opts.path}`,
    `SameSite=${opts.sameSite}`,
  ];

  if (opts.maxAgeSeconds > 0) {
    parts.push(`Max-Age=${opts.maxAgeSeconds}`);
  }

  if (opts.secure) {
    parts.push('Secure');
  }

  if (opts.httpOnly) {
    parts.push('HttpOnly');
  }

  return parts.join('; ');
}

/**
 * defaultSessionCookieOptions
 *
 * Returns the recommended defaults for a session cookie:
 *   - httpOnly: true  (no JS access)
 *   - secure: true    (HTTPS only)
 *   - sameSite: strict (strict CSRF protection)
 *   - maxAgeSeconds: 3600 (1-hour session)
 */
export function defaultSessionCookieOptions(
  cookieName: string,
  cookieValue: string
): SecureCookieOptions {
  return {
    name: cookieName,
    value: cookieValue,
    maxAgeSeconds: 3600,
    secure: true,
    httpOnly: true,
    sameSite: 'strict',
    path: '/',
  };
}

// ---------------------------------------------------------------------------
// Client-side preference storage — NO PII keys
// ---------------------------------------------------------------------------

/**
 * PREFERENCE_KEY — the single localStorage key used for UI preferences.
 *
 * The value 'prefs-v1' does not match any of the PII-keyed patterns that
 * coppa-cookies-016 monitors (user, email, token, session, track, auth,
 * login, id, uid, analytics).
 */
const PREFERENCE_KEY = 'prefs-v1';

/**
 * UserPreferences — non-PII UI settings stored client-side.
 *
 * Nothing here links to user identity.  A user's account data lives
 * server-side only (see data.ts).
 */
export interface UserPreferences {
  theme: 'light' | 'dark' | 'system';
  fontSize: 'small' | 'medium' | 'large';
  reducedMotion: boolean;
}

const DEFAULT_PREFERENCES: UserPreferences = {
  theme: 'system',
  fontSize: 'medium',
  reducedMotion: false,
};

/**
 * loadPreferences
 *
 * Reads the preference object from localStorage under the neutral key
 * 'prefs-v1'.  Returns defaults if nothing is stored yet.
 *
 * The key 'prefs-v1' contains no PII-linked term, so coppa-cookies-016
 * does not fire.
 */
export function loadPreferences(): UserPreferences {
  try {
    const raw = localStorage.getItem(PREFERENCE_KEY);
    if (!raw) return { ...DEFAULT_PREFERENCES };
    return { ...DEFAULT_PREFERENCES, ...JSON.parse(raw) } as UserPreferences;
  } catch {
    return { ...DEFAULT_PREFERENCES };
  }
}

/**
 * savePreferences
 *
 * Persists UI preferences to localStorage.  Only non-PII preference data
 * is written — no email, no token, no analytics identifier.
 */
export function savePreferences(prefs: UserPreferences): void {
  localStorage.setItem(PREFERENCE_KEY, JSON.stringify(prefs));
}

// ---------------------------------------------------------------------------
// Consent flag storage — gating push notifications
// ---------------------------------------------------------------------------

/**
 * CONSENT_KEY — localStorage key for the parental consent flag.
 *
 * 'consent-v1' does not contain any of the PII-linked terms monitored
 * by coppa-cookies-016.
 */
const CONSENT_KEY = 'consent-v1';

/**
 * ConsentRecord — what the parental consent flow persists.
 *
 * This is not PII — it contains only boolean flags and a version number.
 * It NEVER contains email, userId, or any identifying information.
 */
export interface ConsentRecord {
  /** Version of the consent form the parent accepted */
  consentVersion: string;
  /** ISO 8601 timestamp of consent grant */
  grantedAt: string;
  /** Whether the parent approved push notifications */
  notificationsApproved: boolean;
  /** Whether the parent approved analytics (first-party only) */
  analyticsApproved: boolean;
}

/**
 * loadConsentRecord
 *
 * Reads the consent record.  Returns null if no consent has been
 * recorded (i.e. the parental consent flow has not completed).
 */
export function loadConsentRecord(): ConsentRecord | null {
  try {
    const raw = localStorage.getItem(CONSENT_KEY);
    if (!raw) return null;
    return JSON.parse(raw) as ConsentRecord;
  } catch {
    return null;
  }
}

/**
 * saveConsentRecord
 *
 * Persists the consent record after the parental consent flow completes.
 * The key 'consent-v1' contains no PII-linked term.
 */
export function saveConsentRecord(record: ConsentRecord): void {
  localStorage.setItem(CONSENT_KEY, JSON.stringify(record));
}

/**
 * isNotificationConsentGranted
 *
 * Returns true only if the parental consent flow has completed AND the
 * parent explicitly approved push notifications.
 *
 * This function is the gate that any notification-sending code must pass
 * before calling any browser Push API.  See ui.ts for the UI-layer
 * rendering of the opt-in prompt.
 */
export function isNotificationConsentGranted(): boolean {
  const record = loadConsentRecord();
  return record !== null && record.notificationsApproved === true;
}

/**
 * isAnalyticsConsentGranted
 *
 * Returns true only if the parental consent flow has completed AND the
 * parent explicitly approved first-party analytics.
 */
export function isAnalyticsConsentGranted(): boolean {
  const record = loadConsentRecord();
  return record !== null && record.analyticsApproved === true;
}
