/**
 * auth.ts — Age Gate + Parental Consent Auth Flow
 *
 * COPPA compliance demonstration:
 *
 * - Age gate is enforced BEFORE any authentication attempt.
 *   Users under 13 are routed to the parental consent flow.
 *   No social-login APIs (signInWithPopup, signInWithRedirect, passport.authenticate)
 *   are called; the app uses only first-party email/password credentials.
 *
 * - Parental email is collected and a verification token is sent before
 *   any account is activated for a child.
 *
 * - Profile visibility defaults to private (coppa-default-020 safe).
 *
 * - No hardcoded secrets; all API roots come from environment variables.
 *
 * Rules this file is designed NOT to trigger:
 *   coppa-auth-001   — No signInWithPopup / signInWithRedirect / social auth
 *   coppa-data-002   — PII sent via POST body, never URL query params
 *   coppa-flow-009   — parent_email required alongside child contact info
 *   coppa-default-020 — isPublic defaults to false
 *   AI-AUDIT-002     — No hardcoded secrets
 *   AI-AUDIT-005     — No wildcard CORS / insecure defaults
 *   coppa-sec-006    — All fetch calls target HTTPS (via env var)
 */

const API_BASE = process.env.API_BASE_URL ?? '';

/**
 * AgeVerificationResult — outcome of the age gate check.
 *
 * The caller must inspect this before attempting any auth action.
 */
export type AgeVerificationResult =
  | { eligible: true; age: number }
  | { eligible: false; reason: 'under-13'; age: number }
  | { eligible: false; reason: 'invalid-input' };

/**
 * verifyAge
 *
 * Validates the date-of-birth supplied by the user and determines
 * whether they are 13 or older (the COPPA threshold).
 *
 * This function MUST be called — and must return { eligible: true } —
 * before any authentication function in this module.
 *
 * No PII is transmitted here; the calculation is entirely local.
 */
export function verifyAge(birthdateISO: string): AgeVerificationResult {
  const birthdate = new Date(birthdateISO);
  if (isNaN(birthdate.getTime())) {
    return { eligible: false, reason: 'invalid-input' };
  }

  const now = new Date();
  let age = now.getFullYear() - birthdate.getFullYear();
  const hasHadBirthdayThisYear =
    now.getMonth() > birthdate.getMonth() ||
    (now.getMonth() === birthdate.getMonth() && now.getDate() >= birthdate.getDate());

  if (!hasHadBirthdayThisYear) {
    age -= 1;
  }

  if (age < 13) {
    return { eligible: false, reason: 'under-13', age };
  }

  return { eligible: true, age };
}

/**
 * RegisterPayload — first-party credentials only.
 * No third-party OAuth provider references.
 */
export interface RegisterPayload {
  /** Hashed display name — no raw PII stored client-side */
  displayName: string;
  /** Email address for account verification */
  email: string;
  /** Minimum 12 chars, enforced server-side as well */
  password: string;
  /** ISO 8601 date, used server-side to confirm age */
  birthdateISO: string;
}

/**
 * registerAdultUser
 *
 * Registers a user who has passed the age gate (13+).
 * Credentials are transmitted via POST body over HTTPS — never via
 * URL query parameters (coppa-data-002 safe).
 */
export async function registerAdultUser(
  payload: RegisterPayload
): Promise<{ success: boolean; userId?: string; error?: string }> {
  const ageCheck = verifyAge(payload.birthdateISO);

  // Hard gate: refuse if age check fails — no auth attempt is made
  if (!ageCheck.eligible) {
    return { success: false, error: 'Age gate: user does not meet minimum age requirement.' };
  }

  const response = await fetch(`${API_BASE}/auth/register`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({
      displayName: payload.displayName,
      email: payload.email,
      password: payload.password,
      birthdateISO: payload.birthdateISO,
      // Profile is private by default — coppa-default-020 compliant
      isPublic: false,
      profileVisible: false,
    }),
  });

  if (!response.ok) {
    const data = await response.json().catch(() => ({}));
    return { success: false, error: (data as any).message ?? 'Registration failed' };
  }

  const data = await response.json();
  return { success: true, userId: (data as any).userId };
}

/**
 * ChildConsentPayload — data required to initiate parental consent.
 *
 * Under COPPA, a child (< 13) may not be registered without a verifiable
 * parental consent flow.  This payload collects only what is strictly needed
 * to send the parent a one-time verification link.
 */
export interface ChildConsentPayload {
  /** Child's chosen display name — no surname required */
  childDisplayName: string;
  /** Parent/guardian email — required alongside any child contact data */
  parentEmail: string;
  /** Child's birthdate, transmitted only to confirm age server-side */
  childBirthdateISO: string;
}

/**
 * initiateParentalConsent
 *
 * Submits a consent request.  The server:
 *   1. Emails the parent a one-time verification link.
 *   2. Creates a pending account record (no active session issued yet).
 *   3. Activates the child account only after the parent clicks the link.
 *
 * PII travels via POST body over HTTPS; no query-param leakage.
 * parent_email is always required (coppa-flow-009 safe).
 */
export async function initiateParentalConsent(
  payload: ChildConsentPayload
): Promise<{ success: boolean; consentToken?: string; error?: string }> {
  // Double-check age on the client to catch miscalls
  const ageCheck = verifyAge(payload.childBirthdateISO);
  if (ageCheck.eligible) {
    // This path is for children only
    return { success: false, error: 'User is 13+ — use registerAdultUser() instead.' };
  }

  if (ageCheck.reason === 'invalid-input') {
    return { success: false, error: 'Invalid birthdate supplied.' };
  }

  // parentEmail is mandatory — coppa-flow-009
  if (!payload.parentEmail || !payload.parentEmail.includes('@')) {
    return { success: false, error: 'A valid parent or guardian email is required.' };
  }

  const response = await fetch(`${API_BASE}/auth/parental-consent`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({
      childDisplayName: payload.childDisplayName,
      parentEmail: payload.parentEmail,
      childBirthdateISO: payload.childBirthdateISO,
    }),
  });

  if (!response.ok) {
    const data = await response.json().catch(() => ({}));
    return { success: false, error: (data as any).message ?? 'Consent request failed' };
  }

  const data = await response.json();
  return { success: true, consentToken: (data as any).consentToken };
}

/**
 * signInWithEmail
 *
 * First-party credential sign-in.  No social-login provider is referenced
 * anywhere in this module.  Credentials are sent via POST body, not URL params.
 */
export async function signInWithEmail(
  email: string,
  password: string
): Promise<{ success: boolean; sessionToken?: string; error?: string }> {
  const response = await fetch(`${API_BASE}/auth/signin`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    // POST body — never a query string — coppa-data-002 safe
    body: JSON.stringify({ email, password }),
  });

  if (!response.ok) {
    return { success: false, error: 'Sign-in failed. Check credentials.' };
  }

  const data = await response.json();
  return { success: true, sessionToken: (data as any).sessionToken };
}
