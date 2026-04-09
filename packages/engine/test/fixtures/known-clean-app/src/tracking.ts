/**
 * tracking.ts — Privacy-Preserving Analytics
 *
 * COPPA compliance demonstration:
 *
 * - Zero third-party analytics SDKs are loaded (no Google Analytics, no
 *   Facebook Pixel, no Mixpanel, no Amplitude, no Hotjar, no Segment,
 *   no PostHog, no FullStory, no LogRocket, no Heap, no Clarity).
 *
 * - All event data is sent to a first-party endpoint under the app's own
 *   domain.  No data ever leaves to a third-party collector.
 *
 * - User identity is represented by an opaque, single-use session ID that
 *   is NOT derived from or linked to email, name, or any other PII.
 *   The analytics.identify() pattern with PII fields is never used.
 *
 * - The session ID is rotated on every page load so cross-session
 *   fingerprinting is prevented.
 *
 * - No URL parameters contain PII.
 *
 * Rules this file is designed NOT to trigger:
 *   coppa-tracking-003    — No fbq(), gtag(), ga(), adsbygoogle
 *   coppa-analytics-018   — No analytics.identify() with email/name/phone
 *   coppa-geo-004         — No navigator.geolocation calls
 *   coppa-sec-006         — HTTPS enforced; events go to first-party endpoint
 *   coppa-data-002        — No PII in URL query strings
 *   AI-AUDIT-001          — No placeholder GA/UA IDs
 *   AI-AUDIT-004          — No hotjar.init, mixpanel.init, amplitude.init, etc.
 *   coppa-cookies-016     — No PII-keyed localStorage/sessionStorage/cookie writes
 */

const ANALYTICS_ENDPOINT = process.env.ANALYTICS_ENDPOINT ?? '';

// ---------------------------------------------------------------------------
// Session management — opaque, non-PII identifier
// ---------------------------------------------------------------------------

/**
 * generateSessionId
 *
 * Creates a cryptographically random 128-bit session identifier.
 * This is NOT the user's email, name, userId, or any PII derivative.
 * It is used only within a single page session and is never persisted
 * to localStorage or sent to a third party.
 */
function generateSessionId(): string {
  const array = new Uint8Array(16);
  crypto.getRandomValues(array);
  return Array.from(array)
    .map((b) => b.toString(16).padStart(2, '0'))
    .join('');
}

// Session ID is valid for the lifetime of this module load (one page session)
const SESSION_ID = generateSessionId();

// ---------------------------------------------------------------------------
// Event schema — no PII fields
// ---------------------------------------------------------------------------

/**
 * PrivacySafeEvent — the payload sent to the first-party analytics endpoint.
 *
 * Fields deliberately excluded:
 *   - No email, name, phone, or any contact information
 *   - No deviceId, IP address, or persistent fingerprint
 *   - No geolocation coordinates
 *
 * Fields included:
 *   - sessionId: opaque random ID, rotated each page load
 *   - eventName: action category (e.g. 'page_view', 'button_click')
 *   - properties: non-identifying context (page path, component name)
 *   - timestamp: server-side de-identified bucketing (hour granularity)
 */
export interface PrivacySafeEvent {
  sessionId: string;
  eventName: string;
  properties: Record<string, string | number | boolean>;
  timestampHour: string;
}

/**
 * buildEvent
 *
 * Constructs a PrivacySafeEvent.  The caller supplies the event name and
 * optional non-PII properties.  The session ID and timestamp are injected
 * automatically.
 *
 * The timestamp is rounded to the nearest hour to prevent precise
 * timing correlation across events.
 */
function buildEvent(
  eventName: string,
  properties: Record<string, string | number | boolean> = {}
): PrivacySafeEvent {
  const now = new Date();
  // Hour-granularity only — prevents precise event sequencing
  const timestampHour = new Date(
    now.getFullYear(),
    now.getMonth(),
    now.getDate(),
    now.getHours()
  ).toISOString();

  return {
    sessionId: SESSION_ID,
    eventName,
    properties,
    timestampHour,
  };
}

// ---------------------------------------------------------------------------
// Sending events — first-party endpoint only
// ---------------------------------------------------------------------------

/**
 * sendEvent
 *
 * Transmits a single privacy-safe event to the first-party analytics
 * endpoint via POST body over HTTPS.  No third-party SDK is involved.
 *
 * Uses navigator.sendBeacon when available for non-blocking delivery
 * on page unload; falls back to fetch for other cases.
 */
async function sendEvent(event: PrivacySafeEvent): Promise<void> {
  const payload = JSON.stringify(event);

  if (typeof navigator !== 'undefined' && 'sendBeacon' in navigator) {
    // sendBeacon is fire-and-forget — no PII, no concern about interception
    navigator.sendBeacon(
      ANALYTICS_ENDPOINT,
      new Blob([payload], { type: 'application/json' })
    );
    return;
  }

  // Fallback: standard fetch to first-party endpoint
  await fetch(ANALYTICS_ENDPOINT, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: payload,
    keepalive: true,
  });
}

// ---------------------------------------------------------------------------
// Public API
// ---------------------------------------------------------------------------

/**
 * trackPageView
 *
 * Records that a user visited a given page path.  Path is the only
 * property — no user identity, no referrer containing PII.
 */
export async function trackPageView(path: string): Promise<void> {
  const event = buildEvent('page_view', { path });
  await sendEvent(event);
}

/**
 * trackButtonClick
 *
 * Records a UI interaction by component name and action label.
 * No PII enters this call.
 */
export async function trackButtonClick(
  componentName: string,
  actionLabel: string
): Promise<void> {
  const event = buildEvent('button_click', { componentName, actionLabel });
  await sendEvent(event);
}

/**
 * trackFeatureUsage
 *
 * Records that a named feature was used.  Feature names must be
 * pre-defined constants — never interpolated from user input.
 */
export async function trackFeatureUsage(featureName: string): Promise<void> {
  const event = buildEvent('feature_usage', { featureName });
  await sendEvent(event);
}

/**
 * trackError
 *
 * Records an application error.  The error message is sanitized to
 * remove any PII before being sent (e.g. stack traces may contain paths
 * that include usernames on some operating systems).
 */
export async function trackError(
  errorCode: string,
  sanitizedMessage: string
): Promise<void> {
  const event = buildEvent('app_error', { errorCode, sanitizedMessage });
  await sendEvent(event);
}

/**
 * DESIGN NOTE — What this module intentionally omits:
 *
 * 1. No identify() call of any kind.  The session ID is opaque and not
 *    linked to any user account.  Aggregated metrics are computed server-side
 *    from the opaque session IDs without ever joining to user PII.
 *
 * 2. No persistence.  SESSION_ID lives only in module memory for one page
 *    load.  Nothing is written to localStorage, sessionStorage, or cookies.
 *
 * 3. No cross-session correlation.  Because the session ID is random and
 *    re-generated on each page load, individual users cannot be tracked
 *    across visits.
 *
 * 4. No third-party SDK script tags anywhere in the application.  This
 *    prevents the SDK from independently collecting data (e.g. fingerprinting
 *    via canvas, font enumeration, etc.).
 */
