# Rules Reference

Halo ships with 26 COPPA rules covering the Children's Online Privacy Protection Act, including COPPA 2.0 provisions effective April 22, 2026.

## COPPA Rules

### coppa-auth-001 — Unverified Social Login Providers
- **Severity:** Critical
- **Detects:** Social login integrations (Google, Facebook, Apple, etc.) without age verification
- **Why it matters:** COPPA requires verifiable parental consent before collecting data from children under 13. Social login can expose PII without consent.
- **Fix:** Implement an age gate before social authentication. Collect age first, require parental consent if under 13.
- **Fixability:** Guided (Tier 2)

### coppa-data-002 — PII in URL Parameters
- **Severity:** Critical
- **Detects:** Personal identifiable information (names, emails, phone numbers) passed in URL query strings
- **Why it matters:** URL parameters appear in server logs, browser history, and referrer headers. PII in URLs creates uncontrolled data exposure.
- **Fix:** Move PII to POST request bodies or encrypted headers. Never pass personal data in URLs.
- **Fixability:** Guided (Tier 2)

### coppa-tracking-003 — Third-Party Ad Trackers
- **Severity:** Critical
- **Detects:** Known advertising SDKs and tracking pixels (Google Ads, Facebook Pixel, etc.)
- **Why it matters:** COPPA prohibits targeted advertising to children. Ad trackers collect behavioral data that enables targeting.
- **Fix:** Remove ad tracking from children's sections. Use privacy-safe contextual advertising if needed.
- **Fixability:** Guided (Tier 2)

### coppa-geo-004 — Precise Geolocation Collection
- **Severity:** Critical
- **Detects:** Geolocation API calls (`navigator.geolocation`, `CLLocationManager`, etc.)
- **Why it matters:** COPPA treats precise geolocation as personal information requiring parental consent before collection.
- **Fix:** Remove geolocation collection or implement parental consent flow before any location access.
- **Fixability:** Guided (Tier 2)

### coppa-retention-005 — Missing Data Retention Limits
- **Severity:** High
- **Detects:** Data storage patterns without explicit retention periods or deletion schedules
- **Why it matters:** COPPA requires data retention only for as long as necessary. Indefinite storage violates the data minimization principle.
- **Fix:** Implement data retention policies with automatic deletion schedules. Document retention periods in your privacy policy.
- **Fixability:** Guided (Tier 2)

### coppa-sec-006 — Unencrypted PII Transmission
- **Severity:** Critical
- **Detects:** HTTP (non-HTTPS) URLs used for data transmission, API calls, or resource loading
- **Why it matters:** COPPA requires reasonable security for children's data. Unencrypted transmission exposes data to interception.
- **Fix:** Upgrade all HTTP endpoints to HTTPS. Enforce TLS for all data transmission.
- **Fixability:** Auto (Tier 1)

### coppa-audio-007 — Unauthorized Audio Recording
- **Severity:** Critical
- **Detects:** MediaRecorder, getUserMedia, or audio recording APIs without consent checks
- **Why it matters:** Audio recording can capture voice biometrics and spoken PII. COPPA treats voice recordings as personal information.
- **Fix:** Require explicit parental consent before enabling any audio recording functionality.
- **Fixability:** Guided (Tier 2)

### coppa-ui-008 — Missing Privacy Policy on Registration
- **Severity:** High
- **Detects:** Registration forms, sign-up flows, and account creation without visible privacy policy links
- **Why it matters:** COPPA requires a clear, prominent link to the privacy policy at every point of data collection.
- **Fix:** Add a visible privacy policy link on all registration and data collection screens.
- **Fixability:** Guided (Tier 2)

### coppa-flow-009 — Direct Contact Without Parent Email
- **Severity:** High
- **Detects:** Contact forms, messaging, or direct communication features without parental email verification
- **Why it matters:** COPPA requires parental notification before a child can communicate with other users or the operator.
- **Fix:** Collect and verify a parent email address before enabling any direct contact features.
- **Fixability:** Guided (Tier 2)

### coppa-sec-010 — Weak Default Passwords
- **Severity:** Medium
- **Detects:** Hardcoded passwords, default credentials, or weak password patterns in code
- **Why it matters:** Weak defaults in children's applications can lead to unauthorized access to children's accounts and data.
- **Fix:** Remove hardcoded passwords. Enforce strong password policies or use passwordless authentication.
- **Fixability:** Auto (Tier 1)

### coppa-ext-011 — Unmoderated Third-Party Chat
- **Severity:** High
- **Detects:** Third-party chat SDKs, messaging libraries, or real-time communication without moderation
- **Why it matters:** COPPA requires monitoring of children's communications. Unmoderated chat exposes children to harmful interactions.
- **Fix:** Implement content moderation, keyword filtering, and human review for chat features accessible to children.
- **Fixability:** Guided (Tier 2)

### coppa-bio-012 — Biometric Data Collection
- **Severity:** Critical
- **Detects:** Face recognition, fingerprint, voice biometrics, or body tracking APIs
- **Why it matters:** COPPA 2.0 specifically adds biometric data to the definition of personal information requiring consent.
- **Fix:** Remove biometric collection from children's features or implement strict parental consent with clear disclosure.
- **Fixability:** Guided (Tier 2)

### coppa-notif-013 — Push Notifications Without Consent
- **Severity:** Medium
- **Detects:** Push notification registration (FCM, APNs, Web Push) without opt-in consent
- **Why it matters:** Notifications can be used for re-engagement marketing to children, which requires parental consent.
- **Fix:** Require explicit parental opt-in before enabling push notifications for child users.
- **Fixability:** Guided (Tier 2)

### coppa-ugc-014 — User-Generated Content Without PII Filter
- **Severity:** High
- **Detects:** UGC submission forms (comments, posts, profiles) without content filtering
- **Why it matters:** Children may inadvertently share PII in user-generated content. Operators must prevent public disclosure of children's personal information.
- **Fix:** Implement PII detection and filtering on all UGC before public display.
- **Fixability:** Guided (Tier 2)

### coppa-sec-015 — XSS Vulnerabilities
- **Severity:** High
- **Detects:** innerHTML usage, dangerouslySetInnerHTML, and unescaped user input in DOM
- **Why it matters:** XSS in children's apps can be exploited to steal session data, inject tracking, or expose children's information.
- **Fix:** Use textContent instead of innerHTML. Sanitize all user input before DOM insertion.
- **Fixability:** Auto (Tier 1)

### coppa-cookies-016 — Missing Cookie Consent
- **Severity:** Medium
- **Detects:** Cookie creation without consent mechanisms (document.cookie, Set-Cookie headers)
- **Why it matters:** COPPA requires disclosure and consent for persistent identifiers used to track children online.
- **Fix:** Implement cookie consent flow. Use session-only cookies where possible. Remove tracking cookies for child users.
- **Fixability:** Auto (Tier 1)

### coppa-ext-017 — Unwarned External Links
- **Severity:** Medium
- **Detects:** Links to external domains without interstitial warnings or confirmation
- **Why it matters:** Children's apps should clearly indicate when navigation leaves the app. External sites may not comply with COPPA.
- **Fix:** Add interstitial warnings before navigating to external domains. Consider an allowlist of approved external sites.
- **Fixability:** Guided (Tier 2)

### coppa-analytics-018 — Analytics User ID Mapping
- **Severity:** High
- **Detects:** Analytics events that include user IDs, making analytics data personally identifiable
- **Why it matters:** When analytics can be linked to individual users, it becomes personal information subject to COPPA.
- **Fix:** Anonymize analytics data. Use aggregate metrics instead of user-level tracking for children.
- **Fixability:** Guided (Tier 2)

### coppa-edu-019 — School Official Verification Bypass
- **Severity:** High
- **Detects:** Educational contexts where teacher/admin accounts lack verification
- **Why it matters:** COPPA allows schools to consent on behalf of parents, but only verified school officials can provide this consent.
- **Fix:** Implement school official verification (email domain, institutional validation) before granting consent authority.
- **Fixability:** Guided (Tier 2)

### coppa-default-020 — Default Public Profile Visibility
- **Severity:** High
- **Detects:** User profiles that default to public visibility
- **Why it matters:** Children's profiles should be private by default. Public profiles expose personal information without explicit consent.
- **Fix:** Set all profiles to private by default. Require explicit parental consent to make a child's profile visible.
- **Fixability:** Auto (Tier 1)

### coppa-bio-021 — Biometric Identifier Storage
- **Severity:** Critical
- **Detects:** Storage of biometric identifiers (face templates, voiceprints, fingerprint hashes) without encryption or retention limits
- **Why it matters:** COPPA 2.0 classifies biometric identifiers as personal information. Storing them without proper safeguards violates data security requirements.
- **Fix:** Encrypt biometric data at rest, enforce strict retention limits, and require parental consent before any biometric storage.
- **Fixability:** Guided (Tier 2)

### coppa-ad-022 — Behavioral Advertising to Children
- **Severity:** Critical
- **Detects:** Behavioral advertising SDKs, retargeting pixels, or interest-based ad configurations in child-directed content
- **Why it matters:** COPPA 2.0 explicitly prohibits behavioral and targeted advertising directed at children under 13.
- **Fix:** Remove behavioral advertising from child-directed sections. Use only contextual advertising if ads are necessary.
- **Fixability:** Guided (Tier 2)

### coppa-sec-023 — Inadequate Data Security Measures
- **Severity:** High
- **Detects:** Missing encryption, lack of access controls, or absent security headers for endpoints handling children's data
- **Why it matters:** COPPA 2.0 strengthens requirements for reasonable data security measures to protect children's personal information.
- **Fix:** Implement encryption in transit and at rest, enforce role-based access controls, and add security headers.
- **Fixability:** Guided (Tier 2)

### coppa-consent-024 — Missing Verifiable Parental Consent
- **Severity:** Critical
- **Detects:** Data collection flows for users under 13 without a verifiable parental consent mechanism
- **Why it matters:** COPPA requires verifiable parental consent before collecting, using, or disclosing personal information from children.
- **Fix:** Implement a verified consent flow (email-plus, credit card verification, or knowledge-based authentication) before collecting data.
- **Fixability:** Guided (Tier 2)

### coppa-retention-025 — Excessive Data Retention
- **Severity:** High
- **Detects:** Children's data stored beyond the purpose for which it was collected, or without documented retention schedules
- **Why it matters:** COPPA 2.0 tightens data minimization requirements, mandating deletion when data is no longer needed for its original purpose.
- **Fix:** Implement automated data lifecycle management with purpose-linked retention periods and scheduled deletion.
- **Fixability:** Guided (Tier 2)

### coppa-disclosure-026 — Insufficient Privacy Notice
- **Severity:** High
- **Detects:** Privacy policies or notices that lack required COPPA disclosures (data types collected, purposes, third-party sharing, parental rights)
- **Why it matters:** COPPA 2.0 requires clear, comprehensive, and accessible privacy notices specifically addressing children's data practices.
- **Fix:** Update privacy notices to include all required COPPA disclosures in clear, age-appropriate language.
- **Fixability:** Flag Only (Tier 3)

---

## Fixability Tiers

Each rule is classified into a remediation tier:

| Tier | Name | Description |
|:-----|:-----|:-----------|
| Tier 1 | **Auto** | Deterministic code transforms. Can be fixed automatically. |
| Tier 2 | **Guided** | Contextual scaffolds with developer customization. |
| Tier 3 | **Flag Only** | Detection + guidance docs. Requires design judgment. |
