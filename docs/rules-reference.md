# Rules Reference

Halo ships with over 100 rules across 9 regulatory packs covering COPPA 2.0, UK AADC, EU DSA, AU Online Safety Act, AU Safety by Design, Utah SB 142, California AADCA, ethical design, and AI-generated code audit.

## COPPA 2.0 Rules

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

---

## Ethical Design Rules

These rules detect design patterns that research associates with negative outcomes for children. They are reported as suggestions to guide ethical design decisions.

### ETHICAL-001 — Infinite Scroll Patterns
- **Severity:** Medium
- **Detects:** IntersectionObserver with auto-fetch, infinite scroll libraries, endless content loading
- **Why it matters:** Infinite scroll removes natural stopping points, leading to extended screen time in children.
- **Design alternatives:** Paginated content, "You've reached the end" messages, session time awareness prompts.
- **Fixability:** Flag Only (Tier 3)

### ETHICAL-002 — Streak Pressure Mechanics
- **Severity:** Medium
- **Detects:** Streak counters, consecutive-day tracking, loss aversion notifications, expiring rewards
- **Why it matters:** Streak mechanics create anxiety and compulsive usage patterns, particularly harmful for children ages 6-12.
- **Design alternatives:** Celebrate without penalty, progress gardens (growth without loss), parent-controlled engagement caps.
- **Fixability:** Flag Only (Tier 3)

### ETHICAL-003 — Variable Ratio Rewards
- **Severity:** High
- **Detects:** Math.random() in reward contexts, loot box mechanics, probability tables, gacha systems
- **Why it matters:** Variable ratio reinforcement is the most addictive reward schedule. It drives compulsive behavior in children.
- **Design alternatives:** Fixed reward schedules, transparent odds, non-randomized progression systems.
- **Fixability:** Flag Only (Tier 3)

### ETHICAL-004 — Manipulative Notification Patterns
- **Severity:** Medium
- **Detects:** Urgency language in notifications, FOMO messaging, social pressure notifications, high-frequency push
- **Why it matters:** Manipulative notifications exploit children's developing executive function and impulse control.
- **Design alternatives:** Calm notifications, parent-controlled frequency, content-focused (not urgency-focused) messaging.
- **Fixability:** Flag Only (Tier 3)

### ETHICAL-005 — Artificial Scarcity
- **Severity:** Medium
- **Detects:** Countdown timers in purchase contexts, fake stock indicators, "limited time" offers
- **Why it matters:** Artificial scarcity creates pressure to make impulsive decisions. Children are less equipped to evaluate urgency claims.
- **Design alternatives:** Honest availability information, no time pressure on purchase decisions, parent approval for transactions.
- **Fixability:** Flag Only (Tier 3)

---

## AI-Generated Code Audit Rules

These rules catch common COPPA risks introduced by AI coding assistants (Copilot, Cursor, ChatGPT). Enable with `--ai-audit`.

### AI-AUDIT-001 — Copilot-Generated Analytics Without Consent
- **Severity:** High
- **Detects:** AI-generated analytics code (Google Analytics, Mixpanel, Amplitude) without child-directed consent flags
- **Why it matters:** AI assistants frequently generate analytics integration code without COPPA-specific configuration parameters.
- **Fixability:** Guided (Tier 2)

### AI-AUDIT-002 — AI-Generated Social Auth Without Age Check
- **Severity:** Critical
- **Detects:** AI-scaffolded OAuth/social login flows missing age verification
- **Why it matters:** AI assistants generate complete auth flows that work correctly but omit COPPA age-gating requirements.
- **Fixability:** Guided (Tier 2)

### AI-AUDIT-003 — AI-Generated localStorage of PII
- **Severity:** High
- **Detects:** Personal data stored in localStorage/sessionStorage without encryption
- **Why it matters:** AI-generated code often persists user data client-side without considering data protection requirements.
- **Fixability:** Guided (Tier 2)

### AI-AUDIT-004 — AI-Generated Geolocation Without Consent
- **Severity:** Critical
- **Detects:** Geolocation API usage without consent flows in AI-generated code
- **Why it matters:** AI assistants generate location features without parental consent requirements for child-directed apps.
- **Fixability:** Guided (Tier 2)

### AI-AUDIT-005 — AI-Generated Push Notifications Without Opt-in
- **Severity:** Medium
- **Detects:** Push notification setup code without explicit opt-in flows
- **Why it matters:** AI-generated notification code typically enables push by default without COPPA-compliant consent.
- **Fixability:** Guided (Tier 2)

### AI-AUDIT-006 — AI-Generated File Upload Without Limits
- **Severity:** High
- **Detects:** File upload handlers without size or type restrictions
- **Why it matters:** Unrestricted file uploads in children's apps can expose the platform to inappropriate content and data risks.
- **Fixability:** Guided (Tier 2)

---

## Australia Safety by Design Rules

Based on the eSafety Commissioner's Safety by Design framework. Enable with `--sector-au-sbd`.

### AU-SBD-001 — Missing User Blocking/Muting
- **Severity:** High
- **Detects:** Social features without user blocking or muting capabilities
- **Why it matters:** Safety by Design requires users to control their interactions. Apps with social features must provide blocking/muting.
- **Fixability:** Guided (Tier 2)

### AU-SBD-002 — Missing Content Reporting
- **Severity:** High
- **Detects:** User-generated content features without reporting mechanisms
- **Why it matters:** Platforms must provide accessible mechanisms for users to report harmful content.
- **Fixability:** Guided (Tier 2)

### AU-SBD-003 — Unrestricted Direct Messaging for Minors
- **Severity:** Critical
- **Detects:** Direct messaging features without age-appropriate safety controls
- **Why it matters:** Unrestricted messaging between unknown users creates grooming and exploitation risks for minors.
- **Fixability:** Guided (Tier 2)

### AU-SBD-004 — Public User Profile by Default
- **Severity:** High
- **Detects:** User profiles that default to public visibility
- **Why it matters:** Safety by Design requires privacy-protective defaults. Child profiles should be private by default.
- **Fixability:** Auto (Tier 1)

### AU-SBD-005 — Missing Automated Content Moderation
- **Severity:** Medium
- **Detects:** Content submission flows without automated moderation or filtering
- **Why it matters:** Platforms hosting user content should implement automated safety checks to detect harmful material.
- **Fixability:** Guided (Tier 2)

### AU-SBD-006 — Missing Safety-by-Design Documentation
- **Severity:** Low
- **Detects:** Projects without safety documentation or policies
- **Why it matters:** The Safety by Design framework requires documented safety assessments and policies.
- **Fixability:** Flag Only (Tier 3)

---

## Australia Online Safety Act Rules

Based on the Online Safety Act 2021 (as amended 2024). Enable with `--sector-au-osa`. Penalties up to AUD $49.5M.

| ID | Rule | Severity |
|:---|:-----|:---------|
| `AU-OSA-001` | Missing age verification at registration | Critical |
| `AU-OSA-002` | Self-declaration age check | High |
| `AU-OSA-003` | Missing under-16 account purge | Critical |
| `AU-OSA-004` | Class 1/Class 2 content without moderation | Critical |
| `AU-OSA-005` | Content removal SLA non-compliance | High |
| `AU-OSA-006` | Minor data retention without TTL | High |
| `AU-OSA-007` | Missing safety impact assessment hook | Medium |
| `AU-OSA-008` | Missing transparency report generation | Medium |
| `AU-OSA-009` | Third-party SDK without safety vetting | High |
| `AU-OSA-010` | Missing complaint mechanism | High |
| `AU-OSA-011` | Cross-border minor data transfer | Critical |
| `AU-OSA-012` | Age-restricted content without re-authentication | High |

---

## UK Age Appropriate Design Code Rules

Based on the ICO Children's Code (AADC) — 15 standards for age-appropriate online services. Enable with `--pack uk-aadc`.

| ID | Rule | Severity |
|:---|:-----|:---------|
| `aadc-defaults-001` | Default privacy set to public | Critical |
| `aadc-defaults-002` | Opt-out tracking enabled by default | High |
| `aadc-minimisation-003` | Excessive personal data collection | High |
| `aadc-sharing-004` | Third-party data sharing without child safety check | Critical |
| `aadc-geolocation-005` | Geolocation enabled by default | Critical |
| `aadc-geolocation-006` | Continuous background location tracking | High |
| `aadc-profiling-007` | Profiling or algorithmic feed enabled by default | Critical |
| `aadc-profiling-008` | Behavioral data collection for recommendation engine | High |
| `aadc-nudge-009` | Pre-checked consent or privacy boxes | High |
| `aadc-nudge-010` | Confirmshaming or guilt-based privacy nudge | High |
| `aadc-nudge-011` | Privacy-weakening reward mechanism | High |
| `aadc-age-012` | Weak age gate using self-declaration only | High |
| `aadc-detrimental-013` | Targeted advertising to minors | Critical |
| `aadc-parental-014` | Covert child monitoring without notification | High |
| `aadc-tools-015` | User content without report or block mechanism | Medium |

---

## EU DSA Article 28 Rules

Based on the EU Digital Services Act Article 28 — online protection of minors on platforms. Enable with `--pack eu-dsa`.

| ID | Rule | Severity |
|:---|:-----|:---------|
| `dsa-ad-profiling-001` | Profiling-based ad targeting without minor exclusion | Critical |
| `dsa-autoplay-002` | Media autoplay without minor-conditional default | High |
| `dsa-infinite-scroll-003` | Infinite scroll without minor gating | High |
| `dsa-push-notify-004` | Push notification registration without minor checks | High |
| `dsa-streak-005` | Streak or engagement loop mechanics | High |
| `dsa-recommender-006` | Behavioral recommendation without non-profiled alternative | Critical |
| `dsa-cross-tracking-007` | Cross-platform tracking of minors | Critical |
| `dsa-ai-disclosure-008` | AI or chatbot interaction without disclosure | High |
| `dsa-ephemeral-009` | Ephemeral or disappearing content feature | Medium |
| `dsa-read-receipts-010` | Read receipts or typing indicators enabled by default | Medium |

---

## Utah SB 142 Rules

Utah's App Store Accountability Act — age assurance, parental consent, and minor protections. Enable with `--pack ut-sb142`.

| ID | Rule | Severity |
|:---|:-----|:---------|
| `ut-sb142-001` | Minor account creation without age assurance | Critical |
| `ut-sb142-002` | Missing parental consent for minor account | Critical |
| `ut-sb142-003` | Default DM access open for minors | High |
| `ut-sb142-004` | Missing parental supervisory tools | High |
| `ut-sb142-005` | Minor profile visible to search engines | Medium |

---

## Canada AADCA Rules

Canada's Age-Appropriate Design Code Act — privacy, profiling, dark patterns, and data minimization for minors. Enable with `--pack caadca`.

| ID | Rule | Severity |
|:---|:-----|:---------|
| `caadca-privacy-001` | Default tracking enabled | Critical |
| `caadca-privacy-002` | Analytics without privacy mode | High |
| `caadca-age-001` | Missing age estimation or verification | High |
| `caadca-profiling-001` | Behavioral profiling without safeguards | Critical |
| `caadca-profiling-002` | Content recommendation without age filter | High |
| `caadca-darkpat-001` | Manipulative consent UI | Critical |
| `caadca-darkpat-002` | Urgency-creating countdown timer | High |
| `caadca-darkpat-003` | Confirmshaming pattern | Medium |
| `caadca-geo-001` | Precise geolocation without purpose | Critical |
| `caadca-datamin-001` | Excessive data collection | High |
| `caadca-iap-001` | One-click purchase without confirmation | Critical |
| `caadca-iap-002` | In-app purchase without parental gate | Critical |
| `caadca-notify-001` | Push notifications without frequency limit | Medium |
| `caadca-transparency-001` | Missing child-friendly privacy notice | High |
| `caadca-ads-001` | Targeted advertising to children | Critical |

---

## Fixability Tiers

Each rule is classified into a remediation tier:

| Tier | Name | Description |
|:-----|:-----|:-----------|
| Tier 1 | **Auto** | Deterministic code transforms. Can be fixed automatically. |
| Tier 2 | **Guided** | Contextual scaffolds with developer customization. |
| Tier 3 | **Flag Only** | Detection + guidance docs. Requires design judgment. |
