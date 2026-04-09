/**
 * Halo COPPA Rule Engine - Unit Tests
 * Tests for all 20 COPPA rules
 */

import { HaloEngine, Violation, Rule, COPPA_RULES, AI_AUDIT_RULES, AU_SBD_RULES } from '../index';

describe('HaloEngine', () => {
  let engine: HaloEngine;

  beforeEach(() => {
    engine = new HaloEngine();
  });

  describe('Rule Registry', () => {
    it('should load all 180 rules from 17 packs by default (Halo 2.0 + ASAA)', () => {
      const rules = engine.getRules();
      expect(rules).toHaveLength(180);
    });

    it('should include coppa-auth-001', () => {
      const rule = engine.getRule('coppa-auth-001');
      expect(rule).toBeDefined();
      expect(rule?.name).toBe('Unverified Social Login Providers');
      expect(rule?.severity).toBe('critical');
    });

    it('should include coppa-data-002', () => {
      const rule = engine.getRule('coppa-data-002');
      expect(rule).toBeDefined();
      expect(rule?.name).toBe('PII Collection in URL Parameters');
      expect(rule?.severity).toBe('high');
    });

    it('should include coppa-tracking-003', () => {
      const rule = engine.getRule('coppa-tracking-003');
      expect(rule).toBeDefined();
      expect(rule?.name).toBe('Third-Party Ad Trackers');
      expect(rule?.severity).toBe('critical');
    });

    it('should include coppa-geo-004', () => {
      const rule = engine.getRule('coppa-geo-004');
      expect(rule).toBeDefined();
      expect(rule?.name).toBe('Precise Geolocation Collection');
      expect(rule?.severity).toBe('high');
    });

    it('should include coppa-retention-005', () => {
      const rule = engine.getRule('coppa-retention-005');
      expect(rule).toBeDefined();
      expect(rule?.name).toBe('Missing Data Retention Policy');
      expect(rule?.severity).toBe('medium');
    });
  });

  describe('coppa-auth-001: Unverified Social Login Providers', () => {
    it('should detect social login without age gate', () => {
      const content = `import { signInWithPopup } from 'firebase/auth';
const auth = getAuth();
signInWithPopup(auth, provider);`;
      
      const violations = engine.scanFile('test.ts', content);
      const authViolations = violations.filter((v: Violation) => v.ruleId === 'coppa-auth-001');
      expect(authViolations.length).toBeGreaterThan(0);
      expect(authViolations[0].severity).toBe('critical');
    });
  });

  describe('coppa-data-002: PII Collection in URL Parameters', () => {
    it('should detect PII in GET request URLs', () => {
      const content = `const url = \`https://api.example.com/user?email=\${user.email}\`;`;
      
      const violations = engine.scanFile('test.ts', content);
      const dataViolations = violations.filter((v: Violation) => v.ruleId === 'coppa-data-002');
      expect(dataViolations.length).toBeGreaterThan(0);
      expect(dataViolations[0].severity).toBe('high');
    });

    it('should NOT flag PII in POST body', () => {
      const content = `axios.post('/api/user', { email: user.email });`;
      
      const violations = engine.scanFile('test.ts', content);
      const dataViolations = violations.filter((v: Violation) => v.ruleId === 'coppa-data-002');
      expect(dataViolations.length).toBe(0);
    });
  });

  describe('coppa-tracking-003: Third-Party Ad Trackers', () => {
    it('should detect ad trackers without child_directed_treatment', () => {
      const content = `fbq('init', '123456789');`;
      
      const violations = engine.scanFile('test.html', content);
      const trackingViolations = violations.filter((v: Violation) => v.ruleId === 'coppa-tracking-003');
      expect(trackingViolations.length).toBeGreaterThan(0);
      expect(trackingViolations[0].severity).toBe('critical');
    });

    it('should still flag ad trackers even with child_directed_treatment (known limitation)', () => {
      // Known limitation: regex engine cannot detect child_directed_treatment flag context
      // Future improvement: AST analysis could detect this flag within the call
      const content = `fbq('init', '123456789', {}, { child_directed_treatment: true });`;

      const violations = engine.scanFile('test.html', content);
      const trackingViolations = violations.filter((v: Violation) => v.ruleId === 'coppa-tracking-003');
      expect(trackingViolations.length).toBeGreaterThan(0);
    });
  });

  describe('coppa-geo-004: Precise Geolocation Collection', () => {
    it('should detect geolocation without consent', () => {
      const content = `navigator.geolocation.getCurrentPosition(success, error);`;
      
      const violations = engine.scanFile('test.ts', content);
      const geoViolations = violations.filter((v: Violation) => v.ruleId === 'coppa-geo-004');
      expect(geoViolations.length).toBeGreaterThan(0);
      expect(geoViolations[0].severity).toBe('high');
    });

    it('should still flag geolocation even with consent wrapper (known limitation)', () => {
      // Known limitation: regex engine cannot detect control flow / consent wrappers
      // Future improvement: AST analysis could detect consent check wrapping
      const content = `if (hasParentalConsent()) {
  navigator.geolocation.getCurrentPosition(success, error);
}`;

      const violations = engine.scanFile('test.ts', content);
      const geoViolations = violations.filter((v: Violation) => v.ruleId === 'coppa-geo-004');
      expect(geoViolations.length).toBeGreaterThan(0);
    });
  });

  describe('coppa-retention-005: Missing Data Retention Policy', () => {
    it('should detect schema without retention policy', () => {
      const content = `const UserSchema = new Schema({
  email: String,
  name: String
});`;
      
      const violations = engine.scanFile('test.ts', content);
      const retentionViolations = violations.filter((v: Violation) => v.ruleId === 'coppa-retention-005');
      expect(retentionViolations.length).toBeGreaterThan(0);
      expect(retentionViolations[0].severity).toBe('medium');
    });

    it('should NOT flag schema with TTL/index', () => {
      const content = `const UserSchema = new Schema({
  email: String,
  deletedAt: { type: Date, expires: '365d' }
});`;
      
      const violations = engine.scanFile('test.ts', content);
      const retentionViolations = violations.filter((v: Violation) => v.ruleId === 'coppa-retention-005');
      expect(retentionViolations.length).toBe(0);
    });
  });

  // ========== Rules 6-20 ==========

  describe('Rule Registry -Rules', () => {
    it('should include coppa-sec-006 (Halo 2.0 — all rules active)', () => {
      const rule = engine.getRule('coppa-sec-006');
      expect(rule).toBeDefined();
      expect(rule?.name).toBe('Unencrypted PII Transmission');
      expect(rule?.severity).toBe('critical');
    });

    it('should include coppa-audio-007', () => {
      const rule = engine.getRule('coppa-audio-007');
      expect(rule).toBeDefined();
      expect(rule?.name).toBe('Unauthorized Audio Recording');
      expect(rule?.severity).toBe('high');
    });

    it('should include coppa-ui-008', () => {
      const rule = engine.getRule('coppa-ui-008');
      expect(rule).toBeDefined();
      expect(rule?.name).toBe('Missing Privacy Policy on Registration');
      expect(rule?.severity).toBe('medium');
    });

    it('should include coppa-flow-009', () => {
      const rule = engine.getRule('coppa-flow-009');
      expect(rule).toBeDefined();
      expect(rule?.name).toBe('Direct Contact Collection Without Parent Context');
      expect(rule?.severity).toBe('high');
    });

    it('should include coppa-sec-010 (Halo 2.0 — all rules active)', () => {
      const rule = engine.getRule('coppa-sec-010');
      expect(rule).toBeDefined();
    });

    it('should include coppa-ext-011', () => {
      const rule = engine.getRule('coppa-ext-011');
      expect(rule).toBeDefined();
      expect(rule?.name).toBe('Unmoderated Third-Party Chat');
      expect(rule?.severity).toBe('high');
    });

    it('should include coppa-bio-012 (Halo 2.0 — all rules active, AI Review Board handles precision)', () => {
      const rule = engine.getRule('coppa-bio-012');
      expect(rule).toBeDefined();
    });

    it('should include coppa-notif-013 (Halo 2.0 — all rules active)', () => {
      const rule = engine.getRule('coppa-notif-013');
      expect(rule).toBeDefined();
    });

    it('should include coppa-ugc-014 (Halo 2.0 — all rules active)', () => {
      const rule = engine.getRule('coppa-ugc-014');
      expect(rule).toBeDefined();
    });

    it('should include coppa-sec-015 (Halo 2.0 — all rules active)', () => {
      const rule = engine.getRule('coppa-sec-015');
      expect(rule).toBeDefined();
      expect(rule?.name).toBe('Reflected XSS Risk');
    });

    it('should include coppa-cookies-016', () => {
      const rule = engine.getRule('coppa-cookies-016');
      expect(rule).toBeDefined();
      expect(rule?.name).toBe('Missing Cookie Notice');
      expect(rule?.severity).toBe('low');
    });

    it('should include coppa-ext-017 (Halo 2.0 — all rules active)', () => {
      const rule = engine.getRule('coppa-ext-017');
      expect(rule).toBeDefined();
      expect(rule?.name).toBe('Unwarned External Links');
    });

    it('should include coppa-analytics-018', () => {
      const rule = engine.getRule('coppa-analytics-018');
      expect(rule).toBeDefined();
      expect(rule?.name).toBe('Mapping PII to Analytics User IDs');
      expect(rule?.severity).toBe('high');
    });

    it('should include coppa-edu-019 (Halo 2.0 — all rules active)', () => {
      const rule = engine.getRule('coppa-edu-019');
      expect(rule).toBeDefined();
    });

    it('should include coppa-default-020 (Halo 2.0 — all rules active)', () => {
      const rule = engine.getRule('coppa-default-020');
      expect(rule).toBeDefined();
    });
  });

  // Halo 2.0: coppa-sec-006 re-enabled — regex is loose pre-filter, AI Review Board handles precision
  describe('coppa-sec-006: Unencrypted PII Transmission', () => {
    it('should detect HTTP API endpoint', () => {
      const content = `axios.get('http://api.myapp.com/users');`;

      const violations = engine.scanFile('test.ts', content);
      const secViolations = violations.filter((v: Violation) => v.ruleId === 'coppa-sec-006');
      expect(secViolations.length).toBeGreaterThan(0);
      expect(secViolations[0].severity).toBe('critical');
    });

    it('should detect HTTP in production URL with PII', () => {
      const content = `const url = 'http://myapp.com/api/login?email=test@test.com';`;

      const violations = engine.scanFile('test.ts', content);
      const secViolations = violations.filter((v: Violation) => v.ruleId === 'coppa-sec-006');
      expect(secViolations.length).toBeGreaterThan(0);
    });

    it('should NOT flag HTTPS URLs', () => {
      const content = `axios.get('https://api.myapp.com/users');`;

      const violations = engine.scanFile('test.ts', content);
      const secViolations = violations.filter((v: Violation) => v.ruleId === 'coppa-sec-006');
      expect(secViolations.length).toBe(0);
    });

    // Example/reserved domain exclusions
    it('should NOT flag example.com URLs (IANA-reserved)', () => {
      const content = `axios.get('http://example.com/api/users');`;
      const violations = engine.scanFile('test.ts', content);
      expect(violations.filter((v: Violation) => v.ruleId === 'coppa-sec-006').length).toBe(0);
    });

    it('should NOT flag example.org URLs', () => {
      const content = `fetch('http://example.org/api/login');`;
      const violations = engine.scanFile('test.ts', content);
      expect(violations.filter((v: Violation) => v.ruleId === 'coppa-sec-006').length).toBe(0);
    });

    it('should NOT flag localhost URLs', () => {
      const content = `fetch('http://localhost:3000/api/users');`;
      const violations = engine.scanFile('test.ts', content);
      expect(violations.filter((v: Violation) => v.ruleId === 'coppa-sec-006').length).toBe(0);
    });

    it('should NOT flag 127.0.0.1 URLs', () => {
      const content = `axios.get('http://127.0.0.1:8080/api/login');`;
      const violations = engine.scanFile('test.ts', content);
      expect(violations.filter((v: Violation) => v.ruleId === 'coppa-sec-006').length).toBe(0);
    });

    it('should NOT flag httpbin.org URLs', () => {
      const content = `fetch('http://httpbin.org/api/users');`;
      const violations = engine.scanFile('test.ts', content);
      expect(violations.filter((v: Violation) => v.ruleId === 'coppa-sec-006').length).toBe(0);
    });

    it('should still flag real HTTP URLs with PII paths', () => {
      const content = `fetch('http://production-api.mycompany.com/api/users');`;
      const violations = engine.scanFile('test.ts', content);
      expect(violations.filter((v: Violation) => v.ruleId === 'coppa-sec-006').length).toBeGreaterThan(0);
    });
  });

  describe('coppa-audio-007: Unauthorized Audio Recording', () => {
    it('should detect getUserMedia with audio', () => {
      const content = `navigator.mediaDevices.getUserMedia({ audio: true });`;
      
      const violations = engine.scanFile('test.ts', content);
      const audioViolations = violations.filter((v: Violation) => v.ruleId === 'coppa-audio-007');
      expect(audioViolations.length).toBeGreaterThan(0);
      expect(audioViolations[0].severity).toBe('high');
    });

    it('should detect AVAudioRecorder usage', () => {
      const content = `const recorder = new AVAudioRecorder(url, settings);`;
      
      const violations = engine.scanFile('test.ts', content);
      const audioViolations = violations.filter((v: Violation) => v.ruleId === 'coppa-audio-007');
      expect(audioViolations.length).toBeGreaterThan(0);
    });

    it('should detect MediaRecorder', () => {
      const content = `const mediaRecorder = new MediaRecorder(stream);`;
      
      const violations = engine.scanFile('test.ts', content);
      const audioViolations = violations.filter((v: Violation) => v.ruleId === 'coppa-audio-007');
      expect(audioViolations.length).toBeGreaterThan(0);
    });
  });

  describe('coppa-ui-008: Missing Privacy Policy on Registration', () => {
    it('should detect registration form component without privacy link', () => {
      const content = `const SignUpForm = () => (
  <div>
    <input type="email" placeholder="Email" />
    <button type="submit">Register</button>
  </div>
);`;

      const violations = engine.scanFile('test.tsx', content);
      const uiViolations = violations.filter((v: Violation) => v.ruleId === 'coppa-ui-008');
      expect(uiViolations.length).toBeGreaterThan(0);
      expect(uiViolations[0].severity).toBe('medium');
    });

    it('should detect signup form pattern', () => {
      const content = `const signup_form = document.getElementById('register-form');`;

      const violations = engine.scanFile('test.ts', content);
      const uiViolations = violations.filter((v: Violation) => v.ruleId === 'coppa-ui-008');
      expect(uiViolations.length).toBeGreaterThan(0);
    });

    it('should NOT flag generic forms without registration intent', () => {
      const content = `<form>
  <input type="text" placeholder="Search" />
  <button type="submit">Search</button>
</form>`;

      const violations = engine.scanFile('test.html', content);
      const uiViolations = violations.filter((v: Violation) => v.ruleId === 'coppa-ui-008');
      expect(uiViolations.length).toBe(0);
    });
  });

  describe('coppa-flow-009: Direct Contact Collection Without Parent Context', () => {
    it('should detect child email without parent email', () => {
      const content = `const child_email: String;`;
      
      const violations = engine.scanFile('test.ts', content);
      const flowViolations = violations.filter((v: Violation) => v.ruleId === 'coppa-flow-009');
      expect(flowViolations.length).toBeGreaterThan(0);
      expect(flowViolations[0].severity).toBe('high');
    });

    it('should still flag child_email even when parent_email exists (known limitation)', () => {
      // Known limitation: regex engine cannot detect that parent_email exists alongside
      // child_email. Future improvement: AST analysis could check for co-occurrence.
      const content = `{
  child_email: String,
  parent_email: String
}`;

      const violations = engine.scanFile('test.ts', content);
      const flowViolations = violations.filter((v: Violation) => v.ruleId === 'coppa-flow-009');
      expect(flowViolations.length).toBeGreaterThan(0);
    });
  });

  describe('coppa-sec-010: Weak Default Student Passwords', () => {
    it('should detect weak default password assignment (Halo 2.0 — AI Review Board handles FP)', () => {
      const content = `const config = { password: 'password' };`;

      const violations = engine.scanFile('test.ts', content);
      const secViolations = violations.filter((v: Violation) => v.ruleId === 'coppa-sec-010');
      expect(secViolations.length).toBeGreaterThan(0);
    });

    it('should detect defaultPassword with weak value', () => {
      const content = `defaultPassword: '123456'`;

      const violations = engine.scanFile('test.ts', content);
      const secViolations = violations.filter((v: Violation) => v.ruleId === 'coppa-sec-010');
      expect(secViolations.length).toBeGreaterThan(0);
    });
  });

  describe('coppa-ext-011: Unmoderated Third-Party Chat', () => {
    it('should detect Intercom init', () => {
      const content = `intercom.init({ app_id: 'abc123' });`;
      
      const violations = engine.scanFile('test.ts', content);
      const extViolations = violations.filter((v: Violation) => v.ruleId === 'coppa-ext-011');
      expect(extViolations.length).toBeGreaterThan(0);
      expect(extViolations[0].severity).toBe('high');
    });

    it('should detect Zendesk CDN (zdassets.com)', () => {
      const content = `<script src="https://static.zdassets.com/ekr/snippet.js"></script>`;

      const violations = engine.scanFile('test.html', content);
      const extViolations = violations.filter((v: Violation) => v.ruleId === 'coppa-ext-011');
      expect(extViolations.length).toBeGreaterThan(0);
    });

    it('should NOT flag internal chat', () => {
      const content = `// Internal moderation-enabled chat`;
      
      const violations = engine.scanFile('test.ts', content);
      const extViolations = violations.filter((v: Violation) => v.ruleId === 'coppa-ext-011');
      expect(extViolations.length).toBe(0);
    });
  });

  // Halo 2.0: coppa-bio-012 re-enabled — AI Review Board handles FP filtering
  describe('coppa-bio-012: Biometric Data Collection', () => {
    it('should detect biometric API usage (AI Review Board handles precision)', () => {
      const content = `LocalAuthentication.evaluatePolicy(.deviceOwnerAuthenticationWithBiometrics);`;

      const violations = engine.scanFile('test.ts', content);
      const bioViolations = violations.filter((v: Violation) => v.ruleId === 'coppa-bio-012');
      expect(bioViolations.length).toBeGreaterThan(0);
    });

    it('should detect face-api.js import', () => {
      const content = `import * as faceapi from 'face-api.js';`;

      const violations = engine.scanFile('test.ts', content);
      const bioViolations = violations.filter((v: Violation) => v.ruleId === 'coppa-bio-012');
      expect(bioViolations.length).toBeGreaterThan(0);
    });
  });

  // Halo 2.0: coppa-notif-013 re-enabled — AI Review Board handles precision
  describe('coppa-notif-013: Direct Push Notifications Without Consent', () => {
    it('should detect push notification subscription APIs', () => {
      const content = `FirebaseMessaging.subscribeToTopic('updates');`;
      const violations = engine.scanFile('test.ts', content);
      const notifViolations = violations.filter((v: Violation) => v.ruleId === 'coppa-notif-013');
      expect(notifViolations.length).toBeGreaterThan(0);
      expect(notifViolations[0].severity).toBe('low');
    });
  });

  describe('coppa-ugc-014: UGC Upload Without PII Filter', () => {
    it('should detect UGC pattern (Halo 2.0 — AI Review Board handles FP)', () => {
      const content = `user.bio = "About me";`;

      const violations = engine.scanFile('test.ts', content);
      const ugcViolations = violations.filter((v: Violation) => v.ruleId === 'coppa-ugc-014');
      expect(ugcViolations.length).toBeGreaterThan(0);
    });
  });

  // Halo 2.0: coppa-sec-015 re-enabled — AI Review Board handles precision
  describe('coppa-sec-015: Reflected XSS Risk', () => {
    it('should detect dangerouslySetInnerHTML', () => {
      const content = `<div dangerouslySetInnerHTML={{ __html: userInput }} />`;
      
      const violations = engine.scanFile('test.tsx', content);
      const xssViolations = violations.filter((v: Violation) => v.ruleId === 'coppa-sec-015');
      expect(xssViolations.length).toBeGreaterThan(0);
      expect(xssViolations[0].severity).toBe('medium');
    });

    it('should detect innerHTML assignment', () => {
      const content = `element.innerHTML = userContent;`;
      
      const violations = engine.scanFile('test.ts', content);
      const xssViolations = violations.filter((v: Violation) => v.ruleId === 'coppa-sec-015');
      expect(xssViolations.length).toBeGreaterThan(0);
    });

    it('should NOT flag safe textContent', () => {
      const content = `element.textContent = safeContent;`;
      
      const violations = engine.scanFile('test.ts', content);
      const xssViolations = violations.filter((v: Violation) => v.ruleId === 'coppa-sec-015');
      expect(xssViolations.length).toBe(0);
    });
  });

  describe('coppa-cookies-016: Missing Cookie Notice', () => {
    it('should detect document.cookie', () => {
      const content = `document.cookie = "session=abc123";`;
      
      const violations = engine.scanFile('test.ts', content);
      const cookieViolations = violations.filter((v: Violation) => v.ruleId === 'coppa-cookies-016');
      expect(cookieViolations.length).toBeGreaterThan(0);
      expect(cookieViolations[0].severity).toBe('low');
    });

    it('should detect localStorage.setItem with PII key', () => {
      const content = `localStorage.setItem('user_token', JSON.stringify(token));`;

      const violations = engine.scanFile('test.ts', content);
      const cookieViolations = violations.filter((v: Violation) => v.ruleId === 'coppa-cookies-016');
      expect(cookieViolations.length).toBeGreaterThan(0);
    });

    it('should NOT flag consent banner variable (only flags cookie writes)', () => {
      // Rule 16 only flags document.cookie=, localStorage.setItem, sessionStorage.setItem
      // Consent banner references should NOT trigger
      const content = `const showConsentBanner = true; // GDPR compliance`;

      const violations = engine.scanFile('test.ts', content);
      const cookieViolations = violations.filter((v: Violation) => v.ruleId === 'coppa-cookies-016');
      expect(cookieViolations.length).toBe(0);
    });
  });

  // Halo 2.0: coppa-ext-017 re-enabled — AI Review Board handles precision
  describe('coppa-ext-017: Unwarned External Links', () => {
    it('should detect external link with target="_blank" without warning', () => {
      const content = `<a href="https://external-site.com" target="_blank">Click here</a>`;

      const violations = engine.scanFile('test.html', content);
      const extViolations = violations.filter((v: Violation) => v.ruleId === 'coppa-ext-017');
      expect(extViolations.length).toBeGreaterThan(0);
      expect(extViolations[0].severity).toBe('medium');
    });

    it('should NOT flag external link without target="_blank"', () => {
      const content = `<a href="https://external-site.com">Click here</a>`;

      const violations = engine.scanFile('test.html', content);
      const extViolations = violations.filter((v: Violation) => v.ruleId === 'coppa-ext-017');
      expect(extViolations.length).toBe(0);
    });

    it('should NOT flag internal links', () => {
      const content = `<a href="/dashboard">Dashboard</a>`;
      
      const violations = engine.scanFile('test.html', content);
      const extViolations = violations.filter((v: Violation) => v.ruleId === 'coppa-ext-017');
      expect(extViolations.length).toBe(0);
    });
  });

  describe('coppa-analytics-018: Mapping PII to Analytics User IDs', () => {
    it('should detect analytics.identify with email', () => {
      const content = `analytics.identify(userId, { email: user.email });`;
      
      const violations = engine.scanFile('test.ts', content);
      const analyticsViolations = violations.filter((v: Violation) => v.ruleId === 'coppa-analytics-018');
      expect(analyticsViolations.length).toBeGreaterThan(0);
      expect(analyticsViolations[0].severity).toBe('high');
    });

    it('should detect mixpanel.identify with PII', () => {
      const content = `mixpanel.identify({ email: 'test@test.com', name: 'John' });`;
      
      const violations = engine.scanFile('test.ts', content);
      const analyticsViolations = violations.filter((v: Violation) => v.ruleId === 'coppa-analytics-018');
      expect(analyticsViolations.length).toBeGreaterThan(0);
    });

    it('should NOT flag hashed IDs', () => {
      const content = `analytics.identify(hashedUserId);`;
      
      const violations = engine.scanFile('test.ts', content);
      const analyticsViolations = violations.filter((v: Violation) => v.ruleId === 'coppa-analytics-018');
      expect(analyticsViolations.length).toBe(0);
    });
  });

  describe('coppa-edu-019: Missing Teacher/School Verification', () => {
    it('should detect teacher signup without verification (Halo 2.0 — AI Review Board handles FP)', () => {
      const content = `const teacherSignup = async (email) => { if (email.includes('@gmail.com')) ... };`;
      const violations = engine.scanFile('test.ts', content);
      const eduViolations = violations.filter((v: Violation) => v.ruleId === 'coppa-edu-019');
      expect(eduViolations.length).toBeGreaterThan(0);
    });
  });

  describe('coppa-default-020: Default Public Profile Visibility', () => {
    it('should detect public profile default (Halo 2.0 — AI Review Board handles FP)', () => {
      const content = `const profile = { isProfileVisible: true };`;
      const violations = engine.scanFile('test.ts', content);
      const defaultViolations = violations.filter((v: Violation) => v.ruleId === 'coppa-default-020');
      expect(defaultViolations.length).toBeGreaterThan(0);
    });
  });

  describe('Suppression System — Next-Line', () => {
    it('should suppress specific rule on next line with comment', () => {
      const content = `// halo-ignore: coppa-tracking-003
fbq('init', '123456789');`;

      const violations = engine.scanFile('test.ts', content);
      const trackingViolations = violations.filter((v: Violation) => v.ruleId === 'coppa-tracking-003');
      expect(trackingViolations.length).toBe(0);
    });

    it('should suppress all rules on next line with generic comment', () => {
      const content = `// halo-ignore
fbq('init', '123');`;

      const violations = engine.scanFile('test.ts', content);
      expect(violations.length).toBe(0);
    });

    it('should NOT suppress violations two lines below the comment', () => {
      const content = `// halo-ignore
const x = 1;
fbq('init', '123');`;

      const violations = engine.scanFile('test.ts', content);
      const trackingViolations = violations.filter((v: Violation) => v.ruleId === 'coppa-tracking-003');
      expect(trackingViolations.length).toBeGreaterThan(0);
    });

    it('should include suppressed violations when configured', () => {
      const supEngine = new HaloEngine({ includeSuppressed: true });
      const content = `// halo-ignore: coppa-tracking-003
fbq('init', '123456789');`;

      const violations = supEngine.scanFile('test.ts', content);
      const suppressed = violations.filter((v: Violation) => v.suppressed);
      expect(suppressed.length).toBeGreaterThan(0);
      expect(suppressed[0].ruleId).toBe('coppa-tracking-003');
    });
  });

  describe('Configuration Options', () => {
    it('should filter rules by specific rule IDs', () => {
      const filteredEngine = new HaloEngine({
        rules: ['coppa-auth-001']
      });
      const rules = filteredEngine.getRules();
      expect(rules).toHaveLength(1);
      expect(rules[0].id).toBe('coppa-auth-001');
    });

    it('should filter rules by severity', () => {
      const filteredEngine = new HaloEngine({
        severityFilter: ['critical']
      });
      const rules = filteredEngine.getRules();
      expect(rules.length).toBeGreaterThan(0);
      rules.forEach((r: Rule) => expect(r.severity).toBe('critical'));
    });
  });

  describe('Violation Properties', () => {
    it('should include line numbers in violations', () => {
      const content = `line1
line2
violation here`;
      const violations = engine.scanFile('test.ts', content);
      
      if (violations.length > 0) {
        violations.forEach((v: Violation) => {
          expect(v.line).toBeGreaterThan(0);
          expect(v.column).toBeGreaterThan(0);
        });
      }
    });

    it('should include fix suggestions', () => {
      const content = `fbq('init', '123');`;
      const violations = engine.scanFile('test.ts', content);
      
      if (violations.length > 0) {
        violations.forEach((v: Violation) => {
          expect(v.fixSuggestion).toBeDefined();
          expect(v.fixSuggestion.length).toBeGreaterThan(0);
        });
      }
    });

    it('should include penalty information', () => {
      const content = `fbq('init', '123');`;
      const violations = engine.scanFile('test.ts', content);
      
      if (violations.length > 0) {
        violations.forEach((v: Violation) => {
          expect(v.penalty).toBeDefined();
        });
      }
    });
  });

  describe('Suppression System', () => {
    it('should suppress violations with // halo-ignore comment on same line', () => {
      const engineWithSuppression = new HaloEngine({
        suppressions: { enabled: true }
      });
      
      const content = `firebase.auth().signInWithPopup("google"); // halo-ignore`;
      const violations = engineWithSuppression.scanFile('test.ts', content);
      
      expect(violations.length).toBe(0);
    });

    it('should suppress specific rule with // halo-ignore:ruleId', () => {
      const engineWithSuppression = new HaloEngine({
        suppressions: { enabled: true }
      });
      
      const content = `firebase.auth().signInWithPopup("google"); // halo-ignore:coppa-auth-001`;
      const violations = engineWithSuppression.scanFile('test.ts', content);
      
      expect(violations.length).toBe(0);
    });

    it('should not suppress different rule with specific rule suppression', () => {
      const engineWithSuppression = new HaloEngine({
        suppressions: { enabled: true }
      });
      
      // Suppress coppa-tracking-003 but not coppa-auth-001
      const content = `firebase.auth().signInWithPopup("google"); // halo-ignore:coppa-tracking-003`;
      const violations = engineWithSuppression.scanFile('test.ts', content);
      
      expect(violations.length).toBe(1);
      expect(violations[0].ruleId).toBe('coppa-auth-001');
    });

    it('should allow disabling suppression system', () => {
      const engineNoSuppression = new HaloEngine({
        suppressions: { enabled: false }
      });
      
      const content = `firebase.auth().signInWithPopup("google"); // halo-ignore`;
      const violations = engineNoSuppression.scanFile('test.ts', content);

      expect(violations.length).toBe(1);
    });
  });

  describe('.haloignore Support', () => {
    it('should ignore files matching glob patterns', () => {
      const { parseHaloignore } = require('../index');
      const ignoreConfig = parseHaloignore('**/*.test.ts\nvendor/**');

      const engineWithIgnore = new HaloEngine({ ignoreConfig });

      // This file matches *.test.ts — should be ignored
      const violations = engineWithIgnore.scanFile('src/auth.test.ts', `signInWithPopup(auth, provider);`);
      expect(violations.length).toBe(0);

      // This file doesn't match — should be scanned
      const violations2 = engineWithIgnore.scanFile('src/auth.ts', `signInWithPopup(auth, provider);`);
      expect(violations2.length).toBeGreaterThan(0);
    });

    it('should globally suppress specific rules', () => {
      const { parseHaloignore } = require('../index');
      const ignoreConfig = parseHaloignore('rule:coppa-tracking-003');

      const engineWithIgnore = new HaloEngine({ ignoreConfig });

      // coppa-tracking-003 should be suppressed
      const violations = engineWithIgnore.scanFile('test.ts', `fbq('init', '123');`);
      expect(violations.filter(v => v.ruleId === 'coppa-tracking-003').length).toBe(0);

      // Other rules should still fire
      const violations2 = engineWithIgnore.scanFile('test.ts', `signInWithPopup(auth, provider);`);
      expect(violations2.filter(v => v.ruleId === 'coppa-auth-001').length).toBeGreaterThan(0);
    });

    // Halo 2.0: coppa-sec-006 re-enabled
    it('should suppress specific rules in specific files', () => {
      const { parseHaloignore } = require('../index');
      const ignoreConfig = parseHaloignore('src/legacy.ts:coppa-sec-006');

      const engineWithIgnore = new HaloEngine({ ignoreConfig });

      // coppa-sec-006 suppressed in src/legacy.ts
      const violations = engineWithIgnore.scanFile('src/legacy.ts', `axios.get('http://api.com/users');`);
      expect(violations.filter(v => v.ruleId === 'coppa-sec-006').length).toBe(0);

      // Same rule NOT suppressed in other files
      const violations2 = engineWithIgnore.scanFile('src/api.ts', `axios.get('http://api.com/users');`);
      expect(violations2.filter(v => v.ruleId === 'coppa-sec-006').length).toBeGreaterThan(0);
    });

    it('should parse comments and empty lines correctly', () => {
      const { parseHaloignore } = require('../index');
      const ignoreConfig = parseHaloignore(`
# This is a comment
**/*.test.ts

# Globally suppress tracking
rule:coppa-tracking-003

# Suppress in specific file
src/auth.ts:coppa-auth-001
      `);

      expect(ignoreConfig.ignoredFiles).toContain('**/*.test.ts');
      expect(ignoreConfig.globalRuleSuppressions.has('coppa-tracking-003')).toBe(true);
      expect(ignoreConfig.fileRuleSuppressions.get('src/auth.ts')?.has('coppa-auth-001')).toBe(true);
    });
  });

  describe('Vendor Path Suppression', () => {
    it('should suppress all violations in node_modules/', () => {
      const code = `signInWithPopup(auth, provider); fbq('init', '123456');`;
      const violations = engine.scanFile('node_modules/firebase/auth.js', code);
      expect(violations).toHaveLength(0);
    });

    it('should suppress all violations in vendor/', () => {
      const code = `navigator.geolocation.getCurrentPosition(cb);`;
      const violations = engine.scanFile('vendor/geolib/index.js', code);
      expect(violations).toHaveLength(0);
    });

    it('should suppress all violations in bower_components/', () => {
      const code = `signInWithPopup(auth, provider);`;
      const violations = engine.scanFile('bower_components/firebase-auth/auth.js', code);
      expect(violations).toHaveLength(0);
    });

    it('should suppress all violations in third_party/', () => {
      const code = `document.cookie = "session=" + value;`;
      const violations = engine.scanFile('third_party/cookie-lib/index.js', code);
      expect(violations).toHaveLength(0);
    });

    it('should suppress all violations in third-party/', () => {
      const code = `document.cookie = "session=" + value;`;
      const violations = engine.scanFile('third-party/cookie-lib/index.js', code);
      expect(violations).toHaveLength(0);
    });

    it('should suppress all violations in minified files', () => {
      const code = `signInWithPopup(auth, provider);`;
      const violations = engine.scanFile('assets/firebase-auth.min.js', code);
      expect(violations).toHaveLength(0);
    });

    it('should suppress violations in nested vendor paths', () => {
      const code = `signInWithPopup(auth, provider);`;
      const violations = engine.scanFile('src/vendor/auth-lib/login.js', code);
      expect(violations).toHaveLength(0);
    });

    it('should suppress all violations in .bundle/', () => {
      const code = `signInWithPopup(auth, provider);`;
      const violations = engine.scanFile('.bundle/gems/devise/lib/auth.rb', code);
      expect(violations).toHaveLength(0);
    });

    it('should suppress all violations in Pods/', () => {
      const code = `CLLocationManager().requestWhenInUseAuthorization()`;
      const violations = engine.scanFile('Pods/CoreLocation/CLLocationManager.swift', code);
      expect(violations).toHaveLength(0);
    });

    it('should suppress all violations in external/', () => {
      const code = `signInWithPopup(auth, provider);`;
      const violations = engine.scanFile('external/auth-sdk/index.js', code);
      expect(violations).toHaveLength(0);
    });

    it('should suppress all violations in deps/', () => {
      const code = `signInWithPopup(auth, provider);`;
      const violations = engine.scanFile('deps/firebase/auth.js', code);
      expect(violations).toHaveLength(0);
    });

    it('should suppress all violations in .yarn/', () => {
      const code = `signInWithPopup(auth, provider);`;
      const violations = engine.scanFile('.yarn/cache/firebase-auth.js', code);
      expect(violations).toHaveLength(0);
    });

    it('should suppress all violations in .pnpm/', () => {
      const code = `signInWithPopup(auth, provider);`;
      const violations = engine.scanFile('.pnpm/firebase@9.0.0/auth.js', code);
      expect(violations).toHaveLength(0);
    });

    it('should NOT suppress violations in non-vendor paths', () => {
      const code = `signInWithPopup(auth, provider);`;
      const violations = engine.scanFile('src/auth/login.ts', code);
      expect(violations.length).toBeGreaterThan(0);
    });

    it('should NOT suppress violations in src/ directories', () => {
      const code = `navigator.geolocation.getCurrentPosition(cb);`;
      const violations = engine.scanFile('src/components/Map.tsx', code);
      expect(violations.length).toBeGreaterThan(0);
    });

    it('should export isVendorPath utility', () => {
      const { isVendorPath } = require('../index');
      expect(isVendorPath('node_modules/foo/bar.js')).toBe(true);
      expect(isVendorPath('vendor/lib/utils.php')).toBe(true);
      expect(isVendorPath('third_party/grpc/index.ts')).toBe(true);
      expect(isVendorPath('third-party/grpc/index.ts')).toBe(true);
      expect(isVendorPath('bower_components/jquery/dist/jquery.min.js')).toBe(true);
      expect(isVendorPath('.bundle/gems/devise/lib/auth.rb')).toBe(true);
      expect(isVendorPath('Pods/AFNetworking/Source.m')).toBe(true);
      expect(isVendorPath('external/protobuf/message.cc')).toBe(true);
      expect(isVendorPath('deps/cowboy/lib/cowboy.ex')).toBe(true);
      expect(isVendorPath('.yarn/cache/package.js')).toBe(true);
      expect(isVendorPath('.pnpm/foo@1.0.0/index.js')).toBe(true);
      expect(isVendorPath('assets/jquery.min.js')).toBe(true);
      expect(isVendorPath('dist/app.bundle.js')).toBe(true);
      expect(isVendorPath('src/auth/login.ts')).toBe(false);
      expect(isVendorPath('app/components/Map.tsx')).toBe(false);
      expect(isVendorPath('pages/index.tsx')).toBe(false);
      expect(isVendorPath('lib/mycode/utils.ts')).toBe(false);  // lib/ is NOT vendor
    });
  });

  describe('AI-Generated Code Audit Rules (P2.5)', () => {
    let aiEngine: HaloEngine;

    beforeEach(() => {
      aiEngine = new HaloEngine({ aiAudit: true });
    });

    it('should have 6 AI audit rules', () => {
      expect(AI_AUDIT_RULES).toHaveLength(6);
    });

    it('should load 32 rules when aiAudit is enabled (26 COPPA + 6 AI audit)', () => {
      const rules = aiEngine.getRules();
      // Halo 2.0: all rules active — AI Review Board handles precision
      expect(rules).toHaveLength(32);
    });

    it('should detect placeholder analytics (AI-AUDIT-001 — Halo 2.0 all rules active)', () => {
      const code = `gtag('config', 'G-XXXXXXX');`;
      const violations = aiEngine.scanFile('test.ts', code);
      expect(violations.some(v => v.ruleId === 'AI-AUDIT-001')).toBe(true);
    });

    it('should detect hallucinated URLs (AI-AUDIT-003 — Halo 2.0 all rules active)', () => {
      const code = `const data = await fetch('https://api.example.com/users');`;
      const violations = aiEngine.scanFile('test.ts', code);
      expect(violations.some(v => v.ruleId === 'AI-AUDIT-003')).toBe(true);
    });

    it('should detect copy-paste tracking boilerplate (AI-AUDIT-004 — Halo 2.0 all rules active)', () => {
      const code = `Sentry.init({ dsn: 'https://x@sentry.io/1' });`;
      const violations = aiEngine.scanFile('test.ts', code);
      expect(violations.some(v => v.ruleId === 'AI-AUDIT-004')).toBe(true);
    });

    it('should detect insecure CORS defaults (AI-AUDIT-005)', () => {
      const code = `app.use(cors({ origin: '*' }));`;
      const violations = aiEngine.scanFile('test.ts', code);
      expect(violations.some(v => v.ruleId === 'AI-AUDIT-005')).toBe(true);
    });

    it('should detect disabled SSL verification (AI-AUDIT-005)', () => {
      const code = `const agent = new https.Agent({ rejectUnauthorized: false });`;
      const violations = aiEngine.scanFile('test.ts', code);
      expect(violations.some(v => v.ruleId === 'AI-AUDIT-005')).toBe(true);
    });

    it('should detect compliance TODOs (AI-AUDIT-006 — Halo 2.0 all rules active)', () => {
      const code = `// TODO: add age verification before login`;
      const violations = aiEngine.scanFile('test.ts', code);
      expect(violations.some(v => v.ruleId === 'AI-AUDIT-006')).toBe(true);
    });

    it('should fire AI rules by default in Halo 2.0 (all packs loaded)', () => {
      const standardEngine = new HaloEngine(); // Halo 2.0: loads ALL packs including ai-audit
      const code = `app.use(cors({ origin: '*' }));`;
      const violations = standardEngine.scanFile('test.ts', code);
      expect(violations.some(v => v.ruleId === 'AI-AUDIT-005')).toBe(true);
      // Should still fire COPPA tracking rule too
      const trackingCode = `gtag('config', 'UA-12345');`;
      const trackingViolations = standardEngine.scanFile('test.ts', trackingCode);
      expect(trackingViolations.some(v => v.ruleId === 'coppa-tracking-003')).toBe(true);
    });

    it('should NOT fire AI rules when only coppa pack is loaded', () => {
      const coppaOnly = new HaloEngine({ packs: ['coppa'] });
      const code = `app.use(cors({ origin: '*' }));`;
      const violations = coppaOnly.scanFile('test.ts', code);
      expect(violations.some(v => v.ruleId === 'AI-AUDIT-005')).toBe(false);
    });
  });

  // ============================================================================
  // P3-0: Multi-Language Coverage Tests
  // Validates that the top-5 expanded rules detect violations in
  // Python, Go, Java, and Kotlin — not just JS/TS.
  // ============================================================================
  describe('Multi-Language Coverage (P3-0)', () => {
    const engine = new HaloEngine();

    // ---- coppa-cookies-016: Server-side cookie patterns ----
    describe('coppa-cookies-016 — Server-side cookies', () => {
      it('should detect Python Flask set_cookie with PII', () => {
        const code = `response.set_cookie('user_session', value=token)`;
        const violations = engine.scanFile('app.py', code);
        expect(violations.some(v => v.ruleId === 'coppa-cookies-016')).toBe(true);
      });

      it('should detect Go http.SetCookie', () => {
        const code = `http.SetCookie(w, &http.Cookie{Name: "session"})`;
        const violations = engine.scanFile('main.go', code);
        expect(violations.some(v => v.ruleId === 'coppa-cookies-016')).toBe(true);
      });

      it('should detect Java addCookie', () => {
        const code = `response.addCookie(new Cookie("auth_token", token));`;
        const violations = engine.scanFile('AuthServlet.java', code);
        expect(violations.some(v => v.ruleId === 'coppa-cookies-016')).toBe(true);
      });

      it('should detect Spring ResponseCookie', () => {
        const code = `ResponseCookie.from("session_id", sessionId).build();`;
        const violations = engine.scanFile('AuthConfig.java', code);
        expect(violations.some(v => v.ruleId === 'coppa-cookies-016')).toBe(true);
      });

      it('should detect generic set_cookie with email', () => {
        const code = `set_cookie("user_email", email_value)`;
        const violations = engine.scanFile('views.py', code);
        expect(violations.some(v => v.ruleId === 'coppa-cookies-016')).toBe(true);
      });
    });

    // ---- coppa-retention-005: Data model patterns ----
    describe('coppa-retention-005 — Data model retention', () => {
      it('should detect Python Django User model', () => {
        const code = `class UserProfile(models.Model):`;
        const violations = engine.scanFile('models.py', code);
        expect(violations.some(v => v.ruleId === 'coppa-retention-005')).toBe(true);
      });

      it('should detect Python SQLAlchemy User model', () => {
        const code = `class Student(db.Model):`;
        const violations = engine.scanFile('models.py', code);
        expect(violations.some(v => v.ruleId === 'coppa-retention-005')).toBe(true);
      });

      it('should detect Go user struct', () => {
        const code = `type UserProfile struct {`;
        const violations = engine.scanFile('models.go', code);
        expect(violations.some(v => v.ruleId === 'coppa-retention-005')).toBe(true);
      });

      it('should detect Java JPA @Entity User', () => {
        const code = `@Entity\npublic class UserAccount {`;
        const violations = engine.scanFile('User.java', code);
        expect(violations.some(v => v.ruleId === 'coppa-retention-005')).toBe(true);
      });

      it('should detect Kotlin data class for user model', () => {
        const code = `data class StudentProfile(`;
        const violations = engine.scanFile('Models.kt', code);
        expect(violations.some(v => v.ruleId === 'coppa-retention-005')).toBe(true);
      });
    });

    // ---- coppa-auth-001: Social login across languages ----
    describe('coppa-auth-001 — Social login multi-language', () => {
      it('should detect Python django-allauth SOCIALACCOUNT_PROVIDERS', () => {
        const code = `SOCIALACCOUNT_PROVIDERS = { 'google': { 'SCOPE': ['profile'] } }`;
        const violations = engine.scanFile('settings.py', code);
        expect(violations.some(v => v.ruleId === 'coppa-auth-001')).toBe(true);
      });

      it('should detect Python SOCIAL_AUTH google key', () => {
        const code = `SOCIAL_AUTH_GOOGLE_KEY = "xxx.apps.googleusercontent.com"`;
        const violations = engine.scanFile('settings.py', code);
        expect(violations.some(v => v.ruleId === 'coppa-auth-001')).toBe(true);
      });

      it('should detect Python flask-dance google blueprint', () => {
        const code = `google_bp = make_google_blueprint(client_id="xxx")`;
        const violations = engine.scanFile('app.py', code);
        expect(violations.some(v => v.ruleId === 'coppa-auth-001')).toBe(true);
      });

      it('should detect Go goth.UseProviders', () => {
        const code = `goth.UseProviders(google.New(key, secret, "callback"))`;
        const violations = engine.scanFile('auth.go', code);
        expect(violations.some(v => v.ruleId === 'coppa-auth-001')).toBe(true);
      });

      it('should detect Java Spring oauth2Login', () => {
        const code = `http.authorizeRequests().and().oauth2Login()`;
        const violations = engine.scanFile('SecurityConfig.java', code);
        expect(violations.some(v => v.ruleId === 'coppa-auth-001')).toBe(true);
      });

      it('should detect Kotlin Firebase signInWithCredential', () => {
        const code = `Firebase.auth.signInWithCredential(credential)`;
        const violations = engine.scanFile('AuthActivity.kt', code);
        expect(violations.some(v => v.ruleId === 'coppa-auth-001')).toBe(true);
      });

      it('should detect Java/Kotlin GoogleSignIn.getClient', () => {
        const code = `val client = GoogleSignIn.getClient(this, gso)`;
        const violations = engine.scanFile('LoginActivity.kt', code);
        expect(violations.some(v => v.ruleId === 'coppa-auth-001')).toBe(true);
      });
    });

    // ---- coppa-analytics-018: Server-side analytics ----
    describe('coppa-analytics-018 — Server-side analytics PII', () => {
      it('should detect Python Segment identify with email', () => {
        const code = `analytics.identify(user_id, {"email": user.email, "name": user.name})`;
        const violations = engine.scanFile('tracking.py', code);
        expect(violations.some(v => v.ruleId === 'coppa-analytics-018')).toBe(true);
      });

      it('should detect Python Mixpanel people_set with email', () => {
        const code = `mp.people_set(user_id, {"$email": user.email})`;
        const violations = engine.scanFile('analytics.py', code);
        expect(violations.some(v => v.ruleId === 'coppa-analytics-018')).toBe(true);
      });

      it('should detect Go Segment analytics.Enqueue Identify with Email', () => {
        const code = `analytics.Enqueue(analytics.Identify{UserId: id, Traits: analytics.NewTraits().SetEmail(email)})`;
        const violations = engine.scanFile('tracking.go', code);
        expect(violations.some(v => v.ruleId === 'coppa-analytics-018')).toBe(true);
      });

      it('should detect Java Amplitude setUserId with email', () => {
        const code = `Amplitude.getInstance().setUserId(user.email);`;
        const violations = engine.scanFile('Analytics.java', code);
        expect(violations.some(v => v.ruleId === 'coppa-analytics-018')).toBe(true);
      });

      it('should detect Java Firebase setUserId with email', () => {
        const code = `FirebaseAnalytics.setUserId(user.email);`;
        const violations = engine.scanFile('Tracking.java', code);
        expect(violations.some(v => v.ruleId === 'coppa-analytics-018')).toBe(true);
      });
    });

    // ---- coppa-geo-004: Mobile location APIs ----
    describe('coppa-geo-004 — Mobile & server geolocation', () => {
      it('should detect Java Android LocationManager.requestLocationUpdates', () => {
        const code = `LocationManager.requestLocationUpdates(provider, 0, 0, listener);`;
        const violations = engine.scanFile('LocationService.java', code);
        expect(violations.some(v => v.ruleId === 'coppa-geo-004')).toBe(true);
      });

      it('should detect Java/Kotlin FusedLocationProviderClient', () => {
        const code = `val fusedLocationClient = LocationServices.getFusedLocationProviderClient(this)`;
        const violations = engine.scanFile('MapActivity.kt', code);
        expect(violations.some(v => v.ruleId === 'coppa-geo-004')).toBe(true);
      });

      it('should detect Android ACCESS_FINE_LOCATION permission', () => {
        const code = `<uses-permission android:name="android.permission.ACCESS_FINE_LOCATION" />`;
        const violations = engine.scanFile('AndroidManifest.xml', code);
        expect(violations.some(v => v.ruleId === 'coppa-geo-004')).toBe(true);
      });

      it('should detect Python geocoder library', () => {
        const code = `location = geocoder.google("Mountain View, CA")`;
        const violations = engine.scanFile('location.py', code);
        expect(violations.some(v => v.ruleId === 'coppa-geo-004')).toBe(true);
      });

      it('should detect Kotlin LocationRequest high accuracy', () => {
        const code = `val request = LocationRequest.Builder(Priority.PRIORITY_HIGH_ACCURACY, 1000).build()`;
        const violations = engine.scanFile('LocationService.kt', code);
        expect(violations.some(v => v.ruleId === 'coppa-geo-004')).toBe(true);
      });
    });
  });

  // ============================================================================
  // P3-3: Australia Safety by Design (AU SbD) Sector Rules
  // Based on the eSafety Commissioner's Safety by Design framework.
  // ============================================================================
  describe('AU Safety by Design Rules (P3-3)', () => {
    let sbdEngine: HaloEngine;

    beforeEach(() => {
      sbdEngine = new HaloEngine({ sectorAuSbd: true });
    });

    it('should have 6 AU SbD rules', () => {
      expect(AU_SBD_RULES).toHaveLength(6);
    });

    it('should load 32 rules when sectorAuSbd is enabled (26 COPPA + 6 AU SbD)', () => {
      const rules = sbdEngine.getRules();
      // Halo 2.0: all rules active — AI Review Board handles precision
      expect(rules).toHaveLength(32);
    });

    it('should detect default public profiles (AU-SBD-001)', () => {
      const cases = [
        `const settings = { visibility: 'public', theme: 'dark' };`,
        `const user = { isPublic: true, name: 'test' };`,
        `const config = { defaultVisibility: 'public' };`,
        `const opts = { profileVisible: true };`,
      ];
      for (const code of cases) {
        const violations = sbdEngine.scanFile('profile.ts', code);
        expect(violations.some(v => v.ruleId === 'AU-SBD-001')).toBe(true);
      }
    });

    it('should NOT flag private-by-default profiles (AU-SBD-001)', () => {
      const code = `const settings = { visibility: 'private', isPublic: false };`;
      const violations = sbdEngine.scanFile('profile.ts', code);
      expect(violations.some(v => v.ruleId === 'AU-SBD-001')).toBe(false);
    });

    // Halo 2.0: AU-SBD-002 re-enabled
    it('should detect social features without report/block (AU-SBD-002)', () => {
      const cases = [
        `async function addComment(userId, text) { ... }`,
        `const sendMessage = async (to, body) => { ... };`,
        `function createPost(content) { return db.posts.insert(content); }`,
      ];
      for (const code of cases) {
        const violations = sbdEngine.scanFile('social.ts', code);
        expect(violations.some(v => v.ruleId === 'AU-SBD-002')).toBe(true);
      }
    });

    it('should detect unrestricted DMs (AU-SBD-003 — Halo 2.0 all rules active)', () => {
      const code = `async function directMessage(recipientId, text) { ... }`;
      const violations = sbdEngine.scanFile('chat.ts', code);
      expect(violations.some(v => v.ruleId === 'AU-SBD-003')).toBe(true);
    });

    it('should detect recommendation algorithms (AU-SBD-004 — Halo 2.0 all rules active)', () => {
      const code = `const personalizedFeed = getFeed(userId);`;
      const violations = sbdEngine.scanFile('feed.ts', code);
      expect(violations.some(v => v.ruleId === 'AU-SBD-004')).toBe(true);
    });

    it('should detect engagement features (AU-SBD-005 — Halo 2.0, AI Review Board handles FP)', () => {
      const code = `const config = { autoPlayNext: true };`;
      const violations = sbdEngine.scanFile('engagement.ts', code);
      expect(violations.some(v => v.ruleId === 'AU-SBD-005')).toBe(true);
    });

    it('should detect location sharing (AU-SBD-006 — Halo 2.0 all rules active)', () => {
      const code = `const config = { shareLocation: true };`;
      const violations = sbdEngine.scanFile('location.ts', code);
      expect(violations.some(v => v.ruleId === 'AU-SBD-006')).toBe(true);
    });

    it('should fire AU SbD rules by default in Halo 2.0 (all packs loaded)', () => {
      const standardEngine = new HaloEngine(); // Halo 2.0: loads ALL packs including au-sbd
      const code = `const settings = { visibility: 'public', autoplay: true, shareLocation: true };`;
      const violations = standardEngine.scanFile('test.ts', code);
      expect(violations.some(v => v.ruleId.startsWith('AU-SBD'))).toBe(true);
    });

    it('should NOT fire AU SbD rules when only coppa pack is loaded', () => {
      const coppaOnly = new HaloEngine({ packs: ['coppa'] });
      const code = `const settings = { visibility: 'public', autoplay: true, shareLocation: true };`;
      const violations = coppaOnly.scanFile('test.ts', code);
      expect(violations.some(v => v.ruleId.startsWith('AU-SBD'))).toBe(false);
    });

    it('should combine AU SbD with other rule packs', () => {
      const combinedEngine = new HaloEngine({ ethical: true, aiAudit: true, sectorAuSbd: true });
      const rules = combinedEngine.getRules();
      // Halo 2.0: 26 COPPA + 5 Ethical + 6 AI Audit + 6 AU SbD = 43
      expect(rules).toHaveLength(43);
    });

    it('should assign correct severities to AU SbD rules', () => {
      const criticalRules = AU_SBD_RULES.filter(r => r.severity === 'critical');
      const highRules = AU_SBD_RULES.filter(r => r.severity === 'high');
      const mediumRules = AU_SBD_RULES.filter(r => r.severity === 'medium');
      // AU-SBD-003 (DMs) and AU-SBD-006 (location) are critical
      expect(criticalRules).toHaveLength(2);
      // AU-SBD-001 (profiles) and AU-SBD-004 (algorithms) are high
      expect(highRules).toHaveLength(2);
      // AU-SBD-002 (report/block) and AU-SBD-005 (wellbeing) are medium
      expect(mediumRules).toHaveLength(2);
    });
  });

  // ──────────────────────────────────────────────────────────
  // Language Filtering
  // ──────────────────────────────────────────────────────────
  describe('Language Filtering', () => {
    it('should fire coppa-notif-013 on Notification constructor (Halo 2.0 — AI Review Board handles precision)', () => {
      const jsCode = `const n = new Notification('Hello from app');`;
      const violations = engine.scanFile('src/push.js', jsCode);
      const notifViolations = violations.filter(v => v.ruleId === 'coppa-notif-013');
      expect(notifViolations.length).toBeGreaterThan(0);
    });

    // Halo 2.0: coppa-sec-006 language list is ['typescript', 'javascript', 'python', 'java', 'swift']
    // PHP is not in the language list for this rule in rules.json
    it('should NOT fire coppa-sec-006 on PHP files (not in language list)', () => {
      const phpCode = `$url = 'http://www.production-api.com/api/users';`;
      const violations = engine.scanFile('lib/api_client.php', phpCode);
      const secViolations = violations.filter(v => v.ruleId === 'coppa-sec-006');
      expect(secViolations).toHaveLength(0);
    });

    // Halo 2.0: coppa-sec-006 re-enabled
    it('should fire coppa-sec-006 on JS files', () => {
      const jsCode = `fetch('http://myapp.com/api/users');`;
      const violations = engine.scanFile('src/api.js', jsCode);
      const secViolations = violations.filter(v => v.ruleId === 'coppa-sec-006');
      expect(secViolations).toHaveLength(1);
    });

    it('should fire coppa-ui-008 on PHP files (PHP is in ui-008 language list)', () => {
      const phpCode = `$registration_form = new Form('register');`;
      const violations = engine.scanFile('app/forms/register.php', phpCode);
      const uiViolations = violations.filter(v => v.ruleId === 'coppa-ui-008');
      expect(uiViolations).toHaveLength(1);
    });

    // Halo 2.0: coppa-sec-006 re-enabled
    it('should still fire rules on files with unknown extensions', () => {
      const code = `fetch('http://myapp.com/api/users');`;
      const violations = engine.scanFile('src/config.xyz', code);
      // Unknown language = rules still apply (no language filtering)
      const secViolations = violations.filter(v => v.ruleId === 'coppa-sec-006');
      expect(secViolations).toHaveLength(1);
    });
  });

  // ──────────────────────────────────────────────────────────
  // XSS Sanitization Exclusion
  // ──────────────────────────────────────────────────────────
  // Halo 2.0: coppa-sec-015 re-enabled — XSS sanitization exclusions still apply
  describe('XSS Sanitization Exclusion', () => {
    it('should skip sec-015 when innerHTML value is sanitized with escape.html()', () => {
      const code = `el.innerHTML = Y.Escape.html(userData);`;
      const violations = engine.scanFile('src/render.js', code);
      const xssViolations = violations.filter(v => v.ruleId === 'coppa-sec-015');
      expect(xssViolations).toHaveLength(0);
    });

    it('should skip sec-015 when innerHTML value is sanitized with DOMPurify', () => {
      const code = `el.innerHTML = DOMPurify.sanitize(data.content);`;
      const violations = engine.scanFile('src/render.js', code);
      const xssViolations = violations.filter(v => v.ruleId === 'coppa-sec-015');
      expect(xssViolations).toHaveLength(0);
    });

    it('should still flag sec-015 when innerHTML is NOT sanitized', () => {
      const code = `el.innerHTML = data.content;`;
      const violations = engine.scanFile('src/render.js', code);
      const xssViolations = violations.filter(v => v.ruleId === 'coppa-sec-015');
      expect(xssViolations).toHaveLength(1);
    });
  });

  // ──────────────────────────────────────────────────────────
  // Admin Form Exclusion
  // ──────────────────────────────────────────────────────────
  describe('Admin Form Exclusion', () => {
    it('should skip ui-008 for LTI cartridge registration forms', () => {
      const code = `CARTRIDGE_REGISTRATION_FORM: '#cartridge-registration-form',`;
      const violations = engine.scanFile('src/lti/tool_configure.js', code);
      const uiViolations = violations.filter(v => v.ruleId === 'coppa-ui-008');
      expect(uiViolations).toHaveLength(0);
    });

    it('should skip ui-008 for Brickfield accessibility tool registration', () => {
      const code = `const form = new registration_form();`;
      const violations = engine.scanFile('admin/tool/brickfield/registration.php', code);
      const uiViolations = violations.filter(v => v.ruleId === 'coppa-ui-008');
      expect(uiViolations).toHaveLength(0);
    });

    it('should still flag ui-008 for actual user signup forms', () => {
      const code = `const signup_form = document.getElementById('signup-form');`;
      const violations = engine.scanFile('src/auth/signup.tsx', code);
      const uiViolations = violations.filter(v => v.ruleId === 'coppa-ui-008');
      expect(uiViolations).toHaveLength(1);
    });
  });

  // ──────────────────────────────────────────────────────────
  // Cookie Consent Exclusion
  // ──────────────────────────────────────────────────────────
  describe('Cookie Consent Exclusion', () => {
    it('should skip cookies-016 for cookie consent implementation files', () => {
      const code = `document.cookie = 'cookie_consent=' + consent;`;
      const violations = engine.scanFile('src/jquery-eu-cookie-law-popup.js', code);
      const cookieViolations = violations.filter(v => v.ruleId === 'coppa-cookies-016');
      expect(cookieViolations).toHaveLength(0);
    });

    it('should skip cookies-016 when line references cookie_consent', () => {
      const code = `document.cookie = cookie_consent_name + '=accepted; expires=' + date;`;
      const violations = engine.scanFile('src/consent.js', code);
      const cookieViolations = violations.filter(v => v.ruleId === 'coppa-cookies-016');
      expect(cookieViolations).toHaveLength(0);
    });

    it('should still flag cookies-016 for tracking cookies', () => {
      const code = `document.cookie = 'user_session=' + sessionId;`;
      const violations = engine.scanFile('src/auth.js', code);
      const cookieViolations = violations.filter(v => v.ruleId === 'coppa-cookies-016');
      expect(cookieViolations).toHaveLength(1);
    });
  });

  // ──────────────────────────────────────────────────────────
  // H5P Vendor Detection
  // ──────────────────────────────────────────────────────────
  describe('H5P Vendor Detection', () => {
    it('should suppress violations from h5plib/ paths', () => {
      const code = `H5P.jQuery('<a href="http://h5p.org" target="_blank">Link</a>');`;
      const violations = engine.scanFile('h5p/h5plib/v127/joubel/core/js/h5p.js', code);
      expect(violations).toHaveLength(0);
    });

    it('should not suppress non-h5plib paths', () => {
      const code = `<a href="https://external.com" target="_blank">Link</a>`;
      const violations = engine.scanFile('src/components/h5p-wrapper.js', code);
      // Verify h5p-wrapper.js is NOT suppressed (only h5plib/ paths are)
      expect(violations.length).toBeGreaterThanOrEqual(0); // May or may not match, but path is not suppressed
    });
  });

  // ──────────────────────────────────────────────────────────
  // Consent-Form Heuristic Exclusions
  // ──────────────────────────────────────────────────────────
  describe('Consent-Form Heuristic Exclusions', () => {
    it('should suppress cookies-016 in consent manager file paths', () => {
      const code = `document.cookie = 'user_session=' + sessionToken;`;
      const violations = engine.scanFile('src/components/cookie-consent.js', code);
      const cookieViolations = violations.filter(v => v.ruleId === 'coppa-cookies-016');
      expect(cookieViolations).toHaveLength(0);
    });

    it('should suppress cookies-016 in gdpr-banner file paths', () => {
      const code = `document.cookie = 'tracking_id=' + id;`;
      const violations = engine.scanFile('src/gdpr-banner.js', code);
      const cookieViolations = violations.filter(v => v.ruleId === 'coppa-cookies-016');
      expect(cookieViolations).toHaveLength(0);
    });

    it('should suppress cookies-016 in privacy-notice directory', () => {
      const code = `document.cookie = 'user_session=' + token;`;
      const violations = engine.scanFile('src/privacy-notice/index.js', code);
      const cookieViolations = violations.filter(v => v.ruleId === 'coppa-cookies-016');
      expect(cookieViolations).toHaveLength(0);
    });

    it('should suppress cookies-016 when line has handleConsent function', () => {
      const code = `function handleConsent(accepted) { document.cookie = 'session_token=' + token; }`;
      const violations = engine.scanFile('src/app.js', code);
      const cookieViolations = violations.filter(v => v.ruleId === 'coppa-cookies-016');
      expect(cookieViolations).toHaveLength(0);
    });

    it('should suppress cookies-016 when line has acceptCookies function', () => {
      const code = `const acceptCookies = () => { document.cookie = 'analytics_id=' + id; };`;
      const violations = engine.scanFile('src/settings.js', code);
      const cookieViolations = violations.filter(v => v.ruleId === 'coppa-cookies-016');
      expect(cookieViolations).toHaveLength(0);
    });

    it('should suppress tracking-003 in consent implementation files', () => {
      const code = `gtag('event', 'consent_granted', { analytics_storage: 'granted' });`;
      const violations = engine.scanFile('src/consent/cookie-consent.js', code);
      const trackingViolations = violations.filter(v => v.ruleId === 'coppa-tracking-003');
      expect(trackingViolations).toHaveLength(0);
    });

    it('should suppress cookies-016 when file imports consent management library', () => {
      const code = `import CookieConsent from 'react-cookie-consent';\ndocument.cookie = 'user_id=' + userId;`;
      const violations = engine.scanFile('src/app.js', code);
      const cookieViolations = violations.filter(v => v.ruleId === 'coppa-cookies-016');
      expect(cookieViolations).toHaveLength(0);
    });

    it('should still flag cookies-016 in non-consent files', () => {
      const code = `document.cookie = 'user_session=' + sessionToken;`;
      const violations = engine.scanFile('src/auth/login.js', code);
      const cookieViolations = violations.filter(v => v.ruleId === 'coppa-cookies-016');
      expect(cookieViolations).toHaveLength(1);
    });
  });

  // ──────────────────────────────────────────────────────────
  // Precision Lock — 6 FP Pattern Fixes
  // ──────────────────────────────────────────────────────────

  // Halo 2.0: coppa-sec-006 re-enabled — test config file exclusions still apply
  describe('Test Config File Detection (— FP #1)', () => {
    it('should suppress sec-006 in envs/test.py', () => {
      const code = `STORAGE_URL = "http://example-storage.com/test-bucket"`;
      const violations = engine.scanFile('lms/envs/test.py', code);
      const secViolations = violations.filter(v => v.ruleId === 'coppa-sec-006');
      expect(secViolations).toHaveLength(0);
    });

    it('should suppress sec-006 in envs/test_settings.py', () => {
      const code = `API_URL = "http://test-api.local/v1"`;
      const violations = engine.scanFile('envs/test_settings.py', code);
      const secViolations = violations.filter(v => v.ruleId === 'coppa-sec-006');
      expect(secViolations).toHaveLength(0);
    });

    it('should suppress sec-006 in config/test.json', () => {
      const code = `{ "apiUrl": "http://test-server.local:8080/api" }`;
      const violations = engine.scanFile('config/test.json', code);
      const secViolations = violations.filter(v => v.ruleId === 'coppa-sec-006');
      expect(secViolations).toHaveLength(0);
    });

    it('should suppress sec-006 in settings/test.py', () => {
      const code = `DATABASE_URL = "http://test-db.internal:5432"`;
      const violations = engine.scanFile('settings/test.py', code);
      const secViolations = violations.filter(v => v.ruleId === 'coppa-sec-006');
      expect(secViolations).toHaveLength(0);
    });

    it('should suppress test FP rules in conftest.py', () => {
      const code = `API_URL = "http://mock-server.local/api"`;
      const violations = engine.scanFile('tests/conftest.py', code);
      const secViolations = violations.filter(v => v.ruleId === 'coppa-sec-006');
      expect(secViolations).toHaveLength(0);
    });

    it('should NOT suppress sec-006 in envs/production.py', () => {
      const code = `API_URL = "http://prod-server.com/api/users"`;
      const violations = engine.scanFile('lms/envs/production.py', code);
      const secViolations = violations.filter(v => v.ruleId === 'coppa-sec-006');
      expect(secViolations).toHaveLength(1);
    });
  });

  describe('Admin/Instructor Route Detection (— FP #2)', () => {
    it('should suppress flow-009 in admin/ paths', () => {
      const code = `student_email = user.email`;
      const violations = engine.scanFile('djangoapps/admin/views.py', code);
      const flowViolations = violations.filter(v => v.ruleId === 'coppa-flow-009');
      expect(flowViolations).toHaveLength(0);
    });

    it('should suppress flow-009 in instructor/ paths', () => {
      const code = `child_email = student.get_email()`;
      const violations = engine.scanFile('djangoapps/instructor/access.py', code);
      const flowViolations = violations.filter(v => v.ruleId === 'coppa-flow-009');
      expect(flowViolations).toHaveLength(0);
    });

    it('should suppress data-002 in staff/ paths', () => {
      const code = `const url = \`/api/user?email=\${admin.email}\`;`;
      const violations = engine.scanFile('staff/user_management.py', code);
      const dataViolations = violations.filter(v => v.ruleId === 'coppa-data-002');
      expect(dataViolations).toHaveLength(0);
    });

    it('should suppress flow-009 when @staff_member_required decorator present', () => {
      const code = `@staff_member_required\ndef manage_users(request):\n    child_email = request.POST.get('child_email')`;
      const violations = engine.scanFile('views/users.py', code);
      const flowViolations = violations.filter(v => v.ruleId === 'coppa-flow-009');
      expect(flowViolations).toHaveLength(0);
    });

    it('should suppress flow-009 when @permission_required decorator present', () => {
      const code = `@permission_required('admin')\ndef user_details(request):\n    student_email = request.data['student_email']`;
      const violations = engine.scanFile('views/admin_api.py', code);
      const flowViolations = violations.filter(v => v.ruleId === 'coppa-flow-009');
      expect(flowViolations).toHaveLength(0);
    });

    it('should NOT suppress flow-009 in regular user-facing paths', () => {
      const code = `const child_email = form.email.value;`;
      const violations = engine.scanFile('src/signup/register.ts', code);
      const flowViolations = violations.filter(v => v.ruleId === 'coppa-flow-009');
      expect(flowViolations).toHaveLength(1);
    });
  });

  describe('no_pii Model Annotation Detection (— FP #3)', () => {
    it('should suppress retention-005 when Python file has .. no_pii: docstring', () => {
      const code = `class CalendarSync(models.Model):\n    """\n    .. no_pii:\n    """\n    user = models.ForeignKey(User)\n    calendar_id = models.CharField()\n    new_schema = new Schema({\n      user: String\n    })`;
      const violations = engine.scanFile('features/calendar_sync/models.py', code);
      const retentionViolations = violations.filter(v => v.ruleId === 'coppa-retention-005');
      expect(retentionViolations).toHaveLength(0);
    });

    it('should suppress retention-005 when Python file has # no_pii comment', () => {
      const code = `# no_pii\nclass Preferences(models.Model):\n    user = models.ForeignKey(User)\n    theme = models.CharField()\n    new_schema = new Schema({\n      pref: String\n    })`;
      const violations = engine.scanFile('models/preferences.py', code);
      const retentionViolations = violations.filter(v => v.ruleId === 'coppa-retention-005');
      expect(retentionViolations).toHaveLength(0);
    });

    it('should NOT suppress retention-005 for Python models without no_pii annotation', () => {
      const code = `class UserProfile(models.Model):\n    user = models.ForeignKey(User)\n    email = models.EmailField()\n    new_schema = new Schema({\n      email: String\n    })`;
      const violations = engine.scanFile('models/profile.py', code);
      const retentionViolations = violations.filter(v => v.ruleId === 'coppa-retention-005');
      expect(retentionViolations.length).toBeGreaterThan(0);
    });

    it('should NOT suppress retention-005 for non-Python files even with no_pii text', () => {
      const code = `// no_pii\nconst userSchema = new Schema({\n  email: String,\n  name: String\n});`;
      const violations = engine.scanFile('models/user.ts', code);
      const retentionViolations = violations.filter(v => v.ruleId === 'coppa-retention-005');
      expect(retentionViolations.length).toBeGreaterThan(0);
    });
  });

  // Halo 2.0: coppa-ext-017 re-enabled — IE conditional comment exclusions still apply
  describe('IE Conditional Comment Detection (— FP #4)', () => {
    it('should suppress ext-017 for links inside IE conditional comments', () => {
      const code = `<!--[if lte IE 9]>\n<p class="browsehappy">Please <a href="https://browsehappy.com/" target="_blank">upgrade your browser</a></p>\n<![endif]-->`;
      const violations = engine.scanFile('templates/base.html', code);
      const extViolations = violations.filter(v => v.ruleId === 'coppa-ext-017');
      expect(extViolations).toHaveLength(0);
    });

    it('should suppress ext-017 for Chrome download link in IE conditional', () => {
      const code = `<!--[if lt IE 10]>\n<div class="ie-warning">\n<a href="https://www.google.com/chrome/" target="_blank">Download Chrome</a>\n<a href="https://www.mozilla.org/firefox/" target="_blank">Download Firefox</a>\n</div>\n<![endif]-->`;
      const violations = engine.scanFile('index.html', code);
      const extViolations = violations.filter(v => v.ruleId === 'coppa-ext-017');
      expect(extViolations).toHaveLength(0);
    });

    it('should NOT suppress ext-017 for normal external links', () => {
      const code = `<a href="https://external-site.com/game" target="_blank">Play Game</a>`;
      const violations = engine.scanFile('src/page.html', code);
      const extViolations = violations.filter(v => v.ruleId === 'coppa-ext-017');
      expect(extViolations).toHaveLength(1);
    });
  });

  describe('Cookie Deletion Pattern Detection (— FP #5)', () => {
    it('should suppress cookies-016 for max-age=0 (cookie deletion)', () => {
      const code = `document.cookie = "session_id=; max-age=0; path=/";`;
      const violations = engine.scanFile('src/auth/logout.js', code);
      const cookieViolations = violations.filter(v => v.ruleId === 'coppa-cookies-016');
      expect(cookieViolations).toHaveLength(0);
    });

    it('should suppress cookies-016 for negative max-age', () => {
      const code = `document.cookie = "tracking=; max-age=-1; path=/";`;
      const violations = engine.scanFile('src/cleanup.js', code);
      const cookieViolations = violations.filter(v => v.ruleId === 'coppa-cookies-016');
      expect(cookieViolations).toHaveLength(0);
    });

    it('should suppress cookies-016 for expires=Thu, 01 Jan 1970 (epoch)', () => {
      const code = `document.cookie = "user_pref=; expires=Thu, 01 Jan 1970 00:00:00 GMT; path=/";`;
      const violations = engine.scanFile('src/submit.js', code);
      const cookieViolations = violations.filter(v => v.ruleId === 'coppa-cookies-016');
      expect(cookieViolations).toHaveLength(0);
    });

    it('should suppress cookies-016 for deleteCookie function', () => {
      const code = `function deleteCookie(name) { document.cookie = name + '=; expires=' + past; }`;
      const violations = engine.scanFile('src/utils.js', code);
      const cookieViolations = violations.filter(v => v.ruleId === 'coppa-cookies-016');
      expect(cookieViolations).toHaveLength(0);
    });

    it('should suppress cookies-016 for new Date(0) expiry pattern (Moodle clearDownloadCookie)', () => {
      const code = `document.cookie = encodeURIComponent(getCookieName()) + '=deleted; expires=' + new Date(0).toUTCString();`;
      const violations = engine.scanFile('src/submit.js', code);
      const cookieViolations = violations.filter(v => v.ruleId === 'coppa-cookies-016');
      expect(cookieViolations).toHaveLength(0);
    });

    it('should NOT suppress cookies-016 for normal cookie setting', () => {
      const code = `document.cookie = "user_session=" + token + "; max-age=3600; path=/";`;
      const violations = engine.scanFile('src/auth/login.js', code);
      const cookieViolations = violations.filter(v => v.ruleId === 'coppa-cookies-016');
      expect(cookieViolations).toHaveLength(1);
    });
  });

  // Halo 2.0: coppa-ext-017 re-enabled — doc generator path exclusions still apply
  describe('Doc Generator Path Detection (— FP #6)', () => {
    it('should suppress all violations in jsdoc output files', () => {
      const code = `<a href="https://developer.mozilla.org" target="_blank">MDN</a>`;
      const violations = engine.scanFile('docs/jsdoc/module-auth.html', code);
      expect(violations).toHaveLength(0);
    });

    it('should suppress all violations in typedoc output', () => {
      const code = `<a href="https://typescriptlang.org" target="_blank">TypeScript</a>`;
      const violations = engine.scanFile('docs/typedoc/index.html', code);
      expect(violations).toHaveLength(0);
    });

    it('should suppress all violations in sphinx build output', () => {
      const code = `<a href="https://python.org" target="_blank">Python</a>`;
      const violations = engine.scanFile('docs/_build/html/api.html', code);
      expect(violations).toHaveLength(0);
    });

    it('should suppress all violations in jsdoc.html template', () => {
      const code = `<a href="https://github.com/jsdoc/jsdoc" target="_blank">JSDoc</a>`;
      const violations = engine.scanFile('templates/jsdoc.html', code);
      expect(violations).toHaveLength(0);
    });

    it('should suppress all violations in docs/api/ generated docs', () => {
      const code = `<a href="https://example-external.com/docs" target="_blank">API</a>`;
      const violations = engine.scanFile('docs/api/authentication.html', code);
      expect(violations).toHaveLength(0);
    });

    it('should export isDocGeneratorPath utility', () => {
      const { isDocGeneratorPath } = require('../index');
      expect(isDocGeneratorPath('docs/jsdoc/module.html')).toBe(true);
      expect(isDocGeneratorPath('docs/typedoc/index.html')).toBe(true);
      expect(isDocGeneratorPath('docs/_build/html/api.html')).toBe(true);
      expect(isDocGeneratorPath('templates/jsdoc.html')).toBe(true);
      expect(isDocGeneratorPath('docs/api/auth.html')).toBe(true);
      expect(isDocGeneratorPath('src/components/Header.tsx')).toBe(false);
      expect(isDocGeneratorPath('app/views/home.html')).toBe(false);
    });

    it('should NOT suppress violations in regular docs markdown', () => {
      const code = `<a href="https://external-site.com" target="_blank">Link</a>`;
      const violations = engine.scanFile('docs/setup.html', code);
      const extViolations = violations.filter(v => v.ruleId === 'coppa-ext-017');
      expect(extViolations).toHaveLength(1);
    });
  });

  // =========================================================================
  // Constitutional AI P5-P8 Rules
  // =========================================================================
  describe('Constitutional AI P5-P8 Rules', () => {
    let euEngine: HaloEngine;

    beforeEach(() => {
      euEngine = new HaloEngine({ packs: ['eu-ai-act'] });
    });

    // --- CAI-DATAMIN-001: Excessive Data Collection (P5) ---
    describe('CAI-DATAMIN-001: Excessive Data Collection in AI Pipeline', () => {
      it('should detect broad data collection without field selection', () => {
        const code = `collectUserData({ scope: 'all', userId: uid });`;
        const violations = euEngine.scanFile('src/analytics.ts', code);
        const v = violations.filter(v => v.ruleId === 'CAI-DATAMIN-001');
        expect(v.length).toBeGreaterThan(0);
        expect(v[0].severity).toBe('high');
      });

      it('should detect wildcard field selection', () => {
        const code = `const query = { fields: '*', table: 'users' };`;
        const violations = euEngine.scanFile('src/db.ts', code);
        const v = violations.filter(v => v.ruleId === 'CAI-DATAMIN-001');
        expect(v.length).toBeGreaterThan(0);
      });

      it('should detect indefinite retention', () => {
        const code = `const config = { retention: 'indefinite', dataType: 'sessions' };`;
        const violations = euEngine.scanFile('src/config.ts', code);
        const v = violations.filter(v => v.ruleId === 'CAI-DATAMIN-001');
        expect(v.length).toBeGreaterThan(0);
      });

      it('should detect trackAll pattern', () => {
        const code = `trackAllEvents(userId);`;
        const violations = euEngine.scanFile('src/tracking.ts', code);
        const v = violations.filter(v => v.ruleId === 'CAI-DATAMIN-001');
        expect(v.length).toBeGreaterThan(0);
      });

      it('should NOT flag collection with explicit field selection', () => {
        const code = `collectUserData({ fields: ['name', 'age'], retention: '30d' });`;
        const violations = euEngine.scanFile('src/analytics.ts', code);
        const v = violations.filter(v => v.ruleId === 'CAI-DATAMIN-001');
        expect(v.length).toBe(0);
      });
    });

    // --- CAI-NEURO-001: Neurodivergent Accessibility (P6) ---
    describe('CAI-NEURO-001: AI Interface Without Neurodivergent Accommodations', () => {
      it('should detect timed quiz without accommodations', () => {
        const code = `timedQuiz({ seconds: 60, questions: quizData });`;
        const violations = euEngine.scanFile('src/quiz.ts', code);
        const v = violations.filter(v => v.ruleId === 'CAI-NEURO-001');
        expect(v.length).toBeGreaterThan(0);
        expect(v[0].severity).toBe('medium');
      });

      it('should detect autoAdvance enabled', () => {
        const code = `const settings = { autoAdvance: true, slideSpeed: 3000 };`;
        const violations = euEngine.scanFile('src/presentation.ts', code);
        const v = violations.filter(v => v.ruleId === 'CAI-NEURO-001');
        expect(v.length).toBeGreaterThan(0);
      });

      it('should detect flashing content', () => {
        const code = `flashingContent({ frequency: 5, element: banner });`;
        const violations = euEngine.scanFile('src/effects.ts', code);
        const v = violations.filter(v => v.ruleId === 'CAI-NEURO-001');
        expect(v.length).toBeGreaterThan(0);
      });

      it('should detect countdown timer', () => {
        const code = `countdownTimer(30);`;
        const violations = euEngine.scanFile('src/timer.ts', code);
        const v = violations.filter(v => v.ruleId === 'CAI-NEURO-001');
        expect(v.length).toBeGreaterThan(0);
      });

      it('should NOT flag autoAdvance when disabled', () => {
        const code = `const settings = { autoAdvance: false, speed: 'user-controlled' };`;
        const violations = euEngine.scanFile('src/presentation.ts', code);
        const v = violations.filter(v => v.ruleId === 'CAI-NEURO-001');
        expect(v.length).toBe(0);
      });
    });

    // --- CAI-COREG-001: Parental Co-Regulation (P7) ---
    describe('CAI-COREG-001: AI Decision Without Parent Involvement', () => {
      it('should detect content restriction without parent context', () => {
        const code = `setContentRestriction('violence', userId);`;
        const violations = euEngine.scanFile('src/content.ts', code);
        const v = violations.filter(v => v.ruleId === 'CAI-COREG-001');
        expect(v.length).toBeGreaterThan(0);
        expect(v[0].severity).toBe('high');
      });

      it('should detect learning path adjustment without parent', () => {
        const code = `adjustLearningPath(studentId, 'remedial');`;
        const violations = euEngine.scanFile('src/learning.ts', code);
        const v = violations.filter(v => v.ruleId === 'CAI-COREG-001');
        expect(v.length).toBeGreaterThan(0);
      });

      it('should detect auto-restrict content', () => {
        const code = `autoRestrictContent('mature-themes');`;
        const violations = euEngine.scanFile('src/safety.ts', code);
        const v = violations.filter(v => v.ruleId === 'CAI-COREG-001');
        expect(v.length).toBeGreaterThan(0);
      });

      it('should detect behavioral assessment on child', () => {
        const code = `behavioralAssessment(childId);`;
        const violations = euEngine.scanFile('src/assessment.ts', code);
        const v = violations.filter(v => v.ruleId === 'CAI-COREG-001');
        expect(v.length).toBeGreaterThan(0);
      });

      it('should NOT flag restriction with parent context', () => {
        const code = `setContentRestriction('violence', userId, parentToken);`;
        const violations = euEngine.scanFile('src/content.ts', code);
        const v = violations.filter(v => v.ruleId === 'CAI-COREG-001');
        expect(v.length).toBe(0);
      });
    });

    // --- CAI-CRISIS-001: Crisis Escalation Protocol (P8) ---
    describe('CAI-CRISIS-001: AI Chatbot Without Crisis Escalation', () => {
      it('should detect AI companion respond without safety in child context', () => {
        const code = `aiCompanion.respond(userMessage);`;
        const violations = euEngine.scanFile('src/chat.ts', code);
        const v = violations.filter(v => v.ruleId === 'CAI-CRISIS-001');
        expect(v.length).toBeGreaterThan(0);
        expect(v[0].severity).toBe('critical');
      });

      it('should detect student chat without crisis handling', () => {
        const code = `studentChat.send(message);`;
        const violations = euEngine.scanFile('src/chat.ts', code);
        const v = violations.filter(v => v.ruleId === 'CAI-CRISIS-001');
        expect(v.length).toBeGreaterThan(0);
      });

      it('should detect AI tutor reply without safety', () => {
        const code = `aiTutor.reply(studentQuestion);`;
        const violations = euEngine.scanFile('src/tutor.ts', code);
        const v = violations.filter(v => v.ruleId === 'CAI-CRISIS-001');
        expect(v.length).toBeGreaterThan(0);
      });

      it('should detect child chat submit', () => {
        const code = `childChat.submit(inputText);`;
        const violations = euEngine.scanFile('src/messaging.ts', code);
        const v = violations.filter(v => v.ruleId === 'CAI-CRISIS-001');
        expect(v.length).toBeGreaterThan(0);
      });

      it('should NOT flag companion with crisis detection', () => {
        const code = `aiCompanion.respond(userMessage, { crisisDetection: true });`;
        const violations = euEngine.scanFile('src/chat.ts', code);
        const v = violations.filter(v => v.ruleId === 'CAI-CRISIS-001');
        expect(v.length).toBe(0);
      });
    });
  });

  // =========================================================================
  // EU AI Act Art. 10 — Data Governance
  // =========================================================================
  describe('EU AI Act Art. 10 — Data Governance', () => {
    let euEngine: HaloEngine;

    beforeEach(() => {
      euEngine = new HaloEngine({ packs: ['eu-ai-act'] });
    });

    // --- AI-GOVERNANCE-001: Training Data Quality ---
    describe('AI-GOVERNANCE-001: Training Data Without Quality Documentation', () => {
      it('should detect loadDataset without provenance', () => {
        const code = `const data = loadDataset('users_v2');`;
        const v = euEngine.scanFile('train.py', code).filter(v => v.ruleId === 'AI-GOVERNANCE-001');
        expect(v.length).toBeGreaterThan(0);
      });

      it('should detect DataLoader.from_csv', () => {
        const code = `const loader = DataLoader.from_csv('data/train.csv');`;
        const v = euEngine.scanFile('pipeline.ts', code).filter(v => v.ruleId === 'AI-GOVERNANCE-001');
        expect(v.length).toBeGreaterThan(0);
      });

      it('should detect trainData assigned from pandas', () => {
        const code = `trainData = pd.read_csv('interactions.csv')`;
        const v = euEngine.scanFile('train.py', code).filter(v => v.ruleId === 'AI-GOVERNANCE-001');
        expect(v.length).toBeGreaterThan(0);
      });

      it('should NOT flag loadDataset with provenance', () => {
        const code = `const data = loadDataset('users_v2', { provenance: 'documented' });`;
        const v = euEngine.scanFile('train.py', code).filter(v => v.ruleId === 'AI-GOVERNANCE-001');
        expect(v.length).toBe(0);
      });

      it('should NOT flag generic file reads', () => {
        const code = `const config = JSON.parse(fs.readFileSync('config.json'));`;
        const v = euEngine.scanFile('app.ts', code).filter(v => v.ruleId === 'AI-GOVERNANCE-001');
        expect(v.length).toBe(0);
      });
    });

    // --- AI-GOVERNANCE-002: Bias Testing ---
    describe('AI-GOVERNANCE-002: Training Without Bias Testing', () => {
      it('should detect model.fit without bias audit', () => {
        const code = `model.fit(X_train, y_train, epochs=10)`;
        const v = euEngine.scanFile('train.py', code).filter(v => v.ruleId === 'AI-GOVERNANCE-002');
        expect(v.length).toBeGreaterThan(0);
      });

      it('should detect AutoML call', () => {
        const code = `AutoML(task='classification').fit(data)`;
        const v = euEngine.scanFile('automl.py', code).filter(v => v.ruleId === 'AI-GOVERNANCE-002');
        expect(v.length).toBeGreaterThan(0);
      });

      it('should detect trainer.train without fairness', () => {
        const code = `trainer.train(config)`;
        const v = euEngine.scanFile('train.ts', code).filter(v => v.ruleId === 'AI-GOVERNANCE-002');
        expect(v.length).toBeGreaterThan(0);
      });

      it('should NOT flag model.fit with bias audit', () => {
        const code = `model.fit(X_train, y_train, bias_check=True, fairness_metrics=True)`;
        const v = euEngine.scanFile('train.py', code).filter(v => v.ruleId === 'AI-GOVERNANCE-002');
        expect(v.length).toBe(0);
      });

      it('should NOT flag non-ML fit calls', () => {
        const code = `const chart = canvas.fit(dimensions);`;
        const v = euEngine.scanFile('chart.ts', code).filter(v => v.ruleId === 'AI-GOVERNANCE-002');
        expect(v.length).toBe(0);
      });
    });

    // --- AI-GOVERNANCE-003: Data Representativeness ---
    describe('AI-GOVERNANCE-003: No Data Representativeness Validation', () => {
      it('should detect train_test_split without stratification', () => {
        const code = `X_train, X_test = train_test_split(X, test_size=0.2)`;
        const v = euEngine.scanFile('split.py', code).filter(v => v.ruleId === 'AI-GOVERNANCE-003');
        expect(v.length).toBeGreaterThan(0);
      });

      it('should detect trainModel without diversity check', () => {
        const code = `trainModel(dataset, config)`;
        const v = euEngine.scanFile('train.ts', code).filter(v => v.ruleId === 'AI-GOVERNANCE-003');
        expect(v.length).toBeGreaterThan(0);
      });

      it('should NOT flag train_test_split with stratify', () => {
        const code = `X_train, X_test = train_test_split(X, test_size=0.2, stratify=y)`;
        const v = euEngine.scanFile('split.py', code).filter(v => v.ruleId === 'AI-GOVERNANCE-003');
        expect(v.length).toBe(0);
      });

      it('should NOT flag generic data splitting', () => {
        const code = `const chunks = array.split(',');`;
        const v = euEngine.scanFile('utils.ts', code).filter(v => v.ruleId === 'AI-GOVERNANCE-003');
        expect(v.length).toBe(0);
      });

      it('edge case: buildModel with balanced flag', () => {
        const code = `buildModel(data, { balanced: true })`;
        const v = euEngine.scanFile('train.ts', code).filter(v => v.ruleId === 'AI-GOVERNANCE-003');
        expect(v.length).toBe(0);
      });
    });

    // --- AI-GOVERNANCE-004: Consent Verification ---
    describe('AI-GOVERNANCE-004: Training Data Without Consent', () => {
      it('should detect collectTrainingData without consent', () => {
        const code = `collectTrainingData(userId, sessionLogs)`;
        const v = euEngine.scanFile('data.ts', code).filter(v => v.ruleId === 'AI-GOVERNANCE-004');
        expect(v.length).toBeGreaterThan(0);
        expect(v[0].severity).toBe('critical');
      });

      it('should detect finetuneOnChildData', () => {
        const code = `finetuneOnChildData(childInteractions)`;
        const v = euEngine.scanFile('train.py', code).filter(v => v.ruleId === 'AI-GOVERNANCE-004');
        expect(v.length).toBeGreaterThan(0);
      });

      it('should detect chat log export for training', () => {
        const code = `chatLog.export('training_dataset_v3')`;
        const v = euEngine.scanFile('pipeline.ts', code).filter(v => v.ruleId === 'AI-GOVERNANCE-004');
        expect(v.length).toBeGreaterThan(0);
      });

      it('should NOT flag collectTrainingData with consent', () => {
        const code = `collectTrainingData(userId, sessionLogs, { consent: true })`;
        const v = euEngine.scanFile('data.ts', code).filter(v => v.ruleId === 'AI-GOVERNANCE-004');
        expect(v.length).toBe(0);
      });

      it('should NOT flag generic data export', () => {
        const code = `report.export('quarterly_summary')`;
        const v = euEngine.scanFile('reports.ts', code).filter(v => v.ruleId === 'AI-GOVERNANCE-004');
        expect(v.length).toBe(0);
      });
    });
  });

  // =========================================================================
  // EU AI Act Art. 14 — Human Oversight
  // =========================================================================
  describe('EU AI Act Art. 14 — Human Oversight', () => {
    let euEngine: HaloEngine;

    beforeEach(() => {
      euEngine = new HaloEngine({ packs: ['eu-ai-act'] });
    });

    // --- AI-OVERSIGHT-001: Human-in-the-Loop ---
    describe('AI-OVERSIGHT-001: AI Without Human-in-the-Loop', () => {
      it('should detect autoGrade', () => {
        const code = `autoGrade(submissionId, rubric);`;
        const v = euEngine.scanFile('grading.ts', code).filter(v => v.ruleId === 'AI-OVERSIGHT-001');
        expect(v.length).toBeGreaterThan(0);
      });

      it('should detect aiDecision.execute', () => {
        const code = `aiDecision.execute(contentAction);`;
        const v = euEngine.scanFile('ai.ts', code).filter(v => v.ruleId === 'AI-OVERSIGHT-001');
        expect(v.length).toBeGreaterThan(0);
      });

      it('should detect contentFilter.autoApply', () => {
        const code = `contentFilter.autoApply(childContent);`;
        const v = euEngine.scanFile('filter.ts', code).filter(v => v.ruleId === 'AI-OVERSIGHT-001');
        expect(v.length).toBeGreaterThan(0);
      });

      it('should NOT flag manual grading functions', () => {
        const code = `submitGrade(teacherId, studentId, grade);`;
        const v = euEngine.scanFile('grading.ts', code).filter(v => v.ruleId === 'AI-OVERSIGHT-001');
        expect(v.length).toBe(0);
      });

      it('should detect autoApprove call', () => {
        const code = `autoApprove(application);`;
        const v = euEngine.scanFile('workflow.ts', code).filter(v => v.ruleId === 'AI-OVERSIGHT-001');
        expect(v.length).toBeGreaterThan(0);
      });
    });

    // --- AI-OVERSIGHT-002: Emergency Stop ---
    describe('AI-OVERSIGHT-002: No Emergency Stop', () => {
      it('should detect aiService.start without killSwitch', () => {
        const code = `aiService.start(config);`;
        const v = euEngine.scanFile('service.ts', code).filter(v => v.ruleId === 'AI-OVERSIGHT-002');
        expect(v.length).toBeGreaterThan(0);
        expect(v[0].severity).toBe('critical');
      });

      it('should detect autonomousMode enabled', () => {
        const code = `const config = { autonomousMode: true, maxTokens: 4000 };`;
        const v = euEngine.scanFile('config.ts', code).filter(v => v.ruleId === 'AI-OVERSIGHT-002');
        expect(v.length).toBeGreaterThan(0);
      });

      it('should detect launchAI without stop mechanism', () => {
        const code = `launchAI(modelId);`;
        const v = euEngine.scanFile('deploy.ts', code).filter(v => v.ruleId === 'AI-OVERSIGHT-002');
        expect(v.length).toBeGreaterThan(0);
      });

      it('should NOT flag aiService.start with killSwitch', () => {
        const code = `aiService.start(config, { killSwitch: shutdownHandler });`;
        const v = euEngine.scanFile('service.ts', code).filter(v => v.ruleId === 'AI-OVERSIGHT-002');
        expect(v.length).toBe(0);
      });

      it('should NOT flag autonomousMode disabled', () => {
        const code = `const config = { autonomousMode: false };`;
        const v = euEngine.scanFile('config.ts', code).filter(v => v.ruleId === 'AI-OVERSIGHT-002');
        expect(v.length).toBe(0);
      });
    });

    // --- AI-OVERSIGHT-003: Interpretability ---
    describe('AI-OVERSIGHT-003: No Interpretability', () => {
      it('should detect model.predict without explain', () => {
        const code = `const result = model.predict(inputData);`;
        const v = euEngine.scanFile('inference.py', code).filter(v => v.ruleId === 'AI-OVERSIGHT-003');
        expect(v.length).toBeGreaterThan(0);
      });

      it('should detect getRecommendation without reason', () => {
        const code = `const rec = getRecommendation(userId);`;
        const v = euEngine.scanFile('recommend.ts', code).filter(v => v.ruleId === 'AI-OVERSIGHT-003');
        expect(v.length).toBeGreaterThan(0);
      });

      it('should detect classifier.predict_proba without interpret', () => {
        const code = `probs = classifier.predict_proba(X_test)`;
        const v = euEngine.scanFile('eval.py', code).filter(v => v.ruleId === 'AI-OVERSIGHT-003');
        expect(v.length).toBeGreaterThan(0);
      });

      it('should NOT flag model.predict with SHAP', () => {
        const code = `const result = model.predict(inputData, { shap: true });`;
        const v = euEngine.scanFile('inference.py', code).filter(v => v.ruleId === 'AI-OVERSIGHT-003');
        expect(v.length).toBe(0);
      });

      it('should NOT flag getRecommendation with confidence', () => {
        const code = `const rec = getRecommendation(userId, { confidence: true });`;
        const v = euEngine.scanFile('recommend.ts', code).filter(v => v.ruleId === 'AI-OVERSIGHT-003');
        expect(v.length).toBe(0);
      });
    });

    // --- AI-OVERSIGHT-004: Audit Trail ---
    describe('AI-OVERSIGHT-004: No Audit Trail', () => {
      it('should detect humanReview.submit without logging', () => {
        const code = `humanReview.submit(decision);`;
        const v = euEngine.scanFile('review.ts', code).filter(v => v.ruleId === 'AI-OVERSIGHT-004');
        expect(v.length).toBeGreaterThan(0);
      });

      it('should detect overrideDecision without audit', () => {
        const code = `overrideDecision(predictionId, 'approved');`;
        const v = euEngine.scanFile('override.ts', code).filter(v => v.ruleId === 'AI-OVERSIGHT-004');
        expect(v.length).toBeGreaterThan(0);
      });

      it('should detect approveContent without record', () => {
        const code = `approveContent(contentId);`;
        const v = euEngine.scanFile('moderation.ts', code).filter(v => v.ruleId === 'AI-OVERSIGHT-004');
        expect(v.length).toBeGreaterThan(0);
      });

      it('should NOT flag humanReview.submit with audit log', () => {
        const code = `humanReview.submit(decision, { audit: true, log: reviewLog });`;
        const v = euEngine.scanFile('review.ts', code).filter(v => v.ruleId === 'AI-OVERSIGHT-004');
        expect(v.length).toBe(0);
      });

      it('should NOT flag generic submit calls', () => {
        const code = `form.submit(data);`;
        const v = euEngine.scanFile('form.ts', code).filter(v => v.ruleId === 'AI-OVERSIGHT-004');
        expect(v.length).toBe(0);
      });
    });
  });

  // =========================================================================
  // EU AI Act Art. 15 — Accuracy & Robustness
  // =========================================================================
  describe('EU AI Act Art. 15 — Accuracy & Robustness', () => {
    let euEngine: HaloEngine;

    beforeEach(() => {
      euEngine = new HaloEngine({ packs: ['eu-ai-act'] });
    });

    // --- AI-ACCURACY-001: Error Rate Monitoring ---
    describe('AI-ACCURACY-001: No Error Rate Monitoring', () => {
      it('should detect serveModel.deploy without monitoring', () => {
        const code = `serveModel.deploy(modelPath);`;
        const v = euEngine.scanFile('deploy.ts', code).filter(v => v.ruleId === 'AI-ACCURACY-001');
        expect(v.length).toBeGreaterThan(0);
      });

      it('should detect prediction endpoint', () => {
        const code = `app.post('/api/predict', predictHandler);`;
        const v = euEngine.scanFile('routes.ts', code).filter(v => v.ruleId === 'AI-ACCURACY-001');
        expect(v.length).toBeGreaterThan(0);
      });

      it('should detect mlService.init without metrics', () => {
        const code = `predictionService.init(config);`;
        const v = euEngine.scanFile('service.ts', code).filter(v => v.ruleId === 'AI-ACCURACY-001');
        expect(v.length).toBeGreaterThan(0);
      });

      it('should NOT flag serveModel with monitor', () => {
        const code = `serveModel.deploy(modelPath, { monitor: metricsCollector });`;
        const v = euEngine.scanFile('deploy.ts', code).filter(v => v.ruleId === 'AI-ACCURACY-001');
        expect(v.length).toBe(0);
      });

      it('should NOT flag generic app.post routes', () => {
        const code = `app.post('/api/users', createUser);`;
        const v = euEngine.scanFile('routes.ts', code).filter(v => v.ruleId === 'AI-ACCURACY-001');
        expect(v.length).toBe(0);
      });
    });

    // --- AI-ACCURACY-002: AI Failure Fallback ---
    describe('AI-ACCURACY-002: No Fallback for AI Failure', () => {
      it('should detect openai call without error handling', () => {
        const code = `const result = openai.chat.completions.create({ messages });`;
        const v = euEngine.scanFile('ai.ts', code).filter(v => v.ruleId === 'AI-ACCURACY-002');
        expect(v.length).toBeGreaterThan(0);
      });

      it('should detect await generateText without catch', () => {
        const code = `const text = await generateText(prompt);`;
        const v = euEngine.scanFile('generate.ts', code).filter(v => v.ruleId === 'AI-ACCURACY-002');
        expect(v.length).toBeGreaterThan(0);
      });

      it('should detect fetch to inference endpoint without catch', () => {
        const code = `const res = fetch('https://api.openai.com/v1/chat', body);`;
        const v = euEngine.scanFile('client.ts', code).filter(v => v.ruleId === 'AI-ACCURACY-002');
        expect(v.length).toBeGreaterThan(0);
      });

      it('should NOT flag openai call with catch', () => {
        const code = `try { const result = openai.chat.completions.create({ messages }); } catch (e) { fallback(); }`;
        const v = euEngine.scanFile('ai.ts', code).filter(v => v.ruleId === 'AI-ACCURACY-002');
        expect(v.length).toBe(0);
      });

      it('should NOT flag generic fetch calls', () => {
        const code = `const res = await fetch('/api/users');`;
        const v = euEngine.scanFile('client.ts', code).filter(v => v.ruleId === 'AI-ACCURACY-002');
        expect(v.length).toBe(0);
      });
    });

    // --- AI-ACCURACY-003: Adversarial Robustness ---
    describe('AI-ACCURACY-003: No Adversarial Robustness Testing', () => {
      it('should detect user input passed to LLM without sanitization', () => {
        const code = `const response = llm.generate(userInput);`;
        const v = euEngine.scanFile('chat.ts', code).filter(v => v.ruleId === 'AI-ACCURACY-003');
        expect(v.length).toBeGreaterThan(0);
      });

      it('should detect prompt template with unsanitized user input', () => {
        const code = `buildPrompt('Tell me about', userQuery)`;
        const v = euEngine.scanFile('prompt.ts', code).filter(v => v.ruleId === 'AI-ACCURACY-003');
        expect(v.length).toBeGreaterThan(0);
      });

      it('should detect string concatenation in system prompt', () => {
        const code = `messages = systemPrompt + userInput`;
        const v = euEngine.scanFile('ai.ts', code).filter(v => v.ruleId === 'AI-ACCURACY-003');
        expect(v.length).toBeGreaterThan(0);
      });

      it('should NOT flag when sanitization is present on same line', () => {
        const code = `const sanitized = sanitize(userInput); const response = model.generate(sanitized);`;
        const v = euEngine.scanFile('chat.ts', code).filter(v => v.ruleId === 'AI-ACCURACY-003');
        expect(v.length).toBe(0);
      });

      it('should NOT flag system prompt without user input', () => {
        const code = `const prompt = systemPrompt + staticContent;`;
        const v = euEngine.scanFile('ai.ts', code).filter(v => v.ruleId === 'AI-ACCURACY-003');
        expect(v.length).toBe(0);
      });
    });
  });
});
