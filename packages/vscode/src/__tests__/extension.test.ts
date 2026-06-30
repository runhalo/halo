/**
 * Halo VS Code Extension — Unit Tests
 * Tests engine integration and rule coverage without VS Code runtime
 */

import { HaloEngine, COPPA_RULES, Violation } from '@runhalo/engine';

describe('Halo VS Code Extension', () => {
  describe('Engine Integration', () => {
    it('should have access to HaloEngine', () => {
      const engine = new HaloEngine();
      expect(engine).toBeDefined();
    });

    it('should expose the public COPPA rule registry', () => {
      expect(COPPA_RULES).toHaveLength(21);
      expect(COPPA_RULES.every(rule => rule.id.startsWith('coppa'))).toBe(true);
    });

    it('should have correct rule IDs in order', () => {
      const expectedIds = [
        'coppa-auth-001', 'coppa-data-002', 'coppa-tracking-003',
        'coppa-geo-004', 'coppa-retention-005', 'coppa-sec-006',
        'coppa-audio-007', 'coppa-ui-008', 'coppa-flow-009',
        'coppa-sec-010', 'coppa-ext-011', 'coppa-bio-012',
        'coppa-notif-013', 'coppa-ugc-014', 'coppa-sec-015',
        'coppa-cookies-016', 'coppa-ext-017', 'coppa-analytics-018',
        'coppa-edu-019', 'coppa-default-020', 'coppa-ads-021'
      ];
      const actualIds = COPPA_RULES.map(r => r.id);
      expect(actualIds).toEqual(expectedIds);
    });

    it('should have valid severity for all rules', () => {
      const validSeverities = ['critical', 'high', 'medium', 'low'];
      COPPA_RULES.forEach(rule => {
        expect(validSeverities).toContain(rule.severity);
      });
    });

    it('should have fix suggestions for all rules', () => {
      COPPA_RULES.forEach(rule => {
        expect(rule.fixSuggestion.length).toBeGreaterThan(0);
      });
    });

    it('should have penalty information for all rules', () => {
      COPPA_RULES.forEach(rule => {
        expect(rule.penalty.length).toBeGreaterThan(0);
      });
    });
  });

  describe('Scanning — Simulated IDE Workflow', () => {
    const engine = new HaloEngine({ suppressions: { enabled: true } });

    it('should scan TypeScript file and return violations', () => {
      const code = `import { signInWithPopup } from 'firebase/auth';
signInWithPopup(auth, provider);`;
      const violations = engine.scanFile('src/auth.ts', code);
      expect(violations.length).toBeGreaterThan(0);
      expect(violations[0].ruleId).toBe('coppa-auth-001');
      expect(violations[0].filePath).toBe('src/auth.ts');
    });

    it('should return line and column numbers for IDE gutter markers', () => {
      const code = `fbq('init', '123');`;
      const violations = engine.scanFile('analytics.js', code);
      expect(violations.length).toBeGreaterThan(0);
      expect(violations[0].line).toBe(1);
      expect(violations[0].column).toBeGreaterThan(0);
    });

    it('should return empty array for clean files', () => {
      const code = `function hello() { console.log("Hello"); }`;
      const violations = engine.scanFile('clean.ts', code);
      expect(violations).toEqual([]);
    });

    it('should respect same-line suppression comments', () => {
      const code = `fbq('init', '123'); // halo-ignore: coppa-tracking-003`;
      const violations = engine.scanFile('test.ts', code);
      expect(violations.filter(v => v.ruleId === 'coppa-tracking-003').length).toBe(0);
    });

    it('should respect next-line suppression comments', () => {
      const code = `// halo-ignore: coppa-tracking-003
fbq('init', '123');`;
      const violations = engine.scanFile('test.ts', code);
      expect(violations.filter(v => v.ruleId === 'coppa-tracking-003').length).toBe(0);
    });

    it('should detect multiple violation types in one file', () => {
      const code = `fbq('init', '123');
navigator.geolocation.getCurrentPosition(success, error);
element.innerHTML = userInput;`;
      const violations = engine.scanFile('mixed.ts', code);
      const ruleIds = [...new Set(violations.map(v => v.ruleId))];
      expect(ruleIds.length).toBeGreaterThanOrEqual(3);
    });
  });

  describe('Severity Mapping', () => {
    it('should categorize critical rules correctly', () => {
      const criticalRules = COPPA_RULES.filter(r => r.severity === 'critical');
      const criticalIds = criticalRules.map(r => r.id);
      expect(criticalIds).toContain('coppa-auth-001');
      expect(criticalIds).toContain('coppa-tracking-003');
      expect(criticalIds).toContain('coppa-sec-006');
      expect(criticalIds).toContain('coppa-bio-012');
      expect(criticalIds).toContain('coppa-default-020');
    });

    it('should have at least one rule per severity level', () => {
      const severityCounts = {
        critical: COPPA_RULES.filter(r => r.severity === 'critical').length,
        high: COPPA_RULES.filter(r => r.severity === 'high').length,
        medium: COPPA_RULES.filter(r => r.severity === 'medium').length,
        low: COPPA_RULES.filter(r => r.severity === 'low').length,
      };
      expect(severityCounts.critical).toBeGreaterThan(0);
      expect(severityCounts.high).toBeGreaterThan(0);
      expect(severityCounts.medium).toBeGreaterThan(0);
      expect(severityCounts.low).toBeGreaterThan(0);
    });
  });

  describe('Explain Rule', () => {
    const engine = new HaloEngine();

    it('should explain all public COPPA rules', () => {
      COPPA_RULES.forEach(rule => {
        const explanation = engine.explainRule(rule.id);
        expect(explanation).toContain(rule.id);
        expect(explanation).not.toContain('not found');
        expect(explanation.length).toBeGreaterThan(50);
      });
    });

    it('should return "not found" for unknown rule', () => {
      const explanation = engine.explainRule('coppa-fake-999');
      expect(explanation).toContain('not found');
    });
  });

  describe('Fix Suggestions', () => {
    const engine = new HaloEngine();

    it('should provide fix for coppa-auth-001', () => {
      const fix = engine.getFixSuggestion('coppa-auth-001');
      expect(fix).toContain('age');
    });

    it('should provide fix for coppa-tracking-003', () => {
      const fix = engine.getFixSuggestion('coppa-tracking-003');
      expect(fix).toContain('child_directed_treatment');
    });

    it('should return "not found" for unknown rule', () => {
      const fix = engine.getFixSuggestion('coppa-fake-999');
      expect(fix).toContain('not found');
    });
  });
});
