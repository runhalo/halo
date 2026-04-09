/**
 * Framework Allowlisting System - Unit Tests
 *
 * Validates that framework profiles correctly suppress and downgrade
 * COPPA violations based on built-in framework protections.
 */

import {
  getFrameworkProfile,
  listFrameworks,
  applyFrameworkOverrides,
} from '../frameworks';

/** Minimal violation factory for test fixtures. */
function makeViolation(ruleId: string, severity: string) {
  return {
    ruleId,
    severity,
    ruleName: `Test rule ${ruleId}`,
    filePath: 'test.ts',
    line: 1,
    column: 1,
    message: `Violation of ${ruleId}`,
    codeSnippet: '',
    fixSuggestion: '',
  };
}

describe('Framework Allowlisting System', () => {
  // ──────────────────────────────────────────────────────────
  // getFrameworkProfile
  // ──────────────────────────────────────────────────────────

  describe('getFrameworkProfile', () => {
    it('returns the correct profile for nextjs', () => {
      const profile = getFrameworkProfile('nextjs');
      expect(profile).not.toBeNull();
      expect(profile!.id).toBe('nextjs');
      expect(profile!.name).toBe('Next.js');
      expect(profile!.ecosystem).toBe('javascript');
      expect(profile!.handled_rules.length).toBeGreaterThan(0);
      expect(profile!.safe_patterns.length).toBeGreaterThan(0);
    });

    it('returns the correct profile for django', () => {
      const profile = getFrameworkProfile('django');
      expect(profile).not.toBeNull();
      expect(profile!.id).toBe('django');
      expect(profile!.name).toBe('Django');
      expect(profile!.ecosystem).toBe('python');
    });

    it('returns the correct profile for rails', () => {
      const profile = getFrameworkProfile('rails');
      expect(profile).not.toBeNull();
      expect(profile!.id).toBe('rails');
      expect(profile!.name).toBe('Ruby on Rails');
      expect(profile!.ecosystem).toBe('ruby');
    });

    it('returns null for an unknown framework', () => {
      const profile = getFrameworkProfile('unknown');
      expect(profile).toBeNull();
    });
  });

  // ──────────────────────────────────────────────────────────
  // listFrameworks
  // ──────────────────────────────────────────────────────────

  describe('listFrameworks', () => {
    it('returns all registered framework ids in sorted order', () => {
      const frameworks = listFrameworks();
      expect(frameworks).toEqual(['angular', 'django', 'nextjs', 'rails', 'react', 'vue']);
    });
  });

  // ──────────────────────────────────────────────────────────
  // applyFrameworkOverrides — Next.js
  // ──────────────────────────────────────────────────────────

  describe('applyFrameworkOverrides — Next.js', () => {
    it('suppresses coppa-sec-006 violations', () => {
      const violations = [
        makeViolation('coppa-sec-006', 'critical'),
        makeViolation('coppa-auth-001', 'critical'),
      ];

      const result = applyFrameworkOverrides(violations, 'nextjs');

      expect(result.violations).toHaveLength(1);
      expect(result.violations[0].ruleId).toBe('coppa-auth-001');
      expect(result.suppressedCount).toBe(1);
    });

    it('downgrades coppa-sec-015 severity to low', () => {
      const violations = [makeViolation('coppa-sec-015', 'medium')];

      const result = applyFrameworkOverrides(violations, 'nextjs');

      expect(result.violations).toHaveLength(1);
      expect(result.violations[0].ruleId).toBe('coppa-sec-015');
      expect(result.violations[0].severity).toBe('low');
      expect(result.downgradedCount).toBe(1);
    });

    it('does NOT suppress coppa-auth-001 (not in nextjs profile)', () => {
      const violations = [makeViolation('coppa-auth-001', 'critical')];

      const result = applyFrameworkOverrides(violations, 'nextjs');

      expect(result.violations).toHaveLength(1);
      expect(result.violations[0].ruleId).toBe('coppa-auth-001');
      expect(result.violations[0].severity).toBe('critical');
      expect(result.suppressedCount).toBe(0);
      expect(result.downgradedCount).toBe(0);
    });

    it('downgrades coppa-ext-017 to low', () => {
      const violations = [makeViolation('coppa-ext-017', 'medium')];

      const result = applyFrameworkOverrides(violations, 'nextjs');

      expect(result.violations).toHaveLength(1);
      expect(result.violations[0].severity).toBe('low');
      expect(result.downgradedCount).toBe(1);
    });

    it('downgrades coppa-cookies-016 to low', () => {
      const violations = [makeViolation('coppa-cookies-016', 'low')];

      const result = applyFrameworkOverrides(violations, 'nextjs');

      expect(result.violations).toHaveLength(1);
      expect(result.violations[0].severity).toBe('low');
      expect(result.downgradedCount).toBe(1);
    });
  });

  // ──────────────────────────────────────────────────────────
  // applyFrameworkOverrides — Django
  // ──────────────────────────────────────────────────────────

  describe('applyFrameworkOverrides — Django', () => {
    it('suppresses coppa-sec-015 violations', () => {
      const violations = [makeViolation('coppa-sec-015', 'medium')];

      const result = applyFrameworkOverrides(violations, 'django');

      expect(result.violations).toHaveLength(0);
      expect(result.suppressedCount).toBe(1);
    });

    it('suppresses coppa-sec-006 violations', () => {
      const violations = [makeViolation('coppa-sec-006', 'critical')];

      const result = applyFrameworkOverrides(violations, 'django');

      expect(result.violations).toHaveLength(0);
      expect(result.suppressedCount).toBe(1);
    });

    it('suppresses coppa-sec-010 violations', () => {
      const violations = [makeViolation('coppa-sec-010', 'medium')];

      const result = applyFrameworkOverrides(violations, 'django');

      expect(result.violations).toHaveLength(0);
      expect(result.suppressedCount).toBe(1);
    });

    it('downgrades coppa-retention-005 to low', () => {
      const violations = [makeViolation('coppa-retention-005', 'medium')];

      const result = applyFrameworkOverrides(violations, 'django');

      expect(result.violations).toHaveLength(1);
      expect(result.violations[0].severity).toBe('low');
      expect(result.downgradedCount).toBe(1);
    });
  });

  // ──────────────────────────────────────────────────────────
  // applyFrameworkOverrides — Rails
  // ──────────────────────────────────────────────────────────

  describe('applyFrameworkOverrides — Rails', () => {
    it('suppresses coppa-sec-015 violations', () => {
      const violations = [makeViolation('coppa-sec-015', 'medium')];

      const result = applyFrameworkOverrides(violations, 'rails');

      expect(result.violations).toHaveLength(0);
      expect(result.suppressedCount).toBe(1);
    });

    it('suppresses coppa-sec-006 violations', () => {
      const violations = [makeViolation('coppa-sec-006', 'critical')];

      const result = applyFrameworkOverrides(violations, 'rails');

      expect(result.violations).toHaveLength(0);
      expect(result.suppressedCount).toBe(1);
    });

    it('downgrades coppa-data-002 to low', () => {
      const violations = [makeViolation('coppa-data-002', 'high')];

      const result = applyFrameworkOverrides(violations, 'rails');

      expect(result.violations).toHaveLength(1);
      expect(result.violations[0].severity).toBe('low');
      expect(result.downgradedCount).toBe(1);
    });

    it('downgrades coppa-retention-005 to low', () => {
      const violations = [makeViolation('coppa-retention-005', 'medium')];

      const result = applyFrameworkOverrides(violations, 'rails');

      expect(result.violations).toHaveLength(1);
      expect(result.violations[0].severity).toBe('low');
      expect(result.downgradedCount).toBe(1);
    });
  });

  // ──────────────────────────────────────────────────────────
  // Counts and edge cases
  // ──────────────────────────────────────────────────────────

  describe('counts and edge cases', () => {
    it('returns correct combined counts for mixed suppress/downgrade', () => {
      const violations = [
        makeViolation('coppa-sec-006', 'critical'),   // suppress
        makeViolation('coppa-sec-015', 'medium'),      // downgrade
        makeViolation('coppa-ext-017', 'medium'),      // downgrade
        makeViolation('coppa-cookies-016', 'low'),     // downgrade
        makeViolation('coppa-auth-001', 'critical'),   // pass through
      ];

      const result = applyFrameworkOverrides(violations, 'nextjs');

      expect(result.suppressedCount).toBe(1);
      expect(result.downgradedCount).toBe(3);
      expect(result.violations).toHaveLength(4);
    });

    it('passes through all violations for an unknown framework', () => {
      const violations = [
        makeViolation('coppa-sec-006', 'critical'),
        makeViolation('coppa-sec-015', 'medium'),
      ];

      const result = applyFrameworkOverrides(violations, 'unknown-framework');

      expect(result.violations).toHaveLength(2);
      expect(result.suppressedCount).toBe(0);
      expect(result.downgradedCount).toBe(0);
    });

    it('handles an empty violations array', () => {
      const result = applyFrameworkOverrides([], 'nextjs');

      expect(result.violations).toHaveLength(0);
      expect(result.suppressedCount).toBe(0);
      expect(result.downgradedCount).toBe(0);
    });

    it('does not mutate the original violations array', () => {
      const original = makeViolation('coppa-sec-015', 'medium');
      const violations = [original];

      applyFrameworkOverrides(violations, 'nextjs');

      // Original violation object should retain its original severity
      expect(original.severity).toBe('medium');
    });

    it('does not mutate the original violations array reference', () => {
      const violations = [
        makeViolation('coppa-sec-006', 'critical'),
        makeViolation('coppa-auth-001', 'critical'),
      ];

      const result = applyFrameworkOverrides(violations, 'nextjs');

      // Original array should still have both items
      expect(violations).toHaveLength(2);
      // Result should have only the non-suppressed one
      expect(result.violations).toHaveLength(1);
    });
  });
});
