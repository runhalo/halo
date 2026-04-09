/**
 * Halo Compliance Score Engine — Unit Tests
 *  Weighted scoring model tests
 */

import { ComplianceScoreEngine } from '../scoring';
import type { ComplianceScoreResult, LetterGrade } from '../scoring';
import type { Violation } from '../index';

// Helper to create a minimal violation
function makeViolation(overrides: Partial<Violation>): Violation {
  return {
    ruleId: '',
    ruleName: '',
    severity: 'medium',
    filePath: 'test.ts',
    line: 1,
    column: 1,
    message: '',
    codeSnippet: '',
    fixSuggestion: '',
    ...overrides,
  };
}

describe('ComplianceScoreEngine', () => {
  let engine: ComplianceScoreEngine;

  beforeEach(() => {
    engine = new ComplianceScoreEngine();
  });

  // ==================== Grade Thresholds ====================

  describe('getGrade', () => {
    it('should return A for scores 90-100', () => {
      expect(engine.getGrade(100)).toBe('A');
      expect(engine.getGrade(95)).toBe('A');
      expect(engine.getGrade(90)).toBe('A');
    });

    it('should return B for scores 75-89', () => {
      expect(engine.getGrade(89)).toBe('B');
      expect(engine.getGrade(80)).toBe('B');
      expect(engine.getGrade(75)).toBe('B');
    });

    it('should return C for scores 60-74', () => {
      expect(engine.getGrade(74)).toBe('C');
      expect(engine.getGrade(65)).toBe('C');
      expect(engine.getGrade(60)).toBe('C');
    });

    it('should return D for scores 40-59', () => {
      expect(engine.getGrade(59)).toBe('D');
      expect(engine.getGrade(50)).toBe('D');
      expect(engine.getGrade(40)).toBe('D');
    });

    it('should return F for scores 0-39', () => {
      expect(engine.getGrade(39)).toBe('F');
      expect(engine.getGrade(20)).toBe('F');
      expect(engine.getGrade(0)).toBe('F');
    });
  });

  // ==================== calculate() ====================

  describe('calculate', () => {
    it('should return perfect score with no violations', () => {
      const result = engine.calculate([], 10);
      expect(result.score).toBe(100);
      expect(result.grade).toBe('A');
      expect(result.totalViolations).toBe(0);
      expect(result.pointsDeducted).toBe(0);
      expect(result.filesScanned).toBe(10);
      expect(result.rulesTriggered).toEqual([]);
      expect(result.bySeverity).toEqual({ critical: 0, high: 0, medium: 0, low: 0 });
    });

    it('should deduct 10 points per critical violation', () => {
      const violations = [
        makeViolation({ ruleId: 'coppa-auth-001', severity: 'critical' }),
      ];
      const result = engine.calculate(violations, 5);
      expect(result.score).toBe(90);
      expect(result.grade).toBe('A');
      expect(result.pointsDeducted).toBe(10);
      expect(result.bySeverity.critical).toBe(1);
    });

    it('should deduct 5 points per high violation', () => {
      const violations = [
        makeViolation({ ruleId: 'coppa-sec-006', severity: 'high' }),
        makeViolation({ ruleId: 'coppa-sec-010', severity: 'high' }),
      ];
      const result = engine.calculate(violations, 5);
      expect(result.score).toBe(90);
      expect(result.grade).toBe('A');
      expect(result.pointsDeducted).toBe(10);
      expect(result.bySeverity.high).toBe(2);
    });

    it('should deduct 2 points per medium violation', () => {
      const violations = [
        makeViolation({ ruleId: 'coppa-cookies-016', severity: 'medium' }),
        makeViolation({ ruleId: 'coppa-notif-019', severity: 'medium' }),
        makeViolation({ ruleId: 'coppa-default-020', severity: 'medium' }),
      ];
      const result = engine.calculate(violations, 5);
      expect(result.score).toBe(94);
      expect(result.grade).toBe('A');
      expect(result.pointsDeducted).toBe(6);
      expect(result.bySeverity.medium).toBe(3);
    });

    it('should deduct 1 point per low violation', () => {
      const violations = [
        makeViolation({ ruleId: 'coppa-sec-007', severity: 'low' }),
        makeViolation({ ruleId: 'coppa-sec-008', severity: 'low' }),
      ];
      const result = engine.calculate(violations, 5);
      expect(result.score).toBe(98);
      expect(result.grade).toBe('A');
      expect(result.pointsDeducted).toBe(2);
      expect(result.bySeverity.low).toBe(2);
    });

    it('should handle mixed severity violations', () => {
      const violations = [
        makeViolation({ ruleId: 'coppa-auth-001', severity: 'critical' }),
        makeViolation({ ruleId: 'coppa-sec-006', severity: 'high' }),
        makeViolation({ ruleId: 'coppa-cookies-016', severity: 'medium' }),
        makeViolation({ ruleId: 'coppa-sec-007', severity: 'low' }),
      ];
      const result = engine.calculate(violations, 10);
      // 100 - 10 - 5 - 2 - 1 = 82
      expect(result.score).toBe(82);
      expect(result.grade).toBe('B');
      expect(result.pointsDeducted).toBe(18);
      expect(result.totalViolations).toBe(4);
      expect(result.bySeverity).toEqual({ critical: 1, high: 1, medium: 1, low: 1 });
    });

    it('should floor score at 0 (never go negative)', () => {
      const violations = Array.from({ length: 15 }, (_, i) =>
        makeViolation({ ruleId: `coppa-auth-00${i}`, severity: 'critical' })
      );
      const result = engine.calculate(violations, 5);
      // 15 critical × 10 = 150 deducted, but floor at 0
      expect(result.score).toBe(0);
      expect(result.grade).toBe('F');
      expect(result.pointsDeducted).toBe(150);
    });

    it('should track unique rules triggered (sorted)', () => {
      const violations = [
        makeViolation({ ruleId: 'coppa-sec-010', severity: 'high' }),
        makeViolation({ ruleId: 'coppa-auth-001', severity: 'critical' }),
        makeViolation({ ruleId: 'coppa-sec-010', severity: 'high' }), // duplicate
        makeViolation({ ruleId: 'coppa-cookies-016', severity: 'medium' }),
      ];
      const result = engine.calculate(violations, 5);
      expect(result.rulesTriggered).toEqual([
        'coppa-auth-001',
        'coppa-cookies-016',
        'coppa-sec-010',
      ]);
    });

    it('should pass through filesScanned count', () => {
      const result = engine.calculate([], 42);
      expect(result.filesScanned).toBe(42);
    });

    it('should default filesScanned to 0', () => {
      const result = engine.calculate([]);
      expect(result.filesScanned).toBe(0);
    });

    // ==================== Realistic Scenarios ====================

    it('should score a clean repo as 100/A', () => {
      const result = engine.calculate([], 500);
      expect(result.score).toBe(100);
      expect(result.grade).toBe('A');
      expect(result.summary).toContain('No violations found');
    });

    it('should score a repo with minor issues as B', () => {
      // 3 high + 2 medium = 15 + 4 = 19 deducted → 81/B
      const violations = [
        makeViolation({ ruleId: 'coppa-sec-006', severity: 'high' }),
        makeViolation({ ruleId: 'coppa-sec-010', severity: 'high' }),
        makeViolation({ ruleId: 'coppa-sec-015', severity: 'high' }),
        makeViolation({ ruleId: 'coppa-cookies-016', severity: 'medium' }),
        makeViolation({ ruleId: 'coppa-default-020', severity: 'medium' }),
      ];
      const result = engine.calculate(violations, 100);
      expect(result.score).toBe(81);
      expect(result.grade).toBe('B');
    });

    it('should score a repo like Habitica (many violations) appropriately', () => {
      // Simulate: 689 violations, mostly medium/low
      // Say 5 critical, 20 high, 200 medium, 464 low
      // 5×10 + 20×5 + 200×2 + 464×1 = 50 + 100 + 400 + 464 = 1014
      // Score = max(0, 100 - 1014) = 0/F
      const violations: Violation[] = [];
      for (let i = 0; i < 5; i++) violations.push(makeViolation({ ruleId: 'r-c', severity: 'critical' }));
      for (let i = 0; i < 20; i++) violations.push(makeViolation({ ruleId: 'r-h', severity: 'high' }));
      for (let i = 0; i < 200; i++) violations.push(makeViolation({ ruleId: 'r-m', severity: 'medium' }));
      for (let i = 0; i < 464; i++) violations.push(makeViolation({ ruleId: 'r-l', severity: 'low' }));
      const result = engine.calculate(violations, 500);
      expect(result.score).toBe(0);
      expect(result.grade).toBe('F');
      expect(result.totalViolations).toBe(689);
    });

    it('should score a well-maintained repo with few issues as A', () => {
      // 2 low = 2 deducted → 98/A
      const violations = [
        makeViolation({ ruleId: 'coppa-sec-007', severity: 'low' }),
        makeViolation({ ruleId: 'coppa-sec-008', severity: 'low' }),
      ];
      const result = engine.calculate(violations, 200);
      expect(result.score).toBe(98);
      expect(result.grade).toBe('A');
    });

    it('should score edge case: exactly on grade boundary', () => {
      // Score = 90 → A
      const v90 = [makeViolation({ ruleId: 'r', severity: 'critical' })]; // -10
      expect(engine.calculate(v90).score).toBe(90);
      expect(engine.calculate(v90).grade).toBe('A');

      // Score = 89 → B
      const v89 = [
        makeViolation({ ruleId: 'r', severity: 'critical' }),
        makeViolation({ ruleId: 'r2', severity: 'low' }),
      ]; // -11
      expect(engine.calculate(v89).score).toBe(89);
      expect(engine.calculate(v89).grade).toBe('B');

      // Score = 75 → B
      const v75: Violation[] = [];
      for (let i = 0; i < 5; i++) v75.push(makeViolation({ ruleId: 'r', severity: 'high' })); // -25
      expect(engine.calculate(v75).score).toBe(75);
      expect(engine.calculate(v75).grade).toBe('B');

      // Score = 60 → C
      const v60: Violation[] = [];
      for (let i = 0; i < 4; i++) v60.push(makeViolation({ ruleId: 'r', severity: 'critical' })); // -40
      expect(engine.calculate(v60).score).toBe(60);
      expect(engine.calculate(v60).grade).toBe('C');

      // Score = 40 → D
      const v40: Violation[] = [];
      for (let i = 0; i < 6; i++) v40.push(makeViolation({ ruleId: 'r', severity: 'critical' })); // -60
      expect(engine.calculate(v40).score).toBe(40);
      expect(engine.calculate(v40).grade).toBe('D');

      // Score = 39 → F
      const v39: Violation[] = [];
      for (let i = 0; i < 6; i++) v39.push(makeViolation({ ruleId: 'r', severity: 'critical' })); // -60
      v39.push(makeViolation({ ruleId: 'r2', severity: 'low' })); // -1 more
      expect(engine.calculate(v39).score).toBe(39);
      expect(engine.calculate(v39).grade).toBe('F');
    });
  });

  // ==================== formatSummary ====================

  describe('formatSummary', () => {
    it('should format zero violations', () => {
      const summary = engine.formatSummary(100, 'A', 0, { critical: 0, high: 0, medium: 0, low: 0 });
      expect(summary).toBe('COPPA Compliance Score: 100/100 (A) — No violations found');
    });

    it('should format single critical violation', () => {
      const summary = engine.formatSummary(90, 'A', 1, { critical: 1, high: 0, medium: 0, low: 0 });
      expect(summary).toBe('COPPA Compliance Score: 90/100 (A) — 1 violation(s): 1 critical');
    });

    it('should format mixed severity violations', () => {
      const summary = engine.formatSummary(82, 'B', 4, { critical: 1, high: 1, medium: 1, low: 1 });
      expect(summary).toBe('COPPA Compliance Score: 82/100 (B) — 4 violation(s): 1 critical, 1 high, 1 medium, 1 low');
    });

    it('should only include non-zero severity counts', () => {
      const summary = engine.formatSummary(90, 'A', 2, { critical: 0, high: 2, medium: 0, low: 0 });
      expect(summary).toBe('COPPA Compliance Score: 90/100 (A) — 2 violation(s): 2 high');
    });

    it('should format F grade correctly', () => {
      const summary = engine.formatSummary(0, 'F', 50, { critical: 5, high: 10, medium: 15, low: 20 });
      expect(summary).toBe('COPPA Compliance Score: 0/100 (F) — 50 violation(s): 5 critical, 10 high, 15 medium, 20 low');
    });
  });

  // ==================== Integration with calculate() ====================

  describe('calculate summary integration', () => {
    it('should include correct summary in result', () => {
      const violations = [
        makeViolation({ ruleId: 'coppa-auth-001', severity: 'critical' }),
        makeViolation({ ruleId: 'coppa-sec-006', severity: 'high' }),
      ];
      const result = engine.calculate(violations, 10);
      expect(result.summary).toBe('COPPA Compliance Score: 85/100 (B) — 2 violation(s): 1 critical, 1 high');
    });

    it('should include correct summary for clean scan', () => {
      const result = engine.calculate([], 100);
      expect(result.summary).toBe('COPPA Compliance Score: 100/100 (A) — No violations found');
    });
  });
});
