/**
 * Halo Compliance Score Engine
 * Weighted scoring model: severity × category weight → 0-100 score + letter grade
 *
 *  The single metric that transforms Halo from lint tool to compliance platform.
 *
 * Scoring model:
 *   Start at 100, deduct points per violation based on severity:
 *   - Critical: -10 points (auth, data collection, age gates — highest penalty exposure)
 *   - High:     -5 points  (XSS, weak crypto, geolocation — significant risk)
 *   - Medium:   -2 points  (public defaults, cookies, notifications — moderate risk)
 *   - Low:      -1 point   (HTTP in comments, minor UI patterns — cosmetic)
 *   Floor at 0. Letter grade: A (90+), B (75+), C (60+), D (40+), F (<40).
 */

import type { Violation, Severity } from './index';

// ==================== Types ====================

export type LetterGrade = 'A' | 'B' | 'C' | 'D' | 'F';

export interface ComplianceScoreResult {
  /** Numeric score 0-100 */
  score: number;
  /** Letter grade A-F */
  grade: LetterGrade;
  /** Total violations counted */
  totalViolations: number;
  /** Violations broken down by severity */
  bySeverity: Record<Severity, number>;
  /** Total points deducted */
  pointsDeducted: number;
  /** How many files were scanned */
  filesScanned: number;
  /** Unique rules that triggered */
  rulesTriggered: string[];
  /** Summary line for CLI output */
  summary: string;
}

// ==================== Constants ====================

/** Points deducted per violation by severity */
const SEVERITY_WEIGHTS: Record<Severity, number> = {
  critical: 10,
  high: 5,
  medium: 2,
  low: 1,
};

/** Score thresholds for letter grades */
const GRADE_THRESHOLDS: { min: number; grade: LetterGrade }[] = [
  { min: 90, grade: 'A' },
  { min: 75, grade: 'B' },
  { min: 60, grade: 'C' },
  { min: 40, grade: 'D' },
  { min: 0, grade: 'F' },
];

// ==================== Score Engine ====================

export class ComplianceScoreEngine {
  /**
   * Calculate compliance score from a set of violations.
   *
   * @param violations - All violations from a scan (unsuppressed only)
   * @param filesScanned - Number of files scanned (for context)
   * @returns ComplianceScoreResult with score, grade, and breakdown
   */
  calculate(violations: Violation[], filesScanned: number = 0): ComplianceScoreResult {
    const bySeverity: Record<Severity, number> = {
      critical: 0,
      high: 0,
      medium: 0,
      low: 0,
    };

    const rulesTriggered = new Set<string>();

    for (const v of violations) {
      bySeverity[v.severity] = (bySeverity[v.severity] || 0) + 1;
      rulesTriggered.add(v.ruleId);
    }

    const pointsDeducted =
      bySeverity.critical * SEVERITY_WEIGHTS.critical +
      bySeverity.high * SEVERITY_WEIGHTS.high +
      bySeverity.medium * SEVERITY_WEIGHTS.medium +
      bySeverity.low * SEVERITY_WEIGHTS.low;

    const score = Math.max(0, 100 - pointsDeducted);
    const grade = this.getGrade(score);

    const summary = this.formatSummary(score, grade, violations.length, bySeverity);

    return {
      score,
      grade,
      totalViolations: violations.length,
      bySeverity,
      pointsDeducted,
      filesScanned,
      rulesTriggered: Array.from(rulesTriggered).sort(),
      summary,
    };
  }

  /**
   * Get letter grade for a numeric score.
   */
  getGrade(score: number): LetterGrade {
    for (const threshold of GRADE_THRESHOLDS) {
      if (score >= threshold.min) {
        return threshold.grade;
      }
    }
    return 'F';
  }

  /**
   * Format a human-readable summary line for CLI output.
   */
  formatSummary(
    score: number,
    grade: LetterGrade,
    totalViolations: number,
    bySeverity: Record<Severity, number>
  ): string {
    if (totalViolations === 0) {
      return `COPPA Compliance Score: 100/100 (A) — No violations found`;
    }

    const parts: string[] = [];
    if (bySeverity.critical > 0) parts.push(`${bySeverity.critical} critical`);
    if (bySeverity.high > 0) parts.push(`${bySeverity.high} high`);
    if (bySeverity.medium > 0) parts.push(`${bySeverity.medium} medium`);
    if (bySeverity.low > 0) parts.push(`${bySeverity.low} low`);

    return `COPPA Compliance Score: ${score}/100 (${grade}) — ${totalViolations} violation(s): ${parts.join(', ')}`;
  }
}
