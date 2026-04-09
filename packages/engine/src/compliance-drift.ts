/**
 * Compliance Drift Detection
 *
 *  Detects compliance posture changes between scans.
 * Used by recurring scan infrastructure to alert on regressions.
 *
 * Don't Go Backwards Rule: This is an enrichment module.
 * If drift detection fails, the scan continues without alerts.
 */

export interface ScanSnapshot {
  id: string;
  scanDate: string;
  grade: string;
  score: number;
  totalViolations: number;
  bySeverity: { critical: number; high: number; medium: number; low: number };
  findingsAdded: number;
  findingsResolved: number;
}

export interface DriftAlert {
  type: 'regression' | 'improvement' | 'new_critical' | 'grade_change';
  severity: 'critical' | 'warning' | 'info';
  message: string;
  details: string;
  previousValue: string;
  currentValue: string;
}

export interface DriftAnalysis {
  alerts: DriftAlert[];
  hasRegression: boolean;
  hasImprovement: boolean;
  scoreDelta: number;
  gradeChanged: boolean;
  summary: string;
}

/**
 * Analyze compliance drift between two scan snapshots.
 */
export function analyzeDrift(current: ScanSnapshot, previous: ScanSnapshot): DriftAnalysis {
  const alerts: DriftAlert[] = [];
  const scoreDelta = current.score - previous.score;
  const gradeChanged = current.grade !== previous.grade;

  // Grade change
  if (gradeChanged) {
    const gradeOrder = ['F', 'D', 'C', 'B', 'A'];
    const prevIdx = gradeOrder.indexOf(previous.grade);
    const currIdx = gradeOrder.indexOf(current.grade);
    const isRegression = currIdx < prevIdx;

    alerts.push({
      type: 'grade_change',
      severity: isRegression ? 'critical' : 'info',
      message: isRegression
        ? `Grade dropped from ${previous.grade} to ${current.grade}`
        : `Grade improved from ${previous.grade} to ${current.grade}`,
      details: `Score: ${previous.score} → ${current.score} (${scoreDelta > 0 ? '+' : ''}${scoreDelta})`,
      previousValue: previous.grade,
      currentValue: current.grade,
    });
  }

  // Score regression
  if (scoreDelta < -5) {
    alerts.push({
      type: 'regression',
      severity: scoreDelta < -15 ? 'critical' : 'warning',
      message: `Compliance score dropped by ${Math.abs(scoreDelta)} points`,
      details: `${previous.score}/100 → ${current.score}/100`,
      previousValue: `${previous.score}`,
      currentValue: `${current.score}`,
    });
  }

  // Score improvement
  if (scoreDelta > 5) {
    alerts.push({
      type: 'improvement',
      severity: 'info',
      message: `Compliance score improved by ${scoreDelta} points`,
      details: `${previous.score}/100 → ${current.score}/100`,
      previousValue: `${previous.score}`,
      currentValue: `${current.score}`,
    });
  }

  // New critical findings
  const newCritical = current.bySeverity.critical - previous.bySeverity.critical;
  if (newCritical > 0) {
    alerts.push({
      type: 'new_critical',
      severity: 'critical',
      message: `${newCritical} new critical finding${newCritical !== 1 ? 's' : ''} detected`,
      details: `Critical findings: ${previous.bySeverity.critical} → ${current.bySeverity.critical}`,
      previousValue: `${previous.bySeverity.critical}`,
      currentValue: `${current.bySeverity.critical}`,
    });
  }

  // Net findings change
  if (current.findingsAdded > 0) {
    alerts.push({
      type: 'regression',
      severity: 'warning',
      message: `${current.findingsAdded} new finding${current.findingsAdded !== 1 ? 's' : ''} introduced`,
      details: current.findingsResolved > 0
        ? `+${current.findingsAdded} new, -${current.findingsResolved} resolved (net ${current.findingsAdded - current.findingsResolved > 0 ? '+' : ''}${current.findingsAdded - current.findingsResolved})`
        : `${current.findingsAdded} new finding(s)`,
      previousValue: `${previous.totalViolations}`,
      currentValue: `${current.totalViolations}`,
    });
  }

  if (current.findingsResolved > 0) {
    alerts.push({
      type: 'improvement',
      severity: 'info',
      message: `${current.findingsResolved} finding${current.findingsResolved !== 1 ? 's' : ''} resolved`,
      details: `Total: ${previous.totalViolations} → ${current.totalViolations}`,
      previousValue: `${previous.totalViolations}`,
      currentValue: `${current.totalViolations}`,
    });
  }

  const hasRegression = alerts.some(a => a.type === 'regression' || a.type === 'new_critical' || (a.type === 'grade_change' && a.severity !== 'info'));
  const hasImprovement = alerts.some(a => a.type === 'improvement' || (a.type === 'grade_change' && a.severity === 'info'));

  // Generate summary
  let summary: string;
  if (alerts.length === 0) {
    summary = `No change: Grade ${current.grade} (${current.score}/100), ${current.totalViolations} violations`;
  } else if (hasRegression && !hasImprovement) {
    summary = `Regression: Grade ${previous.grade}→${current.grade}, score ${scoreDelta > 0 ? '+' : ''}${scoreDelta}`;
  } else if (hasImprovement && !hasRegression) {
    summary = `Improvement: Grade ${previous.grade}→${current.grade}, score +${scoreDelta}`;
  } else {
    summary = `Mixed: ${alerts.filter(a => a.severity === 'critical').length} critical, ${alerts.filter(a => a.severity === 'warning').length} warnings, ${alerts.filter(a => a.severity === 'info').length} improvements`;
  }

  return {
    alerts,
    hasRegression,
    hasImprovement,
    scoreDelta,
    gradeChanged,
    summary,
  };
}

/**
 * Format drift analysis for CLI output.
 */
export function formatDriftCLI(analysis: DriftAnalysis): string {
  if (analysis.alerts.length === 0) return '';

  const lines: string[] = ['\n\u2500'.repeat(55), '\ud83d\udcca Compliance Drift Analysis'];

  for (const alert of analysis.alerts) {
    const icon = alert.severity === 'critical' ? '\u274c'
      : alert.severity === 'warning' ? '\u26a0\ufe0f'
      : '\u2705';
    lines.push(`  ${icon} ${alert.message}`);
    lines.push(`     ${alert.details}`);
  }

  lines.push('\u2500'.repeat(55));
  return lines.join('\n');
}

/**
 * Format drift analysis for Discord/Slack notifications.
 */
export function formatDriftNotification(analysis: DriftAnalysis): {
  title: string;
  color: string;
  fields: Array<{ name: string; value: string }>;
} {
  const color = analysis.hasRegression ? '#ef4444' : analysis.hasImprovement ? '#22c55e' : '#6366f1';

  return {
    title: analysis.summary,
    color,
    fields: analysis.alerts.map(a => ({
      name: `${a.severity === 'critical' ? '\u274c' : a.severity === 'warning' ? '\u26a0\ufe0f' : '\u2705'} ${a.message}`,
      value: a.details,
    })),
  };
}
