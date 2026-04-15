import { analyzeDrift, formatDriftCLI, formatDriftNotification, ScanSnapshot } from '../compliance-drift';

const baseSnapshot: ScanSnapshot = {
  id: 'snap-1',
  scanDate: '2026-03-15T00:00:00Z',
  grade: 'B',
  score: 78,
  totalViolations: 12,
  bySeverity: { critical: 1, high: 3, medium: 5, low: 3 },
  findingsAdded: 0,
  findingsResolved: 0,
};

function snap(overrides: Partial<ScanSnapshot>): ScanSnapshot {
  return { ...baseSnapshot, ...overrides };
}

describe('ComplianceDrift', () => {
  describe('analyzeDrift', () => {
    it('detects no change', () => {
      const result = analyzeDrift(snap({ id: 'snap-2' }), baseSnapshot);
      expect(result.alerts).toHaveLength(0);
      expect(result.hasRegression).toBe(false);
      expect(result.hasImprovement).toBe(false);
      expect(result.scoreDelta).toBe(0);
    });

    it('detects grade regression', () => {
      const current = snap({ id: 'snap-2', grade: 'D', score: 55 });
      const result = analyzeDrift(current, baseSnapshot);
      expect(result.gradeChanged).toBe(true);
      expect(result.hasRegression).toBe(true);
      const gradeAlert = result.alerts.find(a => a.type === 'grade_change');
      expect(gradeAlert).toBeDefined();
      expect(gradeAlert!.severity).toBe('critical');
      expect(gradeAlert!.message).toContain('dropped from B to D');
    });

    it('detects grade improvement', () => {
      const current = snap({ id: 'snap-2', grade: 'A', score: 92 });
      const result = analyzeDrift(current, baseSnapshot);
      expect(result.gradeChanged).toBe(true);
      expect(result.hasImprovement).toBe(true);
      const gradeAlert = result.alerts.find(a => a.type === 'grade_change');
      expect(gradeAlert!.severity).toBe('info');
      expect(gradeAlert!.message).toContain('improved from B to A');
    });

    it('detects score regression > 5 points', () => {
      const current = snap({ id: 'snap-2', score: 70 });
      const result = analyzeDrift(current, baseSnapshot);
      expect(result.scoreDelta).toBe(-8);
      const scoreAlert = result.alerts.find(a => a.type === 'regression' && a.message.includes('score'));
      expect(scoreAlert).toBeDefined();
      expect(scoreAlert!.severity).toBe('warning');
    });

    it('marks severe regression as critical (>15 points)', () => {
      const current = snap({ id: 'snap-2', score: 50, grade: 'D' });
      const result = analyzeDrift(current, baseSnapshot);
      const scoreAlert = result.alerts.find(a => a.type === 'regression' && a.message.includes('score'));
      expect(scoreAlert!.severity).toBe('critical');
    });

    it('detects score improvement > 5 points', () => {
      const current = snap({ id: 'snap-2', score: 88, grade: 'A' });
      const result = analyzeDrift(current, baseSnapshot);
      expect(result.hasImprovement).toBe(true);
      const impAlert = result.alerts.find(a => a.type === 'improvement' && a.message.includes('score'));
      expect(impAlert).toBeDefined();
    });

    it('detects new critical findings', () => {
      const current = snap({
        id: 'snap-2',
        bySeverity: { critical: 3, high: 3, medium: 5, low: 3 },
      });
      const result = analyzeDrift(current, baseSnapshot);
      const critAlert = result.alerts.find(a => a.type === 'new_critical');
      expect(critAlert).toBeDefined();
      expect(critAlert!.severity).toBe('critical');
      expect(critAlert!.message).toContain('2 new critical');
    });

    it('detects new findings added', () => {
      const current = snap({ id: 'snap-2', findingsAdded: 5, totalViolations: 17 });
      const result = analyzeDrift(current, baseSnapshot);
      const addedAlert = result.alerts.find(a => a.message.includes('new finding'));
      expect(addedAlert).toBeDefined();
    });

    it('detects findings resolved', () => {
      const current = snap({ id: 'snap-2', findingsResolved: 3, totalViolations: 9 });
      const result = analyzeDrift(current, baseSnapshot);
      const resolvedAlert = result.alerts.find(a => a.message.includes('resolved'));
      expect(resolvedAlert).toBeDefined();
      expect(resolvedAlert!.type).toBe('improvement');
    });

    it('handles mixed regression and improvement', () => {
      const current = snap({
        id: 'snap-2',
        score: 75,
        grade: 'B',
        findingsAdded: 3,
        findingsResolved: 5,
        totalViolations: 10,
      });
      const result = analyzeDrift(current, baseSnapshot);
      expect(result.hasRegression).toBe(true);
      expect(result.hasImprovement).toBe(true);
      expect(result.summary).toContain('Mixed');
    });

    it('generates correct summary for pure regression', () => {
      const current = snap({ id: 'snap-2', score: 60, grade: 'D' });
      const result = analyzeDrift(current, baseSnapshot);
      expect(result.summary).toContain('Regression');
    });

    it('generates correct summary for pure improvement', () => {
      const current = snap({ id: 'snap-2', score: 92, grade: 'A' });
      const result = analyzeDrift(current, baseSnapshot);
      expect(result.summary).toContain('Improvement');
    });

    it('ignores small score changes (<=5)', () => {
      const current = snap({ id: 'snap-2', score: 75 });
      const result = analyzeDrift(current, baseSnapshot);
      // Score delta is -3, should not trigger score regression alert
      const scoreAlert = result.alerts.find(a => a.message.includes('score'));
      expect(scoreAlert).toBeUndefined();
    });
  });

  describe('formatDriftCLI', () => {
    it('returns empty string when no alerts', () => {
      const analysis = analyzeDrift(snap({ id: 'snap-2' }), baseSnapshot);
      expect(formatDriftCLI(analysis)).toBe('');
    });

    it('formats alerts with icons', () => {
      const current = snap({ id: 'snap-2', score: 50, grade: 'D' });
      const output = formatDriftCLI(analyzeDrift(current, baseSnapshot));
      expect(output).toContain('Compliance Drift Analysis');
      expect(output.length).toBeGreaterThan(0);
    });
  });

  describe('formatDriftNotification', () => {
    it('uses red color for regression', () => {
      const current = snap({ id: 'snap-2', score: 50, grade: 'D' });
      const notif = formatDriftNotification(analyzeDrift(current, baseSnapshot));
      expect(notif.color).toBe('#ef4444');
    });

    it('uses green color for improvement', () => {
      const current = snap({ id: 'snap-2', score: 92, grade: 'A' });
      const notif = formatDriftNotification(analyzeDrift(current, baseSnapshot));
      expect(notif.color).toBe('#22c55e');
    });

    it('returns fields for each alert', () => {
      const current = snap({ id: 'snap-2', score: 50, grade: 'D' });
      const notif = formatDriftNotification(analyzeDrift(current, baseSnapshot));
      expect(notif.fields.length).toBeGreaterThan(0);
    });
  });
});
