/**
 * COPPA 2.0 Countdown Utility
 *
 * tier-gated: Shared across all output surfaces (CLI, GitHub Action, PDF, dashboard).
 * COPPA 2.0 enforcement begins April 22, 2026.
 * Maximum penalty: $53,088 per violation per day.
 *
 * Don't Go Backwards Rule: Every customer touchpoint includes this countdown.
 */

const COPPA_2_ENFORCEMENT_DATE = new Date('2026-04-22T00:00:00Z');
const PENALTY_PER_VIOLATION_PER_DAY = 53088;

export interface CoppaCountdown {
  /** Days until enforcement (0 if already active) */
  days: number;
  /** Human-readable message */
  message: string;
  /** Whether COPPA 2.0 is currently in effect */
  isActive: boolean;
  /** The enforcement date */
  enforcementDate: Date;
  /** Maximum penalty per violation per day */
  penaltyPerDay: number;
}

/**
 * Get the current COPPA 2.0 countdown status.
 * Used by every output surface in Halo.
 */
export function getCoppaCountdown(now?: Date): CoppaCountdown {
  const currentDate = now || new Date();
  const diffMs = COPPA_2_ENFORCEMENT_DATE.getTime() - currentDate.getTime();
  const days = Math.max(0, Math.ceil(diffMs / 86400000));

  if (days > 0) {
    return {
      days,
      message: `COPPA 2.0 enforcement begins April 22, 2026 \u2014 ${days} day${days === 1 ? '' : 's'}`,
      isActive: false,
      enforcementDate: COPPA_2_ENFORCEMENT_DATE,
      penaltyPerDay: PENALTY_PER_VIOLATION_PER_DAY,
    };
  }

  return {
    days: 0,
    message: 'COPPA 2.0 is NOW IN EFFECT',
    isActive: true,
    enforcementDate: COPPA_2_ENFORCEMENT_DATE,
    penaltyPerDay: PENALTY_PER_VIOLATION_PER_DAY,
  };
}

/**
 * Format the COPPA countdown for CLI output (with ANSI colors).
 */
export function formatCoppaCountdownCLI(countdown?: CoppaCountdown): string {
  const cd = countdown || getCoppaCountdown();
  const lines = [
    '\u2500'.repeat(55),
  ];

  if (cd.isActive) {
    lines.push(`\x1b[31m\x1b[1m\u26a0\ufe0f  COPPA 2.0 is NOW IN EFFECT\x1b[0m`);
    lines.push(`   Maximum penalty: $${cd.penaltyPerDay.toLocaleString()}/violation/day`);
  } else {
    lines.push(`\x1b[33m\u26a0\ufe0f  ${cd.message}\x1b[0m`);
    lines.push(`   Maximum penalty: $${cd.penaltyPerDay.toLocaleString()}/violation/day`);
  }

  lines.push('\u2500'.repeat(55));
  return lines.join('\n');
}

/**
 * Format the COPPA countdown for GitHub Action PR comments (Markdown).
 */
export function formatCoppaCountdownMarkdown(countdown?: CoppaCountdown): string {
  const cd = countdown || getCoppaCountdown();

  if (cd.isActive) {
    return [
      '---',
      `> \u26a0\ufe0f **COPPA 2.0 is NOW IN EFFECT**`,
      `> Maximum penalty: $${cd.penaltyPerDay.toLocaleString()} per violation per day`,
      `> Run \`npx @runhalo/cli scan . --review\` for AI-verified compliance check`,
    ].join('\n');
  }

  return [
    '---',
    `> \u26a0\ufe0f **COPPA 2.0 enforcement begins April 22, 2026 \u2014 ${cd.days} day${cd.days === 1 ? '' : 's'}**`,
    `> Maximum penalty: $${cd.penaltyPerDay.toLocaleString()} per violation per day`,
    `> Run \`npx @runhalo/cli scan . --review\` for AI-verified compliance check`,
  ].join('\n');
}

/**
 * Format for PDF report headers.
 */
export function formatCoppaCountdownPDF(countdown?: CoppaCountdown): {
  text: string;
  severity: 'urgent' | 'warning' | 'active';
} {
  const cd = countdown || getCoppaCountdown();

  if (cd.isActive) {
    return {
      text: 'COPPA 2.0 IS NOW IN EFFECT — Ensure ongoing compliance',
      severity: 'active',
    };
  }

  if (cd.days <= 30) {
    return {
      text: `COPPA 2.0 ENFORCEMENT IN ${cd.days} DAYS — April 22, 2026`,
      severity: 'urgent',
    };
  }

  return {
    text: `COPPA 2.0 enforcement begins April 22, 2026 (${cd.days} days)`,
    severity: 'warning',
  };
}

// ─── Auto-Rotating Regulatory Deadlines ────────────────

export interface RegulatoryDeadline {
  name: string;
  date: Date;
  jurisdiction: string;
  penalty: string;
  isActive: boolean;
  daysUntil: number;
}

const REGULATORY_DEADLINES = [
  { name: 'COPPA 2.0', date: '2026-04-22', jurisdiction: 'Federal (US)', penalty: '$53,088/violation/day' },
  { name: 'Utah ASAA', date: '2026-05-06', jurisdiction: 'Utah', penalty: 'TBD' },
  { name: 'SC AADC (S.142)', date: '2026-07-01', jurisdiction: 'South Carolina', penalty: '$2,500/child/violation' },
  { name: 'Alabama ASAA', date: '2027-10-01', jurisdiction: 'Alabama', penalty: 'TBD' },
];

/**
 * Get the next upcoming regulatory deadline, or the most recent if all have passed.
 */
export function getNextDeadline(now?: Date): RegulatoryDeadline {
  const currentDate = now || new Date();

  // Find first upcoming deadline
  for (const dl of REGULATORY_DEADLINES) {
    const date = new Date(dl.date + 'T00:00:00Z');
    const diffMs = date.getTime() - currentDate.getTime();
    const days = Math.ceil(diffMs / 86400000);
    if (days > 0) {
      return { name: dl.name, date, jurisdiction: dl.jurisdiction, penalty: dl.penalty, isActive: false, daysUntil: days };
    }
  }

  // All deadlines passed — show the most recently passed one as "NOW IN EFFECT"
  const last = REGULATORY_DEADLINES[REGULATORY_DEADLINES.length - 1];
  return { name: last.name, date: new Date(last.date + 'T00:00:00Z'), jurisdiction: last.jurisdiction, penalty: last.penalty, isActive: true, daysUntil: 0 };
}

/**
 * Format the next regulatory deadline for CLI output (with ANSI colors).
 * Replaces the single-deadline COPPA countdown with auto-rotating deadlines.
 */
export function formatRegulatoryCountdownCLI(now?: Date): string {
  const dl = getNextDeadline(now);
  const lines: string[] = [];

  if (dl.isActive) {
    lines.push(`\x1b[31m\x1b[1m\u26a0\ufe0f  ${dl.name} is NOW IN EFFECT\x1b[0m — ${dl.jurisdiction}`);
    if (dl.penalty !== 'TBD') {
      lines.push(`   Penalty: ${dl.penalty}`);
    }
  } else {
    lines.push(`\x1b[33m\u26a0\ufe0f  ${dl.name} enforcement in ${dl.daysUntil} day${dl.daysUntil === 1 ? '' : 's'}\x1b[0m — ${dl.jurisdiction}`);
    if (dl.penalty !== 'TBD') {
      lines.push(`   Penalty: ${dl.penalty}`);
    }
  }

  return lines.join('\n');
}

/**
 * Format dollar exposure from violations for CLI upsell.
 */
export function formatDollarExposure(totalViolations: number): string {
  const dailyExposure = totalViolations * PENALTY_PER_VIOLATION_PER_DAY;
  if (dailyExposure >= 1_000_000) {
    return `$${(dailyExposure / 1_000_000).toFixed(1)}M/day`;
  }
  return `$${Math.round(dailyExposure / 1_000).toLocaleString()}K/day`;
}

export { COPPA_2_ENFORCEMENT_DATE, PENALTY_PER_VIOLATION_PER_DAY };
