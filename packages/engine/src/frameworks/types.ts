/**
 * Framework Allowlisting Type Definitions
 *
 * Defines the type contracts for framework profiles that declare which
 * COPPA/ethical rules a framework already handles natively. When a developer
 * declares their framework in .halorc.json, Halo uses these profiles to
 * suppress or downgrade rules the framework covers automatically.
 */

export type FrameworkAction = 'suppress' | 'downgrade';

export interface FrameworkRuleOverride {
  rule_id: string;
  action: FrameworkAction;
  downgrade_to?: 'critical' | 'high' | 'medium' | 'low';
  condition?: string;       // Human-readable condition description
  reason: string;           // Why this framework handles this rule
  documentation_url?: string;
}

export interface FrameworkSafePattern {
  description: string;
  patterns: RegExp[];
  applies_to_rules: string[];
}

export interface FrameworkProfile {
  id: string;               // "nextjs", "django", "rails"
  name: string;             // "Next.js"
  ecosystem: 'javascript' | 'python' | 'ruby';
  handled_rules: FrameworkRuleOverride[];
  safe_patterns: FrameworkSafePattern[];
}
