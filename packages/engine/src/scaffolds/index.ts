/**
 * Scaffold Template Registry
 * Maps scaffoldIds (from REMEDIATION_MAP) to template generators
 */

import type { Framework } from '../framework-detect';

// ── Types ──────────────────────────────────────────────────────────

export interface ScaffoldTemplate {
  scaffoldId: string;
  name: string;
  description: string;
  /** Rule IDs this scaffold addresses */
  ruleIds: string[];
  /** Generate scaffold files for a given framework */
  generate(framework: Framework, typescript: boolean): ScaffoldFile[];
}

export interface ScaffoldFile {
  /** Relative path where the file should be written (e.g., "components/AgeGate.tsx") */
  relativePath: string;
  /** File content */
  content: string;
  /** Human-readable description of what this file does */
  description: string;
}

// ── Registry ───────────────────────────────────────────────────────

import { ageGateAuthTemplate } from './templates/age-gate-auth';
import { consentCookiesTemplate } from './templates/consent-cookies';
import { piiSanitizerTemplate } from './templates/pii-sanitizer';
import { retentionPolicyTemplate } from './templates/retention-policy';

export const SCAFFOLD_REGISTRY: Map<string, ScaffoldTemplate> = new Map([
  ['age-gate-auth', ageGateAuthTemplate],
  ['consent-cookies', consentCookiesTemplate],
  ['pii-sanitizer', piiSanitizerTemplate],
  ['retention-policy', retentionPolicyTemplate],
]);
