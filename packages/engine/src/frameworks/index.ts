/**
 * Framework Allowlisting System
 *
 * Entry point for Halo's framework-aware rule management. When a developer
 * declares their framework in .halorc.json (e.g. { "framework": "nextjs" }),
 * Halo loads the corresponding profile and automatically suppresses or
 * downgrades rules that the framework already handles natively.
 *
 * Usage:
 *   import { applyFrameworkOverrides } from './frameworks';
 *   const result = applyFrameworkOverrides(violations, 'nextjs');
 *   // result.violations  — filtered/downgraded violations
 *   // result.suppressedCount — number of violations removed
 *   // result.downgradedCount — number of violations with reduced severity
 */

export type { FrameworkAction, FrameworkRuleOverride, FrameworkSafePattern, FrameworkProfile } from './types';

import { FrameworkProfile } from './types';
import { nextjsProfile } from './nextjs';
import { djangoProfile } from './django';
import { railsProfile } from './rails';
import { reactProfile } from './react';
import { vueProfile } from './vue';
import { angularProfile } from './angular';

/**
 * Minimal violation shape used by the framework system to avoid circular
 * imports with the engine's Violation type. Any object with at least ruleId
 * and severity will work.
 */
interface ViolationLike {
  ruleId: string;
  severity: string;
  [key: string]: any;
}

/** Registry of all built-in framework profiles keyed by id. */
const FRAMEWORK_REGISTRY: Record<string, FrameworkProfile> = {
  nextjs: nextjsProfile,
  django: djangoProfile,
  rails: railsProfile,
  react: reactProfile,
  vue: vueProfile,
  angular: angularProfile,
};

/**
 * Look up a framework profile by its id.
 *
 * @param id - Framework identifier (e.g. "nextjs", "django", "rails")
 * @returns The matching FrameworkProfile, or null if not found
 */
export function getFrameworkProfile(id: string): FrameworkProfile | null {
  return FRAMEWORK_REGISTRY[id] ?? null;
}

/**
 * List all registered framework ids.
 *
 * @returns Sorted array of framework id strings
 */
export function listFrameworks(): string[] {
  return Object.keys(FRAMEWORK_REGISTRY).sort();
}

/**
 * Apply a framework's rule overrides to a set of violations.
 *
 * For each violation whose ruleId appears in the framework's handled_rules:
 * - "suppress" removes the violation from the output entirely
 * - "downgrade" reduces the violation's severity to the specified level
 *
 * Violations whose ruleId is NOT in the framework's profile are passed
 * through unchanged.
 *
 * @param violations - Array of violation objects to filter
 * @param frameworkId - Framework identifier to look up
 * @returns Object with the filtered violations array and counts
 */
export function applyFrameworkOverrides<T extends ViolationLike>(
  violations: T[],
  frameworkId: string,
): { violations: T[]; suppressedCount: number; downgradedCount: number } {
  const profile = getFrameworkProfile(frameworkId);

  if (!profile) {
    return { violations: [...violations], suppressedCount: 0, downgradedCount: 0 };
  }

  // Build a lookup map from rule_id to override for O(1) access
  const overrideMap = new Map(
    profile.handled_rules.map((override) => [override.rule_id, override]),
  );

  let suppressedCount = 0;
  let downgradedCount = 0;
  const filtered: T[] = [];

  for (const violation of violations) {
    const override = overrideMap.get(violation.ruleId);

    if (!override) {
      filtered.push(violation);
      continue;
    }

    if (override.action === 'suppress') {
      suppressedCount++;
      // Violation is removed from output
      continue;
    }

    if (override.action === 'downgrade' && override.downgrade_to) {
      downgradedCount++;
      // Create a shallow copy with the new severity to avoid mutating the original
      filtered.push({ ...violation, severity: override.downgrade_to });
      continue;
    }

    // Fallback: pass through if action is unrecognized
    filtered.push(violation);
  }

  return { violations: filtered, suppressedCount, downgradedCount };
}
