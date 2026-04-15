/**
 * Scaffold Engine — generates code scaffolds for Tier 2 guided fixes
 *
 * Integrates with REMEDIATION_MAP to produce framework-specific code templates
 * that address COPPA compliance issues detected by the Halo scanner.
 *
 * Template-based (not LLM): deterministic, zero API cost, works offline.
 */

import { REMEDIATION_MAP } from './index';
import { detectFramework, type Framework, type FrameworkDetectionResult } from './framework-detect';
import { SCAFFOLD_REGISTRY, type ScaffoldFile } from './scaffolds/index';

export interface GuidedFixResult {
  /** The scaffold template ID (from REMEDIATION_MAP) */
  scaffoldId: string;
  /** The primary rule ID that triggered this scaffold */
  ruleId: string;
  /** Generated files for this scaffold */
  files: ScaffoldFile[];
  /** Framework used for generation */
  framework: Framework;
}

export interface GuidedFixSummary {
  /** Total scaffolds generated */
  totalScaffolds: number;
  /** Total files generated across all scaffolds */
  totalFiles: number;
  /** Scaffold IDs that were generated */
  generatedIds: string[];
  /** Scaffold IDs that were needed but have no template yet */
  unavailableIds: string[];
  /** Framework detected/used */
  framework: Framework;
  /** Whether TypeScript was detected */
  typescript: boolean;
}

export class ScaffoldEngine {
  /**
   * Get scaffold IDs applicable to a set of violations.
   * Returns only IDs that have templates in the registry.
   */
  getApplicableScaffolds(violations: { ruleId: string }[]): string[] {
    const scaffoldIds = new Set<string>();
    for (const v of violations) {
      const spec = REMEDIATION_MAP[v.ruleId];
      if (spec?.fixability === 'guided' && spec.scaffoldId) {
        if (SCAFFOLD_REGISTRY.has(spec.scaffoldId)) {
          scaffoldIds.add(spec.scaffoldId);
        }
      }
    }
    return Array.from(scaffoldIds);
  }

  /**
   * Get scaffold IDs that are needed but don't have templates yet.
   * Used to show "docs available" instead of "scaffold available".
   */
  getUnavailableScaffolds(violations: { ruleId: string }[]): string[] {
    const scaffoldIds = new Set<string>();
    for (const v of violations) {
      const spec = REMEDIATION_MAP[v.ruleId];
      if (spec?.fixability === 'guided' && spec.scaffoldId) {
        if (!SCAFFOLD_REGISTRY.has(spec.scaffoldId)) {
          scaffoldIds.add(spec.scaffoldId);
        }
      }
    }
    return Array.from(scaffoldIds);
  }

  /**
   * Generate scaffold files for guided violations.
   * Deduplicates by scaffoldId — won't generate the same scaffold twice.
   */
  generateScaffolds(
    violations: { ruleId: string }[],
    projectPath: string,
    frameworkOverride?: Framework
  ): GuidedFixResult[] {
    const detection = detectFramework(projectPath);
    const framework = frameworkOverride || detection.framework;
    const typescript = detection.typescript;
    const results: GuidedFixResult[] = [];
    const seen = new Set<string>();

    for (const v of violations) {
      const spec = REMEDIATION_MAP[v.ruleId];
      if (!spec?.scaffoldId || seen.has(spec.scaffoldId)) continue;
      if (spec.fixability !== 'guided') continue;

      const template = SCAFFOLD_REGISTRY.get(spec.scaffoldId);
      if (!template) continue;

      seen.add(spec.scaffoldId);
      const files = template.generate(framework, typescript);
      results.push({
        scaffoldId: spec.scaffoldId,
        ruleId: v.ruleId,
        files,
        framework,
      });
    }

    return results;
  }

  /**
   * Get a full summary of what would be generated for a set of violations.
   */
  getSummary(
    violations: { ruleId: string }[],
    projectPath: string,
    frameworkOverride?: Framework
  ): GuidedFixSummary {
    const detection = detectFramework(projectPath);
    const framework = frameworkOverride || detection.framework;
    const available = this.getApplicableScaffolds(violations);
    const unavailable = this.getUnavailableScaffolds(violations);
    const results = this.generateScaffolds(violations, projectPath, frameworkOverride);

    return {
      totalScaffolds: results.length,
      totalFiles: results.reduce((sum, r) => sum + r.files.length, 0),
      generatedIds: available,
      unavailableIds: unavailable,
      framework,
      typescript: detection.typescript,
    };
  }

  /**
   * List all scaffold IDs that have templates registered.
   */
  listAvailable(): string[] {
    return Array.from(SCAFFOLD_REGISTRY.keys());
  }
}
