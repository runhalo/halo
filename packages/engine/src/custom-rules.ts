/**
 * Custom Rules Engine
 *
 * Allows Enterprise users to define custom detection patterns
 * via a `.halorc.json` file in their project root.
 *
 * Format:
 * {
 *   "customRules": [
 *     {
 *       "id": "custom-pii-001",
 *       "name": "SSN Collection",
 *       "severity": "critical",
 *       "description": "Social Security Number patterns detected",
 *       "patterns": ["\\d{3}-\\d{2}-\\d{4}", "ssn|social.?security"],
 *       "fixSuggestion": "Remove SSN collection or use tokenized identifiers",
 *       "filePatterns": ["*.ts", "*.js"]
 *     }
 *   ],
 *   "ignoreRules": ["coppa-tracking-003"],
 *   "severityOverrides": {
 *     "coppa-geo-004": "critical"
 *   }
 * }
 */

import * as fs from 'fs';
import * as path from 'path';

export interface CustomRule {
  id: string;
  name: string;
  severity: 'critical' | 'high' | 'medium' | 'low';
  description: string;
  patterns: string[];
  fixSuggestion: string;
  filePatterns?: string[];
}

export interface HaloConfig {
  customRules: CustomRule[];
  ignoreRules: string[];
  severityOverrides: Record<string, 'critical' | 'high' | 'medium' | 'low'>;
}

const DEFAULT_CONFIG: HaloConfig = {
  customRules: [],
  ignoreRules: [],
  severityOverrides: {},
};

/**
 * Load .halorc.json from a project directory.
 * Returns default config if file doesn't exist or is invalid.
 */
export function loadHaloConfig(projectDir: string): HaloConfig {
  const configPaths = [
    path.join(projectDir, '.halorc.json'),
    path.join(projectDir, '.halorc'),
    path.join(projectDir, 'halo.config.json'),
  ];

  for (const configPath of configPaths) {
    try {
      if (fs.existsSync(configPath)) {
        const raw = fs.readFileSync(configPath, 'utf-8');
        const parsed = JSON.parse(raw);
        return {
          customRules: validateCustomRules(parsed.customRules || []),
          ignoreRules: Array.isArray(parsed.ignoreRules) ? parsed.ignoreRules : [],
          severityOverrides: parsed.severityOverrides || {},
        };
      }
    } catch (err) {
      console.warn(`[halo] Failed to load config from ${configPath}:`, err);
    }
  }

  return DEFAULT_CONFIG;
}

/**
 * Validate custom rules — reject malformed entries.
 */
function validateCustomRules(rules: unknown[]): CustomRule[] {
  if (!Array.isArray(rules)) return [];

  return rules.filter((rule: any) => {
    if (!rule.id || typeof rule.id !== 'string') return false;
    if (!rule.name || typeof rule.name !== 'string') return false;
    if (!['critical', 'high', 'medium', 'low'].includes(rule.severity)) return false;
    if (!Array.isArray(rule.patterns) || rule.patterns.length === 0) return false;

    // Validate regex patterns
    for (const pattern of rule.patterns) {
      try {
        new RegExp(pattern);
      } catch {
        console.warn(`[halo] Invalid regex in custom rule ${rule.id}: ${pattern}`);
        return false;
      }
    }

    // Ensure custom rule IDs don't conflict with built-in rules
    if (!rule.id.startsWith('custom-')) {
      console.warn(`[halo] Custom rule IDs must start with "custom-": ${rule.id}`);
      return false;
    }

    return true;
  }) as CustomRule[];
}

/**
 * Convert custom rules to the format the engine expects.
 */
export function compileCustomRules(rules: CustomRule[]): Array<{
  id: string;
  name: string;
  severity: 'critical' | 'high' | 'medium' | 'low';
  description: string;
  patterns: RegExp[];
  fixSuggestion: string;
}> {
  return rules.map(rule => ({
    id: rule.id,
    name: rule.name,
    severity: rule.severity,
    description: rule.description,
    patterns: rule.patterns.map(p => new RegExp(p, 'gi')),
    fixSuggestion: rule.fixSuggestion || 'Review this code for compliance issues',
  }));
}
