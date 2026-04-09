#!/usr/bin/env node

/**
 * Halo CLI - Child Safety Compliance Scanner
 * Usage: runhalo scan <path> [options]
 */

import { Command } from 'commander';
import { glob } from 'glob';
import * as fs from 'fs';
import * as path from 'path';
import * as os from 'os';
import * as readline from 'readline';
import { HaloEngine, Violation, ScanResult, EngineConfig, parseHaloignore, IgnoreConfig, shouldIgnoreFile, FixEngine, REMEDIATION_MAP, ComplianceScoreEngine, AI_AUDIT_RULES, loadRulesFromJSON, loadRulesFromJSONByPack, compileRawRules, JSONRule, detectSDKsFromPackageJson, generateSDKContext, getCoppaCountdown, formatCoppaCountdownCLI, formatCoppaCountdownPDF, getUpgradeCTA, createTierContext, buildImportGraph, summarizeImportGraph, formatImportGraphForReview, formatRegulatoryCountdownCLI, formatDollarExposure } from '@runhalo/engine';
import PDFDocument from 'pdfkit';

// Output formats
type OutputFormat = 'json' | 'sarif' | 'text';

// CLI configuration
const program = new Command();

/**
 * .halorc.json configuration file schema
 */
interface HaloRcConfig {
  packs?: string[];
  severity_threshold?: 'critical' | 'high' | 'medium' | 'low';
  ignore?: string[];
  notifications?: {
    discord_webhook?: string;
    slack_webhook?: string;
  };

  framework?: string;       // e.g., "nextjs", "django", "rails"
  astAnalysis?: boolean;     // Enable AST-based analysis (default: true for JS/TS)

  reviewBoard?: boolean;     // Enable AI Review Board (Pro/Enterprise)
  licenseKey?: string;       // License key (alternative to HALO_LICENSE_KEY env var)
}

interface CLIOptions {
  format: OutputFormat;
  include: string[];
  exclude: string[];
  rules: string[];
  severity: string[];
  output: string;
  verbose: boolean;
  ethicalPreview: boolean;
  report: string | boolean;
  aiAudit: boolean;
  sectorAuSbd: boolean;
  sectorAuOsa: boolean;
  pack: string[];
  offline: boolean;

  framework?: string;
  astAnalysis?: boolean;

  reviewBoard?: boolean;
  licenseKey?: string;
}

/**
 * Get default file patterns to scan
 */
function getDefaultPatterns(): string[] {
  return [
    '**/*.ts',
    '**/*.js',
    '**/*.tsx',
    '**/*.jsx',
    '**/*.py',
    '**/*.swift',
    '**/*.java',
    '**/*.kt',
    '**/*.sql',
    '**/*.html',
    '**/*.vue',
    '**/*.svelte',
    // Added Phase B: languages previously missing (C++, C#, PHP, QML)
    '**/*.php',
    '**/*.cpp',
    '**/*.h',
    '**/*.hpp',
    '**/*.cs',
    '**/*.qml',
    // Added P3-0: Go, Ruby, XML for multi-language coverage
    '**/*.go',
    '**/*.rb',
    '**/*.xml',
    '**/*.erb'
  ];
}

/**
 * Get default exclusion patterns
 */
function getDefaultExcludePatterns(): string[] {
  return [
    // Package and build artifacts
    'node_modules/**',
    'dist/**',
    'build/**',
    '.git/**',
    'coverage/**',
    '.next/**',
    '.svelte-kit/**',
    '.nuxt/**',

    // Minified and bundled files (major FP source — vendor code is not your code)
    '**/*.min.js',
    '**/*.min.mjs',
    '**/*.bundle.js',
    '**/*.chunk.js',

    // Vendor directories (bundled third-party code, not your code)
    '**/vendor/**',
    '**/bower_components/**',

    // Test files (compliance scans shouldn't flag test code)
    '**/__tests__/**',
    '**/__mocks__/**',
    '**/fixtures/**',
    '**/testdata/**',
    '**/*.test.ts',
    '**/*.test.js',
    '**/*.test.tsx',
    '**/*.test.jsx',
    '**/*.spec.ts',
    '**/*.spec.js',
    '**/*.spec.tsx',
    '**/*.spec.jsx',
    '**/test_*.py',
    '**/conftest.py',
    '**/*_test.py',
    '**/*_test.go',

    // Lock files
    '**/package-lock.json',
    '**/yarn.lock',
    '**/pnpm-lock.yaml'
  ];
}

/**
 * Format violations as SARIF output
 */
function formatSARIF(results: ScanResult[], rules: any[]): string {
  const sarif = {
    version: '2.1.0',
    $schema: 'https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json',
    runs: [{
      tool: {
        driver: {
          name: 'Halo',
          version: '1.0.0',
          informationUri: 'https://runhalo.dev',
          rules: rules.map(r => ({
            id: r.id,
            name: r.name,
            shortDescription: { text: r.description },
            helpUri: `https://runhalo.dev/rules/${r.id}`,
            defaultConfiguration: { level: r.severity === 'critical' || r.severity === 'high' ? 'error' : r.severity === 'medium' ? 'warning' : 'note' }
          }))
        }
      },
      results: results.flatMap(result => 
        result.violations.map(v => ({
          ruleId: v.ruleId,
          level: v.severity === 'critical' || v.severity === 'high' ? 'error' : 'warning',
          message: { text: v.message },
          locations: [{
            physicalLocation: {
              artifactLocation: {
                uri: result.filePath,
                uriBaseId: 'SRCROOT'
              },
              region: {
                startLine: v.line,
                startColumn: v.column
              }
            }
          }]
        }))
      )
    }]
  };
  return JSON.stringify(sarif, null, 2);
}

/**
 * Format violations as JSON output
 */
function formatJSON(results: ScanResult[], scoreResult?: any): string {
  const output: any = {
    version: '1.0.0',
    scannedAt: new Date().toISOString(),
    totalFiles: results.length,
    totalViolations: results.reduce((sum, r) => sum + r.violations.length, 0),
    results: results
  };
  if (scoreResult) {
    output.complianceScore = {
      score: scoreResult.score,
      grade: scoreResult.grade,
      pointsDeducted: scoreResult.pointsDeducted,
      bySeverity: scoreResult.bySeverity,
      rulesTriggered: scoreResult.rulesTriggered,
    };
  }
  return JSON.stringify(output, null, 2);
}

// ANSI color codes for terminal output
const colors = {
  reset: '\x1b[0m',
  bold: '\x1b[1m',
  dim: '\x1b[2m',
  red: '\x1b[31m',
  yellow: '\x1b[33m',
  blue: '\x1b[34m',
  cyan: '\x1b[36m',
  white: '\x1b[37m',
  bgRed: '\x1b[41m',
  bgYellow: '\x1b[43m',
  bgBlue: '\x1b[44m',
  magenta: '\x1b[35m',
  green: '\x1b[32m',
};

// Detect if color should be used (respect NO_COLOR env and pipe detection)
const useColor = !process.env.NO_COLOR && process.stdout.isTTY !== false;

function c(color: string, text: string): string {
  return useColor ? `${color}${text}${colors.reset}` : text;
}

// ──────────────────────────────────────────────────────────────

// Data validated against live engine rule set. matchConfidence filters
// ensure only relevant enforcement precedents are shown.
// ──────────────────────────────────────────────────────────────
interface EnforcementCase {
  company: string;
  fine: number;
  date: string;
  jurisdiction: string;
  violation: string;
  confidence: 'direct' | 'related';
}

// Enforcement lookup: rule_id → matching enforcement cases
// Source of truth: halo-admin/src/data/regulatory-actions.ts
const ENFORCEMENT_DATA: Record<string, EnforcementCase[]> = {};

// Build the lookup table from inline enforcement data
(function buildEnforcementLookup() {
  const cases = [
    { company: 'Epic Games', fine: 275_000_000, date: '2022-12', jurisdiction: 'COPPA', violation: 'Tracking + dark patterns in child accounts', rules: [{ id: 'coppa-tracking-003', c: 'direct' as const }, { id: 'coppa-ui-008', c: 'direct' as const }] },
    { company: 'Amazon Alexa', fine: 25_000_000, date: '2023-05', jurisdiction: 'COPPA', violation: 'Voice recording retention without deletion workflows', rules: [{ id: 'coppa-audio-007', c: 'direct' as const }, { id: 'coppa-data-002', c: 'related' as const }] },
    { company: 'Microsoft Xbox', fine: 20_000_000, date: '2023-06', jurisdiction: 'COPPA', violation: 'Data collection before verifiable parental consent', rules: [{ id: 'coppa-auth-001', c: 'direct' as const }] },
    { company: 'Disney YouTube', fine: 10_000_000, date: '2025-03', jurisdiction: 'COPPA', violation: 'Third-party data collection on kids channels', rules: [{ id: 'coppa-ext-017', c: 'direct' as const }, { id: 'coppa-tracking-003', c: 'direct' as const }] },
    { company: 'Edmodo', fine: 6_000_000, date: '2023-05', jurisdiction: 'COPPA', violation: 'Kids data used for advertising profiles', rules: [{ id: 'coppa-tracking-003', c: 'direct' as const }, { id: 'coppa-analytics-018', c: 'direct' as const }] },
    { company: 'NGL Labs', fine: 5_000_000, date: '2024-07', jurisdiction: 'COPPA', violation: 'Anonymous messaging + safety risk exposure', rules: [{ id: 'coppa-default-020', c: 'direct' as const }, { id: 'coppa-ext-011', c: 'direct' as const }, { id: 'coppa-ui-008', c: 'related' as const }] },
    { company: 'HyperBeard', fine: 4_000_000, date: '2020-06', jurisdiction: 'COPPA', violation: 'Ad network tracking inside kids games', rules: [{ id: 'coppa-tracking-003', c: 'direct' as const }, { id: 'coppa-analytics-018', c: 'direct' as const }] },
    { company: 'Kuuhubb Recolor', fine: 3_000_000, date: '2021-07', jurisdiction: 'COPPA', violation: 'Data collection without consent flow', rules: [{ id: 'coppa-auth-001', c: 'direct' as const }] },
    { company: 'OpenX', fine: 2_000_000, date: '2021-12', jurisdiction: 'COPPA', violation: 'Location data harvested from kids apps', rules: [{ id: 'coppa-geo-004', c: 'direct' as const }, { id: 'coppa-tracking-003', c: 'direct' as const }] },
    { company: 'Weight Watchers Kurbo', fine: 1_500_000, date: '2022-03', jurisdiction: 'COPPA', violation: 'Health data captured without consent', rules: [{ id: 'coppa-bio-012', c: 'direct' as const }, { id: 'coppa-sec-006', c: 'related' as const }] },
    { company: 'Tilting Point Media', fine: 500_000, date: '2024-06', jurisdiction: 'COPPA/CCPA', violation: 'Unauthorized disclosure of kids info', rules: [{ id: 'coppa-ext-017', c: 'direct' as const }, { id: 'coppa-data-002', c: 'direct' as const }] },
    { company: 'Instagram (Meta)', fine: 405_000_000, date: '2022-09', jurisdiction: 'GDPR Art.8', violation: 'Exposed children\'s contact info publicly', rules: [{ id: 'coppa-default-020', c: 'direct' as const }, { id: 'coppa-auth-001', c: 'direct' as const }, { id: 'coppa-sec-006', c: 'related' as const }] },
    { company: 'TikTok (EU)', fine: 345_000_000, date: '2023-09', jurisdiction: 'GDPR Art.8', violation: 'Default public accounts for children, dark patterns', rules: [{ id: 'coppa-default-020', c: 'direct' as const }, { id: 'coppa-ui-008', c: 'direct' as const }, { id: 'coppa-auth-001', c: 'direct' as const }] },
    { company: 'Google (YouTube)', fine: 170_000_000, date: '2019-09', jurisdiction: 'COPPA', violation: 'Cookies + persistent identifiers from children\'s channels', rules: [{ id: 'coppa-cookies-016', c: 'direct' as const }, { id: 'coppa-tracking-003', c: 'direct' as const }, { id: 'coppa-analytics-018', c: 'direct' as const }] },
    { company: 'Reddit', fine: 14_470_000, date: '2026-02', jurisdiction: 'AADC', violation: 'Inadequate age gating under UK Children\'s Code', rules: [{ id: 'coppa-auth-001', c: 'direct' as const }, { id: 'coppa-default-020', c: 'direct' as const }, { id: 'coppa-ui-008', c: 'related' as const }] },
    { company: 'Musical.ly (TikTok)', fine: 5_700_000, date: '2019-02', jurisdiction: 'COPPA', violation: 'PII collection from children, social features without safeguards', rules: [{ id: 'coppa-default-020', c: 'direct' as const }, { id: 'coppa-ext-011', c: 'direct' as const }, { id: 'coppa-auth-001', c: 'direct' as const }] },
    { company: 'Apitor Technology', fine: 500_000, date: '2025-09', jurisdiction: 'COPPA', violation: 'Robot toy tracked location without parental consent', rules: [{ id: 'coppa-geo-004', c: 'direct' as const }, { id: 'coppa-auth-001', c: 'direct' as const }] },
    { company: 'MediaLab (Imgur)', fine: 247_590, date: '2026-02', jurisdiction: 'AADC', violation: 'No age assurance, children exposed to adult content', rules: [{ id: 'coppa-auth-001', c: 'direct' as const }, { id: 'coppa-default-020', c: 'direct' as const }] },
  ];

  for (const c of cases) {
    for (const rule of c.rules) {
      if (!ENFORCEMENT_DATA[rule.id]) ENFORCEMENT_DATA[rule.id] = [];
      ENFORCEMENT_DATA[rule.id].push({
        company: c.company,
        fine: c.fine,
        date: c.date,
        jurisdiction: c.jurisdiction,
        violation: c.violation,
        confidence: rule.c,
      });
    }
  }
})();

function formatFine(amount: number | undefined | null): string {
  if (amount == null || typeof amount !== 'number' || isNaN(amount)) return "$Unknown";
  if (amount >= 1_000_000_000) return `$${(amount / 1_000_000_000).toFixed(1)}B`;
  if (amount >= 1_000_000) return `$${(amount / 1_000_000).toFixed(0)}M`;
  if (amount >= 1_000) return `$${(amount / 1_000).toFixed(0)}K`;
  if (amount === 0) return 'DOJ action';
  return `$${amount.toLocaleString()}`;
}

/** Safely format comparable_case which may be a string or an object from edge function */
function formatCase(val: unknown): string {
  if (!val) return '';
  if (typeof val === 'string') return val;
  if (typeof val === 'object') {
    const obj = val as Record<string, unknown>;
    // Common shapes: { name, fine, year } or { case_name, penalty }
    return obj.name as string || obj.case_name as string || JSON.stringify(val);
  }
  return String(val);
}

// COPPA Rule amendment compliance deadline
const COPPA_DEADLINE = new Date('2026-04-22');
function daysUntilDeadline(): number {
  const now = new Date();
  return Math.max(0, Math.ceil((COPPA_DEADLINE.getTime() - now.getTime()) / (1000 * 60 * 60 * 24)));
}

// Enforcement tier classification for a violation
type EnforcementTier = 'enforcement-risk' | 'regulatory-scrutiny' | 'hardening';

// Rules that are directly addressed by COPPA 2.0 amendment (April 22, 2026)
const COPPA_2_RULES = new Set([
  'coppa-auth-001',     // Age verification strengthened
  'coppa-tracking-003', // Ad tracking restrictions expanded
  'coppa-bio-012',      // Biometric data explicitly covered
  'coppa-data-002',     // Data minimization requirements
  'coppa-retention-005', // Retention limits codified
  'coppa-notif-013',    // Push notification consent required
  'coppa-geo-004',      // Location data restrictions
  'coppa-audio-007',    // Voice data as biometric
]);

function classifyTier(ruleId: string): EnforcementTier {
  if (ENFORCEMENT_DATA[ruleId]?.some(c => c.confidence === 'direct')) return 'enforcement-risk';
  if (COPPA_2_RULES.has(ruleId) || ENFORCEMENT_DATA[ruleId]?.some(c => c.confidence === 'related')) return 'regulatory-scrutiny';
  return 'hardening';
}

/**
 * Format violations as human-readable text
 */
function formatText(results: ScanResult[], verbose: boolean = false, fileCount: number = 0, scoreResult?: any): string {
  // Load confidence map for verbose mode
  let confidenceMap: Record<string, string> = {};
  if (verbose) {
    try {
      const rulesJsonPath = require.resolve('@runhalo/engine/rules/rules.json');
      const rulesData = JSON.parse(fs.readFileSync(rulesJsonPath, 'utf-8'));
      for (const rule of rulesData.rules || []) {
        if (rule.id && rule.confidence) {
          confidenceMap[rule.id] = rule.confidence;
        }
      }
    } catch { /* ignore — confidence display is optional */ }
  }

  let output = '';
  let totalViolations = 0;
  let criticalCount = 0;
  let highCount = 0;
  let mediumCount = 0;
  let lowCount = 0;
  let filesWithViolations = 0;


  let enforcementRiskCount = 0;
  let regulatoryScrutinyCount = 0;
  let hardeningCount = 0;
  const enforcementMatchedFines = new Set<string>(); // Track unique cases for aggregate fine total

  for (const result of results) {
    if (result.violations.length === 0) continue;

    filesWithViolations++;
    totalViolations += result.violations.length;

    // Count by severity
    for (const v of result.violations) {
      switch (v.severity) {
        case 'critical': criticalCount++; break;
        case 'high': highCount++; break;
        case 'medium': mediumCount++; break;
        case 'low': lowCount++; break;
      }
    }

    output += `\n${c(colors.bold, result.filePath)}\n`;

    for (const violation of result.violations) {
      // Severity tag with color
      let severityTag: string;
      switch (violation.severity) {
        case 'critical':
          severityTag = c(colors.red + colors.bold, 'CRITICAL');
          break;
        case 'high':
          severityTag = c(colors.yellow + colors.bold, 'HIGH');
          break;
        case 'medium':
          severityTag = c(colors.blue, 'MEDIUM');
          break;
        default:
          severityTag = c(colors.dim, 'LOW');
      }


      let astBadge = '';
      if (violation.astVerdict === 'confirmed') {
        astBadge = c(colors.red, ' [AST ✓]');
      } else if (violation.astVerdict === 'suppressed') {
        astBadge = c(colors.dim, ' [AST suppressed]');
      } else if (violation.astVerdict === 'regex_only') {
        astBadge = c(colors.dim, ' [regex]');
      }


      let confidenceBadge = '';
      if (violation.confidence !== undefined) {
        const confVal = violation.confidence;
        const confStr = confVal.toFixed(2);
        if (confVal >= 0.7) {
          confidenceBadge = c(colors.red, ` [${confStr}]`);
        } else if (confVal >= 0.4) {
          confidenceBadge = c(colors.yellow, ` [${confStr}]`);
        } else {
          confidenceBadge = c(colors.dim, ` [${confStr}]`);
        }
      }


      const tier = classifyTier(violation.ruleId);
      switch (tier) {
        case 'enforcement-risk': enforcementRiskCount++; break;
        case 'regulatory-scrutiny': regulatoryScrutinyCount++; break;
        case 'hardening': hardeningCount++; break;
      }

      // Always show line:column (developer-standard format)
      const location = c(colors.dim, `${violation.line}:${violation.column}`);
      output += `  ${location}  ${severityTag}  ${c(colors.cyan, violation.ruleId)}${astBadge}${confidenceBadge}\n`;
      output += `  ${c(colors.dim, '│')} ${violation.message}\n`;


      const enforcementCases = ENFORCEMENT_DATA[violation.ruleId];
      if (enforcementCases) {
        // Show top 2 direct matches by fine amount (most impactful)
        const directCases = enforcementCases
          .filter(ec => ec.confidence === 'direct' && ec.fine > 0)
          .sort((a, b) => b.fine - a.fine)
          .slice(0, 2);
        for (const ec of directCases) {
          output += `  ${c(colors.dim, '│')} ${c(colors.red, '⚖️')}  Related enforcement precedent: ${ec.jurisdiction} v. ${ec.company} (${formatFine(ec.fine)}, ${ec.date})\n`;
          enforcementMatchedFines.add(`${ec.company}-${ec.date}`);
        }
      }
      // Show COPPA 2.0 deadline for rules affected by the amendment
      if (COPPA_2_RULES.has(violation.ruleId)) {
        const days = daysUntilDeadline();
        if (days > 0) {
          output += `  ${c(colors.dim, '│')} ${c(colors.yellow, '⚠️')}  COPPA Rule amendment compliance deadline: April 22, 2026 (${days} days)\n`;
        }
      }

      if (verbose) {
        output += `  ${c(colors.dim, '│')} ${c(colors.magenta, '💡')} ${violation.fixSuggestion}\n`;
        if (violation.penalty) {
          output += `  ${c(colors.dim, '│')} ${c(colors.red, '⚠')}  Penalty: ${violation.penalty}\n`;
        }
        if (violation.astReason) {
          output += `  ${c(colors.dim, '│')} ${c(colors.dim, '🔬')} AST: ${violation.astReason}\n`;
        }
        if (violation.confidenceReason) {
          output += `  ${c(colors.dim, '│')} ${c(colors.dim, '📊')} ${violation.confidenceReason}\n`;
        }
        const conf = confidenceMap[violation.ruleId];
        if (conf) {
          const confColor = conf === 'high' ? colors.green : conf === 'medium' ? colors.yellow : colors.red;
          output += `  ${c(colors.dim, '│')} Rule confidence: ${c(confColor, conf)}\n`;
        }
      }
      output += '\n';
    }
  }

  if (totalViolations === 0) {
    const scannedMsg = fileCount > 0 ? ` (${fileCount} files scanned)` : '';
    let cleanOutput = `${c(colors.bold, '✅ No COPPA issues detected!')}${scannedMsg}\n`;
    // Show perfect score for clean repos
    if (scoreResult) {
      cleanOutput += `\n${formatScoreLine(scoreResult)}\n`;
    }

    cleanOutput += `\n${c(colors.dim, '📋 Optimized for Python/PHP web applications. Coverage expanding to additional frameworks.')}\n`;
    return cleanOutput;
  }


  let totalEnforcementFines = 0;
  const seenCases = new Set<string>();
  for (const result of results) {
    for (const v of result.violations) {
      const cases = ENFORCEMENT_DATA[v.ruleId];
      if (cases) {
        for (const ec of cases) {
          if (ec.confidence === 'direct') {
            const key = `${ec.company}-${ec.date}`;
            if (!seenCases.has(key)) {
              seenCases.add(key);
              totalEnforcementFines += ec.fine;
            }
          }
        }
      }
    }
  }

  // Summary header
  let header = `\n${c(colors.bold, `⚠  Found ${totalViolations} issue(s)`)}`;
  header += ` across ${filesWithViolations} file(s)`;
  if (fileCount > 0) {
    header += ` (${fileCount} files scanned)`;
  }

  if (enforcementRiskCount > 0) {
    header += ` — ${c(colors.red + colors.bold, `${enforcementRiskCount} match active enforcement patterns`)} (${formatFine(totalEnforcementFines)} in historical fines)`;
  }
  header += '\n';


  const tierParts: string[] = [];
  if (enforcementRiskCount > 0) tierParts.push(c(colors.red + colors.bold, `${enforcementRiskCount} enforcement-risk`));
  if (regulatoryScrutinyCount > 0) tierParts.push(c(colors.yellow + colors.bold, `${regulatoryScrutinyCount} regulatory scrutiny`));
  if (hardeningCount > 0) tierParts.push(c(colors.dim, `${hardeningCount} hardening`));
  header += `   ${tierParts.join(c(colors.dim, ' · '))}\n`;

  // Severity breakdown (secondary)
  const parts: string[] = [];
  if (criticalCount > 0) parts.push(c(colors.red + colors.bold, `${criticalCount} critical`));
  if (highCount > 0) parts.push(c(colors.yellow + colors.bold, `${highCount} high`));
  if (mediumCount > 0) parts.push(c(colors.blue, `${mediumCount} medium`));
  if (lowCount > 0) parts.push(c(colors.dim, `${lowCount} low`));
  header += `   ${c(colors.dim, 'Severity:')} ${parts.join(c(colors.dim, ' · '))}\n`;

  // Compliance score line with grade context labels
  if (scoreResult) {
    header += `\n${formatScoreLine(scoreResult, enforcementRiskCount, regulatoryScrutinyCount, hardeningCount)}\n`;
  }


  if (totalViolations > 0) {
    const exposure = formatDollarExposure(totalViolations);
    header += `\n${c(colors.yellow + colors.bold, `💰 ${totalViolations} violations = ${exposure} potential exposure`)}`;
    header += `\n${c(colors.dim, '   AI Review removes false positives from your results')} ${c(colors.cyan, '→ runhalo.dev/upgrade')}\n`;
  }


  header += `\n${c(colors.dim, '📋 180 rules across 13 jurisdictions. Regex pre-filter — AI Review Board provides precision.')}\n`;


  if (enforcementRiskCount > 0) {
    header += `\n${c(colors.dim, 'Enforcement citations are historical references, not risk assessments. Consult legal counsel for compliance guidance.')}\n`;
  }

  return header + output;
}

/**
 * Format the compliance score line with grade coloring
 */
function formatScoreLine(scoreResult: any, enforcementRisk: number = 0, regulatoryScrutiny: number = 0, hardening: number = 0): string {
  const { score, grade } = scoreResult;

  // Color the grade based on value
  let gradeColor: string;
  switch (grade) {
    case 'A':
      gradeColor = '\x1b[32m'; // green
      break;
    case 'B':
      gradeColor = '\x1b[36m'; // cyan
      break;
    case 'C':
      gradeColor = '\x1b[33m'; // yellow
      break;
    case 'D':
      gradeColor = '\x1b[33m'; // yellow
      break;
    default:
      gradeColor = '\x1b[31m'; // red for F
  }

  const gradeStr = c(gradeColor + colors.bold, grade);
  const scoreStr = c(colors.bold, `${score}/100`);

  let line = `${c(colors.bold, '📊 COPPA Compliance Score:')} ${scoreStr} (${gradeStr})`;


  const total = enforcementRisk + regulatoryScrutiny + hardening;
  if (total > 0) {
    const contextParts: string[] = [];
    if (enforcementRisk > 0) contextParts.push(`${enforcementRisk} enforcement-risk items`);
    if (regulatoryScrutiny > 0) contextParts.push(`${regulatoryScrutiny} under regulatory scrutiny`);
    if (hardening > 0) contextParts.push(`${hardening} hardening items`);
    line += `\n   ${c(colors.dim, contextParts.join(', '))}`;

    // Gap-to-compliance guidance
    if (enforcementRisk > 0 && (grade === 'D' || grade === 'F')) {
      line += `\n   ${c(colors.yellow, `Gap to compliance: Address the ${enforcementRisk} enforcement-risk items to reach C grade.`)}`;
    } else if (enforcementRisk > 0 && grade === 'C') {
      line += `\n   ${c(colors.yellow, `Gap to compliance: Resolve enforcement-risk items and regulatory scrutiny items for B grade.`)}`;
    }
  }

  return line;
}

/**
 * Format trend line comparing current score to last scan for the same project.
 * Returns empty string if no prior history exists.
 */
function formatTrend(currentScore: number, projectPath: string): string {
  const history = loadHistory();
  const projectHistory = history.filter(h => h.projectPath === projectPath);
  if (projectHistory.length === 0) return '';

  const last = projectHistory[projectHistory.length - 1];
  const diff = currentScore - last.score;

  if (diff > 0) {
    return `  ${c('\x1b[32m', `↑ ${last.score}% → ${currentScore}% (+${diff} since last scan)`)}`;
  } else if (diff < 0) {
    return `  ${c(colors.red, `↓ ${last.score}% → ${currentScore}% (${diff} since last scan)`)}`;
  } else {
    return `  ${c(colors.dim, `→ ${currentScore}% (no change since last scan)`)}`;
  }
}

// ==================== HTML Report Generator ====================

/**
 * Generate a self-contained HTML compliance report.
 * Light theme for email-ability. All CSS inline. No external dependencies.
 */
function generateHtmlReport(
  results: ScanResult[],
  scoreResult: any,
  fileCount: number,
  projectPath: string,
  history?: ScanHistoryEntry[]
): string {
  const scanDate = new Date().toLocaleDateString('en-US', {
    weekday: 'long', year: 'numeric', month: 'long', day: 'numeric'
  });
  const scanTime = new Date().toLocaleTimeString('en-US', {
    hour: '2-digit', minute: '2-digit'
  });
  const totalViolations = results.reduce((sum, r) => sum + r.violations.length, 0);
  const allViolations = results.flatMap(r => r.violations);

  // Grade color
  const gradeColorMap: Record<string, string> = {
    A: '#22c55e', B: '#3b82f6', C: '#eab308', D: '#f97316', F: '#ef4444'
  };
  const gradeColor = gradeColorMap[scoreResult.grade] || '#6b7280';

  // Trend HTML
  let trendHtml = '';
  if (history && history.length > 0) {
    const projectHistory = history.filter(h => h.projectPath === projectPath);
    if (projectHistory.length > 0) {
      const last = projectHistory[projectHistory.length - 1];
      const diff = scoreResult.score - last.score;
      if (diff > 0) {
        trendHtml = `<div style="margin-top:8px;color:#22c55e;font-size:14px;">↑ ${last.score}% → ${scoreResult.score}% (+${diff} since last scan)</div>`;
      } else if (diff < 0) {
        trendHtml = `<div style="margin-top:8px;color:#ef4444;font-size:14px;">↓ ${last.score}% → ${scoreResult.score}% (${diff} since last scan)</div>`;
      } else {
        trendHtml = `<div style="margin-top:8px;color:#6b7280;font-size:14px;">→ ${scoreResult.score}% (no change since last scan)</div>`;
      }
    }
  }

  // Severity bar segments
  const { critical = 0, high = 0, medium = 0, low = 0 } = scoreResult.bySeverity || {};
  const severityTotal = critical + high + medium + low;
  const severityBar = severityTotal > 0 ? `
    <div style="display:flex;height:8px;border-radius:4px;overflow:hidden;margin:12px 0;">
      ${critical > 0 ? `<div style="width:${(critical / severityTotal * 100).toFixed(1)}%;background:#ef4444;"></div>` : ''}
      ${high > 0 ? `<div style="width:${(high / severityTotal * 100).toFixed(1)}%;background:#f97316;"></div>` : ''}
      ${medium > 0 ? `<div style="width:${(medium / severityTotal * 100).toFixed(1)}%;background:#eab308;"></div>` : ''}
      ${low > 0 ? `<div style="width:${(low / severityTotal * 100).toFixed(1)}%;background:#3b82f6;"></div>` : ''}
    </div>` : '';

  // Violations by file
  const violationsHtml = results.map(result => {
    if (result.violations.length === 0) return '';
    const relPath = path.relative(projectPath, result.filePath) || result.filePath;
    const fileViolations = result.violations.map(v => {
      const sevColors: Record<string, string> = {
        critical: '#ef4444', high: '#f97316', medium: '#eab308', low: '#3b82f6'
      };
      const sevColor = sevColors[v.severity] || '#6b7280';
      const sevBg: Record<string, string> = {
        critical: '#fef2f2', high: '#fff7ed', medium: '#fefce8', low: '#eff6ff'
      };
      const bg = sevBg[v.severity] || '#f9fafb';

      const snippet = v.codeSnippet
        ? `<pre style="background:#f1f5f9;border:1px solid #e2e8f0;border-radius:4px;padding:8px;font-size:12px;overflow-x:auto;margin:4px 0 0 0;">${escapeHtml(v.codeSnippet)}</pre>`
        : '';

      return `
        <div style="padding:12px;margin:8px 0;background:${bg};border-left:3px solid ${sevColor};border-radius:4px;">
          <div style="display:flex;align-items:center;gap:8px;margin-bottom:4px;">
            <span style="display:inline-block;padding:2px 8px;border-radius:12px;font-size:11px;font-weight:600;color:white;background:${sevColor};text-transform:uppercase;">${v.severity}</span>
            <code style="font-size:12px;color:#6366f1;">${v.ruleId}</code>
            <span style="font-size:12px;color:#6b7280;">Line ${v.line}</span>
          </div>
          <div style="font-size:13px;color:#1e293b;margin-bottom:4px;">${escapeHtml(v.message)}</div>
          ${snippet}
          ${v.fixSuggestion ? `<div style="font-size:12px;color:#059669;margin-top:6px;">💡 ${escapeHtml(v.fixSuggestion)}</div>` : ''}
          ${v.penalty ? `<div style="font-size:11px;color:#dc2626;margin-top:4px;">⚠ Penalty: ${escapeHtml(v.penalty)}</div>` : ''}
        </div>`;
    }).join('');

    return `
      <details style="margin:8px 0;border:1px solid #e2e8f0;border-radius:8px;overflow:hidden;">
        <summary style="padding:12px 16px;background:#f8fafc;cursor:pointer;font-weight:500;font-size:14px;display:flex;justify-content:space-between;align-items:center;">
          <span style="font-family:monospace;color:#1e293b;">${escapeHtml(relPath)}</span>
          <span style="background:#fee2e2;color:#dc2626;padding:2px 8px;border-radius:12px;font-size:12px;font-weight:600;">${result.violations.length} issue${result.violations.length !== 1 ? 's' : ''}</span>
        </summary>
        <div style="padding:8px 16px 16px 16px;">
          ${fileViolations}
        </div>
      </details>`;
  }).filter(Boolean).join('');

  // Auto-fixable section
  const autoFixable = allViolations.filter(v =>
    ['coppa-sec-006', 'coppa-sec-010', 'coppa-sec-015', 'coppa-default-020'].includes(v.ruleId)
  );
  const autoFixHtml = autoFixable.length > 0 ? `
    <div style="margin:24px 0;padding:16px;background:#f0fdf4;border:1px solid #bbf7d0;border-radius:8px;">
      <h3 style="margin:0 0 8px 0;color:#166534;font-size:16px;">🔧 Auto-Fixable Issues (${autoFixable.length})</h3>
      <p style="margin:0 0 12px 0;color:#15803d;font-size:13px;">These violations can be automatically fixed. Run:</p>
      <code style="display:block;background:#166534;color:#bbf7d0;padding:10px 14px;border-radius:6px;font-size:13px;">npx runhalo fix .</code>
    </div>` : '';

  // Recommendations
  const recommendations: string[] = [];
  if (critical > 0) recommendations.push(`<li style="color:#dc2626;"><strong>Fix ${critical} critical issue${critical !== 1 ? 's' : ''} immediately</strong> — these represent the highest compliance risk and largest potential penalties.</li>`);
  if (high > 0) recommendations.push(`<li style="color:#ea580c;"><strong>Address ${high} high-severity issue${high !== 1 ? 's' : ''}</strong> — these are significant compliance gaps that should be resolved before release.</li>`);
  if (autoFixable.length > 0) recommendations.push(`<li style="color:#059669;"><strong>Run <code>npx runhalo fix .</code></strong> to automatically resolve ${autoFixable.length} issue${autoFixable.length !== 1 ? 's' : ''} (HTTP→HTTPS, default privacy settings, input sanitization).</li>`);
  if (medium > 0) recommendations.push(`<li style="color:#ca8a04;">Review ${medium} medium-severity issue${medium !== 1 ? 's' : ''} — these may require design changes or policy updates.</li>`);
  if (totalViolations === 0) recommendations.push(`<li style="color:#22c55e;"><strong>No issues detected!</strong> Your codebase passes all current COPPA compliance checks.</li>`);

  return `<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>Halo COPPA Compliance Report — ${scanDate}</title>
  <style>
    * { margin: 0; padding: 0; box-sizing: border-box; }
    body { font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, 'Helvetica Neue', Arial, sans-serif; color: #1e293b; background: #ffffff; line-height: 1.6; }
    .container { max-width: 800px; margin: 0 auto; padding: 32px 24px; }
    h1 { font-size: 24px; font-weight: 700; margin-bottom: 4px; }
    h2 { font-size: 18px; font-weight: 600; margin: 32px 0 16px 0; color: #0f172a; border-bottom: 2px solid #e2e8f0; padding-bottom: 8px; }
    .header { border-bottom: 3px solid #6366f1; padding-bottom: 24px; margin-bottom: 32px; }
    .score-section { display: flex; align-items: center; gap: 32px; margin: 24px 0; }
    .score-circle { width: 120px; height: 120px; border-radius: 50%; display: flex; align-items: center; justify-content: center; flex-shrink: 0; }
    .score-inner { width: 96px; height: 96px; border-radius: 50%; background: white; display: flex; flex-direction: column; align-items: center; justify-content: center; }
    .score-value { font-size: 28px; font-weight: 700; }
    .score-label { font-size: 11px; color: #6b7280; text-transform: uppercase; letter-spacing: 0.05em; }
    .grade-badge { display: inline-block; font-size: 36px; font-weight: 800; padding: 4px 16px; border-radius: 8px; }
    .severity-table { width: 100%; border-collapse: collapse; margin: 12px 0; }
    .severity-table td, .severity-table th { padding: 8px 12px; text-align: left; border-bottom: 1px solid #f1f5f9; font-size: 13px; }
    .severity-table th { color: #6b7280; font-weight: 500; font-size: 12px; text-transform: uppercase; letter-spacing: 0.05em; }
    .severity-dot { display: inline-block; width: 10px; height: 10px; border-radius: 50%; margin-right: 6px; }
    .recommendations { margin: 16px 0; }
    .recommendations li { margin: 8px 0; font-size: 14px; line-height: 1.5; }
    .footer { margin-top: 48px; padding-top: 24px; border-top: 1px solid #e2e8f0; color: #94a3b8; font-size: 12px; }
    details summary::-webkit-details-marker { display: none; }
    details summary::before { content: '▶ '; font-size: 10px; color: #94a3b8; }
    details[open] summary::before { content: '▼ '; }
    @media (max-width: 600px) { .score-section { flex-direction: column; align-items: flex-start; } }
    @media print { details { open: true; } details[open] summary { display: none; } }
  </style>
</head>
<body>
  <div class="container">
    <div class="header">
      <div style="display:flex;align-items:center;gap:12px;margin-bottom:16px;">
        <div style="width:32px;height:32px;border-radius:8px;background:linear-gradient(135deg,#6366f1,#a855f7);display:flex;align-items:center;justify-content:center;">
          <span style="color:white;font-weight:700;font-size:14px;">H</span>
        </div>
        <h1>COPPA Compliance Report</h1>
      </div>
      <div style="font-size:13px;color:#6b7280;">
        <span>${scanDate} at ${scanTime}</span>
        <span style="margin:0 8px;">·</span>
        <span>${fileCount} files scanned</span>
        <span style="margin:0 8px;">·</span>
        <span style="font-family:monospace;">${escapeHtml(projectPath)}</span>
      </div>
    </div>

    <div class="score-section">
      <div class="score-circle" style="background:conic-gradient(${gradeColor} ${scoreResult.score * 3.6}deg, #e2e8f0 0);">
        <div class="score-inner">
          <div class="score-value">${scoreResult.score}</div>
          <div class="score-label">out of 100</div>
        </div>
      </div>
      <div>
        <div class="grade-badge" style="color:${gradeColor};background:${gradeColor}15;">Grade ${scoreResult.grade}</div>
        <div style="margin-top:8px;font-size:14px;color:#475569;">${totalViolations} violation${totalViolations !== 1 ? 's' : ''} found across ${results.filter(r => r.violations.length > 0).length} file${results.filter(r => r.violations.length > 0).length !== 1 ? 's' : ''}</div>
        ${trendHtml}
      </div>
    </div>

    <h2>Severity Breakdown</h2>
    ${severityBar}
    <table class="severity-table">
      <tr><th>Severity</th><th>Count</th><th>Points Deducted</th></tr>
      <tr><td><span class="severity-dot" style="background:#ef4444;"></span>Critical</td><td><strong>${critical}</strong></td><td>${critical > 0 ? '-' + (critical * 10) : '—'}</td></tr>
      <tr><td><span class="severity-dot" style="background:#f97316;"></span>High</td><td><strong>${high}</strong></td><td>${high > 0 ? '-' + (high * 5) : '—'}</td></tr>
      <tr><td><span class="severity-dot" style="background:#eab308;"></span>Medium</td><td><strong>${medium}</strong></td><td>${medium > 0 ? '-' + (medium * 2) : '—'}</td></tr>
      <tr><td><span class="severity-dot" style="background:#3b82f6;"></span>Low</td><td><strong>${low}</strong></td><td>${low > 0 ? '-' + low : '—'}</td></tr>
    </table>

    ${autoFixHtml}

    ${totalViolations > 0 ? `<h2>Violations by File</h2>${violationsHtml}` : ''}

    ${recommendations.length > 0 ? `
    <h2>Recommendations</h2>
    <ol class="recommendations">
      ${recommendations.join('\n      ')}
    </ol>` : ''}

    <div class="footer">
      <p><strong>Disclaimer:</strong> Halo is a developer tool designed to assist with code analysis and identifying potential privacy issues. It is not legal advice and does not guarantee compliance with COPPA, GDPR, or any other regulation. Always consult with qualified legal counsel regarding your specific compliance obligations.</p>
      <p style="margin-top:8px;">Generated by <strong>Halo</strong> v${CLI_VERSION} · <a href="https://runhalo.dev" style="color:#6366f1;">runhalo.dev</a></p>
    </div>
  </div>
</body>
</html>`;
}

/**
 * Escape HTML special characters
 */
function escapeHtml(text: string): string {
  return text
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;')
    .replace(/'/g, '&#39;');
}

// ==================== Module-level scan data for cross-function access ====================
// Stores the last scan's results so the action handler can regenerate the PDF
// with AI Review Board data after the review board runs.
const _lastScanData: {
  results: ScanResult[];
  scoreResult: any;
  fileCount: number;
  projectPath: string;
} = { results: [], scoreResult: null, fileCount: 0, projectPath: '' };

// ==================== PDF Report Generator (P3-2) ====================

// PDF color constants
const PDF_COLORS = {
  primary: '#6366f1',    // Halo accent (indigo)
  purple: '#a855f7',
  green: '#22c55e',
  cyan: '#3b82f6',
  yellow: '#eab308',
  orange: '#f97316',
  red: '#ef4444',
  darkText: '#0f172a',
  bodyText: '#1e293b',
  mutedText: '#64748b',
  lightText: '#94a3b8',
  border: '#e2e8f0',
  lightBg: '#f8fafc',
  white: '#ffffff',
} as const;

function gradeColor(grade: string): string {
  switch (grade) {
    case 'A': return PDF_COLORS.green;
    case 'B': return PDF_COLORS.cyan;
    case 'C': return PDF_COLORS.yellow;
    case 'D': return PDF_COLORS.orange;
    default: return PDF_COLORS.red;
  }
}

function severityColor(severity: string): string {
  switch (severity) {
    case 'critical': return PDF_COLORS.red;
    case 'high': return PDF_COLORS.orange;
    case 'medium': return PDF_COLORS.yellow;
    default: return PDF_COLORS.cyan;
  }
}

/**
 * Generate a tier-gated PDF compliance report.
 * Uses PDFKit — pure JS, no browser dependencies, CI-safe.
 *
 * Tier-gated PDF templates:
 *   Free:       1-page summary (grade, severity, COPPA countdown, upsell CTA)
 *   Pro:        Full scan report (findings, fix suggestions, AI Review Board)
 *   Business:   Compliance attestation (methodology, scan hash, enforcement citations,
 *               dismissed findings, attestation statement, regulatory deadlines)
 *   Enterprise: Same as Business (custom templates via API later)
 */
interface ReviewBoardData {
  results: Array<{
    ruleId: string;
    verdict: string;
    clinicalContext: string;
    reasoning?: string; // Preferred field — use reasoning ?? clinicalContext
    evidenceRefs: string[];
    remediationGuidance: string;
    ageGroupImpact: string[];
    cached: boolean;
    regulatoryContext?: {
      regulation: string;
      enforcement_priority: string;
      penalty_exposure: string;
      urgency_score: number;
      recent_case?: string;
    };
    dollarRisk?: {
      amount_usd: number;
      comparable_case?: string;
      comparable_fine?: string;
      comparable_year?: number;
      confidence: number;
      severity?: string;
    };
  }>;
  summary: { total: number; confirmed: number; downgraded: number; escalated: number; dismissed: number; cache_hits: number };
  risk_summary?: {
    total_exposure_usd: number;
    risk_tier: string;
    confirmed_finding_count: number;
    top_comparable_cases?: Array<{ case_name: string; fine_usd: number; year: number }>;
  };
  marshall_summary?: { enriched_count: number; avg_urgency: number; highest_risk_rule?: string; active_enforcement_count: number };
  cost: { estimated_usd: number; input_tokens?: number; output_tokens?: number };
  latency_ms: number;
}

function generatePdfReport(
  results: ScanResult[],
  scoreResult: any,
  fileCount: number,
  projectPath: string,
  history?: ScanHistoryEntry[],
  reviewData?: ReviewBoardData,
  tier: 'free' | 'pro' | 'business' | 'enterprise' = 'pro'
): Promise<Buffer> {
  return new Promise((resolve, reject) => {
    const isFree = tier === 'free';
    const isBusiness = tier === 'business' || tier === 'enterprise';
    const tierLabel = tier === 'free' ? 'Summary' : tier === 'business' ? 'Attestation' : tier === 'enterprise' ? 'Enterprise' : 'Compliance';

    const doc = new PDFDocument({
      size: 'LETTER',
      margins: { top: 60, bottom: 60, left: 60, right: 60 },
      info: {
        Title: `COPPA 2.0 ${tierLabel} Report`,
        Author: 'Halo by Mindful Media',
        Subject: `Compliance scan of ${projectPath}`,
        Creator: `Halo v${CLI_VERSION}`,
      },
    });

    const chunks: Buffer[] = [];
    doc.on('data', (chunk: Buffer) => chunks.push(chunk));
    doc.on('end', () => resolve(Buffer.concat(chunks)));
    doc.on('error', reject);

    const pageWidth = doc.page.width - 120; // 60px margins each side
    const scanDate = new Date().toLocaleDateString('en-US', {
      weekday: 'long', year: 'numeric', month: 'long', day: 'numeric'
    });
    const scanTime = new Date().toLocaleTimeString('en-US', {
      hour: '2-digit', minute: '2-digit'
    });
    const scanTimestamp = new Date().toISOString();
    const totalViolations = results.reduce((sum, r) => sum + r.violations.length, 0);
    const allViolations = results.flatMap(r => r.violations);
    const { critical = 0, high = 0, medium = 0, low = 0 } = scoreResult.bySeverity || {};

    // Business tier: compute scan hash for immutability
    let scanHash = '';
    if (isBusiness) {
      const crypto = require('crypto');
      const hashInput = JSON.stringify({
        results: results.map(r => ({ filePath: r.filePath, violations: r.violations.map(v => v.ruleId + ':' + v.line) })),
        score: scoreResult.score,
        grade: scoreResult.grade,
        fileCount,
        timestamp: scanTimestamp,
      });
      scanHash = crypto.createHash('sha256').update(hashInput).digest('hex');
    }

    // ═══════════════ HELPER: Page footer ═══════════════
    let pageNum = 0;
    function addFooter() {
      pageNum++;
      const y = doc.page.height - 40;
      doc.save();
      doc.fontSize(7).fillColor(PDF_COLORS.lightText);
      doc.text(`Generated by Halo v${CLI_VERSION} — runhalo.dev`, 60, y, { width: pageWidth / 2, align: 'left' });
      doc.text(`Page ${pageNum}`, 60, y, { width: pageWidth, align: 'right' });
      doc.restore();
    }

    // ═══════════════ COVER PAGE ═══════════════
    doc.save();

    // Logo block
    const logoX = 60;
    const logoY = 100;
    doc.roundedRect(logoX, logoY, 48, 48, 10).fill(PDF_COLORS.primary);
    doc.fontSize(24).fillColor(PDF_COLORS.white).text('H', logoX + 14, logoY + 10, { width: 48 });

    // Title
    doc.fontSize(32).fillColor(PDF_COLORS.darkText).text('COPPA 2.0', 60, 180, { width: pageWidth });
    doc.fontSize(32).fillColor(PDF_COLORS.darkText).text(`${tierLabel} Report`, 60, 220, { width: pageWidth });

    // Divider
    doc.moveTo(60, 270).lineTo(60 + pageWidth, 270).lineWidth(2).strokeColor(PDF_COLORS.primary).stroke();

    // Metadata
    doc.fontSize(11).fillColor(PDF_COLORS.mutedText);
    doc.text(`Project:  ${projectPath}`, 60, 290);
    doc.text(`Date:     ${scanDate} at ${scanTime}`, 60, 308);
    doc.text(`Files:    ${fileCount} files scanned`, 60, 326);
    doc.text(`Scanner:  Halo v${CLI_VERSION}`, 60, 344);
    if (isBusiness) {
      doc.text(`Hash:     ${scanHash.substring(0, 16)}...`, 60, 362);
    }

    // COPPA 2.0 countdown banner
    const coppaInfo = formatCoppaCountdownPDF();
    const bannerY = isBusiness ? 388 : 370;
    const bannerColor = coppaInfo.severity === 'urgent' ? PDF_COLORS.red
      : coppaInfo.severity === 'active' ? PDF_COLORS.red
      : PDF_COLORS.yellow;
    doc.rect(60, bannerY, pageWidth, 28).fill(bannerColor);
    doc.fontSize(10).fillColor(PDF_COLORS.white);
    doc.text(coppaInfo.text, 70, bannerY + 8, { width: pageWidth - 20, align: 'center' });

    // Score display (centered, large)
    const scoreY = bannerY + 50;
    const scoreCenterX = 60 + pageWidth / 2;

    // Score circle background
    doc.circle(scoreCenterX, scoreY, 60).lineWidth(8).strokeColor(PDF_COLORS.border).stroke();
    // Score arc (proportional to score)
    if (scoreResult.score > 0) {
      const startAngle = -Math.PI / 2;
      const endAngle = startAngle + (scoreResult.score / 100) * 2 * Math.PI;
      // Draw score arc
      doc.save();
      doc.circle(scoreCenterX, scoreY, 60).lineWidth(8).strokeColor(gradeColor(scoreResult.grade)).stroke();
      doc.restore();
    }

    // Score number
    doc.fontSize(36).fillColor(PDF_COLORS.darkText);
    const scoreText = `${scoreResult.score}`;
    doc.text(scoreText, scoreCenterX - 30, scoreY - 20, { width: 60, align: 'center' });
    doc.fontSize(10).fillColor(PDF_COLORS.mutedText);
    doc.text('out of 100', scoreCenterX - 30, scoreY + 20, { width: 60, align: 'center' });

    // Grade badge
    doc.fontSize(48).fillColor(gradeColor(scoreResult.grade));
    doc.text(`Grade ${scoreResult.grade}`, 60, scoreY + 80, { width: pageWidth, align: 'center' });

    // Summary line
    doc.fontSize(12).fillColor(PDF_COLORS.bodyText);
    doc.text(
      `${totalViolations} violation${totalViolations !== 1 ? 's' : ''} found across ${results.filter(r => r.violations.length > 0).length} file${results.filter(r => r.violations.length > 0).length !== 1 ? 's' : ''}`,
      60, scoreY + 140, { width: pageWidth, align: 'center' }
    );

    // Confidentiality notice
    doc.fontSize(8).fillColor(PDF_COLORS.lightText);
    doc.text('CONFIDENTIAL — FOR INTERNAL COMPLIANCE USE ONLY', 60, doc.page.height - 80, { width: pageWidth, align: 'center' });

    addFooter();
    doc.restore();

    // ═══════════════ FREE TIER: 1-page summary only ═══════════════
    if (isFree) {
      doc.addPage();
      doc.fontSize(20).fillColor(PDF_COLORS.darkText).text('Scan Summary', 60, 60);
      doc.moveTo(60, 88).lineTo(60 + pageWidth, 88).lineWidth(1).strokeColor(PDF_COLORS.border).stroke();

      let fy = 100;
      doc.fontSize(14).fillColor(PDF_COLORS.bodyText);
      doc.text(`Compliance Score: ${scoreResult.score}/100 (Grade ${scoreResult.grade})`, 60, fy);
      fy += 30;

      // Severity breakdown
      doc.fontSize(12).fillColor(PDF_COLORS.darkText).text('Severity Breakdown', 60, fy);
      fy += 22;
      if (critical > 0) { doc.fontSize(10).fillColor(PDF_COLORS.red).text(`  Critical: ${critical}`, 60, fy); fy += 16; }
      if (high > 0) { doc.fontSize(10).fillColor(PDF_COLORS.orange).text(`  High: ${high}`, 60, fy); fy += 16; }
      if (medium > 0) { doc.fontSize(10).fillColor(PDF_COLORS.yellow).text(`  Medium: ${medium}`, 60, fy); fy += 16; }
      if (low > 0) { doc.fontSize(10).fillColor(PDF_COLORS.cyan).text(`  Low: ${low}`, 60, fy); fy += 16; }
      fy += 20;

      // FP warning + upsell
      doc.rect(60, fy, pageWidth, 80).fill('#fffbeb');
      doc.fontSize(11).fillColor(PDF_COLORS.orange);
      doc.text(`${totalViolations} potential violation${totalViolations !== 1 ? 's' : ''} found.`, 70, fy + 10, { width: pageWidth - 20 });
      doc.fontSize(10).fillColor(PDF_COLORS.bodyText);
      doc.text(
        'This is a regex pre-filter scan. Some findings may be false positives. ' +
        'Upgrade to Halo Pro ($29/mo) for AI-verified results with dollar risk exposure, ' +
        'or Business ($99/mo) for compliance attestation reports.',
        70, fy + 30, { width: pageWidth - 20 }
      );
      fy += 100;

      // Next steps
      doc.fontSize(12).fillColor(PDF_COLORS.darkText).text('Next Steps', 60, fy);
      fy += 22;
      doc.fontSize(10).fillColor(PDF_COLORS.bodyText);
      doc.text('1. Run with --review for AI-verified compliance results (Pro)', 70, fy, { width: pageWidth - 20 }); fy += 16;
      doc.text('2. Generate detailed report: runhalo scan . --report compliance.pdf (Pro)', 70, fy, { width: pageWidth - 20 }); fy += 16;
      doc.text('3. Get attestation report for legal/compliance: Business tier', 70, fy, { width: pageWidth - 20 }); fy += 16;
      doc.text('4. Visit runhalo.dev/pricing for plan comparison', 70, fy, { width: pageWidth - 20 }); fy += 30;

      // Disclaimer
      doc.fontSize(7).fillColor(PDF_COLORS.lightText);
      doc.text(
        'DISCLAIMER: This is an automated code scan summary. It is not legal advice and does not guarantee compliance.',
        60, doc.page.height - 100, { width: pageWidth }
      );

      addFooter();
      doc.end();
      return;
    }

    // ═══════════════ EXECUTIVE SUMMARY ═══════════════
    doc.addPage();

    doc.fontSize(20).fillColor(PDF_COLORS.darkText).text('Executive Summary', 60, 60);
    doc.moveTo(60, 88).lineTo(60 + pageWidth, 88).lineWidth(1).strokeColor(PDF_COLORS.border).stroke();

    let y = 100;

    // Score + grade inline
    doc.fontSize(14).fillColor(PDF_COLORS.bodyText);
    doc.text(`Compliance Score: ${scoreResult.score}/100 (Grade ${scoreResult.grade})`, 60, y);
    y += 30;

    // Trend (if available)
    if (history && history.length > 0) {
      const projectHistory = history.filter((h: ScanHistoryEntry) => h.projectPath === projectPath);
      if (projectHistory.length > 0) {
        const last = projectHistory[projectHistory.length - 1];
        const diff = scoreResult.score - last.score;
        const arrow = diff > 0 ? '↑' : diff < 0 ? '↓' : '→';
        const trendColor = diff > 0 ? PDF_COLORS.green : diff < 0 ? PDF_COLORS.red : PDF_COLORS.mutedText;
        doc.fontSize(11).fillColor(trendColor);
        doc.text(`${arrow} ${last.score}% → ${scoreResult.score}% (${diff > 0 ? '+' : ''}${diff} since last scan)`, 60, y);
        y += 25;
      }
    }

    // Severity breakdown table
    y += 10;
    doc.fontSize(14).fillColor(PDF_COLORS.darkText).text('Severity Breakdown', 60, y);
    y += 25;

    // Table header
    const col1 = 60, col2 = 220, col3 = 320, col4 = 420;
    doc.fontSize(9).fillColor(PDF_COLORS.mutedText);
    doc.text('SEVERITY', col1, y);
    doc.text('COUNT', col2, y);
    doc.text('POINTS DEDUCTED', col3, y);
    doc.text('% OF TOTAL', col4, y);
    y += 18;
    doc.moveTo(60, y).lineTo(60 + pageWidth, y).lineWidth(0.5).strokeColor(PDF_COLORS.border).stroke();
    y += 8;

    const severities = [
      { label: 'Critical', count: critical, points: critical * 10, color: PDF_COLORS.red },
      { label: 'High', count: high, points: high * 5, color: PDF_COLORS.orange },
      { label: 'Medium', count: medium, points: medium * 2, color: PDF_COLORS.yellow },
      { label: 'Low', count: low, points: low * 1, color: PDF_COLORS.cyan },
    ];

    for (const sev of severities) {
      // Colored dot
      doc.circle(col1 + 5, y + 5, 4).fill(sev.color);
      doc.fontSize(10).fillColor(PDF_COLORS.bodyText);
      doc.text(sev.label, col1 + 16, y);
      doc.text(`${sev.count}`, col2, y);
      doc.text(sev.count > 0 ? `-${sev.points}` : '—', col3, y);
      const pct = totalViolations > 0 ? ((sev.count / totalViolations) * 100).toFixed(0) : '0';
      doc.text(`${pct}%`, col4, y);
      y += 20;
    }

    // Total row
    doc.moveTo(60, y).lineTo(60 + pageWidth, y).lineWidth(0.5).strokeColor(PDF_COLORS.border).stroke();
    y += 8;
    doc.fontSize(10).fillColor(PDF_COLORS.darkText);
    doc.text('Total', col1 + 16, y, { bold: true } as any);
    doc.text(`${totalViolations}`, col2, y);
    doc.text(`-${scoreResult.pointsDeducted}`, col3, y);
    y += 30;

    // Key findings
    doc.fontSize(14).fillColor(PDF_COLORS.darkText).text('Key Findings', 60, y);
    y += 25;

    doc.fontSize(10).fillColor(PDF_COLORS.bodyText);
    if (totalViolations === 0) {
      doc.text('No COPPA compliance issues were detected in this codebase. All 20 rules passed.', 60, y, { width: pageWidth });
    } else {
      if (critical > 0) {
        doc.fillColor(PDF_COLORS.red);
        doc.text(`• ${critical} critical issue${critical !== 1 ? 's' : ''} require immediate attention — these represent the highest compliance risk.`, 60, y, { width: pageWidth });
        y += 18;
      }
      if (high > 0) {
        doc.fillColor(PDF_COLORS.orange);
        doc.text(`• ${high} high-severity issue${high !== 1 ? 's' : ''} should be resolved before production release.`, 60, y, { width: pageWidth });
        y += 18;
      }

      // Auto-fixable count
      const autoFixable = allViolations.filter(v =>
        ['coppa-sec-006', 'coppa-sec-010', 'coppa-sec-015', 'coppa-default-020'].includes(v.ruleId)
      );
      if (autoFixable.length > 0) {
        doc.fillColor(PDF_COLORS.green);
        doc.text(`• ${autoFixable.length} issue${autoFixable.length !== 1 ? 's' : ''} can be auto-fixed by running: npx runhalo fix .`, 60, y, { width: pageWidth });
        y += 18;
      }

      // Unique rules triggered
      const uniqueRules = [...new Set(allViolations.map(v => v.ruleId))];
      doc.fillColor(PDF_COLORS.bodyText);
      doc.text(`• ${uniqueRules.length} unique COPPA rule${uniqueRules.length !== 1 ? 's' : ''} triggered across ${fileCount} scanned files.`, 60, y, { width: pageWidth });
    }

    addFooter();

    // ═══════════════ DETAILED FINDINGS ═══════════════
    if (totalViolations > 0) {
      doc.addPage();
      doc.fontSize(20).fillColor(PDF_COLORS.darkText).text('Detailed Findings', 60, 60);
      doc.moveTo(60, 88).lineTo(60 + pageWidth, 88).lineWidth(1).strokeColor(PDF_COLORS.border).stroke();

      y = 100;

      // Group violations by severity
      const bySeverity: Record<string, { file: string; violation: Violation }[]> = {
        critical: [], high: [], medium: [], low: []
      };
      for (const result of results) {
        for (const v of result.violations) {
          const relPath = path.relative(projectPath, result.filePath) || result.filePath;
          bySeverity[v.severity]?.push({ file: relPath, violation: v });
        }
      }

      // PDF Cap: Show max 25 violations to keep PDF under ~10 pages
      // Priority: ALL critical/high first, then fill remaining slots with medium/low
      const PDF_VIOLATION_CAP = 25;
      let violationsShown = 0;
      let violationsOmitted = 0;
      const totalAllItems = Object.values(bySeverity).reduce((sum, items) => sum + items.length, 0);

      for (const severity of ['critical', 'high', 'medium', 'low'] as const) {
        const items = bySeverity[severity];
        if (!items || items.length === 0) continue;

        // Determine how many of this severity to show
        const remainingSlots = PDF_VIOLATION_CAP - violationsShown;
        if (remainingSlots <= 0) {
          violationsOmitted += items.length;
          continue;
        }

        const itemsToShow = items.slice(0, remainingSlots);
        const itemsSkipped = items.length - itemsToShow.length;
        violationsOmitted += itemsSkipped;

        // Check if we need a new page
        if (y > doc.page.height - 150) {
          addFooter();
          doc.addPage();
          y = 60;
        }

        // Severity header
        doc.fontSize(14).fillColor(severityColor(severity));
        doc.text(`${severity.charAt(0).toUpperCase() + severity.slice(1)} (${items.length}${itemsSkipped > 0 ? `, showing ${itemsToShow.length}` : ''})`, 60, y);
        y += 22;

        for (const item of itemsToShow) {
          // Check page break
          if (y > doc.page.height - 120) {
            addFooter();
            doc.addPage();
            y = 60;
          }

          // Violation entry
          doc.fontSize(9).fillColor(severityColor(severity));
          doc.text(severity.toUpperCase(), 60, y);
          doc.fillColor(PDF_COLORS.primary);
          doc.text(item.violation.ruleId, 120, y);
          doc.fillColor(PDF_COLORS.mutedText);
          doc.text(`${item.file}:${item.violation.line}`, 260, y);
          y += 14;

          // Message
          doc.fontSize(9).fillColor(PDF_COLORS.bodyText);
          const msgHeight = doc.heightOfString(item.violation.message, { width: pageWidth - 20 });
          doc.text(item.violation.message, 70, y, { width: pageWidth - 20 });
          y += msgHeight + 4;

          // Code snippet (if available)
          if (item.violation.codeSnippet) {
            const snippet = item.violation.codeSnippet.length > 120
              ? item.violation.codeSnippet.substring(0, 117) + '...'
              : item.violation.codeSnippet;
            doc.rect(70, y, pageWidth - 20, 16).fill(PDF_COLORS.lightBg);
            doc.fontSize(7).fillColor(PDF_COLORS.mutedText);
            doc.text(snippet, 74, y + 4, { width: pageWidth - 28 });
            y += 22;
          }

          // Fix suggestion
          if (item.violation.fixSuggestion) {
            doc.fontSize(8).fillColor(PDF_COLORS.green);
            const fixText = `Fix: ${item.violation.fixSuggestion}`;
            const fixHeight = doc.heightOfString(fixText, { width: pageWidth - 20 });
            doc.text(fixText, 70, y, { width: pageWidth - 20 });
            y += fixHeight + 4;
          }

          // Penalty
          if (item.violation.penalty) {
            doc.fontSize(7).fillColor(PDF_COLORS.red);
            doc.text(`Penalty: ${item.violation.penalty}`, 70, y);
            y += 12;
          }

          y += 8; // spacing between violations
          violationsShown++;
        }

        y += 10; // spacing between severity groups
      }

      // Dashboard CTA for omitted violations
      if (violationsOmitted > 0) {
        if (y > doc.page.height - 120) {
          addFooter();
          doc.addPage();
          y = 60;
        }

        y += 10;
        doc.rect(60, y, pageWidth, 60).fill('#f0f0ff');
        doc.fontSize(11).fillColor(PDF_COLORS.primary);
        doc.text(`${violationsOmitted} additional violation(s) not shown in this report.`, 70, y + 12, { width: pageWidth - 20 });
        doc.fontSize(10).fillColor(PDF_COLORS.bodyText);
        doc.text('View all violations on your Halo Dashboard: https://runhalo.dev/app/dashboard.html', 70, y + 30, { width: pageWidth - 20 });
        y += 70;
      }

      addFooter();
    }

    // ═══════════════ AI REVIEW BOARD ═══════════════
    if (reviewData && reviewData.results.length > 0) {
      doc.addPage();
      doc.fontSize(20).fillColor(PDF_COLORS.darkText).text('AI Review Board Assessment', 60, 60);
      doc.moveTo(60, 88).lineTo(60 + pageWidth, 88).lineWidth(1).strokeColor(PDF_COLORS.border).stroke();

      y = 100;

      // Review Board summary box
      doc.rect(60, y, pageWidth, 70).fill(PDF_COLORS.lightBg);
      doc.fontSize(10).fillColor(PDF_COLORS.bodyText);
      doc.text(`${reviewData.summary.total} violations reviewed by Halo AI Review Board`, 70, y + 8, { width: pageWidth - 20 });
      y += 22;

      const verdictLine = [
        reviewData.summary.escalated > 0 ? `🔴 ${reviewData.summary.escalated} escalated` : '',
        reviewData.summary.confirmed > 0 ? `🟡 ${reviewData.summary.confirmed} confirmed` : '',
        reviewData.summary.downgraded > 0 ? `🟢 ${reviewData.summary.downgraded} downgraded` : '',
        reviewData.summary.dismissed > 0 ? `✅ ${reviewData.summary.dismissed} dismissed` : '',
      ].filter(Boolean).join('   ');
      doc.fontSize(9).fillColor(PDF_COLORS.bodyText);
      doc.text(verdictLine, 70, y, { width: pageWidth - 20 });
      y += 16;

      // Marshall summary
      if (reviewData.marshall_summary) {
        const ms = reviewData.marshall_summary;
        doc.fontSize(8).fillColor(PDF_COLORS.mutedText);
        doc.text(`Marshall Intelligence: ${ms.enriched_count} violations enriched | Avg urgency: ${ms.avg_urgency} | ${ms.active_enforcement_count} in active enforcement areas`, 70, y, { width: pageWidth - 20 });
      }

      y += 40; // past the summary box

      // Per-verdict sections
      const verdictOrder: Array<{ key: string; label: string; color: string; emoji: string }> = [
        { key: 'escalated', label: 'ESCALATED — More Serious Than Initially Detected', color: PDF_COLORS.red, emoji: '🔴' },
        { key: 'confirmed', label: 'CONFIRMED — Violations Validated by AI Review', color: PDF_COLORS.orange, emoji: '🟡' },
        { key: 'downgraded', label: 'DOWNGRADED — Lower Risk Than Severity Suggests', color: PDF_COLORS.green, emoji: '🟢' },
        { key: 'dismissed', label: 'DISMISSED — False Positives Cleared', color: PDF_COLORS.cyan, emoji: '✅' },
      ];

      for (const vType of verdictOrder) {
        const items = reviewData.results.filter(r => r.verdict === vType.key);
        if (items.length === 0) continue;

        if (y > doc.page.height - 140) {
          addFooter();
          doc.addPage();
          y = 60;
        }

        doc.fontSize(12).fillColor(vType.color);
        doc.text(`${vType.emoji} ${vType.label} (${items.length})`, 60, y);
        y += 20;

        // Show up to 10 per verdict type
        const itemsToShow = items.slice(0, 10);
        for (const item of itemsToShow) {
          if (y > doc.page.height - 100) {
            addFooter();
            doc.addPage();
            y = 60;
          }

          // Rule ID + verdict
          doc.fontSize(9).fillColor(PDF_COLORS.primary);
          doc.text(item.ruleId, 70, y);
          y += 14;

          // Clinical context
          if ((item.reasoning || item.clinicalContext)) {
            doc.fontSize(8).fillColor(PDF_COLORS.bodyText);
            const ctxHeight = doc.heightOfString((item.reasoning || item.clinicalContext), { width: pageWidth - 30 });
            doc.text((item.reasoning || item.clinicalContext), 80, y, { width: pageWidth - 30 });
            y += ctxHeight + 4;
          }

          // Age groups
          if (item.ageGroupImpact && item.ageGroupImpact.length > 0) {
            doc.fontSize(7).fillColor(PDF_COLORS.mutedText);
            doc.text(`Ages most affected: ${item.ageGroupImpact.join(', ')}`, 80, y);
            y += 12;
          }

          // Regulatory context (Marshall enrichment)
          if (item.regulatoryContext) {
            const rc = item.regulatoryContext;
            const priorityLabel = rc.enforcement_priority === 'active' ? '🔴 ACTIVE'
              : rc.enforcement_priority === 'watching' ? '🟡 WATCHING' : '⚪ DORMANT';
            doc.fontSize(7).fillColor(PDF_COLORS.red);
            doc.text(`Regulatory: ${rc.regulation} | ${priorityLabel} | Penalty: ${rc.penalty_exposure} | Urgency: ${rc.urgency_score}`, 80, y, { width: pageWidth - 30 });
            y += 12;
            if (rc.recent_case) {
              doc.fontSize(7).fillColor(PDF_COLORS.mutedText);
              doc.text(`Recent precedent: ${rc.recent_case}`, 80, y, { width: pageWidth - 30 });
              y += 12;
            }
          }

          // Remediation
          if (item.remediationGuidance) {
            doc.fontSize(8).fillColor(PDF_COLORS.green);
            const remHeight = doc.heightOfString(`Fix: ${item.remediationGuidance}`, { width: pageWidth - 30 });
            doc.text(`Fix: ${item.remediationGuidance}`, 80, y, { width: pageWidth - 30 });
            y += remHeight + 4;
          }

          y += 8;
        }

        if (items.length > 10) {
          doc.fontSize(8).fillColor(PDF_COLORS.mutedText);
          doc.text(`+ ${items.length - 10} more ${vType.key} violation(s). See full results on your Halo Dashboard.`, 80, y, { width: pageWidth - 30 });
          y += 16;
        }

        y += 10;
      }

      // Review Board footer note
      if (y > doc.page.height - 80) {
        addFooter();
        doc.addPage();
        y = 60;
      }
      doc.fontSize(7).fillColor(PDF_COLORS.lightText);
      doc.text(
        `Reviewed by Halo AI Review Board (Richard + Marshall) in ${reviewData.latency_ms}ms. Cost: $${reviewData.cost.estimated_usd.toFixed(4)}. ${reviewData.summary.cache_hits} results served from cache.`,
        60, y, { width: pageWidth }
      );

      addFooter();
    }

    // ═══════════════ BUSINESS TIER: ATTESTATION SECTIONS ═══════════════
    if (isBusiness) {
      // ── Scan Methodology ──
      doc.addPage();
      doc.fontSize(20).fillColor(PDF_COLORS.darkText).text('Scan Methodology', 60, 60);
      doc.moveTo(60, 88).lineTo(60 + pageWidth, 88).lineWidth(1).strokeColor(PDF_COLORS.border).stroke();

      y = 100;
      doc.fontSize(10).fillColor(PDF_COLORS.bodyText);
      const methodologyItems = [
        ['Scanner Version', `Halo v${CLI_VERSION}`],
        ['Engine', `@runhalo/engine v${CLI_VERSION}`],
        ['Rules Version', '180 rules across 17 packs, 13 jurisdictions'],
        ['Analysis Tiers', 'Tier 1 (Regex) + Tier 2 (AST) + Tier 3 (AI Review Board)'],
        ['AI Model', 'Claude Sonnet 4 (two-agent consensus)'],
        ['Confidence Threshold', 'High (>= 0.7), Medium (0.4-0.69), Low (< 0.4)'],
        ['Scan Date', `${scanDate} at ${scanTime}`],
        ['Scan Timestamp', scanTimestamp],
        ['Files Scanned', `${fileCount}`],
        ['Scan Hash (SHA-256)', scanHash],
      ];

      for (const [label, value] of methodologyItems) {
        doc.fontSize(9).fillColor(PDF_COLORS.mutedText).text(label, 70, y, { width: 160, continued: false });
        doc.fontSize(9).fillColor(PDF_COLORS.bodyText).text(value, 240, y, { width: pageWidth - 190 });
        y += 18;
      }

      y += 20;
      doc.fontSize(10).fillColor(PDF_COLORS.bodyText);
      doc.text(
        'This scan was performed using Halo\'s three-tier detection pipeline. Tier 1 identifies potential compliance issues using pattern-based analysis across all 180 rules. Tier 2 enriches findings with structural code analysis (AST, data-flow tracing, import graph). Tier 3 applies AI-powered compliance reasoning with two-agent consensus, regulatory intelligence, and dollar risk scoring.',
        60, y, { width: pageWidth }
      );
      y += 60;

      doc.text(
        'Findings marked as "dismissed" by the AI Review Board have been assessed as false positives with high confidence. The determination considers code context, framework patterns, scope analysis, and historical false positive rates.',
        60, y, { width: pageWidth }
      );

      addFooter();

      // ── Dismissed Findings ──
      if (reviewData && reviewData.results.length > 0) {
        const dismissed = reviewData.results.filter(r => r.verdict === 'dismissed' || r.verdict === 'downgraded');
        if (dismissed.length > 0) {
          doc.addPage();
          doc.fontSize(20).fillColor(PDF_COLORS.darkText).text('Dismissed Findings', 60, 60);
          doc.fontSize(10).fillColor(PDF_COLORS.mutedText).text(
            'The following findings were reviewed and assessed as false positives or lower risk by the AI Review Board. Included for audit trail completeness.',
            60, 85, { width: pageWidth }
          );
          doc.moveTo(60, 108).lineTo(60 + pageWidth, 108).lineWidth(1).strokeColor(PDF_COLORS.border).stroke();

          y = 120;
          const dismissedToShow = dismissed.slice(0, 20);
          for (const item of dismissedToShow) {
            if (y > doc.page.height - 100) {
              addFooter();
              doc.addPage();
              y = 60;
            }

            doc.fontSize(9).fillColor(PDF_COLORS.mutedText);
            doc.text(`${item.verdict.toUpperCase()} — ${item.ruleId}`, 70, y);
            y += 14;
            if ((item.reasoning || item.clinicalContext)) {
              doc.fontSize(8).fillColor(PDF_COLORS.lightText);
              const ctxH = doc.heightOfString((item.reasoning || item.clinicalContext), { width: pageWidth - 30 });
              doc.text((item.reasoning || item.clinicalContext), 80, y, { width: pageWidth - 30 });
              y += ctxH + 8;
            }
          }
          if (dismissed.length > 20) {
            doc.fontSize(8).fillColor(PDF_COLORS.mutedText);
            doc.text(`+ ${dismissed.length - 20} more dismissed finding(s). See Halo Dashboard for full audit trail.`, 80, y);
          }

          addFooter();
        }
      }

      // ── Enforcement Precedent Citations ──
      if (reviewData) {
        const withEnforcement = reviewData.results.filter(r =>
          (r.verdict === 'confirmed' || r.verdict === 'escalated') && r.regulatoryContext
        );
        if (withEnforcement.length > 0) {
          doc.addPage();
          doc.fontSize(20).fillColor(PDF_COLORS.darkText).text('Enforcement Precedent Citations', 60, 60);
          doc.moveTo(60, 88).lineTo(60 + pageWidth, 88).lineWidth(1).strokeColor(PDF_COLORS.border).stroke();

          y = 100;
          doc.fontSize(9).fillColor(PDF_COLORS.bodyText);
          doc.text(
            'The following enforcement actions are cited as comparable precedents for confirmed findings. These are historical references provided for context and are not predictive of regulatory outcomes.',
            60, y, { width: pageWidth }
          );
          y += 40;

          for (const item of withEnforcement.slice(0, 15)) {
            if (y > doc.page.height - 100) {
              addFooter();
              doc.addPage();
              y = 60;
            }

            doc.fontSize(9).fillColor(PDF_COLORS.primary).text(item.ruleId, 70, y);
            y += 14;
            if (item.regulatoryContext) {
              const rc = item.regulatoryContext;
              doc.fontSize(8).fillColor(PDF_COLORS.bodyText);
              doc.text(`Regulation: ${rc.regulation} | Penalty Exposure: ${rc.penalty_exposure}`, 80, y, { width: pageWidth - 30 });
              y += 14;
              if (rc.recent_case) {
                doc.fontSize(8).fillColor(PDF_COLORS.mutedText);
                doc.text(`Precedent: ${rc.recent_case}`, 80, y, { width: pageWidth - 30 });
                y += 14;
              }
            }
            if (item.dollarRisk) {
              doc.fontSize(8).fillColor(PDF_COLORS.red);
              const caseRef = item.dollarRisk.comparable_case
                ? ` (cf. ${formatCase(item.dollarRisk.comparable_case)}${item.dollarRisk.comparable_fine ? `, ${item.dollarRisk.comparable_fine}` : ''})`
                : '';
              doc.text(`Estimated Risk: $${item.dollarRisk.amount_usd.toLocaleString()}${caseRef}`, 80, y, { width: pageWidth - 30 });
              y += 14;
            }
            y += 8;
          }

          addFooter();
        }
      }

      // ── Attestation Statement ──
      doc.addPage();
      doc.fontSize(20).fillColor(PDF_COLORS.darkText).text('Attestation Statement', 60, 60);
      doc.moveTo(60, 88).lineTo(60 + pageWidth, 88).lineWidth(1).strokeColor(PDF_COLORS.border).stroke();

      y = 110;

      // Attestation box
      doc.rect(60, y, pageWidth, 160).lineWidth(2).strokeColor(PDF_COLORS.primary).stroke();
      y += 15;
      doc.fontSize(11).fillColor(PDF_COLORS.darkText);
      doc.text('COMPLIANCE SCAN ATTESTATION', 80, y, { width: pageWidth - 40, align: 'center' });
      y += 25;
      doc.fontSize(10).fillColor(PDF_COLORS.bodyText);
      doc.text(
        `This report attests that the codebase located at "${path.basename(projectPath)}" was scanned using ` +
        `Halo v${CLI_VERSION} on ${scanDate} at ${scanTime}. The scan employed a three-tier detection methodology ` +
        `(pattern analysis, structural AST analysis, and AI-powered compliance reasoning) covering ${fileCount} source files ` +
        `against 160 compliance rules spanning 12 regulatory jurisdictions.`,
        80, y, { width: pageWidth - 40 }
      );
      y += 70;
      doc.text(
        `The scan identified ${totalViolations} potential compliance finding${totalViolations !== 1 ? 's' : ''}` +
        (reviewData ? `, of which ${reviewData.summary.confirmed + reviewData.summary.escalated} were confirmed by AI review` : '') +
        `. This report represents reasonable measures taken to identify children\'s privacy compliance issues in the scanned codebase.`,
        80, y, { width: pageWidth - 40 }
      );
      y += 50;

      doc.fontSize(9).fillColor(PDF_COLORS.mutedText);
      doc.text(`Scan Hash: ${scanHash}`, 80, y, { width: pageWidth - 40 });
      y += 30;

      // Regulatory deadline section
      y += 20;
      doc.fontSize(14).fillColor(PDF_COLORS.darkText).text('Regulatory Deadlines', 60, y);
      y += 22;

      const coppaCD = getCoppaCountdown();
      doc.fontSize(10);
      if (coppaCD.isActive) {
        doc.fillColor(PDF_COLORS.red).text('COPPA 2.0 Final Rule — NOW IN EFFECT', 70, y, { width: pageWidth - 20 });
      } else {
        doc.fillColor(PDF_COLORS.orange).text(`COPPA 2.0 Final Rule — ${coppaCD.days} days until enforcement (April 22, 2026)`, 70, y, { width: pageWidth - 20 });
      }
      y += 18;
      doc.fillColor(PDF_COLORS.bodyText);
      doc.text(`Maximum penalty: $${coppaCD.penaltyPerDay.toLocaleString()} per violation per day`, 70, y, { width: pageWidth - 20 });
      y += 30;

      // Finding-specific deadlines
      const uniqueRegs = new Set<string>();
      if (reviewData) {
        for (const r of reviewData.results) {
          if (r.regulatoryContext?.regulation) uniqueRegs.add(r.regulatoryContext.regulation);
        }
      }
      if (uniqueRegs.size > 0) {
        doc.fontSize(10).fillColor(PDF_COLORS.bodyText);
        doc.text(`Regulations implicated by findings: ${Array.from(uniqueRegs).join(', ')}`, 70, y, { width: pageWidth - 20 });
      }

      // Legal disclaimer alongside attestation
      y = doc.page.height - 130;
      doc.moveTo(60, y).lineTo(60 + pageWidth, y).lineWidth(0.5).strokeColor(PDF_COLORS.border).stroke();
      y += 10;
      doc.fontSize(7).fillColor(PDF_COLORS.lightText);
      doc.text(
        'IMPORTANT: This attestation confirms that a technical compliance scan was performed. It does not constitute legal advice, ' +
        'a legal opinion, or a guarantee of regulatory compliance. Halo identifies potential code-level compliance issues but cannot ' +
        'assess organizational policies, data processing agreements, or operational practices. Organizations should engage qualified ' +
        'legal counsel and compliance professionals for comprehensive compliance assessment. The scan hash above can be used to ' +
        'verify the integrity and authenticity of this specific scan result.',
        60, y, { width: pageWidth }
      );

      addFooter();
    }

    // ═══════════════ RECOMMENDATIONS ═══════════════
    doc.addPage();
    doc.fontSize(20).fillColor(PDF_COLORS.darkText).text('Recommendations', 60, 60);
    doc.moveTo(60, 88).lineTo(60 + pageWidth, 88).lineWidth(1).strokeColor(PDF_COLORS.border).stroke();

    y = 100;
    let recNum = 1;

    doc.fontSize(10).fillColor(PDF_COLORS.bodyText);

    if (totalViolations === 0) {
      doc.text('No issues detected. This codebase passes all current COPPA 2.0 compliance checks.', 60, y, { width: pageWidth });
      y += 20;
      doc.text('Recommended next steps:', 60, y, { width: pageWidth });
      y += 16;
      doc.text(`${recNum++}. Schedule regular scans as part of your CI/CD pipeline.`, 70, y, { width: pageWidth - 20 });
      y += 16;
      doc.text(`${recNum++}. Enable ethical design rules with --ethical-preview for proactive compliance.`, 70, y, { width: pageWidth - 20 });
      y += 16;
      doc.text(`${recNum++}. Run "npx runhalo init --ide" to teach your AI coding assistants COPPA rules.`, 70, y, { width: pageWidth - 20 });
    } else {
      if (critical > 0) {
        doc.fillColor(PDF_COLORS.red);
        doc.text(`${recNum++}. Fix ${critical} critical issue${critical !== 1 ? 's' : ''} immediately — these represent the highest compliance risk and largest potential penalties.`, 70, y, { width: pageWidth - 20 });
        y += 22;
      }
      if (high > 0) {
        doc.fillColor(PDF_COLORS.orange);
        doc.text(`${recNum++}. Address ${high} high-severity issue${high !== 1 ? 's' : ''} before production release — these are significant compliance gaps.`, 70, y, { width: pageWidth - 20 });
        y += 22;
      }

      const autoFixable = allViolations.filter(v =>
        ['coppa-sec-006', 'coppa-sec-010', 'coppa-sec-015', 'coppa-default-020'].includes(v.ruleId)
      );
      if (autoFixable.length > 0) {
        doc.fillColor(PDF_COLORS.green);
        doc.text(`${recNum++}. Run "npx runhalo fix ." to automatically resolve ${autoFixable.length} issue${autoFixable.length !== 1 ? 's' : ''}.`, 70, y, { width: pageWidth - 20 });
        y += 22;
      }

      if (medium > 0) {
        doc.fillColor(PDF_COLORS.yellow);
        doc.text(`${recNum++}. Review ${medium} medium-severity issue${medium !== 1 ? 's' : ''} — these may require design changes or policy updates.`, 70, y, { width: pageWidth - 20 });
        y += 22;
      }

      doc.fillColor(PDF_COLORS.bodyText);
      doc.text(`${recNum++}. Integrate Halo into your CI pipeline: uses: runhalo/action@v1 in GitHub Actions.`, 70, y, { width: pageWidth - 20 });
      y += 22;
      doc.text(`${recNum++}. Run "npx runhalo init --ide" to teach AI coding assistants COPPA compliance patterns.`, 70, y, { width: pageWidth - 20 });
      y += 22;
      doc.text(`${recNum++}. Schedule re-scan after remediations to track compliance improvement.`, 70, y, { width: pageWidth - 20 });
    }

    // COPPA 2.0 context
    y += 30;
    doc.fontSize(14).fillColor(PDF_COLORS.darkText).text('Regulatory Context', 60, y);
    y += 22;
    doc.fontSize(9).fillColor(PDF_COLORS.bodyText);
    doc.text(
      'The COPPA 2.0 Final Rule (published April 22, 2025) updates the Children\'s Online Privacy Protection Act with new requirements for data retention, biometric data, push notifications, and advertising. The 12-month compliance grace period ends April 22, 2026, after which enforcement begins with penalties up to $54,540 per violation per child per day.',
      60, y, { width: pageWidth }
    );

    // Disclaimer
    y = doc.page.height - 130;
    doc.moveTo(60, y).lineTo(60 + pageWidth, y).lineWidth(0.5).strokeColor(PDF_COLORS.border).stroke();
    y += 10;
    doc.fontSize(7).fillColor(PDF_COLORS.lightText);
    doc.text(
      'DISCLAIMER: Halo is a developer tool designed to assist with code analysis and identifying potential privacy issues. It is not legal advice and does not guarantee compliance with COPPA, GDPR, or any other regulation. Always consult with qualified legal counsel regarding your specific compliance obligations. This report is generated automatically and should be reviewed by a qualified compliance professional.',
      60, y, { width: pageWidth }
    );

    addFooter();

    // Finalize
    doc.end();
  });
}

/**
 * Load .haloignore from a directory (walks up to find it)
 */
function loadHaloignore(startDir: string): IgnoreConfig | undefined {
  let dir = path.resolve(startDir);
  const root = path.parse(dir).root;

  while (dir !== root) {
    const ignorePath = path.join(dir, '.haloignore');
    if (fs.existsSync(ignorePath)) {
      try {
        const content = fs.readFileSync(ignorePath, 'utf-8');
        return parseHaloignore(content);
      } catch {
        return undefined;
      }
    }
    dir = path.dirname(dir);
  }
  return undefined;
}

/**
 * Detect the project framework by scanning project files.
 * Checks package.json, Gemfile, go.mod, Cargo.toml, manage.py, requirements.txt.
 * Returns a framework identifier string or null if unknown.
 */
function detectProjectFramework(dir: string): string | null {
  // Check package.json for JS/TS frameworks
  const pkgPath = path.join(dir, 'package.json');
  if (fs.existsSync(pkgPath)) {
    try {
      const pkg = JSON.parse(fs.readFileSync(pkgPath, 'utf-8'));
      const allDeps: Record<string, string> = {
        ...(pkg.dependencies || {}),
        ...(pkg.devDependencies || {}),
      };

      // Order matters: check specific frameworks before generic ones
      if (allDeps['next']) return 'nextjs';
      if (allDeps['@angular/core']) return 'angular';
      if (allDeps['vue']) return 'vue';
      if (allDeps['svelte']) return 'svelte';
      if (allDeps['react']) return 'react';
    } catch {
      // Malformed package.json — continue detection
    }
  }

  // Django: manage.py or requirements.txt with django
  if (fs.existsSync(path.join(dir, 'manage.py'))) return 'django';
  const reqPath = path.join(dir, 'requirements.txt');
  if (fs.existsSync(reqPath)) {
    try {
      const reqs = fs.readFileSync(reqPath, 'utf-8').toLowerCase();
      if (reqs.includes('django')) return 'django';
    } catch {
      // Continue detection
    }
  }

  // Rails: Gemfile with rails
  const gemfilePath = path.join(dir, 'Gemfile');
  if (fs.existsSync(gemfilePath)) {
    try {
      const gemfile = fs.readFileSync(gemfilePath, 'utf-8').toLowerCase();
      if (gemfile.includes('rails')) return 'rails';
    } catch {
      // Continue detection
    }
  }

  // Go
  if (fs.existsSync(path.join(dir, 'go.mod'))) return 'go';

  // Rust
  if (fs.existsSync(path.join(dir, 'Cargo.toml'))) return 'rust';

  return null;
}

/**
 * Get default .haloignore content based on detected framework.
 */
function getDefaultHaloignoreContent(framework: string | null): string {
  const lines = [
    '# Halo ignore patterns',
    '# Generated by: runhalo init',
    '',
    'node_modules/',
    'dist/',
    'build/',
    'coverage/',
    '*.min.js',
    '*.bundle.js',
  ];

  // Add framework-specific ignores
  switch (framework) {
    case 'nextjs':
      lines.push('.next/');
      lines.push('.vercel/');
      break;
    case 'angular':
      lines.push('.angular/');
      break;
    case 'vue':
      lines.push('.nuxt/');
      break;
    case 'svelte':
      lines.push('.svelte-kit/');
      break;
    case 'django':
      lines.push('__pycache__/');
      lines.push('*.pyc');
      lines.push('.venv/');
      lines.push('venv/');
      break;
    case 'rails':
      lines.push('tmp/');
      lines.push('log/');
      lines.push('vendor/bundle/');
      break;
    case 'go':
      lines.push('vendor/');
      break;
    case 'rust':
      lines.push('target/');
      break;
  }

  lines.push('');
  return lines.join('\n');
}

/**
 * Create a Halo engine instance
 */
function createEngine(config?: EngineConfig): HaloEngine {
  return new HaloEngine(config);
}

/**
 * Scan a single file
 */
function scanFile(filePath: string, content?: string): Violation[] {
  const engine = new HaloEngine();
  const fileContent = content || fs.readFileSync(filePath, 'utf-8');
  return engine.scanFile(filePath, fileContent);
}

/**
 * Scan a directory
 */
async function scanDirectory(dirPath: string, config?: EngineConfig): Promise<ScanResult[]> {
  // Create two engines: one for active violations, one with suppressions included
  const engine = new HaloEngine(config);
  const suppressionEngine = new HaloEngine({ ...config, includeSuppressed: true });
  const results: ScanResult[] = [];

  const stats = fs.statSync(dirPath);

  if (stats.isDirectory()) {
    const patterns = getDefaultPatterns();
    const excludes = getDefaultExcludePatterns();

    let allFiles: string[] = [];
    for (const pattern of patterns) {
      const fullPattern = path.join(dirPath, pattern);
      const files = await glob(fullPattern, {
        ignore: excludes,
        absolute: true
      });
      allFiles.push(...files);
    }

    const uniqueFiles = [...new Set(allFiles)];

    for (const filePath of uniqueFiles) {
      try {
        const content = fs.readFileSync(filePath, 'utf-8');
        const violations = engine.scanFile(filePath, content);
        const allViolations = suppressionEngine.scanFile(filePath, content);
        const suppressedViolations = allViolations.filter(v => v.suppressed);

        results.push({
          filePath,
          violations,
          suppressedViolations,
          scannedAt: new Date().toISOString(),
          totalViolations: violations.length,
          suppressedCount: suppressedViolations.length
        });
      } catch (err) {
        // Skip files that can't be read
      }
    }
  } else {
    const content = fs.readFileSync(dirPath, 'utf-8');
    const violations = engine.scanFile(dirPath, content);
    const allViolations = suppressionEngine.scanFile(dirPath, content);
    const suppressedViolations = allViolations.filter(v => v.suppressed);

    results.push({
      filePath: dirPath,
      violations,
      suppressedViolations,
      scannedAt: new Date().toISOString(),
      totalViolations: violations.length,
      suppressedCount: suppressedViolations.length
    });
  }
  
  return results;
}

// ==================== First-Run Email Prompt ====================

const HALO_CONFIG_DIR = path.join(os.homedir(), '.halo');
const HALO_CONFIG_PATH = path.join(HALO_CONFIG_DIR, 'config.json');
const HALO_HISTORY_PATH = path.join(HALO_CONFIG_DIR, 'history.json');
const MAX_HISTORY_ENTRIES = 100;
const CLI_VERSION = '0.2.1';

const SUPABASE_URL = 'https://wrfwcmyxxbafcdvxlmug.supabase.co';
const SUPABASE_ANON_KEY = 'eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJpc3MiOiJzdXBhYmFzZSIsInJlZiI6IndyZndjbXl4eGJhZmNkdnhsbXVnIiwicm9sZSI6ImFub24iLCJpYXQiOjE3NzIzNDc5MzIsImV4cCI6MjA4NzkyMzkzMn0.6Wj58QDuojPAY_ArVbZvjhcFVuX5VvzqjaEg0FkoYJI';

// Rules Engine API
const RULES_API_BASE = `${SUPABASE_URL}/functions/v1`;
const RULES_CACHE_TTL_MS = 24 * 60 * 60 * 1000; // 24 hours
const RULES_CACHE_PATH = path.join(os.homedir(), '.halo', 'rules-cache.json');
const RULES_FETCH_TIMEOUT_MS = 5000; // 5 second timeout

interface RulesCache {
  etag: string | null;
  packs: string[];
  rules: JSONRule[];
  fetchedAt: string;
}

/**
 * Fetch rules from the Supabase rules-fetch edge function.
 * Returns raw JSON rules (not compiled) or null on failure.
 */
async function fetchRulesFromAPI(packs: string[], verbose: boolean): Promise<{ rules: JSONRule[]; etag: string | null } | null> {
  try {
    const url = `${RULES_API_BASE}/rules-fetch?packs=${packs.join(',')}`;
    const cachedEtag = readRulesCache()?.etag;

    const headers: Record<string, string> = {};
    if (cachedEtag) {
      headers['If-None-Match'] = cachedEtag;
    }

    const controller = new AbortController();
    const timeout = setTimeout(() => controller.abort(), RULES_FETCH_TIMEOUT_MS);

    const res = await fetch(url, { headers, signal: controller.signal });
    clearTimeout(timeout);

    if (res.status === 304) {
      if (verbose) console.error('📡 Rules API: 304 Not Modified (cache hit)');
      return null; // Caller should use cache
    }

    if (!res.ok) {
      if (verbose) console.error(`📡 Rules API: ${res.status} ${res.statusText}`);
      return null;
    }

    const data = await res.json() as { rules?: JSONRule[] };
    const etag = res.headers.get('etag');

    if (verbose) console.error(`📡 Rules API: fetched ${data.rules?.length || 0} rules`);

    return { rules: data.rules || [], etag };
  } catch (err: any) {
    if (verbose) console.error(`📡 Rules API: fetch failed (${err.name === 'AbortError' ? 'timeout' : err.message})`);
    return null;
  }
}

/**
 * Read the local rules cache.
 */
function readRulesCache(): RulesCache | null {
  try {
    if (fs.existsSync(RULES_CACHE_PATH)) {
      const cache: RulesCache = JSON.parse(fs.readFileSync(RULES_CACHE_PATH, 'utf-8'));
      return cache;
    }
  } catch {
    // Corrupt cache — ignore
  }
  return null;
}

/**
 * Write rules to the local cache.
 */
function writeRulesCache(etag: string | null, packs: string[], rules: JSONRule[]): void {
  try {
    const cacheDir = path.dirname(RULES_CACHE_PATH);
    if (!fs.existsSync(cacheDir)) {
      fs.mkdirSync(cacheDir, { recursive: true });
    }
    const cache: RulesCache = {
      etag,
      packs,
      rules,
      fetchedAt: new Date().toISOString(),
    };
    fs.writeFileSync(RULES_CACHE_PATH, JSON.stringify(cache, null, 2), 'utf-8');
  } catch {
    // Silent failure — never block scan
  }
}

/**
 * Load bundled baseline rules from @runhalo/engine's rules.json.
 */
function loadBaselineRules(packs: string[]): JSONRule[] | null {
  try {
    const rulesJsonPath = require.resolve('@runhalo/engine/rules/rules.json');
    const data = JSON.parse(fs.readFileSync(rulesJsonPath, 'utf-8'));
    return (data.rules || []).filter((r: JSONRule) =>
      r.packs.some(p => packs.includes(p))
    );
  } catch {
    return null;
  }
}

/**
 * Map CLI options to pack IDs.
 * --pack takes precedence. Legacy flags still supported.
 * Halo 2.0: defaults to ALL packs (loose pre-filter for AI Review Board).
 */
function resolvePacks(options: CLIOptions): string[] {
  // Explicit --pack flag takes priority
  if (options.pack && options.pack.length > 0) {
    return options.pack;
  }

  // Legacy boolean flags — if ANY are set, use selective mode
  if (options.ethicalPreview || options.aiAudit || options.sectorAuSbd || options.sectorAuOsa) {
    const packs = ['coppa'];
    if (options.ethicalPreview) packs.push('ethical');
    if (options.aiAudit) packs.push('ai-audit');
    if (options.sectorAuSbd) packs.push('au-sbd');
    if (options.sectorAuOsa) packs.push('au-osa');
    return packs;
  }

  // Halo 2.0 default: all 17 packs active as loose pre-filters
  return [
    'coppa', 'ethical', 'ai-audit', 'au-sbd', 'ut-sb142', 'uk-aadc',
    'eu-dsa', 'au-osa', 'caadca', 'eu-ai-act', 'gdpr-art8', 'india-dpdp',
    'brazil-lgpd', 'canada-pipeda', 'south-korea-pipa', 'behavioral-design',
    'asaa',
  ];
}

/**
 * Resolve rules with fallback chain:
 *   API (fresh) → 304 cache hit → local cache (stale OK) → bundled baseline → null
 */
async function resolveRules(packs: string[], offline: boolean, verbose: boolean): Promise<JSONRule[] | null> {
  // 1. Try API (unless offline)
  if (!offline) {
    const apiResult = await fetchRulesFromAPI(packs, verbose);
    if (apiResult && apiResult.rules.length > 0) {
      // Fresh rules from API — cache and use
      writeRulesCache(apiResult.etag, packs, apiResult.rules);
      return apiResult.rules;
    }
    // apiResult === null could mean 304 (use cache) or failure (also try cache)
  }

  // 2. Try local cache
  const cache = readRulesCache();
  if (cache && cache.rules.length > 0) {
    const cacheAge = Date.now() - new Date(cache.fetchedAt).getTime();
    const isFresh = cacheAge < RULES_CACHE_TTL_MS;
    const packsMatch = packs.every(p => cache.packs.includes(p));

    if (packsMatch) {
      if (verbose) {
        console.error(`📦 Using cached rules (${isFresh ? 'fresh' : 'stale'}, ${cache.rules.length} rules)`);
      }
      return cache.rules;
    }
  }

  // 3. Try bundled baseline
  const baseline = loadBaselineRules(packs);
  if (baseline && baseline.length > 0) {
    if (verbose) {
      console.error(`📦 Using bundled baseline rules (${baseline.length} rules)`);
    }
    return baseline;
  }

  // 4. Return null — engine will use hardcoded fallback
  if (verbose) {
    console.error('📦 No cached/baseline rules found, engine will use hardcoded fallback');
  }
  return null;
}

interface HaloConfig {
  email?: string;
  prompted: boolean;
  promptedAt: string;
  consent: boolean;
  license_key?: string;
  tier?: 'free' | 'pro' | 'enterprise';
  scans_today?: number;
  scan_date?: string;
}

interface ScanHistoryEntry {
  scannedAt: string;
  score: number;
  grade: string;
  totalViolations: number;
  suppressedCount: number;
  bySeverity: { critical: number; high: number; medium: number; low: number };
  filesScanned: number;
  projectPath: string;
  rulesTriggered: string[];
}

function loadConfig(): HaloConfig | null {
  try {
    if (fs.existsSync(HALO_CONFIG_PATH)) {
      return JSON.parse(fs.readFileSync(HALO_CONFIG_PATH, 'utf-8'));
    }
  } catch {
    // Ignore corrupt config
  }
  return null;
}

function saveConfig(config: HaloConfig): void {
  try {
    if (!fs.existsSync(HALO_CONFIG_DIR)) {
      fs.mkdirSync(HALO_CONFIG_DIR, { recursive: true });
    }
    fs.writeFileSync(HALO_CONFIG_PATH, JSON.stringify(config, null, 2), 'utf-8');
  } catch {
    // Silent failure — never block scan
  }
}

// ==================== Scan History ====================

function loadHistory(): ScanHistoryEntry[] {
  try {
    if (fs.existsSync(HALO_HISTORY_PATH)) {
      const data = JSON.parse(fs.readFileSync(HALO_HISTORY_PATH, 'utf-8'));
      return Array.isArray(data) ? data : [];
    }
  } catch {
    // Silent failure — never block scan
  }
  return [];
}

function saveHistory(entry: ScanHistoryEntry): void {
  try {
    if (!fs.existsSync(HALO_CONFIG_DIR)) {
      fs.mkdirSync(HALO_CONFIG_DIR, { recursive: true });
    }
    const history = loadHistory();
    history.push(entry);
    // FIFO: keep last MAX_HISTORY_ENTRIES
    const trimmed = history.slice(-MAX_HISTORY_ENTRIES);
    fs.writeFileSync(HALO_HISTORY_PATH, JSON.stringify(trimmed, null, 2), 'utf-8');
  } catch {
    // Silent failure — never block scan
  }
}

/**
 * Send webhook notifications to Discord and/or Slack after a scan completes.
 * Non-blocking — failures are logged but never affect the scan exit code.
 */
async function sendWebhookNotifications(
  rcConfig: HaloRcConfig | undefined,
  lastEntry: ScanHistoryEntry,
  verbose: boolean
): Promise<void> {
  const notifications = rcConfig?.notifications;
  if (!notifications) return;

  const { discord_webhook, slack_webhook } = notifications;
  if (!discord_webhook && !slack_webhook) return;

  const hasFailed = lastEntry.totalViolations > 0;
  const filesScanned = String(lastEntry.filesScanned);
  const violations = String(lastEntry.totalViolations);
  const grade = lastEntry.grade || 'N/A';
  const topRules = lastEntry.rulesTriggered.slice(0, 5).join(', ') || 'None';
  const timestamp = new Date().toISOString();

  // Discord webhook
  if (discord_webhook) {
    try {
      const discordPayload = {
        embeds: [{
          title: '\u{1F6E1}\uFE0F Halo Scan Complete',
          color: hasFailed ? 15158332 : 3066993,
          fields: [
            { name: 'Files Scanned', value: filesScanned, inline: true },
            { name: 'Violations', value: violations, inline: true },
            { name: 'Grade', value: grade, inline: true },
            { name: 'Top Rules', value: topRules, inline: false },
          ],
          footer: { text: 'Halo \u2014 runhalo.dev' },
          timestamp,
        }],
      };

      const controller = new AbortController();
      const timeout = setTimeout(() => controller.abort(), 5000);
      const res = await fetch(discord_webhook, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json', 'Authorization': `Bearer ${SUPABASE_ANON_KEY}` },
        body: JSON.stringify(discordPayload),
        signal: controller.signal,
      });
      clearTimeout(timeout);

      if (verbose) {
        console.error(res.ok
          ? '\u2709\uFE0F  Notification sent to Discord'
          : `\u26A0\uFE0F  Discord webhook returned ${res.status}`);
      }
    } catch (err) {
      if (verbose) {
        console.error(`\u26A0\uFE0F  Discord webhook failed: ${err instanceof Error ? err.message : err}`);
      }
    }
  }

  // Slack webhook
  if (slack_webhook) {
    try {
      const slackPayload = {
        blocks: [
          {
            type: 'header',
            text: { type: 'plain_text', text: '\u{1F6E1}\uFE0F Halo Scan Complete' },
          },
          {
            type: 'section',
            fields: [
              { type: 'mrkdwn', text: `*Files Scanned*\n${filesScanned}` },
              { type: 'mrkdwn', text: `*Violations*\n${violations}` },
              { type: 'mrkdwn', text: `*Grade*\n${grade}` },
            ],
          },
          {
            type: 'section',
            fields: [
              { type: 'mrkdwn', text: `*Top Rules*\n${topRules}` },
            ],
          },
        ],
      };

      const controller = new AbortController();
      const timeout = setTimeout(() => controller.abort(), 5000);
      const res = await fetch(slack_webhook, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json', 'Authorization': `Bearer ${SUPABASE_ANON_KEY}` },
        body: JSON.stringify(slackPayload),
        signal: controller.signal,
      });
      clearTimeout(timeout);

      if (verbose) {
        console.error(res.ok
          ? '\u2709\uFE0F  Notification sent to Slack'
          : `\u26A0\uFE0F  Slack webhook returned ${res.status}`);
      }
    } catch (err) {
      if (verbose) {
        console.error(`\u26A0\uFE0F  Slack webhook failed: ${err instanceof Error ? err.message : err}`);
      }
    }
  }
}

async function submitCliLead(email: string): Promise<void> {
  try {
    const res = await fetch(`${SUPABASE_URL}/rest/v1/halo_leads`, {
      method: 'POST',
      headers: {
        'apikey': SUPABASE_ANON_KEY,
        'Authorization': `Bearer ${SUPABASE_ANON_KEY}`,
        'Content-Type': 'application/json',
        'Prefer': 'return=minimal',
      },
      body: JSON.stringify({
        email,
        source: 'cli',
        cli_version: CLI_VERSION,
        node_version: process.version,
        os: os.platform(),
        consent_given: true,
        consent_text: 'Opted in via Halo CLI first-run prompt',
      }),
    });
    // Silent — don't care about response
  } catch {
    // Silent failure — never block scan
  }
}

// ==================== License Validation & Scan Limits (P3-1) ====================

const FREE_SCAN_LIMIT = 5;

/**
 * Validate a license key against Supabase validate-license edge function.
 * Returns license info or null on failure.
 */
async function validateLicenseKey(licenseKey: string): Promise<{
  valid: boolean;
  tier?: string;
  email?: string;
  status?: string;
  expires_at?: string;
  error?: string;
} | null> {
  try {
    const res = await fetch(`${SUPABASE_URL}/functions/v1/validate-license`, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        'Authorization': `Bearer ${SUPABASE_ANON_KEY}`,
      },
      body: JSON.stringify({ license_key: licenseKey }),
    });
    const data = await res.json() as any;
    return {
      valid: !!data.valid,
      tier: data.tier,
      email: data.email,
      status: data.status,
      expires_at: data.expires_at,
      error: data.error,
    };
  } catch {
    return null;
  }
}

/**
 * Activate a license key — validates via Supabase, stores in ~/.halo/config.json.
 */
async function activateLicense(licenseKey: string): Promise<number> {
  console.log(`\n  ${c(colors.dim, 'Validating license key...')}`);

  const result = await validateLicenseKey(licenseKey);

  if (!result || !result.valid) {
    console.error(`\n  ${c(colors.red + colors.bold, '✗ Invalid license key')}`);
    if (result?.error) {
      console.error(`  ${c(colors.dim, result.error)}`);
    }
    console.error(`\n  ${c(colors.dim, 'Get a license at')} ${c(colors.cyan, 'https://runhalo.dev/#pricing?utm_source=cli&utm_medium=scan&utm_campaign=free_upgrade')}\n`);
    return 1;
  }

  // Save to config
  const existing = loadConfig() || {
    prompted: true,
    promptedAt: new Date().toISOString(),
    consent: false,
  };

  saveConfig({
    ...existing,
    license_key: licenseKey,
    tier: result.tier as HaloConfig['tier'],
    email: result.email || existing.email,
  });

  const tierLabel = result.tier === 'enterprise' ? 'Enterprise' : 'Pro';
  console.log(`\n  ${c('\x1b[32m' + colors.bold, `✓ Halo ${tierLabel} activated!`)}`);
  console.log(`  ${c(colors.dim, 'Email:')} ${result.email}`);
  console.log(`  ${c(colors.dim, 'Tier:')}  ${c(colors.cyan, tierLabel)}`);
  if (result.expires_at) {
    const expiryDate = new Date(result.expires_at).toLocaleDateString('en-US', {
      year: 'numeric', month: 'long', day: 'numeric'
    });
    console.log(`  ${c(colors.dim, 'Valid until:')} ${expiryDate}`);
  }
  console.log(`\n  ${c(colors.dim, 'Unlimited scans. All Pro features unlocked.')}`);
  console.log(`  ${c(colors.dim, 'Run')} ${c(colors.cyan, 'halo scan . --report --ethical')} ${c(colors.dim, 'to get started.')}\n`);

  return 0;
}

/**
 * Check scan limit for free-tier users.
 * Returns true if scan is allowed, false if blocked.
 * CI environments always bypass limits.
 */
function checkScanLimit(): boolean {
  // CI always unlimited — never break builds
  if (process.env.CI || process.stdout.isTTY === false) {
    return true;
  }

  const config = loadConfig();

  // Pro/Enterprise: unlimited
  if (config?.tier === 'pro' || config?.tier === 'enterprise') {
    return true;
  }

  // Free tier: check daily limit
  const today = new Date().toISOString().split('T')[0]; // YYYY-MM-DD

  if (config?.scan_date !== today) {
    // New day — reset counter
    saveConfig({
      ...config,
      prompted: config?.prompted ?? true,
      promptedAt: config?.promptedAt ?? new Date().toISOString(),
      consent: config?.consent ?? false,
      scans_today: 1,
      scan_date: today,
    });
    return true;
  }

  const scansToday = config?.scans_today ?? 0;

  if (scansToday >= FREE_SCAN_LIMIT) {
    // Limit reached — show upgrade message
    console.error('');
    console.error(`  ${c(colors.yellow + colors.bold, `⚡ Daily scan limit reached (${FREE_SCAN_LIMIT}/${FREE_SCAN_LIMIT})`)}`);
    console.error(`  ${c(colors.dim, 'Free tier allows 5 scans per day. Your scans reset at midnight.')}`);
    console.error('');
    console.error(`  ${c(colors.cyan, 'Upgrade to Halo Pro ($29/mo)')}`);
    console.error(`  ${c(colors.dim, '→ Unlimited scans, AI Review Board, compliance reports, guided fixes')}`);
    console.error(`  ${c(colors.dim, '→')} ${c(colors.cyan, 'https://runhalo.dev/#pricing?utm_source=cli&utm_medium=scan_limit&utm_campaign=free_upgrade')}`);
    console.error('');
    return false;
  }

  // Show scan count so users feel the limit approaching
  if (scansToday > 0 && scansToday < FREE_SCAN_LIMIT) {
    const remaining = FREE_SCAN_LIMIT - scansToday;
    console.error(c(colors.dim, `  📊 Scan ${scansToday + 1} of ${FREE_SCAN_LIMIT} today (${remaining} remaining)`));
  }

  // Increment counter
  saveConfig({
    ...config,
    prompted: config?.prompted ?? true,
    promptedAt: config?.promptedAt ?? new Date().toISOString(),
    consent: config?.consent ?? false,
    scans_today: scansToday + 1,
    scan_date: today,
  });

  return true;
}

/**
 * Check if a Pro feature is available for the current user.
 * Returns true if allowed, false with upsell message if blocked.
 */
function checkProFeature(featureName: string, flagName: string): boolean {
  // CI always has access — don't break pipelines
  if (process.env.CI || process.stdout.isTTY === false) {
    return true;
  }

  const config = loadConfig();

  if (config?.tier === 'pro' || config?.tier === 'enterprise') {
    return true;
  }

  console.error('');
  console.error(`  ${c(colors.yellow + colors.bold, `⚡ ${featureName} requires Halo Pro`)}`);
  console.error(`  ${c(colors.dim, `The ${flagName} flag is a Pro feature.`)}`);
  console.error('');
  console.error(`  ${c(colors.cyan, 'Upgrade to Halo Pro ($29/mo)')}`);
  console.error(`  ${c(colors.dim, '→ Unlimited scans, ethical design rules, HTML reports, guided fixes')}`);
  console.error(`  ${c(colors.dim, '→')} ${c(colors.cyan, 'https://runhalo.dev/#pricing?utm_source=cli&utm_medium=scan&utm_campaign=free_upgrade')}`);
  console.error('');
  return false;
}

/**
 * First-run email prompt — one-time, optional, non-blocking.
 * Auto-skips when: config exists, --no-prompt, !isTTY, CI env.
 */
async function firstRunPrompt(noPrompt: boolean): Promise<void> {
  // Skip conditions
  if (noPrompt) return;
  if (!process.stdin.isTTY) return;
  if (process.env.CI) return;

  const existing = loadConfig();
  if (existing?.prompted) return;

  // Show prompt on stderr (never pollute stdout JSON/SARIF)
  process.stderr.write('\n');
  process.stderr.write('  Welcome to Halo! 👋\n');
  process.stderr.write('  Stay updated on COPPA scanning, new rules, and Pro features.\n');
  process.stderr.write('  We\'ll send occasional product updates. No spam. Unsubscribe anytime.\n');
  process.stderr.write('\n');

  const rl = readline.createInterface({
    input: process.stdin,
    output: process.stderr,
  });

  return new Promise<void>((resolve) => {
    rl.question('  Email (Enter to skip): ', (answer) => {
      rl.close();

      const email = answer.trim();

      if (email && email.includes('@')) {
        // Save config with email
        saveConfig({
          email,
          prompted: true,
          promptedAt: new Date().toISOString(),
          consent: true,
        });
        // Submit to Supabase (fire-and-forget)
        submitCliLead(email).catch(() => {});
        process.stderr.write(`  ${c('\x1b[32m', '✓')} Thanks! We'll keep you posted.\n\n`);
      } else {
        // Skipped — save that we prompted (never ask again)
        saveConfig({
          prompted: true,
          promptedAt: new Date().toISOString(),
          consent: false,
        });
        process.stderr.write('\n');
      }

      resolve();
    });
  });
}

/**
 * Main scan function
 */
async function scan(paths: string[], options: CLIOptions): Promise<number> {
  // Validate paths exist
  const scanRoot = paths[0] || '.';
  if (!fs.existsSync(scanRoot)) {
    console.error(`❌ Path not found: ${scanRoot}`);
    return 3;
  }

  // Load .haloignore from the first scan path
  let ignoreConfig: IgnoreConfig | undefined;
  try {
    ignoreConfig = loadHaloignore(
      fs.statSync(scanRoot).isDirectory() ? scanRoot : path.dirname(scanRoot)
    );
  } catch {
    // Ignore errors loading .haloignore
  }

  if (options.verbose && ignoreConfig) {
    console.error('📋 Loaded .haloignore configuration');
  }

  // Auto-detect project domains from package.json to reduce ext-017 FPs
  const projectDomains: string[] = [];
  try {
    const projectRoot = fs.statSync(scanRoot).isDirectory() ? scanRoot : path.dirname(scanRoot);
    const pkgPath = path.join(projectRoot, 'package.json');
    if (fs.existsSync(pkgPath)) {
      const pkg = JSON.parse(fs.readFileSync(pkgPath, 'utf-8'));
      // Hosting platforms that should never be treated as "own domain"
      const hostingPlatforms = ['github.com', 'github.io', 'gitlab.com', 'bitbucket.org', 'npmjs.com', 'npmjs.org', 'herokuapp.com', 'vercel.app', 'netlify.app'];
      // Extract domains from homepage, repository, and name
      if (pkg.homepage) {
        try {
          const url = new URL(pkg.homepage);
          if (!hostingPlatforms.includes(url.hostname)) {
            projectDomains.push(url.hostname);
          }
        } catch { /* not a URL */ }
      }
      if (typeof pkg.repository === 'string' && pkg.repository.includes('github.com')) {
        // Extract org/repo name as potential domain hint
        const repoMatch = pkg.repository.match(/github\.com[/:]([\w-]+)\/([\w-]+)/);
        if (repoMatch) {
          projectDomains.push(`${repoMatch[2]}.com`);
          projectDomains.push(`${repoMatch[2]}.org`);
          projectDomains.push(`${repoMatch[2]}.io`);
        }
      } else if (pkg.repository?.url) {
        const repoMatch = pkg.repository.url.match(/github\.com[/:]([\w-]+)\/([\w-]+)/);
        if (repoMatch) {
          projectDomains.push(`${repoMatch[2]}.com`);
          projectDomains.push(`${repoMatch[2]}.org`);
          projectDomains.push(`${repoMatch[2]}.io`);
        }
      }
      // Use package name as domain hint
      if (pkg.name) {
        const cleanName = pkg.name.replace(/^@[\w-]+\//, '').replace(/-/g, '');
        if (cleanName.length >= 3) {
          projectDomains.push(`${cleanName}.com`);
          projectDomains.push(`${cleanName}.org`);
          projectDomains.push(`${cleanName}.io`);
        }
      }
    }
  } catch {
    // Ignore errors detecting project domains
  }

  if (options.verbose && projectDomains.length > 0) {
    console.error(`🏠 Detected project domains: ${[...new Set(projectDomains)].join(', ')}`);
  }

  // Resolve rules via API/cache/baseline fallback chain
  const packs = resolvePacks(options);
  const resolvedRawRules = await resolveRules(packs, options.offline, options.verbose);
  const resolvedRules = resolvedRawRules ? compileRawRules(resolvedRawRules) : undefined;

  const engineConfig: EngineConfig = {
    includePatterns: options.include,
    excludePatterns: options.exclude,
    rules: options.rules.length > 0 ? options.rules : undefined,
    severityFilter: options.severity.length > 0 ? options.severity as any[] : undefined,
    ignoreConfig,
    projectDomains: projectDomains.length > 0 ? [...new Set(projectDomains)] : undefined,

    framework: options.framework,
    astAnalysis: options.astAnalysis,
    // If we got rules from API/cache, use loadedRules. Otherwise fall through to legacy flags.
    ...(resolvedRules
      ? { loadedRules: resolvedRules }
      : {
          ethical: options.ethicalPreview,
          aiAudit: options.aiAudit,
          sectorAuSbd: options.sectorAuSbd,
          sectorAuOsa: options.sectorAuOsa,
        }),
  };

  const engine = new HaloEngine(engineConfig);
  const suppressionEngine = new HaloEngine({ ...engineConfig, includeSuppressed: true });

  const results: ScanResult[] = [];
  let fileCount = 0;

  // Collect all files to scan
  const allFiles: string[] = [];
  
  for (const scanPath of paths) {
    const stats = fs.statSync(scanPath);
    
    if (stats.isDirectory()) {
      const patterns = options.include.length > 0 
        ? options.include 
        : getDefaultPatterns();
      
      const excludes = options.exclude.length > 0 
        ? options.exclude 
        : getDefaultExcludePatterns();
      
      for (const pattern of patterns) {
        const fullPattern = path.join(scanPath, pattern);
        const files = await glob(fullPattern, {
          ignore: excludes,
          absolute: true
        });
        allFiles.push(...files);
      }
    } else if (stats.isFile()) {
      allFiles.push(scanPath);
    }
  }

  // Deduplicate files
  let uniqueFiles = [...new Set(allFiles)];

  // Belt-and-suspenders: filter out test files that slip through glob exclusion
  // (e.g., Django's tests.py files which aren't *inside* a tests/ directory)
  const isTestFile = (filePath: string): boolean => {
    const normalized = filePath.replace(/\\/g, '/');
    const segments = normalized.split('/');
    // Check directory segments
    if (segments.some(s =>
      s === '__tests__' || s === '__mocks__' ||
      s === 'fixtures' || s === 'testdata'
    )) return true;
    // Check file name patterns
    const fileName = segments[segments.length - 1] || '';
    if (/\.(?:test|spec)\.[jt]sx?$/.test(fileName)) return true;
    if (/^test_.*\.py$/.test(fileName)) return true;
    if (/^tests\.py$/.test(fileName)) return true;
    if (/^conftest\.py$/.test(fileName)) return true;
    if (/_test\.py$/.test(fileName)) return true;
    if (/_test\.go$/.test(fileName)) return true;
    return false;
  };

  const beforeFilter = uniqueFiles.length;
  uniqueFiles = uniqueFiles.filter(f => !isTestFile(f));
  const filteredCount = beforeFilter - uniqueFiles.length;

  // ─── Large Repo Guardrails ───────────────────────────────────────────────
  // Tier-based file count caps to prevent runaway scans on monorepos
  const configTier = loadConfig()?.tier || 'free';
  const FILE_COUNT_LIMITS: Record<string, number> = {
    free: 5000,
    pro: 10000,
    business: 25000,
    enterprise: 50000,
  };
  const SCAN_TIMEOUT_MS: Record<string, number> = {
    free: 60_000,       // 60 seconds
    pro: 300_000,       // 5 minutes
    business: 600_000,  // 10 minutes
    enterprise: 900_000, // 15 minutes
  };
  const fileLimit = FILE_COUNT_LIMITS[configTier] || FILE_COUNT_LIMITS.free;
  const scanTimeout = SCAN_TIMEOUT_MS[configTier] || SCAN_TIMEOUT_MS.free;

  if (uniqueFiles.length > fileLimit) {
    const tierLabel = configTier.charAt(0).toUpperCase() + configTier.slice(1);
    console.error(`\n⚠️  Repository has ${uniqueFiles.length.toLocaleString()} files — exceeds ${tierLabel} tier limit of ${fileLimit.toLocaleString()}.`);
    console.error(`   Scanning the first ${fileLimit.toLocaleString()} files (sorted by path).`);
    if (configTier === 'free' || configTier === 'pro') {
      console.error(`   ${c(colors.cyan, 'Upgrade to scan more files →')} https://runhalo.dev/#pricing`);
    }
    console.error('');
    uniqueFiles = uniqueFiles.slice(0, fileLimit);
  }

  if (options.verbose) {
    if (filteredCount > 0) {
      console.error(`🧪 Excluded ${filteredCount} test files`);
    }
    console.error(`🔍 Scanning ${uniqueFiles.length} files...`);
    if (uniqueFiles.length === 0) {
      console.error(`\n⚠️  No scannable files found in the target directory.`);
      console.error(`   Halo scans: .ts, .js, .tsx, .jsx, .py, .swift, .java, .go, .rb, .php, .vue, .svelte`);
      console.error(`   Excluded: node_modules, dist, build, vendor, __tests__, *.min.js`);
      console.error(`   Try: npx runhalo scan ./src or specify --include "**/*.js"\n`);
    }
  }

  // Scan start banner (text format only, stderr so it doesn't pollute JSON/SARIF)
  if (options.format === 'text') {
    const packNameMap: Record<string, string> = {
      'coppa': 'COPPA',
      'ethical': 'Ethical Design',
      'ai-audit': 'AI Audit',
      'au-sbd': 'AU Safety by Design',
      'au-osa': 'AU Online Safety Act',
      'caadca': 'California AADCA',
      'eu-ai-act': 'EU AI Act (Children)',
      'ut-sb142': 'Utah SB 142',
      'uk-aadc': 'UK AADC',
      'eu-dsa': 'EU DSA',
      'gdpr-art8': 'GDPR Art. 8',
      'india-dpdp': 'India DPDP',
      'brazil-lgpd': 'Brazil LGPD',
      'canada-pipeda': 'Canada PIPEDA',
      'south-korea-pipa': 'South Korea PIPA',
      'behavioral-design': 'Behavioral Design',
      'asaa': 'ASAA (Multi-State)',
    };
    // Halo 2.0: short-circuit for all packs (180 rules, 13 jurisdictions)
    const packLabel = packs.length >= 17
      ? '180 rules · 13 jurisdictions'
      : packs.map(p => packNameMap[p] || p).join(' + ');
    console.error(c(colors.dim, `🔍 Scanning ${uniqueFiles.length} files (${packLabel})...`));
  }

  // Max file size: 1MB (skip large/binary files)
  const MAX_FILE_SIZE = 1024 * 1024;

  // ─── Scan Loop with Timeout + Progress ───────────────────────────────────
  const scanStartTime = Date.now();
  const totalFiles = uniqueFiles.length;
  const showProgress = options.format === 'text' && totalFiles > 500;
  let lastProgressPct = 0;
  let timedOut = false;

  for (const filePath of uniqueFiles) {
    // Check scan timeout
    const elapsed = Date.now() - scanStartTime;
    if (elapsed > scanTimeout) {
      const tierLabel = configTier.charAt(0).toUpperCase() + configTier.slice(1);
      console.error(`\n⚠️  Scan timeout reached (${(scanTimeout / 1000)}s ${tierLabel} tier limit) after ${fileCount.toLocaleString()} of ${totalFiles.toLocaleString()} files.`);
      console.error(`   Results below are partial. To scan the full repo, upgrade your tier.`);
      if (configTier === 'free' || configTier === 'pro') {
        console.error(`   ${c(colors.cyan, 'Upgrade →')} https://runhalo.dev/#pricing`);
      }
      console.error('');
      timedOut = true;
      break;
    }

    // Progress indicator for large repos (every 10%)
    if (showProgress) {
      const pct = Math.floor((fileCount / totalFiles) * 100);
      if (pct >= lastProgressPct + 10) {
        lastProgressPct = pct;
        const elapsedSec = ((Date.now() - scanStartTime) / 1000).toFixed(1);
        process.stderr.write(`\r${c(colors.dim, `  ${pct}% (${fileCount.toLocaleString()}/${totalFiles.toLocaleString()} files, ${elapsedSec}s)`)}`);
      }
    }

    try {
      // Skip files that are too large (likely not source code)
      const stat = fs.statSync(filePath);
      if (stat.size > MAX_FILE_SIZE) {
        if (options.verbose) {
          console.error(`⏭️  Skipping large file: ${filePath} (${(stat.size / 1024).toFixed(0)}KB)`);
        }
        continue;
      }

      const content = fs.readFileSync(filePath, 'utf-8');

      // Skip binary files (check for null bytes in first 512 chars)
      if (content.substring(0, 512).includes('\0')) {
        continue;
      }


      const ext = path.extname(filePath).toLowerCase();
      const isJSTS = ['.ts', '.tsx', '.js', '.jsx'].includes(ext);
      const useAST = isJSTS && (options.framework || options.astAnalysis !== false);
      const lang = ['.ts', '.tsx'].includes(ext) ? 'typescript' : 'javascript';

      const violations = useAST
        ? engine.scanFileWithAST(filePath, content, lang as any)
        : engine.scanFile(filePath, content);
      const allViolations = suppressionEngine.scanFile(filePath, content);
      const suppressedViolations = allViolations.filter(v => v.suppressed);

      if (violations.length > 0 || suppressedViolations.length > 0) {
        results.push({
          filePath,
          violations,
          suppressedViolations,
          scannedAt: new Date().toISOString(),
          totalViolations: violations.length,
          suppressedCount: suppressedViolations.length
        });
      }
      fileCount++;
    } catch (err) {
      if (options.verbose) {
        console.error(`⚠️  Error reading ${filePath}:`, err);
      }
    }
  }

  // Clear progress line
  if (showProgress && !timedOut) {
    process.stderr.write(`\r${c(colors.dim, `  100% (${fileCount.toLocaleString()} files, ${((Date.now() - scanStartTime) / 1000).toFixed(1)}s)`)}\n`);
  }

  // Calculate compliance score
  const allViolations = results.flatMap(r => r.violations);
  const totalSuppressedCount = results.reduce((sum, r) => sum + r.suppressedCount, 0);

  // Store violations for --upload (needs to survive to the upload block)
  // Using a module-scoped variable since upload runs in a different try/catch block
  (globalThis as any).__haloViolationsForUpload = allViolations.map(v => ({
    ruleId: v.ruleId,
    ruleName: v.ruleName,
    severity: v.severity,
    file: v.filePath,
    filePath: v.filePath,
    line: v.line,
    column: v.column,
    message: v.message,
    codeSnippet: v.codeSnippet,
    name: v.ruleName,
  }));
  const scorer = new ComplianceScoreEngine();
  const scoreResult = scorer.calculate(allViolations, fileCount);

  // Scan history: compute trend BEFORE saving (so we compare to previous, not current)
  const projectPath = path.resolve(paths[0] || '.');
  const trendLine = formatTrend(scoreResult.score, projectPath);

  // Save to history (silent, never blocks)
  saveHistory({
    scannedAt: new Date().toISOString(),
    score: scoreResult.score,
    grade: scoreResult.grade,
    totalViolations: scoreResult.totalViolations,
    suppressedCount: totalSuppressedCount,
    bySeverity: scoreResult.bySeverity,
    filesScanned: fileCount,
    projectPath,
    rulesTriggered: scoreResult.rulesTriggered,
  });

  // Format output
  let output: string;
  switch (options.format) {
    case 'sarif':
      output = formatSARIF(results, engine.getRules());
      break;
    case 'json':
      output = formatJSON(results, scoreResult);
      break;
    default:
      output = formatText(results, options.verbose, fileCount, scoreResult);
      // Append trend line for text output
      if (trendLine) {
        output += trendLine + '\n';
      }
  }

  // Store scan data for potential PDF regeneration with AI Review Board data
  _lastScanData.results = results;
  _lastScanData.scoreResult = scoreResult;
  _lastScanData.fileCount = fileCount;
  _lastScanData.projectPath = projectPath;

  // Generate report if requested (HTML or PDF based on filename extension)
  // Note: if --review-board is also set, the PDF will be regenerated with AI data
  // in the action handler after the review board completes.
  if (options.report) {
    const reportFilename = typeof options.report === 'string'
      ? options.report
      : 'halo-report.html';
    const projectHistory = loadHistory().filter(
      h => h.projectPath === projectPath
    );
    // Exclude the entry we just saved (last one) so trend is accurate
    const historyForReport = projectHistory.slice(0, -1);

    if (reportFilename.endsWith('.pdf')) {
      // PDF report — tier determines template (free=summary, pro=full, business=attestation)
      const pdfTier = (process.env.HALO_TIER as 'free' | 'pro' | 'business' | 'enterprise') || 'free';
      const pdfBuffer = await generatePdfReport(results, scoreResult, fileCount, projectPath, historyForReport, undefined, pdfTier);
      fs.writeFileSync(reportFilename, pdfBuffer);
      const tierLabels: Record<string, string> = { free: 'Summary', pro: 'Compliance', business: 'Attestation', enterprise: 'Enterprise' };
      console.error(`📄 PDF ${tierLabels[pdfTier] || 'Compliance'} report written to ${reportFilename}`);
    } else {
      // HTML report (default)
      const html = generateHtmlReport(results, scoreResult, fileCount, projectPath, historyForReport);
      fs.writeFileSync(reportFilename, html, 'utf-8');
      console.error(`📄 HTML report written to ${reportFilename}`);
    }
  }

  // Write output (only one path — no duplication)
  if (options.output) {
    fs.writeFileSync(options.output, output);
    console.error(`📄 Results written to ${options.output}`);
  } else {
    process.stdout.write(output);
  }

  // Post-scan CTA (text format only — goes to stderr so it won't pollute piped output)
  if (options.format === 'text') {
    const totalViolations = results.reduce((sum, r) => sum + r.violations.length, 0);

    console.error('');
    console.error('─────────────────────────────────────────');


    if (totalViolations > 0) {
      const exposure = formatDollarExposure(totalViolations);
      console.error(`💰 ${totalViolations} violations found = ${exposure} potential exposure`);
      console.error('   AI Review removes false positives from your results → runhalo.dev/upgrade');
    } else {
      console.error('✅ No violations found');
    }

    console.error('─────────────────────────────────────────');


    console.error(formatRegulatoryCountdownCLI());

    // Dashboard link
    console.error('📊 Dashboard: runhalo.dev/app/dashboard');
    console.error('');
  }

  // Return exit code based on violations
  const hasCriticalOrHigh = results.some(r =>
    r.violations.some(v => v.severity === 'critical' || v.severity === 'high')
  );

  if (hasCriticalOrHigh) {
    return 2; // Critical violations found
  }
  if (results.length > 0) {
    return 1; // Violations found (medium/low only)
  }
  return 0; // No violations
}

// ==================== Fix Command ====================

interface FixCLIOptions {
  dryRun: boolean;
  rules: string[];
  verbose: boolean;
  include: string[];
  exclude: string[];
  guided: boolean;
  framework?: string;
  scaffoldDir?: string;
}

/**
 * Main fix function
 * Flow: discover files → scan → filter auto-fixable → apply fixes → re-scan → write (or dry-run)
 */
async function fix(paths: string[], options: FixCLIOptions): Promise<number> {
  const scanRoot = paths[0] || '.';
  if (!fs.existsSync(scanRoot)) {
    console.error(`❌ Path not found: ${scanRoot}`);
    return 3;
  }

  const engine = new HaloEngine({});
  const fixer = new FixEngine();

  // Collect files (reuse scan discovery logic)
  const allFiles: string[] = [];

  for (const scanPath of paths) {
    let stats: fs.Stats;
    try {
      stats = fs.statSync(scanPath);
    } catch {
      console.error(`❌ Path not found: ${scanPath}`);
      return 3;
    }

    if (stats.isDirectory()) {
      const patterns = options.include.length > 0
        ? options.include
        : getDefaultPatterns();
      const excludes = options.exclude.length > 0
        ? options.exclude
        : getDefaultExcludePatterns();

      for (const pattern of patterns) {
        const fullPattern = path.join(scanPath, pattern);
        const files = await glob(fullPattern, {
          ignore: excludes,
          absolute: true
        });
        allFiles.push(...files);
      }
    } else if (stats.isFile()) {
      allFiles.push(path.resolve(scanPath));
    }
  }

  const uniqueFiles = [...new Set(allFiles)];

  if (options.verbose) {
    console.error(`🔍 Scanning ${uniqueFiles.length} files for auto-fixable violations...`);
  }

  const MAX_FILE_SIZE = 1024 * 1024;
  let totalApplied = 0;
  let totalSkipped = 0;
  let totalFiles = 0;
  let filesFixed = 0;
  const fixedRuleIds = new Set<string>();

  // Track all violations for Pro tease summary
  let totalAutoViolations = 0;
  let totalGuidedViolations = 0;
  let totalFlagOnlyViolations = 0;

  for (const filePath of uniqueFiles) {
    try {
      const stat = fs.statSync(filePath);
      if (stat.size > MAX_FILE_SIZE) continue;

      const content = fs.readFileSync(filePath, 'utf-8');
      if (content.substring(0, 512).includes('\0')) continue;

      const violations = engine.scanFile(filePath, content);
      if (violations.length === 0) {
        totalFiles++;
        continue;
      }

      // Count violations by tier for Pro tease
      for (const v of violations) {
        const spec = REMEDIATION_MAP[v.ruleId];
        if (!spec) continue;
        switch (spec.fixability) {
          case 'auto': totalAutoViolations++; break;
          case 'guided': totalGuidedViolations++; break;
          case 'flag-only': totalFlagOnlyViolations++; break;
        }
      }

      // Apply auto-fixes
      const result = fixer.applyFixes(content, violations, {
        rules: options.rules.length > 0 ? options.rules : undefined,
      });

      const applied = result.fixes.filter(f => f.status === 'applied');
      const skipped = result.fixes.filter(f => f.status === 'skipped');

      if (applied.length > 0) {
        filesFixed++;
        totalApplied += applied.length;
        applied.forEach(f => fixedRuleIds.add(f.ruleId));

        if (options.dryRun) {
          // Show diff
          const diff = fixer.generateDiff(filePath, content, result.fixedContent);
          console.log(diff);
          console.log('');
        } else {
          // Write fixed content
          fs.writeFileSync(filePath, result.fixedContent, 'utf-8');
        }

        // Show warnings for behavior-changing fixes
        for (const f of applied) {
          if (f.warning) {
            const relPath = path.relative(process.cwd(), filePath);
            console.error(`  ${c(colors.yellow, '⚠')}  ${c(colors.dim, relPath + ':' + f.line)} ${c(colors.yellow, f.warning)}`);
          }
        }

        if (options.verbose) {
          const relPath = path.relative(process.cwd(), filePath);
          console.error(`  ${c(colors.cyan, '✓')} ${relPath}: ${applied.length} fix(es) applied`);
        }
      }

      totalSkipped += skipped.length;
      totalFiles++;
    } catch (err) {
      if (options.verbose) {
        console.error(`⚠️  Error processing ${filePath}:`, err);
      }
    }
  }

  // Summary
  console.error('');
  if (totalApplied > 0) {
    const action = options.dryRun ? 'Would auto-fix' : 'Auto-fixed';
    console.error(`${c(colors.bold + colors.cyan, `✓ ${action} ${totalApplied} issue(s)`)} across ${filesFixed} file(s) (${fixedRuleIds.size} rule(s))`);
  } else {
    console.error(`${c(colors.dim, 'No auto-fixable issues found.')}`);
  }

  // Pro tease: show unfixed counts by tier
  const remainingGuided = totalGuidedViolations;
  const remainingFlagOnly = totalFlagOnlyViolations;

  if (remainingGuided > 0 && !options.guided) {
    console.error(`${c(colors.yellow, `⚠ ${remainingGuided} issue(s) need guided fixes`)} ${c(colors.dim, '(run with --guided to generate scaffolds)')}`);
  }
  if (remainingFlagOnly > 0) {
    console.error(`${c(colors.blue, `ℹ ${remainingFlagOnly} issue(s) flagged for design review`)} ${c(colors.dim, '(requires manual assessment)')}`);
  }

  // Guided fixes: generate scaffold files for Tier 2 violations
  if (options.guided && totalGuidedViolations > 0) {
    const { ScaffoldEngine } = require('@runhalo/engine');
    const scaffoldEngine = new ScaffoldEngine();

    // Collect all violations with guided fixability
    const guidedViolations: { ruleId: string }[] = [];
    for (const filePath of uniqueFiles) {
      try {
        const content = fs.readFileSync(filePath, 'utf-8');
        const violations = engine.scanFile(filePath, content);
        for (const v of violations) {
          const spec = REMEDIATION_MAP[v.ruleId];
          if (spec?.fixability === 'guided') {
            guidedViolations.push(v);
          }
        }
      } catch {}
    }

    const projectPath = path.resolve(scanRoot);
    const frameworkOverride = options.framework as any;
    const summary = scaffoldEngine.getSummary(guidedViolations, projectPath, frameworkOverride);

    if (summary.totalScaffolds > 0) {
      console.error('');
      console.error(`${c(colors.bold + colors.cyan, '🔧 Guided Fixes')} (${summary.framework}${summary.typescript ? ' + TypeScript' : ''}):`);

      if (options.dryRun) {
        // Dry run: just show what would be generated
        const results = scaffoldEngine.generateScaffolds(guidedViolations, projectPath, frameworkOverride);
        for (const result of results) {
          console.error(`  ${c(colors.cyan, '●')} ${c(colors.bold, result.scaffoldId)} → ${result.ruleId}`);
          for (const file of result.files) {
            console.error(`    ${c(colors.dim, '→')} ${file.relativePath} — ${file.description}`);
          }
        }
        console.error('');
        console.error(`  ${c(colors.dim, 'Run without --dry-run to write scaffold files.')}`);
      } else {
        // Write scaffold files
        const outputDir = options.scaffoldDir || path.join(process.cwd(), 'halo-scaffolds');
        const results = scaffoldEngine.generateScaffolds(guidedViolations, projectPath, frameworkOverride);
        let filesWritten = 0;

        for (const result of results) {
          for (const file of result.files) {
            const fullPath = path.join(outputDir, file.relativePath);
            fs.mkdirSync(path.dirname(fullPath), { recursive: true });
            fs.writeFileSync(fullPath, file.content, 'utf-8');
            filesWritten++;
            if (options.verbose) {
              console.error(`  ${c(colors.cyan, '✓')} ${path.relative(process.cwd(), fullPath)}`);
            }
          }
        }
        console.error(`${c(colors.bold + colors.cyan, `✓ Generated ${filesWritten} scaffold file(s)`)} in ${path.relative(process.cwd(), outputDir) || outputDir}`);
      }
    }

    // Show unavailable scaffolds (link to docs)
    if (summary.unavailableIds.length > 0) {
      console.error('');
      for (const id of summary.unavailableIds) {
        console.error(`  ${c(colors.dim, '📖')} ${id} — docs: ${c(colors.blue, `https://runhalo.dev/rules/${id}`)}`);
      }
    }
  }

  console.error('');

  // Exit codes: 0 = all good, 1 = partial (some violations remain), 3 = fatal
  if (totalApplied > 0 && (remainingGuided > 0 || remainingFlagOnly > 0)) {
    return 1; // Partial — some issues remain
  }
  return 0;
}

// CLI setup
program
  .name('runhalo')
  .description('Halo \u2014 Ethical code scanner for children\u2019s digital safety')
  .version(require('../package.json').version);

program
  .command('scan')
  .description('Scan source code for child safety compliance violations')
  .argument('[paths...]', 'Paths to scan (default: current directory)', ['.'])
  .option('-f, --format <format>', 'Output format: json, sarif, text', 'text')
  .option('-i, --include <patterns...>', 'File patterns to include')
  .option('-e, --exclude <patterns...>', 'File patterns to exclude')
  .option('-r, --rules <ruleIds...>', 'Specific rules to run (e.g., coppa-auth-001)')
  .option('-s, --severity <levels...>', 'Filter by severity: critical, high, medium, low')
  .option('-o, --output <file>', 'Output file path')
  .option('--ethical-preview', 'Enable experimental ethical design rules (experimental)')
  .option('--ai-audit', 'Enable AI-generated code audit rules (catch AI coding assistant mistakes)')
  .option('--sector-au-sbd', 'Enable Australia Safety by Design sector rules (eSafety Commissioner framework)')
  .option('--sector-au-osa', 'Enable Australia Online Safety Act rules (2021 as amended 2024, under-16 social media ban)')
  .option('--pack <packs...>', 'Rule packs to scan against (e.g., coppa ethical ai-audit au-sbd au-osa)')
  .option('--offline', 'Skip API fetch, use cached or bundled rules only')
  .option('--report [filename]', 'Generate HTML compliance report (default: halo-report.html)')
  .option('--upload', 'Upload scan results to Halo Dashboard (requires Pro)')
  .option('--watch', 'Watch for file changes and re-scan automatically')
  .option('--review-board', 'Enable AI Review Board — clinical assessment of each violation (Pro/Enterprise)')
  .option('--review', 'Run full three-tier analysis: regex → AST → AI Review Board (Pro/Enterprise)')
  .option('--license-key <key>', 'License key for Pro/Enterprise features (or set HALO_LICENSE_KEY env var)')
  .option('--framework <framework>', 'Override framework detection (react, nextjs, vue, angular, django, rails)')
  .option('--no-prompt', 'Skip first-run email prompt')
  .option('-v, --verbose', 'Verbose output')
  .action(async (paths: string[], options: any) => {
    try {
      await firstRunPrompt(options.prompt === false);

      // Pro feature gating (soft upsell — exit 0, not error)

      // Only gate HTML reports (default) as Pro feature; PDF summary is free
      if (options.report) {
        const reportName = typeof options.report === 'string' ? options.report : 'halo-report.html';
        if (!reportName.endsWith('.pdf') && !checkProFeature('HTML Compliance Reports', '--report')) {
          process.exit(0);
        }
      }
      if (options.ethicalPreview && !checkProFeature('Ethical Design Rules', '--ethical-preview')) {
        process.exit(0);
      }
      if (options.aiAudit && !checkProFeature('AI-Generated Code Audit', '--ai-audit')) {
        process.exit(0);
      }
      if (options.sectorAuSbd && !checkProFeature('AU Safety by Design Rules', '--sector-au-sbd')) {
        process.exit(0);
      }
      if (options.sectorAuOsa && !checkProFeature('AU Online Safety Act Rules', '--sector-au-osa')) {
        process.exit(0);
      }
      if (options.upload && !checkProFeature('Dashboard Upload', '--upload')) {
        process.exit(0);
      }
      // --review is the canonical flag, --review-board is the legacy alias
      if (options.review) options.reviewBoard = true;
      if (options.reviewBoard && !checkProFeature('AI Review Board', '--review')) {
        process.exit(0);
      }

      // Scan limit check (soft — exit 0, not error)
      if (!checkScanLimit()) {
        process.exit(0);
      }

      // ==================== .halorc.json Config ====================
      const projectRoot = path.resolve(paths[0] || '.');
      let rcConfig: HaloRcConfig | undefined;
      for (const rcName of ['.halorc.json', '.halorc']) {
        const rcPath = path.join(
          fs.existsSync(projectRoot) && fs.statSync(projectRoot).isDirectory()
            ? projectRoot
            : path.dirname(projectRoot),
          rcName
        );
        if (fs.existsSync(rcPath)) {
          try {
            rcConfig = JSON.parse(fs.readFileSync(rcPath, 'utf-8')) as HaloRcConfig;
            if (options.verbose) {
              console.error(`📋 Loaded ${rcName} configuration`);
            }
          } catch (e) {
            console.error(`⚠️  Failed to parse ${rcName}: ${e instanceof Error ? e.message : e}`);
          }
          break;
        }
      }

      // Merge .halorc.json with CLI flags (CLI flags override)
      const mergedPacks = (options.pack && options.pack.length > 0)
        ? options.pack
        : (rcConfig?.packs || []);
      const mergedExclude = [
        ...(options.exclude || []),
        ...(rcConfig?.ignore || []),
      ];

      const scanOptions: CLIOptions = {
        format: options.format || 'text',
        include: options.include || [],
        exclude: mergedExclude,
        rules: options.rules || [],
        severity: options.severity || [],
        output: options.output || '',
        verbose: options.verbose || false,
        ethicalPreview: options.ethicalPreview || false,
        aiAudit: options.aiAudit || false,
        sectorAuSbd: options.sectorAuSbd || false,
        sectorAuOsa: options.sectorAuOsa || false,
        report: options.report || false,
        pack: mergedPacks,
        offline: options.offline || false,

        framework: options.framework || rcConfig?.framework || detectProjectFramework(
          fs.existsSync(projectRoot) && fs.statSync(projectRoot).isDirectory()
            ? projectRoot
            : path.dirname(projectRoot)
        ) || undefined,
        astAnalysis: rcConfig?.astAnalysis,

        reviewBoard: options.reviewBoard || options.review || rcConfig?.reviewBoard || false,
        licenseKey: options.licenseKey || process.env.HALO_LICENSE_KEY || rcConfig?.licenseKey,
      };

      // ==================== Watch Mode ====================
      if (options.watch) {
        const scanRoot = path.resolve(paths[0] || '.');

        // Load .haloignore for watch filtering
        let watchIgnoreConfig: IgnoreConfig | undefined;
        try {
          watchIgnoreConfig = loadHaloignore(
            fs.statSync(scanRoot).isDirectory() ? scanRoot : path.dirname(scanRoot)
          );
        } catch {
          // Ignore errors loading .haloignore
        }

        const scannableExts = new Set([
          '.ts', '.tsx', '.js', '.jsx', '.mjs', '.cjs',
          '.py', '.go', '.java', '.kt', '.kts',
          '.swift', '.rb', '.php',
          '.html', '.htm', '.vue', '.svelte',
          '.xml', '.cs', '.cpp', '.h', '.hpp', '.qml', '.erb',
        ]);

        const isScannable = (filePath: string): boolean => {
          return scannableExts.has(path.extname(filePath).toLowerCase());
        };

        const isExcluded = (filePath: string): boolean => {
          const rel = path.relative(scanRoot, filePath);
          // Common directory excludes
          if (rel.includes('node_modules') || rel.includes('.git') ||
              rel.includes('dist/') || rel.includes('build/') ||
              rel.includes('coverage/') || rel.includes('.next/')) {
            return true;
          }
          // Respect .haloignore patterns
          if (watchIgnoreConfig && shouldIgnoreFile(rel, watchIgnoreConfig)) {
            return true;
          }
          return false;
        };

        // Count scannable files for status line
        let watchableFileCount = 0;
        const countFiles = (dir: string): void => {
          try {
            const entries = fs.readdirSync(dir, { withFileTypes: true });
            for (const entry of entries) {
              const fullPath = path.join(dir, entry.name);
              if (entry.isDirectory()) {
                if (!['node_modules', '.git', 'dist', 'build', 'coverage', '.next'].includes(entry.name)) {
                  countFiles(fullPath);
                }
              } else if (isScannable(fullPath) && !isExcluded(fullPath)) {
                watchableFileCount++;
              }
            }
          } catch {
            // Skip unreadable directories
          }
        };
        countFiles(scanRoot);

        // Clear terminal and print header
        const clearAndPrintHeader = () => {
          process.stdout.write('\x1B[2J\x1B[0f'); // Clear terminal + move cursor to top
          console.error('👁️  Halo Watch Mode');
          console.error(`   Watching ${watchableFileCount} file(s) in ${path.basename(scanRoot)}/`);
          if (watchIgnoreConfig) console.error('   📋 .haloignore loaded');
          console.error('   Press Ctrl+C to stop.\n');
        };

        clearAndPrintHeader();

        // Initial full scan
        let lastViolationCount = 0;
        let scanNumber = 0;
        const runScan = async () => {
          scanNumber++;
          if (scanNumber > 1) clearAndPrintHeader();

          const startTime = Date.now();
          const exitCode = await scan(paths, { ...scanOptions, format: 'text', output: '' });
          const elapsed = ((Date.now() - startTime) / 1000).toFixed(1);
          const history = loadHistory();
          const lastEntry = history[history.length - 1];
          const violationCount = lastEntry?.totalViolations || 0;
          const delta = violationCount - lastViolationCount;
          const deltaStr = delta > 0
            ? ` \x1B[31m↑ ${delta} new\x1B[0m`
            : delta < 0
            ? ` \x1B[32m↓ ${Math.abs(delta)} fixed\x1B[0m`
            : scanNumber > 1 ? ' \x1B[90m(no change)\x1B[0m' : '';

          console.error(`\n⏱  Scan #${scanNumber} complete in ${elapsed}s — ${violationCount} violation(s)${deltaStr}`);
          console.error(`   ${new Date().toLocaleTimeString()} — Watching for changes...\n`);

          lastViolationCount = violationCount;
          return exitCode;
        };

        await runScan();

        // Debounce: collect changes for 500ms before re-scanning
        let debounceTimer: ReturnType<typeof setTimeout> | null = null;
        const changedFiles = new Set<string>();

        try {
          const watcher = fs.watch(scanRoot, { recursive: true }, (eventType, filename) => {
            if (!filename) return;
            const fullPath = path.join(scanRoot, filename);

            // Only re-scan for scannable file changes, respect .haloignore
            if (!isScannable(fullPath) || isExcluded(fullPath)) return;

            changedFiles.add(filename);

            // Debounce — wait 500ms after last change before re-scanning
            if (debounceTimer) clearTimeout(debounceTimer);
            debounceTimer = setTimeout(async () => {
              const files = Array.from(changedFiles);
              changedFiles.clear();
              console.error(`\n📝 Changed: ${files.join(', ')}`);
              await runScan();
            }, 500);
          });

          // Keep process alive until Ctrl+C
          process.on('SIGINT', () => {
            watcher.close();
            console.error('\n\n👋 Watch mode stopped.');
            process.exit(0);
          });

          // Prevent Node from exiting
          await new Promise(() => {}); // Block forever (until SIGINT)
        } catch (watchErr) {
          console.error(`❌ Watch mode error: ${watchErr instanceof Error ? watchErr.message : watchErr}`);
          console.error('   fs.watch with recursive option requires Node.js 18+ on macOS/Windows.');
          process.exit(3);
        }

        return; // Never reached, but TypeScript needs it
      }

      // ==================== Standard Scan (non-watch) ====================
      const tier1Start = Date.now();
      let exitCode = await scan(paths, scanOptions);
      const tier1Elapsed = Date.now() - tier1Start;

      // Apply .halorc.json severity_threshold (overrides default exit code behavior)
      if (rcConfig?.severity_threshold && exitCode > 0) {
        const severityOrder = ['low', 'medium', 'high', 'critical'];
        const thresholdIdx = severityOrder.indexOf(rcConfig.severity_threshold);
        if (thresholdIdx >= 0) {
          // Re-check: only fail if violations at or above threshold exist
          const history = loadHistory();
          const lastEntry = history[history.length - 1];
          if (lastEntry?.bySeverity) {
            const hasAboveThreshold = severityOrder
              .slice(thresholdIdx)
              .some(sev => (lastEntry.bySeverity as Record<string, number>)[sev] > 0);
            if (!hasAboveThreshold) {
              exitCode = 0; // Below threshold — pass
              if (options.verbose) {
                console.error(`📋 .halorc.json severity_threshold: ${rcConfig.severity_threshold} — violations below threshold, passing`);
              }
            }
          }
        }
      }

      // ==================== SDK Intelligence ====================
      // Best-effort: detect risky SDKs from package.json for AI Review Board context
      let sdkSummary = '';
      try {
        const scanRoot = path.resolve(paths[0] || '.');
        const pkgDir = fs.existsSync(scanRoot) && fs.statSync(scanRoot).isDirectory()
          ? scanRoot
          : path.dirname(scanRoot);
        const pkgJsonPath = path.join(pkgDir, 'package.json');
        if (fs.existsSync(pkgJsonPath)) {
          const pkgContent = fs.readFileSync(pkgJsonPath, 'utf-8');
          const detectedSDKs = detectSDKsFromPackageJson(pkgContent);
          if (detectedSDKs.length > 0) {
            sdkSummary = generateSDKContext(detectedSDKs);
            if (options.verbose) {
              console.error(`🔍 SDK Intelligence: detected ${detectedSDKs.length} SDK(s) with risk profiles`);
            }
          }
        }
      } catch {
        // SDK detection is best-effort — never block the scan
      }

      // ==================== Import Graph ====================
      // Build cross-file import graph for AI Review Board context
      let importGraphContext = '';
      let tier2ASTCount = 0;
      let tier2SuppressedCount = 0;
      let tier2ConfirmedCount = 0;
      try {
        const scanRoot = path.resolve(paths[0] || '.');
        const scanDir = fs.existsSync(scanRoot) && fs.statSync(scanRoot).isDirectory()
          ? scanRoot
          : path.dirname(scanRoot);

        // Collect file contents for import graph (reuse already-scanned files)
        const fileContents = new Map<string, string>();
        for (const result of _lastScanData.results) {
          try {
            const content = fs.readFileSync(result.filePath, 'utf-8');
            const relPath = path.relative(scanDir, result.filePath);
            fileContents.set(relPath, content);
          } catch { /* skip unreadable files */ }
        }

        if (fileContents.size > 0) {
          const importGraph = buildImportGraph(fileContents);
          const summary = summarizeImportGraph(importGraph);
          importGraphContext = formatImportGraphForReview(summary);
          if (options.verbose) {
            console.error(`🔗 Import Graph: ${importGraph.fileCount} files, ${importGraph.edgeCount} edges (${importGraph.buildTimeMs}ms)`);
            if (summary.complianceRelevantImports.length > 0) {
              console.error(`   Compliance-relevant: ${summary.complianceRelevantImports.map(ci => ci.module).join(', ')}`);
            }
          }
        }

        // Compute Tier 2 AST stats from scan results
        const allViolations = _lastScanData.results.flatMap(r => r.violations);
        for (const v of allViolations) {
          if (v.astVerdict && v.astVerdict !== 'regex_only') {
            tier2ASTCount++;
            if (v.astVerdict === 'suppressed') tier2SuppressedCount++;
            if (v.astVerdict === 'confirmed') tier2ConfirmedCount++;
          }
        }
      } catch {
        // Import graph is best-effort — never block the scan
      }

      // ==================== AI Review Board ====================
      let _reviewBoardResult: ReviewBoardData | undefined;
      if (scanOptions.reviewBoard) {
        const licenseKey = scanOptions.licenseKey || loadConfig().license_key;
        if (!licenseKey) {
          console.error('⚠️  AI Review Board requires a license key. Run `halo activate <key>` or pass --license-key.');
        } else {
          try {
            // Extract violations directly from the scan results already in memory
            const allViolations = _lastScanData.results.flatMap(r => r.violations);
            if (allViolations.length > 0) {
              console.error('\n🤖 Running AI Review Board...');
              const reviewUrl = 'https://wrfwcmyxxbafcdvxlmug.supabase.co/functions/v1/ai-review';

              // Chunk violations in batches of 50 (endpoint limit)
              const CHUNK_SIZE = 50;
              const chunks: typeof allViolations[] = [];
              for (let i = 0; i < allViolations.length; i += CHUNK_SIZE) {
                chunks.push(allViolations.slice(i, i + CHUNK_SIZE));
              }
              if (chunks.length > 1) {
                console.error(`  Sending ${allViolations.length} violations in ${chunks.length} batches...`);
              }

              // Process each chunk and merge results
              const tier3Start = Date.now();
              const mergedResults: ReviewBoardData['results'] = [];
              let totalCost = 0;
              let totalLatency = 0;
              let totalCacheHits = 0;
              let totalInputTokens = 0;
              let totalOutputTokens = 0;
              let mergedMarshall: ReviewBoardData['marshall_summary'] | undefined;
              let mergedRiskSummary: ReviewBoardData['risk_summary'] | undefined;
              let chunksFailed = 0;

              for (let ci = 0; ci < chunks.length; ci++) {
                const chunk = chunks[ci];
                if (chunks.length > 1) {
                  console.error(`  Batch ${ci + 1}/${chunks.length} (${chunk.length} violations)...`);
                }

                const reviewRes = await fetch(reviewUrl, {
                  method: 'POST',
                  headers: { 'Content-Type': 'application/json', 'Authorization': `Bearer ${SUPABASE_ANON_KEY}` },
                  body: JSON.stringify({
                    license_key: licenseKey,
                    violations: chunk,
                    repo_metadata: {
                      framework: scanOptions.framework,
                      ...(sdkSummary ? { detectedSDKs: sdkSummary } : {}),
                      ...(importGraphContext ? { importGraph: importGraphContext } : {}),
                    },
                  }),
                });

                if (reviewRes.ok) {
                  const chunkReview = await reviewRes.json() as ReviewBoardData;
                  mergedResults.push(...chunkReview.results);
                  totalCost += chunkReview.cost.estimated_usd;
                  totalLatency += chunkReview.latency_ms;
                  totalCacheHits += chunkReview.summary.cache_hits;
                  totalInputTokens += chunkReview.cost.input_tokens || 0;
                  totalOutputTokens += chunkReview.cost.output_tokens || 0;
                  // Merge risk_summary (take the one with highest exposure)
                  if (chunkReview.risk_summary) {
                    if (!mergedRiskSummary || chunkReview.risk_summary.total_exposure_usd > mergedRiskSummary.total_exposure_usd) {
                      mergedRiskSummary = { ...chunkReview.risk_summary };
                    } else {
                      mergedRiskSummary.total_exposure_usd += chunkReview.risk_summary.total_exposure_usd;
                      mergedRiskSummary.confirmed_finding_count += chunkReview.risk_summary.confirmed_finding_count;
                    }
                  }
                  // Merge marshall summary (take the one with highest urgency)
                  if (chunkReview.marshall_summary) {
                    if (!mergedMarshall || (chunkReview.marshall_summary.avg_urgency > mergedMarshall.avg_urgency)) {
                      mergedMarshall = chunkReview.marshall_summary;
                    }
                    if (mergedMarshall && chunkReview.marshall_summary !== mergedMarshall) {
                      mergedMarshall.enriched_count += chunkReview.marshall_summary.enriched_count;
                      mergedMarshall.active_enforcement_count += chunkReview.marshall_summary.active_enforcement_count;
                    }
                  }
                } else {
                  const err = await reviewRes.json().catch(() => ({})) as { error?: string };
                  console.error(`  ⚠️  Batch ${ci + 1} failed: ${err.error || reviewRes.statusText}`);
                  chunksFailed++;
                }
              }

              if (mergedResults.length > 0) {
                const tier3Elapsed = Date.now() - tier3Start;

                // Build merged ReviewBoardData
                const review: ReviewBoardData = {
                  results: mergedResults,
                  summary: {
                    total: mergedResults.length,
                    confirmed: mergedResults.filter(r => r.verdict === 'confirmed').length,
                    downgraded: mergedResults.filter(r => r.verdict === 'downgraded').length,
                    escalated: mergedResults.filter(r => r.verdict === 'escalated').length,
                    dismissed: mergedResults.filter(r => r.verdict === 'dismissed').length,
                    cache_hits: totalCacheHits,
                  },
                  risk_summary: mergedRiskSummary,
                  marshall_summary: mergedMarshall,
                  cost: { estimated_usd: totalCost, input_tokens: totalInputTokens, output_tokens: totalOutputTokens },
                  latency_ms: totalLatency,
                };
                _reviewBoardResult = review; // Store for PDF report

                // Display Review Board results — Three-tier funnel
                const tier1Secs = (tier1Elapsed / 1000).toFixed(1);
                const tier3Secs = (tier3Elapsed / 1000).toFixed(1);
                const confirmedCount = review.summary.confirmed + review.summary.escalated;
                const dismissedCount = review.summary.dismissed + review.summary.downgraded;

                console.error(`\n${c(colors.bold, '🛡️  Halo AI Review Board')}`);
                console.error(`${c(colors.dim, '⚠️  AI-assisted review — may over-dismiss valid findings. Deterministic engine results (above) are authoritative.')}\n`);

                // Three-tier funnel with timing
                const tier1Dots = '.'.repeat(Math.max(2, 30 - 'Tier 1: Pattern scan '.length));
                const tier2Dots = '.'.repeat(Math.max(2, 30 - 'Tier 2: AST analysis '.length));
                const tier3Dots = '.'.repeat(Math.max(2, 30 - 'Tier 3: AI compliance review '.length));
                console.error(c(colors.dim, `  ⏱ Tier 1: Pattern scan ${tier1Dots} ${tier1Secs}s`) + ` → ${c(colors.bold, `${allViolations.length} potential findings`)}`);
                if (tier2ASTCount > 0) {
                  console.error(c(colors.dim, `  ⏱ Tier 2: AST analysis ${tier2Dots} <1s`) + ` → ${c(colors.bold, `${tier2ASTCount} enriched, ${tier2SuppressedCount} suppressed, ${tier2ConfirmedCount} confirmed`)}`);
                }
                console.error(c(colors.dim, `  ⏱ Tier 3: AI compliance review ${tier3Dots} ${tier3Secs}s`) + ` → ${c(colors.bold, `${dismissedCount} dismissed, ${confirmedCount} confirmed`)}`);

                // Aggregate Risk Summary
                const activeResults = review.results.filter(r => r.verdict === 'confirmed' || r.verdict === 'escalated');
                const activeSeverities = { critical: 0, high: 0, medium: 0, low: 0 };
                for (const r of activeResults) {
                  const sev = r.dollarRisk?.severity || r.regulatoryContext?.enforcement_priority || 'medium';
                  if (sev === 'critical') activeSeverities.critical++;
                  else if (sev === 'high') activeSeverities.high++;
                  else if (sev === 'medium') activeSeverities.medium++;
                  else activeSeverities.low++;
                }

                // Find top risk finding by dollar amount
                let topRiskRule = '';
                let topRiskAmount = 0;
                let topRiskCase = '';
                for (const r of activeResults) {
                  if (r.dollarRisk && r.dollarRisk.amount_usd > topRiskAmount) {
                    topRiskAmount = r.dollarRisk.amount_usd;
                    topRiskRule = r.ruleId;
                    topRiskCase = r.dollarRisk.comparable_case || '';
                  }
                }

                // Use risk_summary if available, otherwise compute from per-finding data
                const totalExposure = review.risk_summary?.total_exposure_usd
                  || activeResults.reduce((sum, r) => sum + (r.dollarRisk?.amount_usd || 0), 0);
                const riskTier = review.risk_summary?.risk_tier || '';

                // Get grade info from last scan data
                const riskGrade = _lastScanData.scoreResult?.grade || '';
                const riskScore = _lastScanData.scoreResult?.score || 0;

                if (totalExposure > 0 || confirmedCount > 0) {
                  console.error(`\n${c(colors.dim, '━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━')}`);
                  const gradeParts: string[] = [];
                  if (riskGrade) gradeParts.push(`Grade: ${riskGrade} (${riskScore}/100)`);
                  if (totalExposure > 0) gradeParts.push(`Estimated Exposure: ${formatFine(totalExposure)}`);
                  console.error(`  ${c(colors.bold, gradeParts.join(' | '))}`);
                  if (topRiskRule && topRiskAmount > 0) {
                    const topCaseStr = topRiskCase ? `, cf. ${topRiskCase}` : '';
                    console.error(`  ${c(colors.yellow, `Top Risk: ${topRiskRule} (${formatFine(topRiskAmount)}${topCaseStr})`)}`);
                  }
                  const sevParts: string[] = [];
                  if (activeSeverities.critical > 0) sevParts.push(`${activeSeverities.critical} critical`);
                  if (activeSeverities.high > 0) sevParts.push(`${activeSeverities.high} high`);
                  if (activeSeverities.medium > 0) sevParts.push(`${activeSeverities.medium} medium`);
                  if (activeSeverities.low > 0) sevParts.push(`${activeSeverities.low} low`);
                  console.error(`  Confirmed: ${confirmedCount} findings${sevParts.length > 0 ? ` | ${sevParts.join(', ')}` : ''}`);
                  console.error(c(colors.dim, '━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━'));
                }

                // Per-finding display with dollar risk
                const critical = review.results.filter(r => r.verdict === 'escalated');
                const confirmed = review.results.filter(r => r.verdict === 'confirmed');
                const downgraded = review.results.filter(r => r.verdict === 'downgraded');
                const dismissed = review.results.filter(r => r.verdict === 'dismissed');

                if (critical.length > 0) {
                  console.error(`\n🔴 ${c(colors.red + colors.bold, `ESCALATED (${critical.length})`)} — More serious than initially detected`);
                  for (const r of critical) {
                    console.error(`  ${c(colors.bold, r.ruleId)}: ${(r.reasoning || r.clinicalContext)}`);
                    if (r.ageGroupImpact?.length > 0) console.error(`   Ages most affected: ${r.ageGroupImpact.join(', ')}`);
                    if (r.dollarRisk) {
                      const caseRef = r.dollarRisk.comparable_case
                        ? ` (cf. ${formatCase(r.dollarRisk.comparable_case)}${r.dollarRisk.comparable_fine ? `, ${r.dollarRisk.comparable_fine}` : ''}${r.dollarRisk.comparable_year ? `, ${r.dollarRisk.comparable_year}` : ''})`
                        : '';
                      const confStr = r.dollarRisk?.confidence ? ` | Confidence: ${r.dollarRisk.confidence.toFixed(2)}` : '';
                      console.error(`   ${c(colors.red, `Risk: ${formatFine(r.dollarRisk.amount_usd)}${caseRef}${confStr}`)}`);
                    }
                    if (r.remediationGuidance) console.error(`   ${c(colors.cyan, `Fix: ${r.remediationGuidance}`)}`);
                  }
                }

                if (confirmed.length > 0) {
                  console.error(`\n🟡 ${c(colors.yellow + colors.bold, `CONFIRMED (${confirmed.length})`)} — Violations validated by AI review`);
                  for (const r of confirmed) {
                    console.error(`  ${c(colors.bold, r.ruleId)}: ${(r.reasoning || r.clinicalContext)}`);
                    if (r.dollarRisk) {
                      const caseRef = r.dollarRisk.comparable_case
                        ? ` (cf. ${formatCase(r.dollarRisk.comparable_case)}${r.dollarRisk.comparable_fine ? `, ${r.dollarRisk.comparable_fine}` : ''}${r.dollarRisk.comparable_year ? `, ${r.dollarRisk.comparable_year}` : ''})`
                        : '';
                      const confStr = r.dollarRisk?.confidence ? ` | Confidence: ${r.dollarRisk.confidence.toFixed(2)}` : '';
                      console.error(`   ${c(colors.yellow, `Risk: ${formatFine(r.dollarRisk.amount_usd)}${caseRef}${confStr}`)}`);
                    }
                    if (r.remediationGuidance) console.error(`   ${c(colors.dim, `Fix: ${r.remediationGuidance}`)}`);
                  }
                }

                if (downgraded.length > 0) {
                  console.error(`\n🟢 ${c(colors.green + colors.bold, `DOWNGRADED (${downgraded.length})`)} — Lower risk than severity suggests`);
                  for (const r of downgraded) {
                    console.error(`  ${r.ruleId}: ${(r.reasoning || r.clinicalContext)}`);
                  }
                }

                if (dismissed.length > 0) {
                  console.error(`\n✅ ${c(colors.dim, `DISMISSED (${dismissed.length})`)} — False positives cleared by AI review`);
                  for (const r of dismissed) {
                    console.error(`  ${c(colors.dim, `${r.ruleId}: ${(r.reasoning || r.clinicalContext)}`)}`);
                  }
                }

                // Scan cost display with token breakdown
                const cacheStr = review.summary?.cache_hits > 0 ? ` (${review.summary.cache_hits} cached)` : '';
                const tokenStr = (review.cost?.input_tokens || review.cost?.output_tokens)
                  ? ` (${(review.cost.input_tokens || 0).toLocaleString()} input tokens, ${(review.cost.output_tokens || 0).toLocaleString()} output tokens)`
                  : '';
                const costDisplay = review.cost?.estimated_usd != null ? `$${review.cost.estimated_usd.toFixed(2)}` : '$—';
                console.error(`\n${c(colors.dim, `AI Review cost: ${costDisplay}${tokenStr}${cacheStr}`)}`);

                // Output ReviewBoardData as JSON to stdout for batch tooling
                // (summary generator's readJsonSafe picks up the last JSON object)
                if (scanOptions.format === 'json') {
                  console.log(JSON.stringify(review));
                }
              } else if (chunksFailed > 0) {
                console.error(`⚠️  AI Review failed: all ${chunksFailed} batches failed`);
              }
            }
          } catch (reviewErr) {
            console.error(`⚠️  AI Review failed: ${reviewErr instanceof Error ? reviewErr.message : reviewErr}`);
          }
        }
      }

      // ==================== Generate PDF Report with AI Review Board data ====================
      // If both --review-board and --report *.pdf are set, regenerate the PDF with review data
      if (options.report && _reviewBoardResult) {
        const reportFilename = typeof options.report === 'string'
          ? options.report
          : 'halo-report.html';
        if (reportFilename.endsWith('.pdf') && _lastScanData.results.length > 0) {
          const projectHistory = loadHistory().filter(
            h => h.projectPath === _lastScanData.projectPath
          );
          const historyForReport = projectHistory.slice(0, -1);
          const pdfTier = (process.env.HALO_TIER as 'free' | 'pro' | 'business' | 'enterprise') || 'pro';
          const pdfBuffer = await generatePdfReport(
            _lastScanData.results,
            _lastScanData.scoreResult,
            _lastScanData.fileCount,
            _lastScanData.projectPath,
            historyForReport,
            _reviewBoardResult,
            pdfTier
          );
          fs.writeFileSync(reportFilename, pdfBuffer);
          console.error(`📄 PDF report updated with AI Review Board assessment`);
        }
      }

      // ==================== Webhook Notifications (Discord/Slack) ====================
      if (rcConfig?.notifications) {
        try {
          const history = loadHistory();
          const lastEntry = history[history.length - 1];
          if (lastEntry) {
            await sendWebhookNotifications(rcConfig, lastEntry, options.verbose);
          }
        } catch (notifyErr) {
          if (options.verbose) {
            console.error(`\u26A0\uFE0F  Webhook notification error: ${notifyErr instanceof Error ? notifyErr.message : notifyErr}`);
          }
        }
      }

      // Upload to Halo Dashboard (non-blocking — upload failure doesn't affect exit code)
      if (options.upload) {
        try {
          const config = loadConfig();
          if (!config.license_key) {
            console.error('⚠️  No license key found. Run `halo activate <key>` first.');
          } else {
            console.error('☁️  Uploading scan results to Halo Dashboard...');
            // Re-scan in JSON format to get structured data for upload
            // Use the scan history to get the latest results
            const history = loadHistory();
            const lastEntry = history[history.length - 1];
            if (lastEntry) {
              const projectPath = path.resolve(paths[0] || '.');
              // Build minimal scan_json from last scan entry
              const scanJsonForUpload = {
                repo: projectPath,
                scannedAt: lastEntry.scannedAt,
                filesScanned: lastEntry.filesScanned,
                totalFiles: lastEntry.filesScanned,
                violations: (globalThis as any).__haloViolationsForUpload || [], // Full violations for dashboard rendering
                score: lastEntry.score,
                grade: lastEntry.grade,
                bySeverity: lastEntry.bySeverity,
                rulesTriggered: lastEntry.rulesTriggered,
                suppressedCount: lastEntry.suppressedCount || 0,
              };

              const uploadUrl = 'https://wrfwcmyxxbafcdvxlmug.supabase.co/functions/v1/upload-scan';
              const res = await fetch(uploadUrl, {
                method: 'POST',
                headers: { 'Content-Type': 'application/json', 'Authorization': `Bearer ${SUPABASE_ANON_KEY}` },
                body: JSON.stringify({
                  license_key: config.license_key,
                  scan_json: scanJsonForUpload,
                  repo_url: projectPath,
                }),
              });

              if (res.ok) {
                const data = await res.json() as { dashboard_url: string; share_url: string };
                console.error(`✅ Uploaded to dashboard: ${data.dashboard_url}`);
                console.error(`🔗 Share: ${data.share_url}`);
              } else {
                const err = await res.json().catch(() => ({})) as { error?: string };
                console.error(`⚠️  Upload failed: ${err.error || res.statusText}`);
              }
            }
          }
        } catch (uploadErr) {
          console.error(`⚠️  Upload failed: ${uploadErr instanceof Error ? uploadErr.message : uploadErr}`);
        }
      }

      process.exit(exitCode);
    } catch (error) {
      console.error('❌ Error:', error instanceof Error ? error.message : error);
      process.exit(3); // Fatal error
    }
  });

program
  .command('fix')
  .description('Auto-fix COPPA violations (Tier 1 deterministic transforms + Tier 2 scaffolds)')
  .argument('[paths...]', 'Paths to fix (default: current directory)', ['.'])
  .option('--dry-run', 'Show diffs without writing changes', false)
  .option('-r, --rules <ruleIds...>', 'Fix specific rules only')
  .option('-i, --include <patterns...>', 'File patterns to include')
  .option('-e, --exclude <patterns...>', 'File patterns to exclude')
  .option('--guided', 'Generate scaffold files for Tier 2 guided fixes', false)
  .option('--framework <framework>', 'Override framework detection: react, nextjs, vue, svelte, plain-js')
  .option('--scaffold-dir <dir>', 'Output directory for scaffold files (default: ./halo-scaffolds)')
  .option('--no-prompt', 'Skip first-run email prompt')
  .option('-v, --verbose', 'Detailed output', false)
  .action(async (paths: string[], options: any) => {
    try {
      await firstRunPrompt(options.prompt === false);

      // Pro feature gating for guided fixes
      if (options.guided && !checkProFeature('Guided Scaffold Generation', '--guided')) {
        process.exit(0);
      }

      const exitCode = await fix(paths, {
        dryRun: options.dryRun || false,
        rules: options.rules || [],
        include: options.include || [],
        exclude: options.exclude || [],
        verbose: options.verbose || false,
        guided: options.guided || false,
        framework: options.framework,
        scaffoldDir: options.scaffoldDir,
      });
      process.exit(exitCode);
    } catch (error) {
      console.error('❌ Error:', error instanceof Error ? error.message : error);
      process.exit(3);
    }
  });

// ==================== Activate Command (License Key) ====================

program
  .command('activate')
  .description('Activate a Halo Pro or Enterprise license key')
  .argument('<key>', 'License key (UUID from your purchase confirmation)')
  .action(async (key: string) => {
    try {
      const exitCode = await activateLicense(key);
      process.exit(exitCode);
    } catch (error) {
      console.error('❌ Error:', error instanceof Error ? error.message : error);
      process.exit(3);
    }
  });

// ==================== Init Command (IDE Rules Files) ====================

interface InitOptions {
  ide: boolean;
  force: boolean;
}

/**
 * COPPA compliance rules content for AI coding assistants.
 * Teaches the assistant to write COPPA-compliant code proactively.
 */
function getIDERulesContent(): string {
  return `# Halo — COPPA 2.0 Compliance Rules for AI Coding Assistants
# Generated by: npx runhalo init --ide
# Docs: https://runhalo.dev/rules
# Scanner: npx runhalo scan .

You are working on a child-directed application subject to COPPA 2.0 (effective April 22, 2026).
All code you generate MUST comply with these rules. Violations carry penalties up to $53,088/day.

## CRITICAL Rules (auto-block in CI)

1. **No Social Login Without Age Gate** (coppa-auth-001)
   Never use signInWithPopup(), passport.authenticate('google'), or OAuth flows
   without first verifying the user is 13+ via date-of-birth check.

2. **No Ad Trackers** (coppa-tracking-003)
   Never add Google Analytics (gtag), Facebook Pixel (fbq), or AdSense (adsbygoogle)
   without setting child_directed_treatment: true.

3. **No Biometric Data Collection** (coppa-bio-012)
   Never use FaceID, TouchID, face-api.js, or voice print APIs without
   explicit verifiable parental consent. Voice prints are biometric data under COPPA 2.0.

4. **No Unencrypted PII** (coppa-sec-006)
   Never use http:// for API endpoints that handle personal information.
   All PII transmission must use https://.

5. **Default Privacy = Private** (coppa-default-020)
   Never set isProfileVisible: true, visibility: "public", or defaultPrivacy: "public".
   All profiles default to private. Privacy by design is required.

## HIGH Rules (flag in PR review)

6. **No PII in URL Parameters** (coppa-data-002)
   Never pass email, name, DOB, or phone as GET query parameters.
   Use POST with request body instead.

7. **No Precise Geolocation** (coppa-geo-004)
   Never use navigator.geolocation.getCurrentPosition() without parental consent.
   Downgrade accuracy to city-level if needed.

8. **No Passive Audio Recording** (coppa-audio-007)
   Never call getUserMedia({audio: true}) or MediaRecorder without click handler
   and parental consent check.

9. **No Unmoderated Chat Widgets** (coppa-ext-011)
   Never add Intercom, Zendesk, Drift, or Freshdesk without age-gating.
   Chat widgets allow children to disclose PII freely.

10. **No PII in Analytics** (coppa-analytics-018)
    Never pass email, name, or phone to analytics.identify(), mixpanel.identify(),
    or segment.identify(). Hash user IDs instead.

11. **No UGC Without PII Filter** (coppa-ugc-014)
    Text areas for bio, about-me, or comments must pass through PII scrubbing
    before database storage.

12. **Parent Email Required for Child Contact** (coppa-flow-009)
    Forms collecting child_email or student_email must also require parent_email.

## MEDIUM Rules (compliance warnings)

13. **Data Retention Required** (coppa-retention-005)
    Database schemas must include deleted_at, expiration_date, or TTL index.
    COPPA requires data retention policies.

14. **Privacy Policy on Registration** (coppa-ui-008)
    Registration forms must include a visible link to the privacy policy.

15. **Secure Default Passwords** (coppa-sec-010)
    Never use "password", "123456", or "changeme" as default/initial passwords.

16. **External Link Warnings** (coppa-ext-017)
    External links opening in _blank should trigger a "You are leaving..." modal.

17. **Push Notification Consent** (coppa-notif-013)
    Push notifications are "Online Contact Info" under COPPA 2.0.
    Gate subscriptions behind parental dashboard settings.

18. **Teacher Account Verification** (coppa-edu-019)
    Teacher sign-ups using @gmail.com bypass the School Official consent exception.
    Restrict to .edu domains or require manual approval.

19. **XSS Prevention** (coppa-sec-015)
    Never use dangerouslySetInnerHTML or .innerHTML with user-controlled content.
    Use DOMPurify or standard JSX rendering.

20. **Cookie Consent** (coppa-cookies-016)
    Cookies or localStorage storing tracking/PII data require a consent banner.

## AI Code Generation Guidelines

When generating code for this project:
- Always add age verification before authentication flows
- Always use HTTPS for API endpoints
- Always default user profiles to private
- Always add cookie consent before setting tracking cookies
- Always use POST (not GET) for forms collecting personal information
- Always add PII scrubbing middleware before storing user-generated content
- Always include data retention/deletion utilities in database schemas
- Never add analytics, tracking, or ad scripts without child_directed_treatment flags
- Never embed third-party chat/support widgets without age-gating logic
- Prefer privacy-preserving alternatives (hashed IDs, aggregated analytics, on-device processing)

## Scan Your Code

Run \`npx runhalo scan .\` to check compliance.
Run \`npx runhalo fix . --guided\` for guided remediation scaffolds.
Run \`npx runhalo scan . --report\` for an HTML compliance report.
`;
}

/**
 * Generate .cursor/rules content (Cursor-specific format)
 */
function getCursorRulesContent(): string {
  return getIDERulesContent();
}

/**
 * Generate .windsurfrules content (Windsurf-specific format)
 */
function getWindsurfRulesContent(): string {
  return getIDERulesContent();
}

/**
 * Generate .github/copilot-instructions.md (GitHub Copilot)
 */
function getCopilotInstructionsContent(): string {
  return getIDERulesContent();
}

/**
 * Init command — detect framework, generate .halorc.json, .haloignore, and IDE rules files.
 */
async function init(projectPath: string, options: InitOptions): Promise<number> {
  const resolvedPath = path.resolve(projectPath);

  // --ide flag: generate AI coding assistant rules files (existing behavior)
  if (options.ide) {
    console.log('🔮 Halo init — Generating AI coding assistant rules...\n');

    const files: { path: string; content: string; label: string }[] = [
      {
        path: path.join(resolvedPath, '.cursor', 'rules'),
        content: getCursorRulesContent(),
        label: 'Cursor'
      },
      {
        path: path.join(resolvedPath, '.windsurfrules'),
        content: getWindsurfRulesContent(),
        label: 'Windsurf'
      },
      {
        path: path.join(resolvedPath, '.github', 'copilot-instructions.md'),
        content: getCopilotInstructionsContent(),
        label: 'GitHub Copilot'
      }
    ];

    let created = 0;
    let skipped = 0;

    for (const file of files) {
      const dir = path.dirname(file.path);
      const relativePath = path.relative(resolvedPath, file.path);

      if (fs.existsSync(file.path) && !options.force) {
        console.log(`  ⏭  ${relativePath} (exists — use --force to overwrite)`);
        skipped++;
        continue;
      }

      try {
        if (!fs.existsSync(dir)) {
          fs.mkdirSync(dir, { recursive: true });
        }
        fs.writeFileSync(file.path, file.content, 'utf-8');
        console.log(`  ✅ ${relativePath} — ${file.label} rules`);
        created++;
      } catch (err) {
        console.error(`  ❌ ${relativePath} — ${err instanceof Error ? err.message : err}`);
      }
    }

    console.log('');
    if (created > 0) {
      console.log(`Created ${created} rules file${created > 1 ? 's' : ''}. Your AI assistant now knows COPPA 2.0.`);
    }
    if (skipped > 0) {
      console.log(`Skipped ${skipped} existing file${skipped > 1 ? 's' : ''}.`);
    }
    console.log('');
    console.log('What happens next:');
    console.log('  • Cursor, Windsurf, and Copilot will read these rules automatically');
    console.log('  • AI-generated code will follow COPPA compliance patterns');
    console.log('  • Run "npx runhalo scan ." to verify compliance');
    console.log('');
    console.log('Full-stack compliance for the AI coding era:');
    console.log('  CI:        uses: runhalo/action@v1 catches violations in PRs');
    console.log('  Local:     npx runhalo scan . catches violations on your machine');
    console.log('  Proactive: AI rules files prevent violations before they\'re written');

    return 0;
  }

  // Default init: auto-detect framework, generate .halorc.json and .haloignore
  console.log('🔮 Halo init — project setup\n');

  // Step 1: Detect framework
  const detectedFramework = detectProjectFramework(resolvedPath);
  if (detectedFramework) {
    console.log(`  🔍 Detected framework: ${c(colors.bold, detectedFramework)}`);
  } else {
    console.log(`  🔍 Framework: ${c(colors.dim, 'not detected (generic config will be generated)')}`);
  }

  let configCreated = false;
  let ignoreCreated = false;

  // Step 2: Generate .halorc.json
  const rcPath = path.join(resolvedPath, '.halorc.json');
  if (fs.existsSync(rcPath) && !options.force) {
    console.log(`  ⏭  .halorc.json (exists — use --force to overwrite)`);
  } else {
    const rcConfig: HaloRcConfig = {
      packs: ['coppa', 'ethical'],
      severity_threshold: 'medium',
      ignore: ['**/test/**', '**/__tests__/**', '**/node_modules/**'],
      astAnalysis: true,
      notifications: {},
    };
    if (detectedFramework) {
      rcConfig.framework = detectedFramework;
    }

    try {
      fs.writeFileSync(rcPath, JSON.stringify(rcConfig, null, 2) + '\n', 'utf-8');
      console.log(`  ✅ .halorc.json — project configuration`);
      configCreated = true;
    } catch (err) {
      console.error(`  ❌ .halorc.json — ${err instanceof Error ? err.message : err}`);
    }
  }

  // Step 3: Generate .haloignore
  const ignorePath = path.join(resolvedPath, '.haloignore');
  if (fs.existsSync(ignorePath) && !options.force) {
    console.log(`  ⏭  .haloignore (exists — use --force to overwrite)`);
  } else {
    try {
      const ignoreContent = getDefaultHaloignoreContent(detectedFramework);
      fs.writeFileSync(ignorePath, ignoreContent, 'utf-8');
      console.log(`  ✅ .haloignore — scan exclusion patterns`);
      ignoreCreated = true;
    } catch (err) {
      console.error(`  ❌ .haloignore — ${err instanceof Error ? err.message : err}`);
    }
  }

  // Step 4: Summary
  console.log('');
  if (configCreated || ignoreCreated) {
    const parts: string[] = [];
    if (configCreated) parts.push('.halorc.json');
    if (ignoreCreated) parts.push('.haloignore');
    console.log(`Created: ${parts.join(', ')}`);
  } else {
    console.log('No files created (all exist — use --force to overwrite).');
  }

  console.log('');
  console.log('Next steps:');
  console.log(`  ${c(colors.bold, 'npx runhalo scan .')}         Scan your project for compliance issues`);
  console.log(`  ${c(colors.bold, 'npx runhalo init --ide')}     Generate AI coding assistant rules files`);
  console.log('');

  return 0;
}

program
  .command('packs')
  .description('List available rule packs')
  .option('-v, --verbose', 'Show detailed pack information')
  .action(async (options: any) => {
    try {
      const verbose = options.verbose || false;

      // Try API first, then cache, then bundled
      let packData: Array<{ pack_id: string; name: string; description: string; jurisdiction: string; is_free: boolean; rule_count: number }> | null = null;

      // Try API
      try {
        const controller = new AbortController();
        const timeout = setTimeout(() => controller.abort(), RULES_FETCH_TIMEOUT_MS);
        const res = await fetch(`${RULES_API_BASE}/rules-catalog`, { signal: controller.signal });
        clearTimeout(timeout);

        if (res.ok) {
          const data = await res.json() as { packs?: typeof packData };
          packData = data.packs || [];
        }
      } catch {
        // API failed — try bundled
      }

      // Fallback: load from bundled rules.json
      if (!packData) {
        try {
          const rulesJsonPath = require.resolve('@runhalo/engine/rules/rules.json');
          const data = JSON.parse(fs.readFileSync(rulesJsonPath, 'utf-8'));
          packData = Object.values(data.packs).map((pack: any) => {
            const ruleCount = (data.rules || []).filter((r: any) => r.packs.includes(pack.id)).length;
            return {
              pack_id: pack.id,
              name: pack.name,
              description: pack.description,
              jurisdiction: pack.jurisdiction,
              is_free: pack.is_free,
              rule_count: ruleCount,
            };
          });
        } catch {
          console.error('❌ Could not load pack information');
          process.exit(1);
        }
      }

      console.log('');
      console.log('Available Rule Packs:');
      console.log('');

      for (const pack of packData!) {
        const tier = pack.is_free ? c(colors.green, 'free') : c(colors.yellow, 'pro');
        const id = c(colors.bold, pack.pack_id);
        console.log(`  ${id} (${tier})  — ${pack.name} — ${pack.rule_count} rules`);
        if (verbose && pack.description) {
          console.log(`    ${c(colors.dim, pack.description)}`);
          if (pack.jurisdiction) {
            console.log(`    ${c(colors.dim, `Jurisdiction: ${pack.jurisdiction}`)}`);
          }
        }
      }

      const totalRules = packData!.reduce((sum, p) => sum + p.rule_count, 0);
      console.log('');
      console.log(`  ${c(colors.dim, `${packData!.length} packs, ${totalRules} total rules`)}`);
      console.log('');
      console.log('Usage:');
      console.log('  npx runhalo scan . --pack coppa ethical');
      console.log('  npx runhalo scan . --pack coppa ai-audit au-sbd au-osa');
      console.log('');
    } catch (error) {
      console.error('❌ Error:', error instanceof Error ? error.message : error);
      process.exit(1);
    }
  });

program
  .command('report')
  .description('Report a false positive detection')
  .argument('<rule-id>', 'Rule ID to report (e.g., coppa-auth-001)')
  .option('-f, --file <path>', 'File path where false positive was detected')
  .option('-l, --line <number>', 'Line number of the detection')
  .option('-e, --email <email>', 'Your email for follow-up')
  .option('--context <text>', 'Code context or explanation')
  .action(async (ruleId: string, options: any) => {
    try {
      const config = loadConfig();
      const licenseKey = config.license_key || null;

      console.log('');
      console.log(`${c(colors.bold, '📋 Reporting false positive for rule:')} ${ruleId}`);

      const body: Record<string, any> = { rule_id: ruleId };
      if (options.file) body.file_path = options.file;
      if (options.line) body.line_number = parseInt(options.line, 10);
      if (options.email) body.reporter_email = options.email;
      if (options.context) body.code_context = options.context;
      if (licenseKey) body.reporter_license_key = licenseKey;

      const controller = new AbortController();
      const timeout = setTimeout(() => controller.abort(), RULES_FETCH_TIMEOUT_MS);
      const res = await fetch(`${RULES_API_BASE}/report-fp`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json', 'Authorization': `Bearer ${SUPABASE_ANON_KEY}` },
        body: JSON.stringify(body),
        signal: controller.signal,
      });
      clearTimeout(timeout);

      if (!res.ok) {
        const err = await res.json().catch(() => ({ error: 'Unknown error' })) as { error?: string };
        throw new Error(err.error || `HTTP ${res.status}`);
      }

      const data = await res.json() as { id: string; status: string };
      console.log(`${c(colors.green, '✅ Report submitted')} — ID: ${data.id}`);
      console.log(`   Status: ${data.status}`);
      console.log('');
      console.log(c(colors.dim, 'Our compliance team will review this report. Thank you!'));
      console.log('');
    } catch (error) {
      if (error instanceof Error && error.name === 'AbortError') {
        console.error('❌ Request timed out. Please try again.');
      } else {
        console.error('❌ Error:', error instanceof Error ? error.message : error);
      }
      process.exit(1);
    }
  });

program
  .command('init')
  .description('Initialize Halo in your project (detect framework, generate .halorc.json and .haloignore)')
  .argument('[path]', 'Project root path (default: current directory)', '.')
  .option('--ide', 'Generate AI coding assistant rules files', false)
  .option('--force', 'Overwrite existing files', false)
  .action(async (projectPath: string, options: any) => {
    try {
      const exitCode = await init(projectPath, {
        ide: options.ide || false,
        force: options.force || false,
      });
      process.exit(exitCode);
    } catch (error) {
      console.error('❌ Error:', error instanceof Error ? error.message : error);
      process.exit(3);
    }
  });


// Export for MCP and testing
export { scan, fix, init, scanFile, scanDirectory, createEngine, formatSARIF, formatJSON, formatText, loadConfig, saveConfig, firstRunPrompt, loadHistory, saveHistory, formatTrend, generateHtmlReport, generatePdfReport, escapeHtml, validateLicenseKey, activateLicense, checkScanLimit, checkProFeature, resolvePacks, resolveRules, fetchRulesFromAPI, readRulesCache, writeRulesCache, loadBaselineRules, FREE_SCAN_LIMIT, HALO_CONFIG_DIR, HALO_CONFIG_PATH, HALO_HISTORY_PATH, MAX_HISTORY_ENTRIES, RULES_CACHE_PATH };

// Run CLI
if (require.main === module) {
  program.parse();
}
