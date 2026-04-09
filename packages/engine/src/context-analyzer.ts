/**
 * Halo ContextAnalyzer v1 — Composite Confidence Scoring
 *
 * Combines 5 signals into a per-violation confidence score (0.0-1.0)
 * that indicates how likely a regex match is a true positive.
 *
 * Signal weights:
 *   AST verdict:          35%
 *   File path context:    15%
 *   Framework handling:   15%
 *   Historical FP rate:   20%
 *   User suppression rate: 15%
 *
 * Thresholds:
 *   >= 0.7  → "high"   — likely true positive
 *   0.4-0.69 → "medium" — review recommended
 *   < 0.4  → "low"    — likely false positive
 */

import { ScopeAnalyzer, ScopeContext } from './scope-analyzer';
import type { ASTVerdict } from './ast-engine';
import type { FrameworkAction } from './frameworks/types';

// ---------------------------------------------------------------------------
// Configuration
// ---------------------------------------------------------------------------

export interface ContextAnalyzerConfig {
  /**
   * Historical false positive rates per rule (0.0-1.0).
   * Fetched from Supabase halo_compliance_scores or computed from suppression logs.
   * Falls back to built-in defaults when not provided.
   */
  historicalFPRates?: Record<string, number>;

  /**
   * User suppression rates per rule (0.0-1.0).
   * Percentage of times users suppress this rule via halo-ignore.
   * Falls back to built-in defaults when not provided.
   */
  suppressionRates?: Record<string, number>;

  /**
   * Active framework (e.g., 'nextjs', 'django', 'rails').
   * Used for framework handling signal.
   */
  framework?: string;
}

// ---------------------------------------------------------------------------
// Signal & result types
// ---------------------------------------------------------------------------

/** Confidence interpretation label */
export type ConfidenceInterpretation = 'high' | 'medium' | 'low';

/**
 * Raw semantic signals fed into the confidence calculation.
 * Each field maps to one of the five weighted signals.
 */
export interface ConfidenceSignals {
  astVerdict?: ASTVerdict;                       // 'confirmed' | 'suppressed' | 'regex_only'
  scopeContext?: {
    isTestFile: boolean;
    isAdminRoute: boolean;
    isUserFacing: boolean;
    isTypeDefinition: boolean;
    isConfigFile: boolean;
  };
  frameworkAction?: FrameworkAction | null;       // 'suppress' | 'downgrade' | null (not handled)
  historicalFpRate?: number;                      // 0.0-1.0
  userSuppressionRate?: number;                   // 0.0-1.0
}

/**
 * Per-signal weighted breakdown of the composite confidence score.
 */
export interface ConfidenceBreakdown {
  ast: number;
  filePath: number;
  framework: number;
  historicalFp: number;
  userSuppression: number;
}

/**
 * Full confidence result with composite score, label, breakdown, and recommendation.
 *
 * Also includes aliases (`confidence`, `interpretation`, `reason`) consumed
 * by HaloEngine when writing back onto Violation objects.
 */
export interface ConfidenceResult {
  /** Composite confidence score (0.0-1.0) */
  score: number;
  /** Interpretation label */
  label: ConfidenceInterpretation;
  /** Per-signal weighted contributions */
  breakdown: ConfidenceBreakdown;
  /** Human-readable recommendation */
  recommendation: string;

  // -- Aliases consumed by HaloEngine (index.ts) --
  /** Alias for score — written to Violation.confidence */
  confidence: number;
  /** Alias for label — written to Violation.confidenceInterpretation */
  interpretation: ConfidenceInterpretation;
  /** Alias for recommendation — written to Violation.confidenceReason */
  reason: string;
}

// ---------------------------------------------------------------------------
// Input type (subset of Violation to avoid circular deps)
// ---------------------------------------------------------------------------

export interface ViolationInput {
  ruleId: string;
  severity?: string;
  line?: number;
  column?: number;
  codeSnippet?: string;
  astVerdict?: ASTVerdict;
  astConfidence?: number;
  astReason?: string;
  frameworkSuppressed?: boolean;
}

// ---------------------------------------------------------------------------
// Signal weights
// ---------------------------------------------------------------------------

const WEIGHTS = {
  ast: 0.35,
  filePath: 0.15,
  framework: 0.15,
  historicalFp: 0.20,
  userSuppression: 0.15,
} as const;

// ---------------------------------------------------------------------------
// Built-in defaults (cold start fallback)
// Updated: reflects FP rate fixes.
// language filtering, vendor paths, sanitized innerHTML, admin forms, example URLs
// consent-form heuristics
// test configs, admin routes, no_pii annotations, IE comments, cookie deletion, doc generators
// ---------------------------------------------------------------------------

const DEFAULT_FP_RATES: Record<string, number> = {
  'coppa-tracking-003': 0.15,    // was 0.22 — admin analytics fix reduces FPs
  'coppa-retention-005': 0.05,   // was 0.18 — no_pii annotation fix
  'coppa-ext-017': 0.05,         // was 0.25 — doc generator + IE conditional fixes
  'coppa-sec-015': 0.05,         // was 0.20 — sanitized innerHTML fix
  'coppa-auth-001': 0.10,        // was 0.15 — enum constant fix
  'coppa-ui-008': 0.05,          // was 0.12 — admin form fix
  'coppa-ugc-014': 0.14,         // unchanged — no specific fix yet
  'coppa-flow-009': 0.05,        // was 0.10 — admin route fix
  'coppa-cookies-016': 0.08,     // was 0.20 — consent + deletion fixes
  'coppa-sec-006': 0.05,         // NEW — test config + example URL fixes
  'coppa-sec-010': 0.25,         // was 0.30 — slightly improved
  'coppa-audio-007': 0.10,       // NEW — some media playback FPs remain
  'ETHICAL-001': 0.15,           // unchanged
  'ETHICAL-002': 0.08,           // unchanged
  'ETHICAL-003': 0.10,           // unchanged
  'ETHICAL-004': 0.12,           // unchanged
  'ETHICAL-005': 0.10,           // unchanged
};

const DEFAULT_SUPPRESSION_RATES: Record<string, number> = {
  'coppa-tracking-003': 0.12,    // was 0.18
  'coppa-retention-005': 0.03,   // was 0.12
  'coppa-ext-017': 0.04,         // was 0.22
  'coppa-sec-015': 0.04,         // was 0.15
  'coppa-auth-001': 0.08,        // was 0.10
  'coppa-ui-008': 0.04,          // was 0.08
  'coppa-ugc-014': 0.06,         // unchanged
  'coppa-flow-009': 0.03,        // was 0.05
  'coppa-cookies-016': 0.05,     // was 0.14
  'coppa-sec-006': 0.03,         // NEW
  'coppa-sec-010': 0.20,         // was 0.25
  'coppa-audio-007': 0.08,       // NEW
  'ETHICAL-001': 0.12,           // unchanged
  'ETHICAL-002': 0.04,           // unchanged
  'ETHICAL-003': 0.05,           // unchanged
  'ETHICAL-004': 0.08,           // unchanged
  'ETHICAL-005': 0.06,           // unchanged
};

// Framework-specific safe rules (suppress/downgrade mappings)
const FRAMEWORK_SAFE_RULES: Record<string, Set<string>> = {
  nextjs: new Set([
    'coppa-cookies-016',
    'coppa-sec-015',
    'coppa-ext-017',
  ]),
  django: new Set([
    'coppa-sec-015',
    'coppa-sec-010',
    'coppa-auth-001',
  ]),
  rails: new Set([
    'coppa-sec-015',
    'coppa-cookies-016',
    'coppa-auth-001',
  ]),
};

// ---------------------------------------------------------------------------
// Signal scoring functions
// ---------------------------------------------------------------------------

/**
 * AST verdict signal (weight: 35%).
 *   confirmed  → 1.0
 *   regex_only → 0.5
 *   suppressed → 0.0
 *   absent     → 0.5 (neutral)
 *
 * When astConfidence is provided alongside a verdict, the raw score is scaled
 * to give more nuance (e.g., confirmed with 0.6 confidence → 0.7 + 0.6*0.3 = 0.88).
 */
function scoreAST(verdict?: ASTVerdict, astConfidence?: number): number {
  if (!verdict) return 0.5;

  switch (verdict) {
    case 'confirmed':
      return astConfidence !== undefined
        ? 0.7 + (astConfidence * 0.3)   // range: 0.7-1.0
        : 1.0;
    case 'regex_only':
      return 0.5;
    case 'suppressed':
      return astConfidence !== undefined
        ? 0.3 - (astConfidence * 0.25)  // range: 0.05-0.3
        : 0.0;
    default:
      return 0.5;
  }
}

/**
 * File path context signal (weight: 15%).
 *   user-facing     → 1.0
 *   admin route     → 0.3
 *   config file     → 0.2
 *   test file       → 0.1
 *   type definition → 0.1
 *   absent/unknown  → 0.5 (neutral)
 *
 * Priority: user-facing > admin > config > test = typedef.
 */
function scoreFilePath(scope?: ConfidenceSignals['scopeContext']): number {
  if (!scope) return 0.5;

  if (scope.isUserFacing)      return 1.0;
  if (scope.isAdminRoute)      return 0.3;
  if (scope.isConfigFile)      return 0.2;
  if (scope.isTestFile)        return 0.1;
  if (scope.isTypeDefinition)  return 0.1;

  // No flags matched — neutral
  return 0.5;
}

/**
 * Framework handling signal (weight: 15%).
 *   suppress      → 0.0 (framework fully handles it)
 *   downgrade     → 0.3
 *   null          → 1.0 (not handled — full weight)
 *   undefined     → 0.5 (neutral — no framework info)
 */
function scoreFramework(action?: FrameworkAction | null): number {
  if (action === undefined) return 0.5;
  if (action === null)       return 1.0;
  switch (action) {
    case 'suppress':  return 0.0;
    case 'downgrade': return 0.3;
    default:          return 0.5;
  }
}

/**
 * Historical FP rate signal (weight: 20%).
 *   0%  FP → 1.0
 *   5%  FP → 0.9
 *   20% FP → 0.6
 *   50% FP → 0.2
 *  100% FP → 0.0
 *
 * Interpolated linearly between anchor points.
 * Absent → 0.5 (neutral).
 */
function scoreHistoricalFP(fpRate?: number): number {
  if (fpRate === undefined || fpRate === null) return 0.5;

  const rate = clamp(fpRate, 0, 1);

  const anchors: [number, number][] = [
    [0.00, 1.0],
    [0.05, 0.9],
    [0.20, 0.6],
    [0.50, 0.2],
    [1.00, 0.0],
  ];

  for (let i = 0; i < anchors.length - 1; i++) {
    const [r0, s0] = anchors[i];
    const [r1, s1] = anchors[i + 1];
    if (rate >= r0 && rate <= r1) {
      const t = (rate - r0) / (r1 - r0);
      return s0 + t * (s1 - s0);
    }
  }

  return 0.0;
}

/**
 * User suppression rate signal (weight: 15%).
 *   0%   → 1.0
 *   50%  → 0.5
 *   100% → 0.0
 *
 * Direct inverse (1 - rate). Absent → 0.5 (neutral).
 */
function scoreUserSuppression(suppressionRate?: number): number {
  if (suppressionRate === undefined || suppressionRate === null) return 0.5;
  return 1.0 - clamp(suppressionRate, 0, 1);
}

/**
 * Determine label + recommendation from composite score.
 */
function interpret(score: number): { label: ConfidenceInterpretation; recommendation: string } {
  if (score >= 0.7) {
    return { label: 'high', recommendation: 'High confidence \u2014 likely true positive' };
  }
  if (score >= 0.4) {
    return { label: 'medium', recommendation: 'Medium confidence \u2014 review recommended' };
  }
  return { label: 'low', recommendation: 'Low confidence \u2014 likely false positive' };
}

// ---------------------------------------------------------------------------
// ContextAnalyzer
// ---------------------------------------------------------------------------

export class ContextAnalyzer {
  private config: ContextAnalyzerConfig;
  private scopeAnalyzer: ScopeAnalyzer;

  constructor(config: ContextAnalyzerConfig = {}) {
    this.config = config;
    this.scopeAnalyzer = new ScopeAnalyzer();
  }

  // -----------------------------------------------------------------------
  // Core: compute confidence from raw semantic signals
  // -----------------------------------------------------------------------

  /**
   * Compute a composite confidence score from individual semantic signals.
   * Each signal is scored independently, then combined via weighted sum.
   */
  computeConfidence(signals: ConfidenceSignals): ConfidenceResult {
    const astRaw        = scoreAST(signals.astVerdict);
    const filePathRaw   = scoreFilePath(signals.scopeContext);
    const frameworkRaw  = scoreFramework(signals.frameworkAction);
    const fpRaw         = scoreHistoricalFP(signals.historicalFpRate);
    const suppressRaw   = scoreUserSuppression(signals.userSuppressionRate);

    const breakdown: ConfidenceBreakdown = {
      ast:             round4(astRaw * WEIGHTS.ast),
      filePath:        round4(filePathRaw * WEIGHTS.filePath),
      framework:       round4(frameworkRaw * WEIGHTS.framework),
      historicalFp:    round4(fpRaw * WEIGHTS.historicalFp),
      userSuppression: round4(suppressRaw * WEIGHTS.userSuppression),
    };

    const composite = round2(clamp(
      breakdown.ast +
      breakdown.filePath +
      breakdown.framework +
      breakdown.historicalFp +
      breakdown.userSuppression,
      0, 1,
    ));

    const { label, recommendation } = interpret(composite);

    return {
      score: composite,
      label,
      breakdown,
      recommendation,
      // Aliases for HaloEngine consumption
      confidence: composite,
      interpretation: label,
      reason: recommendation,
    };
  }

  // -----------------------------------------------------------------------
  // Convenience: compute from violation + optional rate maps
  // -----------------------------------------------------------------------

  /**
   * Analyze a single violation by deriving signals from its fields, file path,
   * and optional FP/suppression rate maps.
   */
  analyzeViolation(
    violation: {
      ruleId: string;
      filePath: string;
      astVerdict?: ASTVerdict | string;
      frameworkAction?: FrameworkAction | string | null;
    },
    fpRates?: Map<string, number>,
    suppressionRates?: Map<string, number>,
  ): ConfidenceResult {
    // Derive scope context from file path via ScopeAnalyzer
    const scope = this.scopeAnalyzer.analyzeFile(violation.filePath, '');

    const signals: ConfidenceSignals = {
      astVerdict: normalizeASTVerdict(violation.astVerdict),
      scopeContext: scope,
      frameworkAction: this.resolveFrameworkAction(
        violation.ruleId,
        normalizeFrameworkAction(violation.frameworkAction),
      ),
      historicalFpRate: fpRates?.get(violation.ruleId)
        ?? this.config.historicalFPRates?.[violation.ruleId]
        ?? DEFAULT_FP_RATES[violation.ruleId],
      userSuppressionRate: suppressionRates?.get(violation.ruleId)
        ?? this.config.suppressionRates?.[violation.ruleId]
        ?? DEFAULT_SUPPRESSION_RATES[violation.ruleId],
    };

    return this.computeConfidence(signals);
  }

  // -----------------------------------------------------------------------
  // Batch: analyze all violations for a file (used by HaloEngine)
  // -----------------------------------------------------------------------

  /**
   * Analyze a list of violations for a given file.
   * More efficient than individual calls — pre-computes file-level scope once.
   * Returns a Map from violation index to ConfidenceResult.
   */
  analyzeFile(
    violations: ViolationInput[],
    filePath: string,
    content: string,
  ): Map<number, ConfidenceResult> {
    const results = new Map<number, ConfidenceResult>();

    // Pre-compute file-level scope once (shared across all violations in file)
    let scope: ScopeContext;
    try {
      scope = this.scopeAnalyzer.analyzeFile(filePath, content);
    } catch {
      scope = {
        isTestFile: false,
        isAdminRoute: false,
        isUserFacing: false,
        isTypeDefinition: false,
        isConfigFile: false,
      };
    }

    for (let i = 0; i < violations.length; i++) {
      const v = violations[i];

      const signals: ConfidenceSignals = {
        astVerdict: v.astVerdict,
        scopeContext: scope,
        frameworkAction: v.frameworkSuppressed
          ? 'suppress' as FrameworkAction
          : this.resolveFrameworkAction(v.ruleId, undefined),
        historicalFpRate: this.config.historicalFPRates?.[v.ruleId]
          ?? DEFAULT_FP_RATES[v.ruleId],
        userSuppressionRate: this.config.suppressionRates?.[v.ruleId]
          ?? DEFAULT_SUPPRESSION_RATES[v.ruleId],
      };

      results.set(i, this.computeConfidence(signals));
    }

    return results;
  }

  // -----------------------------------------------------------------------
  // Private helpers
  // -----------------------------------------------------------------------

  /**
   * Determine framework action for a rule, using the framework safe rules map
   * when no explicit action is provided.
   */
  private resolveFrameworkAction(
    ruleId: string,
    explicitAction?: FrameworkAction | null,
  ): FrameworkAction | null | undefined {
    // Explicit action takes priority
    if (explicitAction !== undefined) return explicitAction;

    const framework = this.config.framework;
    if (!framework) return undefined;

    const safeRules = FRAMEWORK_SAFE_RULES[framework];
    if (safeRules && safeRules.has(ruleId)) {
      return 'suppress';
    }

    // Framework declared but doesn't handle this rule
    return null;
  }
}

// ---------------------------------------------------------------------------
// Utilities
// ---------------------------------------------------------------------------

/** Round to 2 decimal places. */
function round2(n: number): number {
  return Math.round(n * 100) / 100;
}

/** Round to 4 decimal places (for breakdown components to avoid FP noise). */
function round4(n: number): number {
  return Math.round(n * 10000) / 10000;
}

/** Clamp a value to [min, max]. */
function clamp(n: number, min: number, max: number): number {
  return Math.max(min, Math.min(max, n));
}

/** Normalize a loose string to a typed ASTVerdict (or undefined). */
function normalizeASTVerdict(v?: ASTVerdict | string): ASTVerdict | undefined {
  if (!v) return undefined;
  if (v === 'confirmed' || v === 'suppressed' || v === 'regex_only') return v;
  return undefined;
}

/** Normalize a loose string to a typed FrameworkAction | null (or undefined). */
function normalizeFrameworkAction(a?: FrameworkAction | string | null): FrameworkAction | null | undefined {
  if (a === undefined) return undefined;
  if (a === null) return null;
  if (a === 'suppress' || a === 'downgrade') return a;
  return undefined;
}

// ---------------------------------------------------------------------------
// Exports for testing (internal scoring functions)
// ---------------------------------------------------------------------------
export const _internal = {
  scoreAST,
  scoreFilePath,
  scoreFramework,
  scoreHistoricalFP,
  scoreUserSuppression,
  interpret,
  WEIGHTS,
  DEFAULT_FP_RATES,
  DEFAULT_SUPPRESSION_RATES,
};
