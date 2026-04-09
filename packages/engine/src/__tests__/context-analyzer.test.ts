/**
 * ContextAnalyzer v1 Tests
 *
 * Covers:
 *   - Individual signal scoring functions (AST, filePath, framework, historicalFP, userSuppression)
 *   - Weighted composite scoring via computeConfidence
 *   - Label/recommendation thresholds (high >= 0.7, medium 0.4-0.69, low < 0.4)
 *   - Edge cases: all signals, no signals, mixed/conflicting signals
 *   - analyzeViolation convenience method
 *   - analyzeFile batch method (used by HaloEngine)
 *
 * 25+ test cases total across 7 describe blocks.
 */

import {
  ContextAnalyzer,
  ConfidenceSignals,
  ConfidenceResult,
  ViolationInput,
  _internal,
} from '../context-analyzer';

const {
  scoreAST,
  scoreFilePath,
  scoreFramework,
  scoreHistoricalFP,
  scoreUserSuppression,
  interpret,
  WEIGHTS,
} = _internal;

// ===========================================================================
// 1. Individual signal scoring functions
// ===========================================================================

describe('scoreAST', () => {
  it('returns 1.0 for confirmed verdict (no astConfidence)', () => {
    expect(scoreAST('confirmed')).toBe(1.0);
  });

  it('returns 0.5 for regex_only verdict', () => {
    expect(scoreAST('regex_only')).toBe(0.5);
  });

  it('returns 0.0 for suppressed verdict (no astConfidence)', () => {
    expect(scoreAST('suppressed')).toBe(0.0);
  });

  it('returns 0.5 when verdict is undefined (neutral)', () => {
    expect(scoreAST(undefined)).toBe(0.5);
  });

  it('scales confirmed by astConfidence (0.7 + conf * 0.3)', () => {
    expect(scoreAST('confirmed', 0.8)).toBeCloseTo(0.94, 2);
    expect(scoreAST('confirmed', 0.0)).toBeCloseTo(0.7, 2);
    expect(scoreAST('confirmed', 1.0)).toBeCloseTo(1.0, 2);
  });

  it('scales suppressed inversely by astConfidence', () => {
    expect(scoreAST('suppressed', 1.0)).toBeCloseTo(0.05, 2);
    expect(scoreAST('suppressed', 0.0)).toBeCloseTo(0.3, 2);
  });
});

describe('scoreFilePath', () => {
  it('returns 1.0 for user-facing scope', () => {
    expect(scoreFilePath({
      isUserFacing: true, isTestFile: false, isAdminRoute: false,
      isTypeDefinition: false, isConfigFile: false,
    })).toBe(1.0);
  });

  it('returns 0.3 for admin routes', () => {
    expect(scoreFilePath({
      isUserFacing: false, isTestFile: false, isAdminRoute: true,
      isTypeDefinition: false, isConfigFile: false,
    })).toBe(0.3);
  });

  it('returns 0.2 for config files', () => {
    expect(scoreFilePath({
      isUserFacing: false, isTestFile: false, isAdminRoute: false,
      isTypeDefinition: false, isConfigFile: true,
    })).toBe(0.2);
  });

  it('returns 0.1 for test files', () => {
    expect(scoreFilePath({
      isUserFacing: false, isTestFile: true, isAdminRoute: false,
      isTypeDefinition: false, isConfigFile: false,
    })).toBe(0.1);
  });

  it('returns 0.1 for type definitions', () => {
    expect(scoreFilePath({
      isUserFacing: false, isTestFile: false, isAdminRoute: false,
      isTypeDefinition: true, isConfigFile: false,
    })).toBe(0.1);
  });

  it('returns 0.5 when undefined (neutral)', () => {
    expect(scoreFilePath(undefined)).toBe(0.5);
  });

  it('returns 0.5 when no flags are true', () => {
    expect(scoreFilePath({
      isUserFacing: false, isTestFile: false, isAdminRoute: false,
      isTypeDefinition: false, isConfigFile: false,
    })).toBe(0.5);
  });

  it('prioritizes user-facing over other flags', () => {
    expect(scoreFilePath({
      isUserFacing: true, isTestFile: true, isAdminRoute: true,
      isTypeDefinition: false, isConfigFile: false,
    })).toBe(1.0);
  });
});

describe('scoreFramework', () => {
  it('returns 0.0 for suppress', () => {
    expect(scoreFramework('suppress')).toBe(0.0);
  });

  it('returns 0.3 for downgrade', () => {
    expect(scoreFramework('downgrade')).toBe(0.3);
  });

  it('returns 1.0 for null (not handled)', () => {
    expect(scoreFramework(null)).toBe(1.0);
  });

  it('returns 0.5 for undefined (no framework info)', () => {
    expect(scoreFramework(undefined)).toBe(0.5);
  });
});

describe('scoreHistoricalFP', () => {
  it('returns 1.0 for 0% FP rate', () => {
    expect(scoreHistoricalFP(0.0)).toBe(1.0);
  });

  it('returns 0.9 for 5% FP rate', () => {
    expect(scoreHistoricalFP(0.05)).toBeCloseTo(0.9, 4);
  });

  it('returns 0.6 for 20% FP rate', () => {
    expect(scoreHistoricalFP(0.20)).toBeCloseTo(0.6, 4);
  });

  it('returns 0.2 for 50% FP rate', () => {
    expect(scoreHistoricalFP(0.50)).toBeCloseTo(0.2, 4);
  });

  it('returns 0.0 for 100% FP rate', () => {
    expect(scoreHistoricalFP(1.0)).toBeCloseTo(0.0, 4);
  });

  it('returns 0.5 when undefined (neutral)', () => {
    expect(scoreHistoricalFP(undefined)).toBe(0.5);
  });

  it('interpolates linearly between anchor points', () => {
    // 10% is between 5% (0.9) and 20% (0.6): t = (0.10-0.05)/(0.20-0.05) = 1/3
    // score = 0.9 + 1/3 * (0.6 - 0.9) = 0.8
    expect(scoreHistoricalFP(0.10)).toBeCloseTo(0.8, 2);
  });

  it('clamps negative FP rates to 0', () => {
    expect(scoreHistoricalFP(-0.1)).toBe(1.0);
  });

  it('clamps FP rates above 1.0', () => {
    expect(scoreHistoricalFP(1.5)).toBeCloseTo(0.0, 4);
  });
});

describe('scoreUserSuppression', () => {
  it('returns 1.0 for 0% suppression', () => {
    expect(scoreUserSuppression(0.0)).toBe(1.0);
  });

  it('returns 0.5 for 50% suppression', () => {
    expect(scoreUserSuppression(0.5)).toBe(0.5);
  });

  it('returns 0.0 for 100% suppression', () => {
    expect(scoreUserSuppression(1.0)).toBe(0.0);
  });

  it('returns 0.5 when undefined (neutral)', () => {
    expect(scoreUserSuppression(undefined)).toBe(0.5);
  });
});

// ===========================================================================
// 2. Interpretation thresholds
// ===========================================================================

describe('interpret', () => {
  it('returns "high" label for score >= 0.7', () => {
    expect(interpret(0.7).label).toBe('high');
    expect(interpret(0.85).label).toBe('high');
    expect(interpret(1.0).label).toBe('high');
  });

  it('returns "medium" label for score 0.4-0.69', () => {
    expect(interpret(0.4).label).toBe('medium');
    expect(interpret(0.55).label).toBe('medium');
    expect(interpret(0.69).label).toBe('medium');
  });

  it('returns "low" label for score < 0.4', () => {
    expect(interpret(0.39).label).toBe('low');
    expect(interpret(0.2).label).toBe('low');
    expect(interpret(0.0).label).toBe('low');
  });

  it('returns correct recommendation for high', () => {
    expect(interpret(0.8).recommendation).toBe('High confidence \u2014 likely true positive');
  });

  it('returns correct recommendation for medium', () => {
    expect(interpret(0.5).recommendation).toBe('Medium confidence \u2014 review recommended');
  });

  it('returns correct recommendation for low', () => {
    expect(interpret(0.2).recommendation).toBe('Low confidence \u2014 likely false positive');
  });
});

// ===========================================================================
// 3. computeConfidence composite scoring
// ===========================================================================

describe('ContextAnalyzer.computeConfidence', () => {
  let analyzer: ContextAnalyzer;

  beforeEach(() => {
    analyzer = new ContextAnalyzer();
  });

  it('produces high confidence for all-positive signals', () => {
    const result = analyzer.computeConfidence({
      astVerdict: 'confirmed',
      scopeContext: {
        isUserFacing: true, isTestFile: false, isAdminRoute: false,
        isTypeDefinition: false, isConfigFile: false,
      },
      frameworkAction: null,       // not handled -> 1.0
      historicalFpRate: 0.0,       // 0% FP -> 1.0
      userSuppressionRate: 0.0,    // 0% suppression -> 1.0
    });

    expect(result.score).toBe(1.0);
    expect(result.label).toBe('high');
    expect(result.recommendation).toBe('High confidence \u2014 likely true positive');
  });

  it('produces low confidence for all-negative signals', () => {
    const result = analyzer.computeConfidence({
      astVerdict: 'suppressed',
      scopeContext: {
        isUserFacing: false, isTestFile: true, isAdminRoute: false,
        isTypeDefinition: false, isConfigFile: false,
      },
      frameworkAction: 'suppress',  // handled -> 0.0
      historicalFpRate: 1.0,        // 100% FP -> 0.0
      userSuppressionRate: 1.0,     // 100% suppression -> 0.0
    });

    // AST=0.0, filePath=0.1, framework=0.0, fp=0.0, suppress=0.0
    // Weighted: 0 + 0.1*0.15 + 0 + 0 + 0 = 0.015
    expect(result.score).toBeLessThan(0.4);
    expect(result.label).toBe('low');
    expect(result.recommendation).toBe('Low confidence \u2014 likely false positive');
  });

  it('produces neutral (0.5) when no signals are provided', () => {
    const result = analyzer.computeConfidence({});
    // All signals default to 0.5 -> composite = 0.5
    expect(result.score).toBe(0.5);
    expect(result.label).toBe('medium');
  });

  it('includes correct breakdown components that sum to the score', () => {
    const result = analyzer.computeConfidence({
      astVerdict: 'confirmed',
      scopeContext: {
        isUserFacing: true, isTestFile: false, isAdminRoute: false,
        isTypeDefinition: false, isConfigFile: false,
      },
      frameworkAction: null,
      historicalFpRate: 0.0,
      userSuppressionRate: 0.0,
    });

    expect(result.breakdown.ast).toBeCloseTo(WEIGHTS.ast, 3);
    expect(result.breakdown.filePath).toBeCloseTo(WEIGHTS.filePath, 3);
    expect(result.breakdown.framework).toBeCloseTo(WEIGHTS.framework, 3);
    expect(result.breakdown.historicalFp).toBeCloseTo(WEIGHTS.historicalFp, 3);
    expect(result.breakdown.userSuppression).toBeCloseTo(WEIGHTS.userSuppression, 3);

    const breakdownSum =
      result.breakdown.ast +
      result.breakdown.filePath +
      result.breakdown.framework +
      result.breakdown.historicalFp +
      result.breakdown.userSuppression;
    expect(breakdownSum).toBeCloseTo(result.score, 1);
  });

  it('sets aliases (confidence, interpretation, reason) matching primary fields', () => {
    const result = analyzer.computeConfidence({});
    expect(result.confidence).toBe(result.score);
    expect(result.interpretation).toBe(result.label);
    expect(result.reason).toBe(result.recommendation);
  });

  it('clamps composite score to [0.0, 1.0]', () => {
    const maxResult = analyzer.computeConfidence({
      astVerdict: 'confirmed',
      scopeContext: {
        isUserFacing: true, isTestFile: false, isAdminRoute: false,
        isTypeDefinition: false, isConfigFile: false,
      },
      frameworkAction: null,
      historicalFpRate: 0.0,
      userSuppressionRate: 0.0,
    });
    expect(maxResult.score).toBeLessThanOrEqual(1.0);
    expect(maxResult.score).toBeGreaterThanOrEqual(0.0);
  });

  it('produces expected score for a realistic mixed-signal case', () => {
    const result = analyzer.computeConfidence({
      astVerdict: 'regex_only',       // 0.5
      scopeContext: {
        isUserFacing: true,           // 1.0
        isTestFile: false, isAdminRoute: false,
        isTypeDefinition: false, isConfigFile: false,
      },
      frameworkAction: 'downgrade',   // 0.3
      historicalFpRate: 0.20,         // 0.6
      userSuppressionRate: 0.10,      // 0.9
    });

    // Expected: 0.5*0.35 + 1.0*0.15 + 0.3*0.15 + 0.6*0.20 + 0.9*0.15
    //         = 0.175 + 0.15 + 0.045 + 0.12 + 0.135 = 0.625
    expect(result.score).toBeCloseTo(0.63, 1);
    expect(result.label).toBe('medium');
  });

  it('handles test file with confirmed AST (conflicting signals)', () => {
    const result = analyzer.computeConfidence({
      astVerdict: 'confirmed',         // 1.0
      scopeContext: {
        isUserFacing: false,
        isTestFile: true,              // 0.1
        isAdminRoute: false,
        isTypeDefinition: false,
        isConfigFile: false,
      },
      frameworkAction: null,           // 1.0
      historicalFpRate: 0.0,           // 1.0
      userSuppressionRate: 0.0,        // 1.0
    });

    // 1.0*0.35 + 0.1*0.15 + 1.0*0.15 + 1.0*0.20 + 1.0*0.15
    // = 0.35 + 0.015 + 0.15 + 0.20 + 0.15 = 0.865
    expect(result.score).toBeCloseTo(0.87, 1);
    expect(result.label).toBe('high');
  });

  it('handles framework suppression reducing score', () => {
    const result = analyzer.computeConfidence({
      astVerdict: 'confirmed',         // 1.0
      scopeContext: {
        isUserFacing: true,            // 1.0
        isTestFile: false, isAdminRoute: false,
        isTypeDefinition: false, isConfigFile: false,
      },
      frameworkAction: 'suppress',     // 0.0
      historicalFpRate: 0.0,           // 1.0
      userSuppressionRate: 0.0,        // 1.0
    });

    // 1.0*0.35 + 1.0*0.15 + 0.0*0.15 + 1.0*0.20 + 1.0*0.15 = 0.85
    expect(result.score).toBeCloseTo(0.85, 1);
    expect(result.label).toBe('high');
  });

  it('crosses the medium/low boundary at 0.4', () => {
    const result = analyzer.computeConfidence({
      astVerdict: 'suppressed',        // 0.0
      scopeContext: {
        isUserFacing: false,
        isTestFile: false,
        isAdminRoute: true,            // 0.3
        isTypeDefinition: false,
        isConfigFile: false,
      },
      frameworkAction: null,           // 1.0
      historicalFpRate: 0.20,          // 0.6
      userSuppressionRate: 0.50,       // 0.5
    });

    // 0.0*0.35 + 0.3*0.15 + 1.0*0.15 + 0.6*0.20 + 0.5*0.15
    // = 0 + 0.045 + 0.15 + 0.12 + 0.075 = 0.39
    expect(result.score).toBeCloseTo(0.39, 1);
    expect(result.label).toBe('low');
  });

  it('weights sum to 1.0', () => {
    const total = WEIGHTS.ast + WEIGHTS.filePath + WEIGHTS.framework
      + WEIGHTS.historicalFp + WEIGHTS.userSuppression;
    expect(total).toBe(1.0);
  });

  it('AST verdict is the most heavily weighted signal (35%)', () => {
    const confirmed = analyzer.computeConfidence({ astVerdict: 'confirmed' });
    const suppressed = analyzer.computeConfidence({ astVerdict: 'suppressed' });

    // Difference should be 0.35 (1.0-0.0 * weight 0.35), others are identical neutral
    expect(confirmed.score - suppressed.score).toBeCloseTo(0.35, 1);
  });
});

// ===========================================================================
// 4. analyzeViolation convenience method
// ===========================================================================

describe('ContextAnalyzer.analyzeViolation', () => {
  it('derives scope from file path and computes confidence', () => {
    const analyzer = new ContextAnalyzer();
    const result = analyzer.analyzeViolation({
      ruleId: 'coppa-auth-001',
      filePath: 'src/components/LoginForm.tsx',
      astVerdict: 'confirmed',
      frameworkAction: null,
    });

    expect(result.score).toBeGreaterThan(0);
    expect(result.label).toBeDefined();
    expect(result.recommendation).toBeDefined();
    expect(result.confidence).toBe(result.score);
  });

  it('uses provided FP rates map over defaults', () => {
    const analyzer = new ContextAnalyzer();
    const fpRates = new Map([['coppa-auth-001', 0.80]]);

    const result = analyzer.analyzeViolation(
      { ruleId: 'coppa-auth-001', filePath: 'src/lib/auth.ts' },
      fpRates,
    );

    // With 80% FP rate, historical FP signal is very low -> score drops
    expect(result.score).toBeLessThan(0.6);
  });

  it('uses provided suppression rates map over defaults', () => {
    const analyzer = new ContextAnalyzer();
    const suppressionRates = new Map([['coppa-auth-001', 0.90]]);

    const result = analyzer.analyzeViolation(
      { ruleId: 'coppa-auth-001', filePath: 'src/lib/auth.ts' },
      undefined,
      suppressionRates,
    );

    // 90% suppression -> very low suppression signal
    expect(result.score).toBeLessThan(0.6);
  });

  it('normalizes string astVerdict to typed enum', () => {
    const analyzer = new ContextAnalyzer();

    const confirmed = analyzer.analyzeViolation({
      ruleId: 'coppa-auth-001',
      filePath: 'src/lib/auth.ts',
      astVerdict: 'confirmed',
    });

    const suppressed = analyzer.analyzeViolation({
      ruleId: 'coppa-auth-001',
      filePath: 'src/lib/auth.ts',
      astVerdict: 'suppressed',
    });

    expect(confirmed.score).toBeGreaterThan(suppressed.score);
  });

  it('uses framework config for safe rule resolution', () => {
    const analyzer = new ContextAnalyzer({ framework: 'nextjs' });

    // coppa-cookies-016 IS in nextjs safe rules
    const safeResult = analyzer.analyzeViolation({
      ruleId: 'coppa-cookies-016',
      filePath: 'src/pages/index.tsx',
    });

    // coppa-auth-001 is NOT in nextjs safe rules
    const notSafeResult = analyzer.analyzeViolation({
      ruleId: 'coppa-auth-001',
      filePath: 'src/pages/index.tsx',
    });

    // Framework suppression for safe rule should lower its confidence
    expect(safeResult.score).toBeLessThan(notSafeResult.score);
  });

  it('handles invalid astVerdict gracefully (falls back to undefined)', () => {
    const analyzer = new ContextAnalyzer();
    const result = analyzer.analyzeViolation({
      ruleId: 'coppa-auth-001',
      filePath: 'src/lib/auth.ts',
      astVerdict: 'bogus_value' as any,
    });

    // Should not throw; score should be neutral-ish
    expect(result.score).toBeGreaterThanOrEqual(0);
    expect(result.score).toBeLessThanOrEqual(1);
  });
});

// ===========================================================================
// 5. analyzeFile batch method
// ===========================================================================

describe('ContextAnalyzer.analyzeFile', () => {
  it('returns a map with results for each violation', () => {
    const analyzer = new ContextAnalyzer();
    const violations: ViolationInput[] = [
      { ruleId: 'coppa-auth-001', astVerdict: 'confirmed' },
      { ruleId: 'coppa-sec-010', astVerdict: 'regex_only' },
      { ruleId: 'coppa-ext-017', astVerdict: 'suppressed' },
    ];

    const results = analyzer.analyzeFile(violations, 'src/pages/login.tsx', '');
    expect(results.size).toBe(3);
    expect(results.has(0)).toBe(true);
    expect(results.has(1)).toBe(true);
    expect(results.has(2)).toBe(true);
  });

  it('shares file-level scope across all violations', () => {
    const analyzer = new ContextAnalyzer();
    const violations: ViolationInput[] = [
      { ruleId: 'coppa-auth-001', astVerdict: 'confirmed' },
      { ruleId: 'coppa-sec-010', astVerdict: 'confirmed' },
    ];

    const results = analyzer.analyzeFile(violations, 'src/pages/login.tsx', '');
    const r0 = results.get(0)!;
    const r1 = results.get(1)!;

    // File path breakdown should be identical (same file)
    expect(r0.breakdown.filePath).toBe(r1.breakdown.filePath);
  });

  it('handles frameworkSuppressed field on violation input', () => {
    const analyzer = new ContextAnalyzer();
    const violations: ViolationInput[] = [
      { ruleId: 'coppa-auth-001', frameworkSuppressed: true },
      { ruleId: 'coppa-auth-001', frameworkSuppressed: false },
    ];

    const results = analyzer.analyzeFile(violations, 'src/pages/login.tsx', '');
    const suppressed = results.get(0)!;
    const notSuppressed = results.get(1)!;

    expect(suppressed.breakdown.framework).toBeLessThan(notSuppressed.breakdown.framework);
  });

  it('uses config FP/suppression rates for all violations', () => {
    const analyzer = new ContextAnalyzer({
      historicalFPRates: { 'coppa-auth-001': 0.50 },
      suppressionRates: { 'coppa-auth-001': 0.80 },
    });

    const results = analyzer.analyzeFile(
      [{ ruleId: 'coppa-auth-001' }],
      'src/lib/auth.ts',
      '',
    );
    const result = results.get(0)!;

    // High FP and suppression rates should pull score down
    expect(result.score).toBeLessThan(0.5);
  });

  it('returns empty map for empty violations array', () => {
    const analyzer = new ContextAnalyzer();
    const results = analyzer.analyzeFile([], 'src/lib/auth.ts', '');
    expect(results.size).toBe(0);
  });

  it('different violations in same file get different scores', () => {
    const analyzer = new ContextAnalyzer();
    const violations: ViolationInput[] = [
      { ruleId: 'coppa-tracking-003', astVerdict: 'confirmed' },
      { ruleId: 'coppa-sec-010', astVerdict: 'suppressed' },
    ];

    const results = analyzer.analyzeFile(violations, 'src/app.ts', '');
    const confirmed = results.get(0)!;
    const suppressed = results.get(1)!;

    expect(confirmed.score).toBeGreaterThan(suppressed.score);
  });
});

// ===========================================================================
// 6. Edge cases
// ===========================================================================

describe('Edge cases', () => {
  it('handles unknown rule IDs gracefully (falls back to neutral defaults)', () => {
    const analyzer = new ContextAnalyzer();
    const result = analyzer.computeConfidence({
      astVerdict: 'confirmed',
      historicalFpRate: undefined,
      userSuppressionRate: undefined,
    });

    expect(result.score).toBeGreaterThanOrEqual(0);
    expect(result.score).toBeLessThanOrEqual(1);
    expect(['high', 'medium', 'low']).toContain(result.label);
  });

  it('produces consistent results for identical inputs', () => {
    const analyzer = new ContextAnalyzer();
    const signals: ConfidenceSignals = {
      astVerdict: 'confirmed',
      scopeContext: {
        isUserFacing: true, isTestFile: false, isAdminRoute: false,
        isTypeDefinition: false, isConfigFile: false,
      },
      frameworkAction: null,
      historicalFpRate: 0.10,
      userSuppressionRate: 0.05,
    };

    const r1 = analyzer.computeConfidence(signals);
    const r2 = analyzer.computeConfidence(signals);
    expect(r1.score).toBe(r2.score);
    expect(r1.label).toBe(r2.label);
    expect(r1.breakdown).toEqual(r2.breakdown);
  });

  it('handles boundary FP rate values (0 and 1)', () => {
    const analyzer = new ContextAnalyzer();
    const zeroFP = analyzer.computeConfidence({ historicalFpRate: 0.0 });
    const fullFP = analyzer.computeConfidence({ historicalFpRate: 1.0 });
    expect(zeroFP.breakdown.historicalFp).toBeGreaterThan(fullFP.breakdown.historicalFp);
  });

  it('handles analyzeFile with an unknown framework gracefully', () => {
    const analyzer = new ContextAnalyzer({ framework: 'unknown-framework-xyz' });
    const violations: ViolationInput[] = [{ ruleId: 'coppa-auth-001' }];
    const results = analyzer.analyzeFile(violations, 'src/app.ts', '');
    const result = results.get(0)!;

    // Unknown framework: no safe rules -> framework action is null (not handled) -> 1.0
    expect(result.score).toBeGreaterThanOrEqual(0);
    expect(result.score).toBeLessThanOrEqual(1);
  });

  it('every ConfidenceResult has all required fields', () => {
    const analyzer = new ContextAnalyzer();
    const result = analyzer.computeConfidence({
      astVerdict: 'regex_only',
      historicalFpRate: 0.15,
    });

    // Primary fields
    expect(typeof result.score).toBe('number');
    expect(typeof result.label).toBe('string');
    expect(typeof result.recommendation).toBe('string');
    expect(result.breakdown).toBeDefined();
    expect(typeof result.breakdown.ast).toBe('number');
    expect(typeof result.breakdown.filePath).toBe('number');
    expect(typeof result.breakdown.framework).toBe('number');
    expect(typeof result.breakdown.historicalFp).toBe('number');
    expect(typeof result.breakdown.userSuppression).toBe('number');

    // Alias fields
    expect(typeof result.confidence).toBe('number');
    expect(typeof result.interpretation).toBe('string');
    expect(typeof result.reason).toBe('string');
  });
});
