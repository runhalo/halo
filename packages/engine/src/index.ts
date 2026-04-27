/**
 * Halo COPPA Rule Engine
 * Core scanning logic for child safety compliance detection
 *
 *  Added rules 6-20 (coppa-sec-006 through coppa-default-020)
 *  Added suppression system for // halo-ignore comments
 *  Added tree-sitter for AST analysis, YAML rule loading
 */

import * as fs from 'fs';
import * as path from 'path';
import Parser from 'tree-sitter';
import TypeScript from 'tree-sitter-typescript';
import JavaScript from 'tree-sitter-javascript';
import * as yaml from 'js-yaml';
import { ASTRuleEngine } from './ast-engine';
import { applyFrameworkOverrides } from './frameworks';
import { ContextAnalyzer, ConfidenceResult, ConfidenceSignals, ConfidenceInterpretation, ViolationInput } from './context-analyzer';
export type { ConfidenceResult, ConfidenceSignals, ConfidenceInterpretation, ViolationInput };

/**
 * Process-wide AST availability state.
 *
 * The native tree-sitter binding can throw at parse time when the
 * prebuilt NAPI binary doesn't match the host Node ABI (e.g.
 * tree-sitter@0.21.x on Node 24, which produces "Invalid argument"
 * synchronously on every parse() call). When that happens, the
 * engine silently downgrades all violations on that file to
 * regex-only mode. The downgrade is the right runtime behavior —
 * regex matches are still useful — but the previous implementation
 * also called `console.warn` once per file, spamming stderr with
 * dozens of identical stack traces while the user-facing output
 * gave no qualified hint that the run was degraded.
 *
 * Two pieces of state are exposed so the CLI can render a single
 * up-front banner instead:
 *
 *   isAstAvailable() — true unless any parse() has thrown this
 *     process. Once flipped to false, it stays false (we don't
 *     retry per-file; tree-sitter doesn't recover from an ABI
 *     mismatch within a process).
 *
 *   getAstFailureMessage() — the first thrown error's message,
 *     so callers can surface a concrete diagnostic rather than a
 *     generic "AST unavailable" string.
 */
let astAvailableFlag = true;
let astFailureMessage: string | null = null;

export function isAstAvailable(): boolean {
  return astAvailableFlag;
}

export function getAstFailureMessage(): string | null {
  return astFailureMessage;
}

/** Reset AST availability state for a new scan run.
 *
 *  Production usage: `runhalo watch` keeps the same Node process
 *  alive across scan cycles. Without resetting, a transient parse
 *  failure during one cycle would mark every subsequent cycle as
 *  degraded forever. The CLI calls this at the top of each scan()
 *  invocation so each scan is judged on its own.
 *
 *  Test usage: reset state between Jest test files.
 *
 *  Note: for a true tree-sitter ABI mismatch (the Node 24 case),
 *  the very first parse() of the next scan will re-flip the flag
 *  — there's no way to recover within the same process. The reset
 *  exists so transient single-file failures don't pollute later
 *  cycles unnecessarily.
 */
export function resetAstAvailability(): void {
  astAvailableFlag = true;
  astFailureMessage = null;
}

/** @deprecated Use `resetAstAvailability` instead. Kept as a thin
 *  alias for tests that imported the previous underscore-prefixed
 *  name. */
export const _resetAstAvailabilityForTesting = resetAstAvailability;

// Rule severity levels
export type Severity = 'critical' | 'high' | 'medium' | 'low';

// Authority tier: legal weight of a rule's finding
export type AuthorityTier = 'statutory' | 'guidance' | 'voluntary' | 'advisory';

// AST verdict type (shared with ast-engine.ts)
export type ASTVerdict = 'confirmed' | 'suppressed' | 'regex_only';

// Remediation tier: determines fix strategy
// auto = deterministic transform, no LLM
// guided = LLM scaffold + developer customization
// flag-only = detection + guidance docs, no code generation (already shipping)
export type Fixability = 'auto' | 'guided' | 'flag-only';

// Remediation metadata attached to each rule definition
export interface RemediationSpec {
  fixability: Fixability;
  // Tier 1: AST transform type (e.g. "add-flag", "url-upgrade", "strip-field")
  transformType?: string;
  // Tier 2: scaffold template ID for LLM-guided generation
  scaffoldId?: string;
  // Tier 3: guidance doc URL
  guidanceUrl?: string;
  // Estimated compute cost per violation (for cost modeling)
  estimatedCost?: '$0' | '$0.01' | '$0.05';
}

// Violation interface
export interface Violation {
  ruleId: string;
  ruleName: string;
  severity: Severity;
  filePath: string;
  line: number;
  column: number;
  message: string;
  codeSnippet: string;
  fixSuggestion: string;
  penalty?: string;
  suppressed?: boolean;
  suppressionComment?: string;
  // Training corpus fields (future AI learning loop + remediation engine)
  category?: string;       // e.g. "auth", "data", "tracking", "sec", "ui", "ethical"
  language?: string;       // e.g. "typescript", "python", "php"
  matchType?: 'regex' | 'ast' | 'hybrid';  // which detection method fired
  // Remediation fields (schema hook)
  fixability?: Fixability;
  remediation?: RemediationSpec;

  /** AST analysis verdict: confirmed, suppressed, or regex_only */
  astVerdict?: ASTVerdict;
  /** AST analysis confidence: 0.0 to 1.0 */
  astConfidence?: number;
  /** Reason for AST verdict */
  astReason?: string;
  /** Whether this violation was suppressed by framework profile */
  frameworkSuppressed?: boolean;
  /** ContextAnalyzer confidence score (0.0-1.0) */
  confidence?: number;
  /** ContextAnalyzer interpretation */
  confidenceInterpretation?: ConfidenceInterpretation;
  /** ContextAnalyzer reason string */
  confidenceReason?: string;
  /** Whether this violation is from a vendored/third-party library path */
  vendorPath?: boolean;
  /** Authority tier: statutory, guidance, voluntary, or advisory */
  authorityTier?: AuthorityTier;
  /** Regulatory source citation (e.g., "16 CFR §312.5(b)") */
  regulatorySource?: string;

  /** Lines surrounding the match (5 before + 5 after) */
  surroundingCode?: string;
  /** File-level metadata flags computed during scan */
  fileMetadata?: {
    language: string;
    isVendor: boolean;
    isTest: boolean;
    isAdmin: boolean;
    isConsent: boolean;
    isDocGenerator: boolean;
    detectedFramework?: string;

    isMock?: boolean;
    isFixture?: boolean;
    isCIConfig?: boolean;
    isBuildOutput?: boolean;
    isTypeDefinition?: boolean;
    isStorybook?: boolean;
  };
}

// Rule interface
export interface Rule {
  id: string;
  name: string;
  severity: Severity;
  description: string;
  patterns: RegExp[];
  fixSuggestion: string;
  penalty: string;
  languages: string[];
  // Remediation architecture hook (schema only, implementation)
  remediation?: RemediationSpec;

  is_active?: boolean;
  authority_tier?: AuthorityTier;
  knowledge?: {
    regulatory_source?: string;
    [key: string]: any;
  };
}

// Extract category from ruleId (e.g. "coppa-auth-001" → "auth")
function extractCategory(ruleId: string): string {
  const match = ruleId.match(/^coppa-(\w+)-\d+$/);
  return match ? match[1] : 'unknown';
}

// Detect language from file extension
function detectLanguage(filePath: string): string {
  const ext = path.extname(filePath).toLowerCase();
  const langMap: Record<string, string> = {
    '.ts': 'typescript', '.tsx': 'typescript', '.js': 'javascript', '.jsx': 'javascript',
    '.py': 'python', '.swift': 'swift', '.java': 'java', '.kt': 'kotlin',
    '.html': 'html', '.vue': 'vue', '.svelte': 'svelte', '.php': 'php',
    '.cpp': 'cpp', '.h': 'cpp', '.hpp': 'cpp', '.cs': 'csharp',
    '.qml': 'qml', '.sql': 'sql', '.go': 'go', '.rb': 'ruby',
    '.xml': 'xml', '.erb': 'ruby',
  };
  return langMap[ext] || 'unknown';
}

// ============================================================

//
// Consolidates all file-level heuristics into a single classification.
// Designed with `method` field so future Option C (ML classifier) can
// swap in as a backend without rewriting the scan loop.
// ============================================================

export interface FileClassification {
  /** How this classification was determined */
  method: 'heuristic' | 'classifier';
  /** Detected programming language */
  language: string;
  /** Whether the file is in a vendored/third-party directory */
  isVendor: boolean;
  /** Whether the file is a test/spec/fixture file */
  isTest: boolean;
  /** Whether the file is a consent/privacy compliance implementation */
  isConsent: boolean;
  /** Whether the file is in an admin/instructor/staff backend path */
  isAdmin: boolean;
  /** Whether the file is documentation generator output */
  isDocGenerator: boolean;
  /** Whether the file is a Django migration */
  isDjangoMigration: boolean;
  /** Whether the file is a Rails fixture or seed file */
  isFixtureOrSeed: boolean;
  /** Whether the file is a mock/factory file */
  isMockOrFactory: boolean;
  /** Whether the file is a CI/CD config file */
  isCIConfig: boolean;
  /** Whether the file is build output */
  isBuildOutput: boolean;
  /** Whether the file is a type definition only (no runtime code) */
  isTypeDefinition: boolean;
  /** Whether the file is a Storybook story */
  isStorybook: boolean;
  /** Whether the file should be completely skipped (combined signal) */
  shouldSkip: boolean;
  /** Category for why the file should be skipped (if shouldSkip is true) */
  skipReason?: string;
}

/**
 *  Classify a file using deterministic heuristics.
 * Returns a FileClassification object that the scan loop uses to skip
 * files or suppress specific rules.
 *
 * @param filePath — normalized file path (forward slashes)
 * @param contentPrefix — first 3000 chars of file content (for decorator/annotation detection)
 */
export function classifyFile(filePath: string, contentPrefix: string = ''): FileClassification {
  const normalized = filePath.replace(/\\/g, '/');

  const language = detectLanguage(filePath);

  const isVendorResult = isVendorPath(filePath);
  const isDocGeneratorResult = isDocGeneratorPath(filePath);

  // Test/spec/fixture detection (+ 11a, consolidated)
  const isTest = /\.(test|spec)\.(ts|tsx|js|jsx|py|rb|java|go)$/i.test(normalized) ||
    /(^|\/)__tests__\//.test(normalized) ||
    /(^|\/)test\//.test(normalized) ||
    /(^|\/)tests\//.test(normalized) ||
    /(^|\/)spec\//.test(normalized) ||
    /(^|\/)fixtures\//.test(normalized) ||
    /\.(stories|story)\.(ts|tsx|js|jsx)$/i.test(normalized) ||
    /(^|\/)cypress\//.test(normalized) ||
    /(^|\/)e2e\//.test(normalized) ||
    /jest\.config|vitest\.config|playwright\.config/i.test(normalized) ||

    /(^|\/)envs\/test[^/]*\.(py|json|ya?ml|toml|cfg|ini)$/i.test(normalized) ||
    /(^|\/)config\/test[^/]*\.(py|json|ya?ml|toml|cfg|ini|js|ts)$/i.test(normalized) ||
    /(^|\/)settings\/test[^/]*\.(py|json|ya?ml|toml)$/i.test(normalized) ||
    /(^|\/)conftest\.py$/i.test(normalized);

  // Consent/privacy implementation files
  const CONSENT_PATH_PATTERNS = /(?:^|\/)(?:consent|cookie[_-]?(?:consent|banner|preferences|notice|policy)|privacy[_-]?(?:policy|notice|banner|settings)|data[_-]?(?:protection|privacy|consent)|ccpa|compliance|data[_-]?(?:deletion|removal|protection))\b/i;
  const isConsent = CONSENT_PATH_PATTERNS.test(normalized);

  // Admin/instructor/staff backend paths
  // Matches admin directories AND admin.py/admin.rb files (Django/Rails admin registration modules)
  const ADMIN_PATH_PATTERNS = /(?:^|\/)(?:admin|instructor|teacher|staff|management|backoffice|dashboard\/admin|cms|moderator|superuser)(?:\/|\.py|\.rb|\.php|$)/i;
  const isAdmin = ADMIN_PATH_PATTERNS.test(normalized) ||
    /(?:@staff_member_required|@permission_required|@user_passes_test|@login_required.*staff|@admin_required|is_staff|is_superuser)/i.test(contentPrefix);

  // ===  New heuristic patterns ===

  // Django migrations — auto-generated schema changes, no user-facing code
  const isDjangoMigration = /(^|\/)migrations\/\d{4}_[a-zA-Z0-9_]+\.py$/i.test(normalized) ||
    /(^|\/)migrations\/__init__\.py$/i.test(normalized);

  // Rails fixture and seed files — test data, not production behavior
  const isFixtureOrSeed = /(^|\/)fixtures\/[^/]+\.(ya?ml|json|csv)$/i.test(normalized) ||
    /(^|\/)seeds?\//i.test(normalized) ||
    /(^|\/)db\/seeds/i.test(normalized) ||
    /(^|\/)factories?\//i.test(normalized) ||
    /(^|\/)factory\.(ts|js|py|rb)$/i.test(normalized);

  // Mock/factory files — test infrastructure
  const isMockOrFactory = /(?:^|\/)(?:__mocks__|mocks?|fakes?|stubs?)(?:\/|$)/i.test(normalized) ||
    /\.mock\.(ts|tsx|js|jsx|py)$/i.test(normalized) ||
    /\.fake\.(ts|tsx|js|jsx|py)$/i.test(normalized) ||
    /(?:^|\/)(?:mock|fake|stub)[_-]?\w+\.(ts|tsx|js|jsx|py)$/i.test(normalized) ||
    /(?:^|\/)(?:\w+)?[_-](?:mock|fake|stub)\.(ts|tsx|js|jsx|py)$/i.test(normalized);

  // CI/CD configuration files — pipeline definitions, not application code
  const isCIConfig = /(^|\/)\.github\/workflows\//i.test(normalized) ||
    /(^|\/)\.github\/actions\//i.test(normalized) ||
    /(^|\/)\.circleci\//i.test(normalized) ||
    /(^|\/)\.gitlab-ci/i.test(normalized) ||
    /(^|\/)Jenkinsfile$/i.test(normalized) ||
    /(^|\/)\.travis\.yml$/i.test(normalized) ||
    /(^|\/)azure-pipelines/i.test(normalized) ||
    /(^|\/)bitbucket-pipelines/i.test(normalized) ||
    /(^|\/)\.buildkite\//i.test(normalized) ||
    /(^|\/)Dockerfile$/i.test(normalized) ||
    /(^|\/)docker-compose/i.test(normalized);

  // Build output directories — generated code, not source
  const isBuildOutput = /(^|\/)dist\//i.test(normalized) ||
    /(^|\/)build\/(?!src)/i.test(normalized) ||  // build/ but not build/src/
    /(^|\/)\.next\//i.test(normalized) ||
    /(^|\/)\.nuxt\//i.test(normalized) ||
    /(^|\/)\.svelte-kit\//i.test(normalized) ||
    /(^|\/)out\//i.test(normalized) ||
    /(^|\/)\.output\//i.test(normalized) ||
    /(^|\/)coverage\//i.test(normalized) ||
    /(^|\/)\.cache\//i.test(normalized) ||
    /(^|\/)\.parcel-cache\//i.test(normalized) ||
    /(^|\/)\.turbo\//i.test(normalized);

  // Type definition files — no runtime behavior, only type annotations
  const isTypeDefinition = /\.d\.ts$/i.test(normalized) ||
    /\.pyi$/i.test(normalized) ||
    /(^|\/)@types\//i.test(normalized);

  // Storybook stories — UI component demos, not production code
  const isStorybook = /\.(stories|story)\.(ts|tsx|js|jsx|mdx)$/i.test(normalized) ||
    /(^|\/)\.storybook\//i.test(normalized);

  // Determine if file should be completely skipped
  // (vendor and doc generator are already handled at file-discovery level,
  //  but including here for completeness in the classification)
  let shouldSkip = false;
  let skipReason: string | undefined;

  if (isVendorResult) {
    shouldSkip = true;
    skipReason = 'vendor-library';
  } else if (isDocGeneratorResult) {
    shouldSkip = true;
    skipReason = 'doc-generator';
  } else if (isDjangoMigration) {
    shouldSkip = true;
    skipReason = 'django-migration';
  } else if (isBuildOutput) {
    shouldSkip = true;
    skipReason = 'build-output';
  } else if (isTypeDefinition) {
    shouldSkip = true;
    skipReason = 'type-definition';
  } else if (isCIConfig) {
    shouldSkip = true;
    skipReason = 'ci-config';
  }
  // Note: test, consent, admin, mock, fixture, storybook files are NOT fully skipped
  // They get per-rule suppression instead (some rules ARE valid in these files)

  return {
    method: 'heuristic',
    language,
    isVendor: isVendorResult,
    isTest,
    isConsent,
    isAdmin,
    isDocGenerator: isDocGeneratorResult,
    isDjangoMigration,
    isFixtureOrSeed,
    isMockOrFactory,
    isCIConfig,
    isBuildOutput,
    isTypeDefinition,
    isStorybook,
    shouldSkip,
    skipReason,
  };
}

// Suppression interface
export interface SuppressionConfig {
  enabled: boolean;
  commentPattern: string;
}

// YAML Rule Loader - Load rules from coppa-tier-1.yaml
export function loadRulesFromYAML(yamlPath: string): Rule[] {
  try {
    const yamlContent = fs.readFileSync(yamlPath, 'utf-8');
    const config = yaml.load(yamlContent) as any;
    
    if (!config?.rules) {
      console.warn(`No rules found in YAML file: ${yamlPath}`);
      return [];
    }
    
    return config.rules.map((ruleConfig: any) => {
      const metadata = ruleConfig.metadata || {};
      const patterns: RegExp[] = (ruleConfig.patterns || []).map((p: any) => {
        return new RegExp(p.regex.pattern, p.regex.flags || 'g');
      });
      
      return {
        id: metadata.id || '',
        name: metadata.name || '',
        severity: (metadata.severity as Severity) || 'medium',
        description: metadata.coppaSection || '',
        patterns,
        fixSuggestion: ruleConfig.autoFix?.description || '',
        penalty: metadata.penaltyRange || '',
        languages: metadata.languages || []
      };
    });
  } catch (error) {
    console.error(`Error loading YAML rules from ${yamlPath}:`, error);
    return [];
  }
}

// JSON Rule Config interface — matches rules.json schema
export interface JSONRuleConfig {
  version: string;
  generated_at: string;
  packs: Record<string, {
    id: string;
    name: string;
    description: string;
    jurisdiction: string;
    jurisdiction_level: string;
    is_free: boolean;
    effective_date: string | null;
    source_url: string;
  }>;
  rules: JSONRule[];
}

export interface JSONRule {
  id: string;
  name: string;
  severity: Severity;
  category: string;
  description: string;
  patterns: Array<{ pattern: string; flags: string }>;
  fix_suggestion: string;
  penalty: string;
  languages: string[];
  packs: string[];
  fixability: string;
  transform_type: string | null;
  scaffold_id: string | null;
  guidance_url: string | null;
  status?: 'active' | 'draft'; // Draft rules excluded from production loading
  // Authority tier (from legal council validation)
  authority_tier?: AuthorityTier;
  is_active?: boolean;
  knowledge?: {
    plain_description?: string;
    tp_criteria?: string[];
    fp_criteria?: string[];
    rule_logic?: string[];
    regulatory_source?: string;
    tp_examples?: Array<{ code: string; file: string; line: number; explanation: string }>;
    fp_examples?: Array<{ code: string; file: string; line: number; explanation: string }>;
    legal_council?: Record<string, any>;
    [key: string]: any;
  };
  // Attestation Q&A (Tier 3 detection)
  requiresUserInput?: boolean; // Rule cannot be resolved by static + visual analysis alone
  userInputTier?: number; // Always 3 for attestation rules
  questionTemplate?: {
    trigger: string;
    questions: Array<{
      id: string;
      text: string;
      type: 'yes_no' | 'choice' | 'free_text';
      options?: string[];
      verdictMap: Record<string, {
        verdict: string;
        confidence?: number;
        reason?: string;
        nextQuestion?: string;
      }>;
    }>;
  };
}

// Convert a JSON rule definition to the engine's Rule interface
function jsonRuleToRule(jsonRule: JSONRule): Rule {
  const patterns = jsonRule.patterns.map(p => new RegExp(p.pattern, p.flags));

  // Map fixability string to Fixability type
  const fixabilityMap: Record<string, Fixability> = {
    'auto': 'auto',
    'guided': 'guided',
    'flag-only': 'flag-only',
  };

  const remediation: RemediationSpec = {
    fixability: fixabilityMap[jsonRule.fixability] || 'flag-only',
    transformType: jsonRule.transform_type || undefined,
    scaffoldId: jsonRule.scaffold_id || undefined,
    guidanceUrl: jsonRule.guidance_url || undefined,
  };

  return {
    id: jsonRule.id,
    name: jsonRule.name,
    severity: jsonRule.severity,
    description: jsonRule.description,
    patterns,
    fixSuggestion: jsonRule.fix_suggestion,
    penalty: jsonRule.penalty,
    languages: jsonRule.languages,
    remediation,
    authority_tier: jsonRule.authority_tier,
    knowledge: jsonRule.knowledge,
    is_active: jsonRule.is_active,
  };
}

// JSON Rule Loader — Load rules from rules.json
export function loadRulesFromJSON(jsonPath: string): Rule[] {
  try {
    const jsonContent = fs.readFileSync(jsonPath, 'utf-8');
    const config: JSONRuleConfig = JSON.parse(jsonContent);

    if (!config?.rules || !Array.isArray(config.rules)) {
      console.warn(`No rules found in JSON file: ${jsonPath}`);
      return [];
    }

    return config.rules.map(jsonRuleToRule);
  } catch (error) {
    console.error(`Error loading JSON rules from ${jsonPath}:`, error);
    return [];
  }
}

// ── Pack configuration ──
// Every pack fires as a loose pre-filter. AI Review Board handles precision.
export const ALL_PACK_IDS = [
  'coppa',
];

// JSON Rule Loader — Load rules filtered by pack IDs
export function loadRulesFromJSONByPack(jsonPath: string, packIds: string[]): Rule[] {
  try {
    const jsonContent = fs.readFileSync(jsonPath, 'utf-8');
    const config: JSONRuleConfig = JSON.parse(jsonContent);

    if (!config?.rules || !Array.isArray(config.rules)) {
      console.warn(`No rules found in JSON file: ${jsonPath}`);
      return [];
    }

    const packSet = new Set(packIds);
    const filtered = config.rules.filter(r =>
      r.packs.some(p => packSet.has(p)) &&
      r.status !== 'draft' // Exclude draft rules from production loading
    );

    return filtered.map(jsonRuleToRule);
  } catch (error) {
    console.error(`Error loading JSON rules from ${jsonPath}:`, error);
    return [];
  }
}

// Compile raw JSON rule objects (from API/cache) to engine Rule objects
export function compileRawRules(rawRules: JSONRule[]): Rule[] {
  return rawRules.map(jsonRuleToRule);
}

// Tree-sitter Parser for AST analysis
export class TreeSitterParser {
  private parser: Parser;
  
  constructor() {
    this.parser = new Parser();
  }
  
  /**
   * Initialize parser with language
   */
  initialize(language: 'typescript' | 'javascript'): void {
    if (language === 'typescript') {
      this.parser.setLanguage(TypeScript.typescript);
    } else {
      this.parser.setLanguage(JavaScript);
    }
  }
  
  /**
   * Parse code and return AST
   */
  parse(code: string, language: 'typescript' | 'javascript' = 'typescript'): Parser.Tree {
    this.initialize(language);
    return this.parser.parse(code);
  }
  
  /**
   * Find all function calls matching a name pattern
   */
  findFunctionCalls(code: string, functionName: string): Array<{ line: number; column: number }> {
    const results: Array<{ line: number; column: number }> = [];
    const tree = this.parse(code);
    
    const walk = (node: any) => {
      // Check for call_expression nodes
      if (node.type === 'call_expression') {
        const funcNode = node.child(0);
        if (funcNode && funcNode.text === functionName) {
          const startPosition = node.startPosition;
          results.push({
            line: startPosition.row + 1,
            column: startPosition.column + 1
          });
        }
      }
      if (node.children) {
        node.children.forEach(walk);
      }
    };
    
    walk(tree.rootNode);
    return results;
  }
  
  /**
   * Extract all identifiers from code (for pattern matching)
   */
  extractIdentifiers(code: string): string[] {
    const identifiers: string[] = [];
    const tree = this.parse(code);
    
    const walk = (node: any) => {
      if (node.type === 'identifier') {
        identifiers.push(node.text);
      }
      if (node.children) {
        node.children.forEach(walk);
      }
    };
    
    walk(tree.rootNode);
    return identifiers;
  }
}

// Default tree-sitter parser instance
export const treeSitterParser = new TreeSitterParser();

// Parse suppression comments from content
function parseSuppressions(content: string): Map<number, string> {
  const suppressions = new Map<number, string>();
  const lines = content.split('\n');
  const pattern = /\/\/\s*halo-ignore(?::\s*([\w-]+(?:\s*,\s*[\w-]+)*))?/gi;
  
  lines.forEach((line, index) => {
    let match;
    while ((match = pattern.exec(line)) !== null) {
      const ruleIds = match[1] ? match[1].split(',').map((id: string) => id.trim()) : null;
      suppressions.set(index + 1, ruleIds ? ruleIds.join(',') : 'all');
    }
  });
  
  return suppressions;
}

// Check if a violation is suppressed
function isViolationSuppressed(
  violation: Violation,
  suppressions: Map<number, string>,
  globalSuppressions: Set<number>
): boolean {
  // Check same-line suppression (comment on same line as violation)
  const sameLineSuppression = suppressions.get(violation.line);
  if (sameLineSuppression) {
    if (sameLineSuppression === 'all' || sameLineSuppression.includes(violation.ruleId)) {
      return true;
    }
  }

  // Check next-line suppression (comment on line above violation)
  const prevLineSuppression = suppressions.get(violation.line - 1);
  if (prevLineSuppression) {
    if (prevLineSuppression === 'all' || prevLineSuppression.includes(violation.ruleId)) {
      return true;
    }
  }

  // Check global suppression (suppression before any code)
  if (globalSuppressions.has(violation.line)) {
    return true;
  }

  return false;
}

// COPPA Rule Definitions (Tier 1 - All 20 rules)
// Core rules
// Remediation mapping: rule ID → fixability tier + metadata
// Remediation tier spec
// Tier 1 (auto): deterministic AST transforms, no LLM
// Tier 2 (guided): LLM scaffold + developer customization
// Tier 3 (flag-only): detection + guidance docs, no code generation
const REMEDIATION_MAP: Record<string, RemediationSpec> = {
  // Tier 1 — Auto-fix (4 deterministic patterns)
  'coppa-sec-006':    { fixability: 'auto', transformType: 'url-upgrade', estimatedCost: '$0' },         // HTTP → HTTPS
  'coppa-sec-010':    { fixability: 'auto', transformType: 'remove-default', estimatedCost: '$0' },      // Remove hardcoded passwords
  'coppa-sec-015':    { fixability: 'auto', transformType: 'sanitize-input', estimatedCost: '$0' },      // XSS innerHTML → textContent
  'coppa-default-020':{ fixability: 'auto', transformType: 'set-default', estimatedCost: '$0' },         // Default profile → private

  // Tier 2 — Guided (consent flows need developer context)
  'coppa-cookies-016':{ fixability: 'guided', scaffoldId: 'consent-cookies', estimatedCost: '$0.01' },   // Cookie consent

  // Tier 2 — Guided fix (LLM scaffold + developer customization)
  'coppa-auth-001':   { fixability: 'guided', scaffoldId: 'age-gate-auth', estimatedCost: '$0.01' },     // Age gate for social login
  'coppa-data-002':   { fixability: 'guided', scaffoldId: 'pii-sanitizer', estimatedCost: '$0.01' },     // PII removal from URLs
  'coppa-retention-005':{ fixability: 'guided', scaffoldId: 'retention-policy', estimatedCost: '$0.01' }, // Data retention policy
  'coppa-audio-007':  { fixability: 'guided', scaffoldId: 'consent-audio', estimatedCost: '$0.01' },     // Parental consent for audio
  'coppa-ui-008':     { fixability: 'guided', scaffoldId: 'privacy-link', estimatedCost: '$0.01' },      // Privacy policy on registration
  'coppa-flow-009':   { fixability: 'guided', scaffoldId: 'parent-email', estimatedCost: '$0.01' },      // Parent email flow
  'coppa-bio-012':    { fixability: 'guided', scaffoldId: 'consent-biometric', estimatedCost: '$0.01' }, // Biometric consent
  'coppa-ugc-014':    { fixability: 'guided', scaffoldId: 'pii-filter', estimatedCost: '$0.01' },        // UGC PII filtering
  'coppa-analytics-018':{ fixability: 'guided', scaffoldId: 'anonymize-analytics', estimatedCost: '$0.01' }, // Analytics anonymization
  'coppa-edu-019':    { fixability: 'guided', scaffoldId: 'school-verify', estimatedCost: '$0.01' },     // School official verification

  // Tier 2 — Guided (simpler scaffolds)
  'coppa-tracking-003':{ fixability: 'guided', scaffoldId: 'remove-tracker', estimatedCost: '$0.01' },   // Ad tracker removal
  'coppa-geo-004':    { fixability: 'guided', scaffoldId: 'remove-geo', estimatedCost: '$0.01' },        // Geolocation removal
  'coppa-notif-013':  { fixability: 'guided', scaffoldId: 'consent-notif', estimatedCost: '$0.01' },     // Notification consent
  'coppa-ext-017':    { fixability: 'guided', scaffoldId: 'exit-modal', estimatedCost: '$0.01' },        // External link warning
  'coppa-ext-011':    { fixability: 'guided', scaffoldId: 'chat-moderation', estimatedCost: '$0.01' },   // Chat moderation

};

// Look up remediation spec for a rule ID
function getRemediation(ruleId: string): RemediationSpec {
  return REMEDIATION_MAP[ruleId] || { fixability: 'flag-only', estimatedCost: '$0' };
}

/**
 * COPPA_RULES: 21 active COPPA rules exported for direct reference.
 *
 * NOTE: rules.json contains 26 COPPA rules. This constant exports 21 (the original
 * COPPA rules). The 5 COPPA 2.0 rules (coppa-2-021 through coppa-2-025) are loaded
 * dynamically from rules.json and ARE active in production scans, but are not in
 * this constant because they were added later via rules.json, not hardcoded.
 *
 * Day 5 assessment (April 1, 2026):
 *   coppa-2-021 through coppa-2-024: PRODUCTION-READY (code-detectable, solid patterns)
 *   coppa-2-025: DRAFT (behavior-dependent, needs visual scanner for VPC verification)
 *
 * All 26 rules are active in scans via Priority 4 (loadBundledRulesByPack).
 * This constant is only used as a fallback when rules.json is unavailable.
 */
export const COPPA_RULES: Rule[] = [
  // ========== Rules 1-5 ==========
  {
    id: 'coppa-auth-001',
    name: 'PI Collection Via Third-Party Authentication Without VPC',
    severity: 'critical',
    description: 'Social login (Google, Facebook, Twitter) without age gating is prohibited for child-directed apps',
    patterns: [
      // JS/TS — Firebase
      /signInWithPopup\s*\(\s*\w+\s*,\s*['"](google|facebook|twitter|github)['"]/gi,
      /signInWithPopup\s*\(\s*['"](google|facebook|twitter|github)['"]/gi,
      /signInWithPopup\s*\(\s*\w+\s*,\s*\w+\s*\)/gi,
      /firebase\.auth\(\)\s*\.\s*signInWithPopup/gi,
      // JS/TS — Passport.js
      /passport\.authenticate\s*\(\s*['"](google|facebook|twitter)['"]/gi,
      // Python — django-allauth social providers config
      /SOCIALACCOUNT_PROVIDERS\s*=\s*\{[^}]*(?:google|facebook|twitter|github)/gi,
      // Python — python-social-auth backends
      /SOCIAL_AUTH_(?:GOOGLE|FACEBOOK|TWITTER|GITHUB)_(?:KEY|SECRET)/gi,
      // Python — flask-dance blueprints
      /make_(?:google|facebook|twitter|github)_blueprint\s*\(/gi,
      // Python — authlib OAuth registration
      /oauth\.register\s*\(\s*['"](?:google|facebook|twitter|github)['"]/gi,
      // Go — goth social auth providers
      /goth\.UseProviders\s*\(/gi,
      // Java — Spring Security OAuth2 login
      /\.oauth2Login\s*\(\s*\)/gi,
      // Java — Spring OAuth2 client registration
      /ClientRegistration\.withRegistrationId\s*\(\s*['"](?:google|facebook|twitter|github)['"]/gi,
      // Kotlin/Java — Firebase Android
      /Firebase\.auth\.signInWithCredential/gi,
      // Kotlin/Java — Google Sign-In Android
      /GoogleSignIn\.getClient\s*\(/gi,
      // Kotlin/Java — Facebook Login Android SDK
      /LoginManager\.getInstance\s*\(\s*\)\s*\.logIn/gi
    ],
    fixSuggestion: 'Wrap the auth call in a conditional check for user.age >= 13 or use signInWithParentEmail() for children',
    penalty: '$53,088 per violation',
    languages: ['typescript', 'javascript', 'python', 'go', 'java', 'kotlin', 'swift']
  },
  {
    id: 'coppa-data-002',
    name: 'PII Collection in URL Parameters',
    severity: 'high',
    description: 'Email, name, DOB, or phone in GET request URLs exposes PII in logs',
    patterns: [
      /(\?|&)(email|first_?name|last_?name|dob|phone|birthdate)=/gi,
      /axios\.get\s*\(\s*[`'"]https?:\/\/[^\s]*\?[^`'"]*\$\{/gi,
      /fetch\s*\(\s*[`'"]https?:\/\/[^\s]*\?[^`'"]*\$\{/gi,
      /\?[^'"`\s]*\$\{[^}]*(?:\.email|\.firstName|\.lastName|\.dob|\.phone)[^}]*\}/gi,
      // Python — requests.get with PII query params
      /requests\.get\s*\([^)]*params\s*=\s*\{[^}]*(?:email|name|phone|dob|birthdate)/gi,
      // Python — Django/Flask redirect with PII in URL
      /(?:redirect|HttpResponseRedirect)\s*\([^)]*\?[^)]*(?:email|name|phone)/gi,
      // PHP — PII in $_GET superglobal
      /\$_GET\s*\[\s*['"](?:email|first_?name|last_?name|dob|phone|birthdate)['"]\s*\]/gi,
      // Ruby — params[] with PII in GET context
      /request\.query_parameters\s*\[\s*:(?:email|name|phone|dob|birthdate)\s*\]/gi
    ],
    fixSuggestion: 'Switch to POST method and move PII to request body',
    penalty: '$53,088 per violation',
    languages: ['typescript', 'javascript', 'python', 'java', 'swift', 'php', 'ruby']
  },
  {
    id: 'coppa-tracking-003',
    name: 'Third-Party Ad Trackers',
    severity: 'critical',
    description: 'Facebook Pixel, Google Analytics, or other ad trackers without child_directed_treatment flag',
    patterns: [
      /fbq\s*\(\s*['"]init['"]/gi,
      /ga\s*\(\s*['"]create['"]/gi,
      /adsbygoogle/gi,
      /gtag\s*\(\s*['"]config['"]/gi,
      /google-analytics\.com\/analytics\.js/gi,
      // Python — Google Analytics measurement protocol
      /(?:import|from)\s+(?:google\.analytics|pyga|universal_analytics)/gi,
      // Python — Facebook pixel server-side
      /FacebookAdsApi\.init|facebook_business\.adobjects/gi,
      // PHP — Google Analytics server-side
      /(?:TheIconic\\Tracking|Rize\\UriTemplate).*(?:Analytics|Measurement)/gi,
      // PHP — wp_enqueue_script with GA/FB pixel
      /wp_enqueue_script\s*\([^)]*(?:google-analytics|gtag|fbq|facebook-pixel)/gi,
      // Ruby — Google Analytics gems
      /(?:require|gem)\s+['"](?:staccato|google-analytics-rails|gabba)['"]/gi,
      // Java/Kotlin — Firebase Analytics initialization
      /FirebaseAnalytics\.getInstance\s*\(/gi
    ],
    fixSuggestion: 'Add "child_directed_treatment": true or "restrictDataProcessing": true to SDK initialization',
    penalty: '$53,088 per violation',
    languages: ['typescript', 'javascript', 'html', 'python', 'php', 'ruby', 'java', 'kotlin']
  },
  {
    id: 'coppa-geo-004',
    name: 'Precise Geolocation Collection',
    severity: 'high',
    description: 'High-accuracy geolocation without parental consent is prohibited',
    patterns: [
      // JS/TS — browser Geolocation API
      /navigator\.geolocation\.getCurrentPosition/gi,
      /navigator\.geolocation\.watchPosition/gi,
      // Swift — CoreLocation
      /CLLocationManager\.startUpdatingLocation\(\)/gi,
      /locationServices\.requestLocation/gi,
      // Java Android — LocationManager
      /LocationManager\s*\.\s*requestLocationUpdates\s*\(/gi,
      // Java/Kotlin Android — Fused Location Provider (Google Play Services)
      /FusedLocationProviderClient|fusedLocationClient\s*\.\s*(?:requestLocationUpdates|getLastLocation|getCurrentLocation)/gi,
      // Java Android — high accuracy priority
      /LocationRequest\.create\s*\(\s*\)\s*\.\s*setPriority\s*\(\s*LocationRequest\.PRIORITY_HIGH_ACCURACY/gi,
      // Kotlin Android — LocationRequest.Builder
      /LocationRequest\.Builder\s*\(\s*Priority\.PRIORITY_HIGH_ACCURACY/gi,
      // Python — geocoder library
      /geocoder\.(?:ip|google|osm|mapquest)\s*\(/gi,
      // Python — geopy geolocators
      /(?:Nominatim|GoogleV3|Bing)\s*\([^)]*\)\s*\.(?:geocode|reverse)/gi,
      // Android manifest — fine location permission
      /android\.permission\.ACCESS_FINE_LOCATION/gi,
      // PHP — geolocation APIs
      /(?:geoip_record_by_name|geoip_country_code_by_name|maxmind)\s*\(/gi,
      // PHP — WordPress geolocation
      /WC_Geolocation::geolocate_ip|wp_geolocate/gi,
      // Ruby — Geocoder gem
      /Geocoder\.search\s*\(|geocode_by\s+:/gi,
      /reverse_geocoded_by\s+:/gi
    ],
    fixSuggestion: 'Downgrade accuracy to kCLLocationAccuracyThreeKilometers or require parental consent',
    penalty: '$53,088 per violation',
    languages: ['typescript', 'javascript', 'swift', 'kotlin', 'java', 'python', 'xml', 'php', 'ruby']
  },
  {
    id: 'coppa-retention-005',
    name: 'Missing Data Retention Policy',
    severity: 'medium',
    description: 'COPPA 2025 explicitly prohibits indefinite retention of children\'s PI. Operators must retain data only as long as reasonably necessary for the purpose collected. Schemas with PII fields must define retention periods, deletion mechanisms, and purpose limitation.',
    patterns: [
      // JS/TS — Mongoose schemas
      /new\s+Schema\s*\(\s*\{[^{}]*\}/gi,
      // Python — Django models
      /class\s+(?:User|Child|Student|Profile|Account|Member)\w*\s*\(\s*models\.Model\s*\)/gi,
      // Python — SQLAlchemy declarative models
      /class\s+(?:User|Child|Student|Profile|Account|Member)\w*\s*\(\s*(?:Base|db\.Model)\s*\)/gi,
      // Go — GORM model structs with user-related names
      /type\s+(?:User|Child|Student|Profile|Account|Member)\w*\s+struct\s*\{/gi,
      // Java/Kotlin — JPA @Entity on user-related classes
      /@Entity[\s\S]*?class\s+(?:User|Child|Student|Profile|Account|Member)/gi,
      // Kotlin — data class for user models
      /data\s+class\s+(?:User|Child|Student|Profile|Account|Member)\w*\s*\(/gi,
      // PHP — Laravel/WordPress user models
      /class\s+(?:User|Child|Student|Profile|Account|Member)\w*\s+extends\s+(?:Model|Authenticatable|WP_User)/gi,
      // Ruby — ActiveRecord user models
      /class\s+(?:User|Child|Student|Profile|Account|Member)\w*\s*<\s*(?:ApplicationRecord|ActiveRecord::Base)/gi,
      // Android — SharedPreferences/Editor storing user PII
      /(?:putString|putInt|putBoolean)\s*\(\s*['"](?:user_?(?:name|email|id|phone)|child_?(?:name|email|id|dob)|student_?(?:name|email|id)|email|phone|dob|birthdate)['"]/gi
    ],
    fixSuggestion: 'Add explicit retention period (retentionDays, expiresAt, or TTL index), deleted_at column, and document the purpose limitation for data collection per COPPA 2025 § 312.10',
    penalty: '$53,088 per violation (COPPA 2025 indefinite retention prohibition)',
    languages: ['typescript', 'javascript', 'python', 'go', 'java', 'kotlin', 'sql', 'php', 'ruby']
  },

  // ========== Rules 6-20 ==========
  
  // Rule 6: Unencrypted PII Transmission
  {
    id: 'coppa-sec-006',
    name: 'Unencrypted PII Transmission',
    severity: 'critical',
    description: 'HTTP transmission of PII exposes data in transit. All API endpoints handling personal information must use HTTPS.',
    patterns: [
      /(?!.*(?:schemas\.|w3\.org|xmlns\.|\.config|README|example\.com|localhost|127\.0\.0|\.test|\.example|\.invalid|\.local|specification|documentation|comment|\/\/\s))http:\/\/[^\s]*(\/api\/|\/login|\/user|\/register|\/profile)/gi,
      /(?!.*(?:schemas\.|w3\.org|xmlns\.|\.config|README|example\.com|localhost|127\.0\.0|\.test|\.example|\.invalid|\.local|specification|documentation|comment|\/\/\s))http:\/\/localhost:[^\s]*(\/api\/)/gi,
      /(?!.*(?:schemas\.|w3\.org|xmlns\.|\.config|README|example\.com|localhost|127\.0\.0|\.test|\.example|\.invalid|\.local|specification|documentation|comment|\/\/\s))axios\.get\s*\(\s*['"]http:\/\//gi,
      /(?!.*(?:schemas\.|w3\.org|xmlns\.|\.config|README|example\.com|localhost|127\.0\.0|\.test|\.example|\.invalid|\.local|specification|documentation|comment|\/\/\s))fetch\s*\(\s*['"]http:\/\//gi,
      /(?!.*(?:schemas\.|w3\.org|xmlns\.|\.config|README|example\.com|localhost|127\.0\.0|\.test|\.example|\.invalid|\.local|specification|documentation|comment|\/\/\s))http:\/\/[^\s]*email[^\s]*/gi,
      // Python — requests/urllib with HTTP
      /(?!.*(?:schemas\.|w3\.org|xmlns\.|\.config|README|example\.com|localhost|127\.0\.0|\.test|\.example|\.invalid|\.local|specification|documentation|comment|\/\/\s))requests\.(?:get|post)\s*\(\s*['"]http:\/\/(?!localhost)/gi,
      /(?!.*(?:schemas\.|w3\.org|xmlns\.|\.config|README|example\.com|localhost|127\.0\.0|\.test|\.example|\.invalid|\.local|specification|documentation|comment|\/\/\s))urllib\.request\.urlopen\s*\(\s*['"]http:\/\/(?!localhost)/gi,
      // PHP — HTTP API calls
      /(?!.*(?:schemas\.|w3\.org|xmlns\.|\.config|README|example\.com|localhost|127\.0\.0|\.test|\.example|\.invalid|\.local|specification|documentation|comment|\/\/\s))(?:curl_setopt|file_get_contents|wp_remote_get)\s*\([^)]*['"]http:\/\/(?!localhost)/gi,
      // Ruby — HTTP requests
      /(?!.*(?:schemas\.|w3\.org|xmlns\.|\.config|README|example\.com|localhost|127\.0\.0|\.test|\.example|\.invalid|\.local|specification|documentation|comment|\/\/\s))(?:Net::HTTP|HTTParty|Faraday)\.(?:get|post)\s*\([^)]*['"]http:\/\/(?!localhost)/gi
    ],
    fixSuggestion: 'Replace http:// with https:// for all API endpoints and resources',
    penalty: 'Security breach liability + COPPA penalties',
    languages: ['typescript', 'javascript', 'python', 'java', 'swift', 'php', 'ruby']
  },
  
  // Rule 7: Passive Audio Recording
  // Fixed  Skip audio:false, skip AudioContext (playback only), skip import-only
  {
    id: 'coppa-audio-007',
    name: 'Unauthorized Audio Recording',
    severity: 'high',
    description: 'Audio recording without explicit user consent is prohibited. COPPA 2.0 clarifies voice prints as biometric data.',
    patterns: [
      /getUserMedia\s*\(\s*\{[^}]*audio\s*:\s*true[^}]*\}/gi,
      /getUserMedia\s*\(\s*\{\s*audio\s*\}/gi,
      /getUserMedia\s*\(\s*\{\s*audio\s*,/gi,
      /AVAudioSession\s*\.\s*sharedInstance/gi,
      /AVAudioRecorder\s*\(/gi,
      /new\s+AudioRecord\s*\(/gi,
      /new\s+MediaRecorder\s*\(/gi,
      // Python — audio recording libraries
      /(?:import|from)\s+(?:pyaudio|sounddevice|speech_recognition)/gi,
      /sounddevice\.rec\s*\(/gi,
      /Recognizer\(\)\.listen/gi,
      // Java/Kotlin — Android AudioRecord
      /AudioRecord\.Builder\s*\(\s*\)/gi,
      /MediaRecorder\s*\(\s*\)\s*\.setAudioSource/gi
    ],
    fixSuggestion: 'Wrap audio recording in click handler and add parental consent check',
    penalty: '$53,088 per violation',
    languages: ['typescript', 'javascript', 'swift', 'kotlin', 'python', 'java']
  },
  
  // Rule 8: Missing Privacy Policy Link
  // Fixed  Only flag forms with registration-related fields (email, password, name, DOB)
  // Fixed Phase B: Tightened regex — word boundary after "Form" prevents registerFormat/registerOption FPs
  {
    id: 'coppa-ui-008',
    name: 'Missing Privacy Policy on Registration',
    severity: 'medium',
    description: 'Registration forms collecting PII must include a clear link to the privacy policy',
    patterns: [
      // PascalCase component names: SignUpForm, RegisterForm, RegistrationForm, CreateAccountForm
      // \b after Form prevents matching registerFormat, registerFormats, etc.
      /(?!.*(?:admin|Admin|ADMIN|educator|Educator|instructor|teacher|oauth|OAuth|lti|LTI|saml|SAML|sso|SSO|staff|moderator|enrollment|grading|assignment|syllabus|cartridge|yui|superclass|brickfield|sitepolicy|confirmation|FormattedMessage))\b(?:SignUp|Register|Registration|CreateAccount)Form\b/gi,
      // kebab-case / snake_case: sign-up-form, register_form, create-account-form
      /(?!.*(?:admin|Admin|ADMIN|educator|Educator|instructor|teacher|oauth|OAuth|lti|LTI|saml|SAML|sso|SSO|staff|moderator|enrollment|grading|assignment|syllabus|cartridge|yui|superclass|brickfield|sitepolicy|confirmation|FormattedMessage))\b(?:sign[-_]?up|register|registration|create[-_]?account)[-_]form\b/gi,
      // HTML form elements with registration-related ids/classes
      /(?!.*(?:admin|Admin|ADMIN|educator|Educator|instructor|teacher|oauth|OAuth|lti|LTI|saml|SAML|sso|SSO|staff|moderator|enrollment|grading|assignment|syllabus|cartridge|yui|superclass|brickfield|sitepolicy|confirmation|FormattedMessage))<form[^>]*(?:id|class|name)\s*=\s*["'][^"']*(?:register|signup|sign[-_]up|create[-_]account)[^"']*["']/gi,
      // Python — Django/Flask registration form classes
      /(?!.*(?:admin|Admin|ADMIN|educator|Educator|instructor|teacher|oauth|OAuth|lti|LTI|saml|SAML|sso|SSO|staff|moderator|enrollment|grading|assignment|syllabus|cartridge|yui|superclass|brickfield|sitepolicy|confirmation|FormattedMessage))class\s+(?:SignUp|Register|Registration|CreateAccount)Form\s*\(\s*(?:forms\.Form|ModelForm|FlaskForm)/gi,
      // Ruby — Rails registration routes/controllers
      /(?!.*(?:admin|Admin|ADMIN|educator|Educator|instructor|teacher|oauth|OAuth|lti|LTI|saml|SAML|sso|SSO|staff|moderator|enrollment|grading|assignment|syllabus|cartridge|yui|superclass|brickfield|sitepolicy|confirmation|FormattedMessage))def\s+(?:sign_up|register|create_account)\b/gi,
      // PHP — WordPress registration hooks
      /(?!.*(?:admin|Admin|ADMIN|educator|Educator|instructor|teacher|oauth|OAuth|lti|LTI|saml|SAML|sso|SSO|staff|moderator|enrollment|grading|assignment|syllabus|cartridge|yui|superclass|brickfield|sitepolicy|confirmation|FormattedMessage))(?:register_new_user|wp_create_user|user_register)\s*\(/gi
    ],
    fixSuggestion: 'Add <a href="/privacy">Privacy Policy</a> link to registration form footer',
    penalty: 'Compliance failure',
    languages: ['typescript', 'javascript', 'html', 'tsx', 'jsx', 'php', 'python', 'ruby']
  },
  
  // Rule 9: Contact Info Collection Without Parent Email
  {
    id: 'coppa-flow-009',
    name: 'Direct Contact Collection Without Parent Context',
    severity: 'high',
    description: 'Forms collecting child email/phone must also require parent email for consent verification',
    patterns: [
      /(child_email|student_email)\s*:\s*String/gi,
      /(child_email|student_email|kid_email)\s*=/gi,
      // Python — Django model field for child contact
      /(?:child_email|student_email|kid_email)\s*=\s*models\.(?:EmailField|CharField)/gi,
      // PHP — child email in form processing
      /\$(?:child_email|student_email|kid_email)\s*=\s*\$_(?:POST|GET|REQUEST)/gi,
      // Ruby — child contact in params or model
      /(?:child_email|student_email|kid_email)\s*=\s*params\[/gi,
      // Java/Kotlin — child email field
      /(?:private|var|val)\s+\w*\s*(?:childEmail|studentEmail|kidEmail)/gi
    ],
    fixSuggestion: 'Make parent_email required when collecting child contact information',
    penalty: '$53,088 per violation',
    languages: ['typescript', 'javascript', 'python', 'php', 'ruby', 'java', 'kotlin']
  },
  
  // Rule 10: Insecure Default Passwords
  {
    id: 'coppa-sec-010',
    is_active: false,  //W1: 100% FP (0/3 TP) — all hits are test fixture passwords, not production defaults
    name: 'Weak Default Student Passwords',
    severity: 'medium',
    description: 'Default passwords like "password", "123456", or "changeme" create security vulnerabilities',
    patterns: [
      /(password|default_pass|temp_password)\s*=\s*['"](123456|password|changeme|student|welcome)['"]/gi,
      /defaultPassword:\s*['"](123456|password|changeme)['"]/gi,
      /initialPassword:\s*['"](123456|password)['"]/gi,
      /pass\s*=\s*['"](student123|child123|default)['"]/gi
    ],
    fixSuggestion: 'Use a secure random string generator for temporary credentials',
    penalty: 'Security audit failure',
    languages: ['typescript', 'javascript', 'python', 'java', 'swift']
  },
  
  // Rule 11: Third-Party Chat Widgets
  {
    id: 'coppa-ext-011',
    name: 'Unmoderated Third-Party Chat',
    severity: 'high',
    description: 'Third-party chat widgets (Intercom, Zendesk, Drift) allow children to disclose PII freely',
    patterns: [
      /intercom\.init/gi,
      /zendesk\.init/gi,
      /drift\.init/gi,
      /(?!.*(?:help\.|support\.|docs\.|faq|knowledge.?base|status\.))<script[^>]+src=['"][^'"]*intercom/gi,
      /(?!.*(?:help\.|support\.|docs\.|faq|knowledge.?base|status\.))<script[^>]+src=['"][^'"]*(zendesk|zdassets)/gi,
      /(?!.*(?:help\.|zendesk\.com\/hc|freshdesk\.com\/support|support\.|docs\.|faq|knowledge.?base|status\.))(?:Freshdesk|FreshChat)/gi
    ],
    fixSuggestion: 'Disable chat widget for unauthenticated or under-13 users via conditional rendering',
    penalty: '$53,088 per violation',
    languages: ['typescript', 'javascript', 'html']
  },
  
  // Rule 12: Biometric Data Collection

  // Pattern matches generic terms (FaceID, TouchID, FaceDetector) without
  // distinguishing real biometric capture from SDK type definitions, AWS API
  // schemas, and vendor library code. Rebuild requires AST-level context.
  {
    id: 'coppa-bio-012',
    name: 'Biometric Data Collection',
    severity: 'critical',
    is_active: false,
    description: 'COPPA 2025 explicitly adds biometric identifiers to the definition of PI. Face recognition, voice prints, gait analysis, behavioral biometrics (keystroke dynamics, mouse movement patterns), iris/pupil scanning, and health biometric APIs all require verifiable parental consent.',
    patterns: [
      /(?:import\s+.*from\s+['"]face-api\.js['"]|require\s*\(\s*['"]face-api\.js['"]\s*\))/gi,
      /LocalAuthentication.*evaluatePolicy/gi,
      /(?:biometricAuth|BiometricAuth|biometricPrompt|BiometricPrompt)/g,
      /voicePrint|VoicePrint|voiceRecognition|VoiceRecognition|speakerVerification/g,
      /livenessCheck|LivenessCheck|livenessDetection/g,
      /FaceMatcher|FaceDetector|FaceRecognizer|FaceLandmarks/g,
      // Behavioral biometrics (COPPA 2025 expansion)
      /keystrokeDynamic|keystrokePattern|typingBiometric|keyPressAnalysis/g,
      /gaitAnalysis|gaitDetect|gaitRecognition|motionBiometric/g,
      /mouseMovementPattern|cursorTracking|behavioralBiometric/g,
      /irisScann?|pupilDetect|eyeTracking|gazeTracking/gi,
      // Health biometric APIs
      /(?:HKHealthStore|HKQuantityType|HealthKit).*(?:heartRate|stepCount|workout|sleep)/gi,
      /(?:GoogleFit|FitnessOptions|HistoryClient).*(?:heartRate|steps|calories|sleep)/gi,
      // Face detection libraries
      /(?:import|require).*(?:face-api|@mediapipe\/face|@tensorflow\/tfjs-models\/face|deepface|insightface)/gi
    ],
    fixSuggestion: 'Ensure biometric data remains local-only (on-device) or obtain verifiable parental consent per COPPA 2025. Do not transmit biometric identifiers to servers without separate parental consent.',
    penalty: '$53,088 per violation',
    languages: ['typescript', 'javascript', 'swift', 'kotlin', 'python', 'java']
  },
  
  // Rule 13: Push Notifications to Children
  // Rebuilt  removed generic Notification constructor & requestPermission (94.4% FP).
  // Now targets push subscription/registration APIs only.
  {
    id: 'coppa-notif-013',
    name: 'Direct Push Notifications Without Consent',
    severity: 'low',
    description: 'FTC declined to codify push notification restrictions in the 2025 final rule but stated it remains concerned about push notifications and engagement techniques. Best practice: gate push subscriptions behind parental consent. Maps to NGL Labs and Sendit enforcement patterns.',
    patterns: [
      /FirebaseMessaging\.subscribeToTopic(?!.*(?:vendor|node_modules|\.config|\.json|manifest|package\.json|bower|composer|Gemfile|requirements\.txt|Cargo\.toml|\.lock))/g,
      /OneSignal\.(?:promptForPushNotifications|init)\s*\((?!.*(?:vendor|node_modules|\.config|\.json|manifest|package\.json|bower|composer|Gemfile|requirements\.txt|Cargo\.toml|\.lock))/g,
      /sendPushNotification\s*\((?!.*(?:vendor|node_modules|\.config|\.json|manifest|package\.json|bower|composer|Gemfile|requirements\.txt|Cargo\.toml|\.lock))/g,
      /fcm\.send\s*\((?!.*(?:vendor|node_modules|\.config|\.json|manifest|package\.json|bower|composer|Gemfile|requirements\.txt|Cargo\.toml|\.lock))/g,
      /PushManager\.subscribe\s*\((?!.*(?:vendor|node_modules|\.config|\.json|manifest|package\.json|bower|composer|Gemfile|requirements\.txt|Cargo\.toml|\.lock))/g,
      /pushManager\.subscribe\s*\((?!.*(?:vendor|node_modules|\.config|\.json|manifest|package\.json|bower|composer|Gemfile|requirements\.txt|Cargo\.toml|\.lock))/g,
      /messaging\(\)\.getToken\s*\((?!.*(?:vendor|node_modules|\.config|\.json|manifest|package\.json|bower|composer|Gemfile|requirements\.txt|Cargo\.toml|\.lock))/g,
      /registerForPushNotifications\s*\((?!.*(?:vendor|node_modules|\.config|\.json|manifest|package\.json|bower|composer|Gemfile|requirements\.txt|Cargo\.toml|\.lock))/g,
      /addEventListener\s*\(\s*['"]push['"](?!.*(?:vendor|node_modules|\.config|\.json|manifest|package\.json|bower|composer|Gemfile|requirements\.txt|Cargo\.toml|\.lock))/g,
      /expo-notifications(?!.*(?:vendor|node_modules|\.config|\.json|manifest|package\.json|bower|composer|Gemfile|requirements\.txt|Cargo\.toml|\.lock))/g,
      /react-native-push-notification(?!.*(?:vendor|node_modules|\.config|\.json|manifest|package\.json|bower|composer|Gemfile|requirements\.txt|Cargo\.toml|\.lock))/g,
      // Python — Django push notification libraries
      /(?:import|from)\s+(?:webpush|pywebpush|push_notifications|django_push_notifications)(?!.*(?:vendor|node_modules|\.config|\.json|manifest|package\.json|bower|composer|Gemfile|requirements\.txt|Cargo\.toml|\.lock))/gi,
      /webpush\.send\s*\((?!.*(?:vendor|node_modules|\.config|\.json|manifest|package\.json|bower|composer|Gemfile|requirements\.txt|Cargo\.toml|\.lock))/gi,
      // PHP — web-push-php library
      /(?:new\s+)?WebPush\s*\(\s*\[(?!.*(?:vendor|node_modules|\.config|\.json|manifest|package\.json|bower|composer|Gemfile|requirements\.txt|Cargo\.toml|\.lock))/gi,
      /\$webPush->sendOneNotification(?!.*(?:vendor|node_modules|\.config|\.json|manifest|package\.json|bower|composer|Gemfile|requirements\.txt|Cargo\.toml|\.lock))/gi,
      // Ruby — web-push gem
      /WebPush\.payload_send\s*\((?!.*(?:vendor|node_modules|\.config|\.json|manifest|package\.json|bower|composer|Gemfile|requirements\.txt|Cargo\.toml|\.lock))/gi
    ],
    fixSuggestion: 'Gate push notification subscription behind parental dashboard setting',
    penalty: '$53,088 per violation',
    languages: ['typescript', 'javascript', 'swift', 'kotlin', 'python', 'php', 'ruby']
  },
  
  // Rule 14: Unfiltered User Generated Content
  {
    id: 'coppa-ugc-014',
    is_active: false,  //W1: 100% FP (0/3 TP) — all hits are API model property assignments, not child UGC
    name: 'UGC Upload Without PII Filter',
    severity: 'high',
    description: 'Text areas for "bio", "about me", or comments must pass through PII scrubbing before database storage',
    patterns: [
      /<textarea[^>]*placeholder=["'](?:bio|about me|describe yourself)[^"']*["']/gi,
      /user\.bio\s*=/gi,
      /aboutMe\s*=/gi,
      /(?:submit|save|post)Comment\s*\(/gi,
      /saveBio\s*\(|updateBio\s*\(/gi,
      /commentForm.*submit|handleCommentSubmit/gi
    ],
    fixSuggestion: 'Add middleware hook for PII scrubbing (regex or AWS Comprehend) before database storage',
    penalty: '$53,088 per violation',
    languages: ['typescript', 'javascript', 'python']
  },
  
  // Rule 15: XSS Vulnerabilities
  // Fixed  Skip innerHTML='', localization, CSS injection, and self-clearing patterns
  {
    id: 'coppa-sec-015',
    name: 'Reflected XSS Risk',
    severity: 'medium',
    description: 'DangerouslySetInnerHTML or innerHTML with user-controlled content creates XSS vulnerabilities',
    patterns: [
      /dangerouslySetInnerHTML\s*=\s*\{\s*\{\s*__html\s*:\s*(?!['"]<)(?!.*(?:sanitize|Sanitize|purify|Purify|DOMPurify|escape|Escape|clean|xss|JSON\.stringify|sanitized\w*|purified\w*|escaped\w*|cleaned\w*|safeHtml))[^}]*\}\s*\}/gi,
      /\.innerHTML\s*=\s*\$\{/gi,
      /\.innerHTML\s*=\s*(?!['"]?\s*['"]?\s*;)(?!['"]\s*$)(?!\s*['"]\s*$)(?!.*(?:[Ll]ocal(?:ize|ization)|styleContent|sanitize|Sanitize|purify|Purify|Escape\.html|clean|xss|sanitized\w*|purified\w*|escaped\w*|cleaned\w*|safeHtml))[^;]*\b(?:user[A-Z]\w*|userInput|user_input|formData|query|param|req\.|request\.|body\.|data\.(?:value|content|body|html|text|detail|innerHTML))\w*/gi,
      /\.html\s*\(\s*(?:userInput|user_input|req\.|request\.|params?\.)/gi,
      /v-html\s*=\s*["']?(?!.*(?:sanitize|purify|clean|escape|xss))(?:.*(?:userInput|user_input|user\.input|formData|req\.|request\.|query\.|rawHtml))/gi,
      // PHP — echo/print user input without escaping
      /echo\s+\$_(?:GET|POST|REQUEST)\s*\[/gi,
      // PHP — WordPress unescaped output
      /<?php\s+echo\s+\$(?!esc_)/gi,
      // Python — Django mark_safe with user input
      /mark_safe\s*\([^)]*(?:request|user_input|params)/gi,
      // Ruby — Rails raw() with user input
      /raw\s*\(\s*(?:params|@\w*user|@\w*input)/gi,
      // Ruby — html_safe on user input
      /(?:params|request)\[.*\]\.html_safe/gi
    ],
    fixSuggestion: 'Use standard JSX rendering or DOMPurify before setting HTML content',
    penalty: 'Security failure',
    languages: ['typescript', 'javascript', 'tsx', 'jsx', 'vue', 'php', 'python', 'ruby']
  },
  
  // Rule 16: Missing Cookie Consent
  // Fixed  Only flag tracking/PII cookies, not functional preferences (theme, view mode)
  {
    id: 'coppa-cookies-016',
    name: 'Missing Cookie Notice',
    severity: 'low',
    description: 'Cookies or localStorage storing tracking data or PII requires a consent banner',
    patterns: [
      // JS/TS — browser APIs
      /document\.cookie\s*=\s*[^;]*(?:user|email|name|token|session|track|id|uid|analytics)/gi,
      /localStorage\.setItem\s*\(\s*['"][^'"]*(?:user|email|token|session|track|auth|login|id|uid|analytics)[^'"]*['"]/gi,
      /sessionStorage\.setItem\s*\(\s*['"][^'"]*(?:user|email|token|session|track|auth|login|id|uid|analytics)[^'"]*['"]/gi,
      // Python — Flask/Django response.set_cookie()
      /\.set_cookie\s*\(\s*['"][^'"]*(?:user|email|token|session|track|auth|login|uid|analytics)[^'"]*['"]/gi,
      // Go — net/http SetCookie
      /http\.SetCookie\s*\(\s*\w+\s*,\s*&http\.Cookie\s*\{/gi,
      // Java/Kotlin — HttpServletResponse.addCookie
      /\.addCookie\s*\(\s*new\s+Cookie\s*\(/gi,
      // Java/Kotlin — Spring ResponseCookie
      /ResponseCookie\.from\s*\(/gi,
      // Generic — any language setting cookies with PII field names
      /(?:set_cookie|SetCookie|addCookie|add_cookie)\s*\([^)]*(?:user|email|token|session|track|auth|uid|analytics)/gi,
      // PHP — setcookie() with PII
      /setcookie\s*\(\s*['"][^'"]*(?:user|email|token|track|auth|uid|analytics)[^'"]*['"]/gi,
      // PHP — WordPress set_transient with PII
      /set_transient\s*\(\s*['"][^'"]*(?:user|email|auth)[^'"]*['"]/gi,
      // Ruby — Rails cookies[] with PII
      /cookies\s*\[\s*:(?:user|email|token|session|track|auth|uid|analytics)\s*\]/gi
    ],
    fixSuggestion: 'Add a cookie consent banner component before setting tracking or PII cookies',
    penalty: 'Compliance warning',
    languages: ['typescript', 'javascript', 'python', 'go', 'java', 'kotlin', 'php', 'ruby']
  },
  
  // Rule 17: External Links to Non-Child-Safe Sites
  // Fixed  Exclude privacy/TOS links, mailto, and common safe targets
  {
    id: 'coppa-ext-017',
    name: 'Unwarned External Links',
    severity: 'medium',
    description: 'External links in child-facing views should trigger a "You are leaving..." modal',
    patterns: [
      /(?!.*(?:admin|Admin|ADMIN|educator|Educator|instructor|teacher|i18n|locale|translation|locales?\/|lang\/|messages\.|translations\.|bundle))<a[^>]+href=["']https?:\/\/(?!.*(?:privacy|terms|legal|tos|policy|consent|support|help|docs|documentation))[^"']+["'][^>]*target=["']_blank["'][^>]*>/gi,
      /(?!.*(?:admin|Admin|ADMIN|educator|Educator|instructor|teacher|i18n|locale|translation|locales?\/|lang\/|messages\.|translations\.|bundle))window\.open\s*\(\s*['"]https?:\/\/(?!.*(?:privacy|terms|legal|tos|policy))/gi
    ],
    fixSuggestion: 'Wrap external links in SafeLink component with warning modal',
    penalty: 'Warning',
    languages: ['typescript', 'javascript', 'html', 'tsx', 'jsx']
  },
  
  // Rule 18: Analytics User ID Mapping
  {
    id: 'coppa-analytics-018',
    name: 'Mapping PII to Analytics User IDs',
    severity: 'high',
    description: 'Passing email, name, or phone to analytics.identify() exposes PII to third parties',
    patterns: [
      // JS/TS — client-side analytics SDKs
      /analytics\.identify\s*\([^)]*email/gi,
      /mixpanel\.identify.*email/gi,
      /segment\.identify.*email/gi,
      /amplitude\.identify.*email/gi,
      /identify\s*\(\s*\{[^}]*(?:email|name|phone)[^}]*\}/gi,
      // Python — Segment analytics-python
      /analytics\.identify\s*\(\s*\w+\s*,\s*\{[^}]*(?:email|name|phone)/gi,
      // Python — Mixpanel people_set with PII
      /mp\.people_set\s*\([^)]*(?:email|\$email|name|phone)/gi,
      // Go — Segment analytics-go Identify with PII
      /analytics\.Enqueue\s*\(\s*analytics\.Identify\s*\{[^}]*(?:Email|Name|Phone)/gi,
      // Java/Kotlin — Amplitude setUserId with PII
      /Amplitude\.getInstance\s*\(\s*\)\s*\.setUserId\s*\([^)]*email/gi,
      // Java/Kotlin — Mixpanel identify with email
      /MixpanelAPI\.\w*identify\s*\([^)]*email/gi,
      // Java/Kotlin — Firebase Analytics with PII
      /FirebaseAnalytics\.setUserId\s*\([^)]*(?:email|name)/gi,
      // Generic — setUserId with email across languages
      /(?:setUserId|set_user_id)\s*\([^)]*(?:email|\.name|phone)/gi
    ],
    fixSuggestion: 'Hash user ID and omit email/name from analytics payload',
    penalty: '$53,088 per violation',
    languages: ['typescript', 'javascript', 'python', 'go', 'java', 'kotlin']
  },
  
  // Rule 19: School Official Consent Bypass
  // Fixed  Tightened patterns to match actual auth/registration flows only
  {
    id: 'coppa-edu-019',
    is_active: false,
    name: 'Missing Teacher/School Verification',
    severity: 'medium',
    description: 'Teacher accounts using generic email (@gmail.com) bypass "School Official" consent exception',
    patterns: [
      /(?:teacher|educator)(?:Sign[Uu]p|[Rr]egist(?:er|ration))\s*(?:\(|=|:)/gi,
      /createTeacherAccount|registerTeacher|teacherAuth/gi,
      /role\s*(?:=|:)\s*['"]teacher['"].*(?:@gmail|@yahoo|@hotmail)/gi,
      /isTeacher\s*&&\s*!.*\.edu/gi
    ],
    fixSuggestion: 'Restrict teacher sign-ups to verified EDU domains or require manual approval',
    penalty: 'Loss of School Official consent status',
    languages: ['typescript', 'javascript', 'python']
  },
  
  // Rule 20: Default Privacy Settings Public
  {
    id: 'coppa-default-020',
    is_active: false,
    name: 'Default Public Profile Visibility',
    severity: 'critical',
    description: 'Default profile visibility must be private. COPPA 2.0 requires privacy by design.',
    patterns: [
      /isProfileVisible:\s*true/gi,
      /visibility:\s*['"]public['"]/gi,
      /defaultPrivacy:\s*['"]public['"]/gi,
      /isPublic:\s*true[^}]*(profile|User)/gi,
      /profileVisibility\s*=\s*['"]?(?:public|Public)['"]?/gi
    ],
    fixSuggestion: 'Change default visibility to "private" or false',
    penalty: '$53,088 per violation',
    languages: ['typescript', 'javascript', 'python', 'swift']
  },

  // Rule 21: Targeted Advertising Without Separate Consent (COPPA 2025)
  {
    id: 'coppa-ads-021',
    name: 'Targeted Advertising Without Separate Consent',
    severity: 'critical',
    description: 'COPPA 2025 requires separate, specific opt-in consent before collecting children\'s PI for targeted advertising. Marketing consent cannot be bundled with general terms acceptance. Ad SDK initialization without a distinct consent flow is a violation.',
    patterns: [
      // Google AdMob
      /(?:import|require).*(?:google-mobile-ads|@react-native-firebase\/admob|react-native-admob)/gi,
      /(?:GADMobileAds|GADRequest|GADBannerView|GADInterstitial)\.\w+/gi,
      /MobileAds\.initialize|AdRequest\.Builder|AdView|InterstitialAd\.load/gi,
      // Meta Audience Network
      /(?:FBAudienceNetwork|FBAdView|FBInterstitialAd|FBNativeAd)/gi,
      /(?:import|require).*(?:react-native-fbads|@react-native-community\/fbads)/gi,
      // Unity Ads
      /UnityAds\.(?:initialize|show|load)|import\s+UnityAds/gi,
      // IronSource
      /IronSource\.(?:init|showRewardedVideo|loadInterstitial)|import\s+IronSource/gi,
      // AppLovin
      /AppLovin\.(?:initialize|showAd)|import.*AppLovinSDK/gi,
      // Chartboost
      /Chartboost\.(?:start|showInterstitial|cacheInterstitial)/gi,
      // AdColony
      /AdColony\.(?:configure|requestInterstitial)/gi,
      // Vungle
      /Vungle\.(?:init|playAd|loadAd)/gi,
      // MoPub
      /mopub\.(?:loadBanner|loadInterstitial)|MoPubInterstitial/gi
    ],
    fixSuggestion: 'Implement a separate, specific opt-in consent flow for advertising before initializing ad SDKs. Marketing consent must NOT be bundled with general terms acceptance. Use age-gated ad experiences or contextual-only advertising for children under 13.',
    penalty: '$53,088 per violation (COPPA 2025 separate advertising consent requirement)',
    languages: ['typescript', 'javascript', 'swift', 'kotlin', 'java', 'python']
  }
];

// Additional rule packs (Ethical Design, AI Audit, AU Safety by Design, etc.)
// are available with a Pro license key. See https://runhalo.dev/pricing

// .haloignore file parser
export interface IgnoreConfig {
  /** File glob patterns to ignore entirely */
  ignoredFiles: string[];
  /** Global rule suppressions (rule ID → true) */
  globalRuleSuppressions: Set<string>;
  /** Per-file rule suppressions (filePath → Set of rule IDs) */
  fileRuleSuppressions: Map<string, Set<string>>;
}

/**
 * Parse a .haloignore file content
 *
 * Format:
 *   # comment
 *   path/to/file.ts          — ignore entire file
 *   **\/*.test.ts              — glob pattern to ignore files
 *   rule:coppa-auth-001       — globally suppress a rule
 *   src/auth.ts:coppa-auth-001 — suppress rule in specific file
 */
export function parseHaloignore(content: string): IgnoreConfig {
  const config: IgnoreConfig = {
    ignoredFiles: [],
    globalRuleSuppressions: new Set(),
    fileRuleSuppressions: new Map()
  };

  const lines = content.split('\n');
  for (const raw of lines) {
    const line = raw.trim();
    if (!line || line.startsWith('#')) continue;

    if (line.startsWith('rule:')) {
      // Global rule suppression: rule:coppa-auth-001
      const ruleId = line.slice(5).trim();
      if (ruleId) config.globalRuleSuppressions.add(ruleId);
    } else if (line.includes(':coppa-')) {
      // Per-file rule suppression: src/auth.ts:coppa-auth-001
      const colonIdx = line.indexOf(':coppa-');
      const filePath = line.slice(0, colonIdx).trim();
      const ruleId = line.slice(colonIdx + 1).trim();
      if (filePath && ruleId) {
        if (!config.fileRuleSuppressions.has(filePath)) {
          config.fileRuleSuppressions.set(filePath, new Set());
        }
        config.fileRuleSuppressions.get(filePath)!.add(ruleId);
      }
    } else {
      // File glob pattern
      config.ignoredFiles.push(line);
    }
  }

  return config;
}

/**
 *  Check if a file path is in a vendored/third-party library directory.
 * Vendor files are auto-suppressed to eliminate false positives from code the project doesn't control.
 */
export function isVendorPath(filePath: string): boolean {
  const normalized = filePath.replace(/\\/g, '/');
  return /(^|\/)node_modules\//.test(normalized) ||
    /(^|\/)vendor\//.test(normalized) ||
    /(^|\/)bower_components\//.test(normalized) ||
    /(^|\/)third[_-]?party\//.test(normalized) ||
    /(^|\/)\.bundle\//.test(normalized) ||
    /(^|\/)Pods\//.test(normalized) ||
    /(^|\/)external\//.test(normalized) ||
    /(^|\/)deps\//.test(normalized) ||
    /(^|\/)\.yarn\//.test(normalized) ||
    /(^|\/)\.pnpm\//.test(normalized) ||
    // Minified files are almost always vendored/built
    /[.\-]min\.(js|css)$/.test(normalized) ||
    /\.bundle\.js$/.test(normalized) ||
    // Well-known vendored library directories (catches lib/google2-service/, lib/aws-sdk/, etc.)
    /(^|\/)lib\/(google[^/]*|aws[^/]*|yui[^/]*|php[^/]*|jquery[^/]*|bootstrap[^/]*|tinymce[^/]*|h5p[^/]*|firebase[^/]*|simplepie[^/]*|tcpdf[^/]*|guzzle[^/]*|psr[^/]*|font-?awesome[^/]*)\//i.test(normalized) ||
    // H5P vendored libraries (stored under h5p/h5plib/, not lib/)
    /(^|\/)h5plib\//.test(normalized);
}

/**
 *  Check if a file path is in a documentation generator output directory.
 * Doc generator templates and output contain external links, code examples, etc. that are
 * developer-facing, not child-facing content. Flagging these is a false positive.
 */
export function isDocGeneratorPath(filePath: string): boolean {
  const normalized = filePath.replace(/\\/g, '/');
  return /(^|\/)(?:jsdoc|typedoc|apidoc|javadoc|doxygen|sphinx|_build|_static)(?:\/|\.)/i.test(normalized) ||
    // Documentation template files
    /(?:^|\/)(?:jsdoc|typedoc|apidoc)\.(?:html|hbs|tmpl|ejs)$/i.test(normalized) ||
    // Generated API docs
    /(^|\/)(?:docs?\/(?:api|generated|reference|build))\//i.test(normalized) ||
    // Sphinx build output
    /(^|\/)_build\/html\//i.test(normalized) ||
    // Common doc generator config files with template content
    /(?:^|\/)\.jsdoc\.(?:json|js)$/i.test(normalized) ||
    /(?:^|\/)typedoc\.json$/i.test(normalized);
}

/**
 * Check if a file should be ignored based on .haloignore config
 */
export function shouldIgnoreFile(filePath: string, config: IgnoreConfig): boolean {
  const normalized = filePath.replace(/\\/g, '/');
  for (const pattern of config.ignoredFiles) {
    if (minimatch(normalized, pattern)) return true;
  }
  return false;
}

/**
 * Check if a violation should be ignored based on .haloignore config
 */
export function shouldIgnoreViolation(violation: Violation, config: IgnoreConfig): boolean {
  // Global rule suppression
  if (config.globalRuleSuppressions.has(violation.ruleId)) return true;

  // Per-file rule suppression
  const normalized = violation.filePath.replace(/\\/g, '/');
  const fileSuppressions = config.fileRuleSuppressions.get(normalized);
  if (fileSuppressions?.has(violation.ruleId)) return true;

  return false;
}

/**
 * Simple glob matching (supports * and **)
 */
function minimatch(filePath: string, pattern: string): boolean {
  // Convert glob to regex
  const regexStr = pattern
    .replace(/\./g, '\\.')
    .replace(/\*\*/g, '{{GLOBSTAR}}')
    .replace(/\*/g, '[^/]*')
    .replace(/\{\{GLOBSTAR\}\}/g, '.*');
  const regex = new RegExp(`^${regexStr}$`);
  return regex.test(filePath);
}

// Engine configuration
export interface EngineConfig {
  includePatterns?: string[];
  excludePatterns?: string[];
  rules?: string[];
  severityFilter?: Severity[];
  suppressions?: {
    enabled: boolean;
    commentPattern?: string;
  };
  includeSuppressed?: boolean;
  rulesPath?: string;  // Path to YAML rules file
  ignoreConfig?: IgnoreConfig;  // .haloignore config
  projectDomains?: string[];  // Own-domain patterns to exclude from ext-017 (e.g., ['classroomio.com', 'scratch.mit.edu'])
  packs?: string[];        // Pack IDs to load from rules.json (e.g. ['coppa'])
  loadedRules?: Rule[];    // Pre-loaded rules (from CLI API fetch or external source)

  framework?: string;      // Framework ID for allowlisting (e.g., "nextjs", "django", "rails")
  astAnalysis?: boolean;   // Enable AST-based analysis for reduced false positives
  historicalFPRates?: Record<string, number>;  // Per-rule FP rates for ContextAnalyzer
  suppressionRates?: Record<string, number>;   // Per-rule suppression rates for ContextAnalyzer
}

// Scan result
export interface ScanResult {
  filePath: string;
  violations: Violation[];
  suppressedViolations?: Violation[];
  scannedAt: string;
  totalViolations: number;
  suppressedCount: number;
}

// Engine class
export class HaloEngine {
  private config: EngineConfig;
  private rules: Rule[];
  private treeSitter: TreeSitterParser;
  private astEngine: ASTRuleEngine;
  private contextAnalyzer: ContextAnalyzer;

  constructor(config: EngineConfig = {}) {
    this.config = config;
    this.treeSitter = new TreeSitterParser();
    this.astEngine = new ASTRuleEngine();
    this.contextAnalyzer = new ContextAnalyzer({
      framework: config.framework,
      historicalFPRates: config.historicalFPRates,
      suppressionRates: config.suppressionRates,
    });

    // Rule loading priority chain:
    // 1. config.loadedRules — pre-compiled rules from CLI API fetch
    // 2. config.rulesPath — YAML file (legacy)
    // 3. config.packs — load from bundled rules.json filtered by pack
    // 4. Default — Halo 2.0: load ALL packs from bundled rules.json

    if (config.loadedRules && config.loadedRules.length > 0) {
      // Priority 1: Pre-loaded rules (from CLI API fetch or external source)
      this.rules = config.loadedRules;
    } else if (config.rulesPath) {
      // Priority 2: YAML file (legacy)
      const yamlRules = loadRulesFromYAML(config.rulesPath);
      this.rules = yamlRules.length > 0 ? yamlRules : COPPA_RULES;
    } else if (config.packs) {
      // Priority 3: Load from bundled rules.json by pack IDs
      const jsonRules = this.loadBundledRulesByPack(config.packs);
      this.rules = jsonRules.length > 0 ? jsonRules : COPPA_RULES;
    } else {
      // Priority 4 (Halo 2.0): Load ALL packs from bundled rules.json
      // COPPA rules active in free tier. AI Review Board handles precision.
      const resolvedPacks = HaloEngine.resolvePacks(config);
      const jsonRules = this.loadBundledRulesByPack(resolvedPacks);
      this.rules = jsonRules.length > 0 ? jsonRules : COPPA_RULES;
    }


    // Static list ensures rules are disabled regardless of source (API, cache, bundled JSON, hardcoded).
    // is_active flag handles hardcoded rules; DISABLED_RULE_IDS handles all sources.

    // DISABLE: zero GT entries, cannot validate precision
    // CUT (to proposed tier): zero GT entries, pattern too broad for production
    // ── Halo 2.0 (W2): ALL rules active as loose pre-filters ──
    // Precision is handled by Tier 3 (AI Review Board), not by disabling rules.
    // Previously-disabled rules are now active. The AI layer handles false positive
    // elimination via two-agent consensus, graduated patterns, and enforcement context.
    // See: Halo 2.0 Architecture doc for rationale.
    //
    // Rules with known regex limitations (W1 analysis):
    //   High-FP (AI handles): coppa-sec-015, coppa-bio-012, coppa-sec-006,
    //     coppa-ext-017, coppa-sec-010, coppa-ugc-014
    this.rules = this.rules.filter(r => r.is_active !== false);

    // Filter by specific rule IDs if provided (e.g., config.rules = ['coppa-auth-001'])
    if (config.rules && config.rules.length > 0) {
      this.rules = this.rules.filter(r => config.rules!.includes(r.id));
    }

    if (config.severityFilter) {
      this.rules = this.rules.filter(r => config.severityFilter!.includes(r.severity));
    }
  }

  /**
   * Load rules from the bundled rules.json file, filtered by pack IDs.
   * Falls back to empty array if rules.json not found.
   */
  private loadBundledRulesByPack(packIds: string[]): Rule[] {
    try {
      const jsonPath = path.resolve(__dirname, '..', 'rules', 'rules.json');
      return loadRulesFromJSONByPack(jsonPath, packIds);
    } catch (error) {
      return [];
    }
  }

  /**
   * Resolve pack IDs from config.
   * Halo 2.0: defaults to ALL packs (loose pre-filter for AI Review Board).
   * Legacy boolean flags still supported for backward compatibility.
   */
  static resolvePacks(config: EngineConfig): string[] {
    if (config.packs) return config.packs;

    // Halo 2.0 default: all packs active
    return [...ALL_PACK_IDS];
  }

  /**
   * Get the tree-sitter parser for advanced AST analysis
   */
  getParser(): TreeSitterParser {
    return this.treeSitter;
  }

  /**
   * Scan using tree-sitter AST analysis (advanced mode)
   */
  scanFileWithAST(filePath: string, content: string, language: 'typescript' | 'javascript' = 'typescript'): Violation[] {
    // First get regex-based violations
    let violations = this.scanFile(filePath, content);


    try {
      const tree = this.treeSitter.parse(content, language);

      // Legacy  AST-based detection for social login (signInWithPopup)
      const functionCalls = this.treeSitter.findFunctionCalls(content, 'signInWithPopup');
      for (const call of functionCalls) {
        const exists = violations.some(v =>
          v.ruleId === 'coppa-auth-001' &&
          v.line === call.line
        );
        if (!exists) {
          const authRule = this.rules.find(r => r.id === 'coppa-auth-001') || COPPA_RULES.find(r => r.id === 'coppa-auth-001');
          if (authRule) {
            violations.push({
              ruleId: 'coppa-auth-001',
              ruleName: authRule.name,
              severity: authRule.severity,
              filePath,
              line: call.line,
              column: call.column,
              message: `${authRule.name}: Detected via AST analysis`,
              codeSnippet: content.split('\n')[call.line - 1]?.trim() || '',
              fixSuggestion: authRule.fixSuggestion,
              penalty: authRule.penalty,
              category: extractCategory('coppa-auth-001'),
              language: detectLanguage(filePath),
              matchType: 'ast',
              fixability: getRemediation('coppa-auth-001').fixability,
              remediation: getRemediation('coppa-auth-001'),
              authorityTier: (authRule as any).authority_tier || undefined,
              regulatorySource: (authRule as any).knowledge?.regulatory_source || undefined,
            });
          }
        }
      }


      if (this.config.astAnalysis !== false) {
        for (const violation of violations) {
          try {
            const astResult = this.astEngine.analyzeViolationWithPath(
              violation.ruleId,
              filePath,
              content,
              {
                ruleId: violation.ruleId,
                line: violation.line,
                column: violation.column,
                codeSnippet: violation.codeSnippet,
              },
              tree,
            );

            violation.astVerdict = astResult.verdict;
            violation.astConfidence = astResult.confidence;
            violation.astReason = astResult.reason;
            // Update matchType to reflect AST involvement
            if (astResult.verdict !== 'regex_only') {
              violation.matchType = 'hybrid';
            }
          } catch (ruleError) {
            violation.astVerdict = 'regex_only';
            violation.astConfidence = 0;
            violation.astReason = 'AST analysis failed for this violation';
          }
        }
      }
    } catch (error) {
      // If AST parsing fails entirely (typically a native tree-sitter
      // ABI mismatch on a Node version the prebuilt binary doesn't
      // support), fall back to regex-only. Record the failure once
      // at process scope so the CLI can render a single up-front
      // degraded-mode banner; callers shouldn't have to grep stderr
      // to know the run is degraded.
      if (astAvailableFlag) {
        astAvailableFlag = false;
        astFailureMessage = error instanceof Error ? error.message : String(error);
        console.warn('AST parsing unavailable; running in regex-only mode for this process. Cause:', astFailureMessage);
      }
      for (const v of violations) {
        v.astVerdict = 'regex_only';
        v.astConfidence = 0;
      }
    }


    // No longer needed here — scanFile() already filtered/downgraded regex violations.
    // AST-added violations (e.g. signInWithPopup → auth-001) are not in any framework profile.


    const violationInputs: ViolationInput[] = violations.map(v => ({
      ruleId: v.ruleId,
      severity: v.severity,
      line: v.line,
      column: v.column,
      codeSnippet: v.codeSnippet,
      astVerdict: v.astVerdict,
      astConfidence: v.astConfidence,
      astReason: v.astReason,
      frameworkSuppressed: v.frameworkSuppressed,
    }));

    const confidenceResults = this.contextAnalyzer.analyzeFile(
      violationInputs,
      filePath,
      content,
    );

    for (let i = 0; i < violations.length; i++) {
      const result = confidenceResults.get(i);
      if (result) {
        violations[i].confidence = result.confidence;
        violations[i].confidenceInterpretation = result.interpretation;
        violations[i].confidenceReason = result.reason;
      }
    }

    return violations;
  }

  /**
   * Get the ignore config (if any)
   */
  getIgnoreConfig(): IgnoreConfig | undefined {
    return this.config.ignoreConfig;
  }

  /**
   * Scan a single file for violations
   */
  scanFile(filePath: string, content: string): Violation[] {
    // Check .haloignore — skip entire file if matched
    const ignoreConfig = this.config.ignoreConfig;
    if (ignoreConfig && shouldIgnoreFile(filePath, ignoreConfig)) {
      return [];
    }


    // These produce massive false positives (84% FP rate on Moodle — all from lib/, vendor/ paths)
    if (isVendorPath(filePath)) {
      return [];
    }


    // JSDoc templates, Sphinx output, TypeDoc pages — developer tools, not child-facing content
    if (isDocGeneratorPath(filePath)) {
      return [];
    }

    let violations: Violation[] = [];
    const lines = content.split('\n');


    // All heuristics are now in classifyFile() for consistency and future Option C upgrade
    const normalizedPath = filePath.replace(/\\/g, '/');
    const classification = classifyFile(filePath, content.substring(0, 3000));


    // (Django migrations, build output, type definitions, CI configs)
    if (classification.shouldSkip) {
      return [];
    }

    // Rules that commonly false-positive in test/fixture/mock files
    const TEST_FP_RULES = new Set([
      'coppa-sec-010',      // Weak passwords in test fixtures
      'coppa-tracking-003', // Analytics snippets in test mocks
      'coppa-auth-001',     // Auth patterns in test helpers
      'coppa-sec-015',      // XSS patterns in security test cases
      'coppa-sec-006',
    ]);

    // Rules that should be suppressed in consent/compliance implementation files
    // These rules flag patterns that are REQUIRED in consent implementations
    const CONSENT_SUPPRESSED_RULES = new Set([
      'coppa-cookies-016',  // Cookie consent banners MUST set cookies to track consent state
      'coppa-tracking-003', // Consent management may reference tracking to gate it
      'coppa-data-002',     // Consent flows may reference PII fields to declare collection scope
    ]);

    // Rules that FP in admin/instructor code — these patterns exist for managing users, not collecting child data
    const ADMIN_FP_RULES = new Set([
      'coppa-flow-009',     // Contact collection: admin reading existing user emails is not child contact flow
      'coppa-data-002',     // PII in URLs: admin user lookup endpoints are internal tools
      'coppa-ui-008',       // Registration forms: admin user management is not child registration
      'coppa-sec-006',
    ]);

    // ── Graduated Heuristics ──────────────────────────────────
    // Auto-promoted pattern — previously flagged as false positive.
    // Each pattern was dismissed consistently by the AI reviewer and passed
    // MVP validation criteria (min dismissals, min confidence, zero false confirmations).
    // These replace AI review calls with deterministic checks: zero cost, instant execution.

    // Graduated pattern: admin-path
    // 193 consistent dismissals | avg confidence 9.0/10 | 0 false confirmations
    // AI reviewer cost per check: ~$0.014 → now $0.00
    const GRADUATED_ADMIN_RULES = new Set<string>([
      // Additional rule IDs added with Pro license packs
    ]);

    // Graduated pattern: test-file
    // 27 consistent dismissals | avg confidence 9.0/10 | 0 false confirmations
    const GRADUATED_TEST_RULES = new Set<string>([
      // Additional rule IDs added with Pro license packs
    ]);

    // Parse suppression comments
    const suppressions = parseSuppressions(content);

    // Track lines with global suppressions (at top of file)
    const globalSuppressionLines = new Set<number>();
    for (const [line, rules] of suppressions.entries()) {
      if (rules === 'all') {
        globalSuppressionLines.add(line);
      }
    }

    for (const rule of this.rules) {

      if (rule.languages && rule.languages.length > 0 && classification.language !== 'unknown') {
        if (!rule.languages.includes(classification.language)) {
          continue;
        }
      }

      //13a: Skip rules that commonly FP in test/fixture/mock/factory files
      if ((classification.isTest || classification.isMockOrFactory || classification.isFixtureOrSeed) && TEST_FP_RULES.has(rule.id)) {
        continue;
      }


      if (classification.isStorybook) {
        continue;
      }


      // Consent forms MUST set cookies, reference tracking, and handle PII — that's the solution, not the problem
      if (classification.isConsent && CONSENT_SUPPRESSED_RULES.has(rule.id)) {
        continue;
      }


      // Admin functions managing existing user data are not child-facing contact collection flows
      if (classification.isAdmin && ADMIN_FP_RULES.has(rule.id)) {
        continue;
      }

      //Graduated: admin-path — admin files are not child-facing
      // (Promoted from AI Review Board: 193 dismissals, confidence 9.0)
      if (classification.isAdmin && GRADUATED_ADMIN_RULES.has(rule.id)) {
        continue;
      }


      if ((classification.isAdmin || classification.isVendor) && rule.id === 'AU-SBD-002') {
        continue;
      }

      //Graduated: test-file — test/fixture files are not production code
      // (Promoted from AI Review Board: 27 dismissals, confidence 9.0)
      if ((classification.isTest || classification.isMockOrFactory || classification.isFixtureOrSeed) && GRADUATED_TEST_RULES.has(rule.id)) {
        continue;
      }

      // Special handling for coppa-retention-005: skip if schema has retention fields
      if (rule.id === 'coppa-retention-005') {

        // OpenEdX convention: `.. no_pii:` in class docstring means model contains no PII
        // These models have User FKs but only store non-PII data (e.g., calendar sync preferences)
        if (classification.language === 'python' && /(?:\.\.\s*no_pii\s*:|#\s*no[_-]?pii\b|no_pii\s*=\s*True)/i.test(content)) {
          continue;
        }

        // Check if the content has retention-related fields
        const hasRetention = /deletedAt|deleted_at|expires|TTL|retention|paranoid|expiration/i.test(content);
        if (!hasRetention) {
          // Continue with normal pattern matching
        } else {
          // Has retention fields - still scan but be more careful
          // Only flag schemas that clearly lack retention
          const schemaMatches = content.match(/new\s+Schema\s*\(\s*\{[^{}]*\}/gi);
          if (schemaMatches) {
            for (const schemaMatch of schemaMatches) {
              // Check if this specific schema has retention
              const surroundingContext = content.substring(
                Math.max(0, content.indexOf(schemaMatch) - 50),
                Math.min(content.length, content.indexOf(schemaMatch) + schemaMatch.length + 200)
              );
              if (/deletedAt|deleted_at|expires|TTL|paranoid/i.test(surroundingContext)) {
                continue; // Skip this match - has retention
              }
              // This schema lacks retention - fall through to normal pattern matching
            }
          }
        }
      }
      
      for (const pattern of rule.patterns) {
        // Reset regex state
        pattern.lastIndex = 0;
        
        // Find all matches in content
        let match;
        while ((match = pattern.exec(content)) !== null) {
          // Calculate line and column from match position
          const beforeMatch = content.substring(0, match.index);
          const lineNumber = (beforeMatch.match(/\n/g) || []).length + 1;
          
          // Get the line content for snippet
          const lineIndex = lineNumber - 1;
          const lineContent = lines[lineIndex] || '';
          
          // Calculate column
          const lastNewline = beforeMatch.lastIndexOf('\n');
          const column = match.index - lastNewline;

          // Skip if the line is a comment (// or /* or * or <!-- or #)
          const trimmedLine = lineContent.trim();
          if (trimmedLine.startsWith('//') || trimmedLine.startsWith('/*') || trimmedLine.startsWith('*') || trimmedLine.startsWith('<!--') || trimmedLine.startsWith('#')) {
            // Exception: don't skip halo-ignore comments (those are suppression directives)
            if (!trimmedLine.includes('halo-ignore')) {
              continue;
            }
          }

          // For coppa-ext-017: skip matches that are own-domain links
          // Check both match[0] (captures multi-line <a> tags) and lineContent (captures window.open)
          if (rule.id === 'coppa-ext-017' && this.config.projectDomains?.length) {
            const checkText = (match[0] + ' ' + lineContent).toLowerCase();
            const isOwnDomain = this.config.projectDomains.some(domain =>
              checkText.includes(domain.toLowerCase())
            );
            if (isOwnDomain) continue;
          }


          // <!--[if lte IE 9]> ... <![endif]--> are deprecated browser banners, not child-facing links
          // Seen in: OpenEdX templates with Chrome/Firefox download links for IE users
          if (rule.id === 'coppa-ext-017') {
            // Check if we're inside an IE conditional comment block
            const beforeMatch = content.substring(Math.max(0, match.index - 500), match.index);
            const afterMatch = content.substring(match.index, Math.min(content.length, match.index + 500));
            if (/<!--\s*\[if\s+(?:lt|lte|gt|gte|!)?\s*IE/i.test(beforeMatch) && /\[endif\]\s*-->/i.test(afterMatch)) {
              continue;
            }
            // Also skip if the line itself contains the IE conditional pattern
            if (/<!--\s*\[if\s+(?:lt|lte|gt|gte|!)?\s*IE/i.test(lineContent)) {
              continue;
            }
          }

          //16: For coppa-sec-006: skip reserved/example/documentation/standards domains
          // These are IANA-reserved, standards bodies, or universally used in documentation and are never real endpoints
          // Require http:// before the domain to avoid matching domains in email addresses etc.
          if (rule.id === 'coppa-sec-006') {
            const checkText = (match[0] + ' ' + lineContent).toLowerCase();
            if (/http:\/\/(www\.)?(example\.(com|org|net)|localhost(:\d|\/|['"\s]|$)|127\.0\.0\.1|0\.0\.0\.0|\[::1\]|httpbin\.org|jsonplaceholder\.typicode\.com|testserver(\.com)?[\/\s'"]|imsglobal\.org|flickr\.com|w3\.org)/.test(checkText)) {
              continue;
            }

            if (/devstack/.test(checkText)) {
              continue;
            }

            // These are namespace declarations, not API endpoints
            if (/\.xsd['"\s,)]|\/xmlns\/|\/schema\//.test(checkText)) {
              continue;
            }
          }


          // Y.Escape.html(), DOMPurify.sanitize(), etc. show the developer IS handling XSS
          if (rule.id === 'coppa-sec-015') {
            if (/(?:escape\.html|dompurify|sanitize|purify|xss|\.clean\()\s*\(?/i.test(lineContent)) {
              continue;
            }
            // Also skip if the value is a sanitized variable
            if (/(?:sanitized|purified|escaped|cleaned|safeHtml)\w*/i.test(lineContent)) {
              continue;
            }
          }

          // For coppa-ui-008: skip admin/vendor/widget registration contexts
          // These are admin/developer-facing forms or vendor widget methods, not child-facing registration
          if (rule.id === 'coppa-ui-008') {
            if (/cartridge[_-]?registration|brickfield|registersetting|tool_configure|sitepolicy|registration_confirmation/i.test(lineContent) ||
                /cartridge[_-]?registration|brickfield|registersetting|yui2?[-_]container|sitepolicy|registration_confirmation/i.test(normalizedPath)) {
              continue;
            }
            // YUI widget method calls (registerForm is a container widget method, not child registration)
            if (/\.(registerForm|subscribe)\s*\(/i.test(lineContent) && /superclass|subscribe|\.call\b/i.test(lineContent)) {
              continue;
            }
          }


          // Files/code implementing cookie consent are the solution, not the problem
          if (rule.id === 'coppa-cookies-016') {
            // File path patterns: cookie-consent.js, consent-banner.js, etc.
            if (/cookie[_-]?(consent|law|notice|banner|policy|popup|preferences)/i.test(normalizedPath) ||
                /(?:consent|privacy|data[_-]?protection)[_-]?(?:banner|popup|modal|notice|manager)/i.test(normalizedPath)) {
              continue;
            }
            // Line-level: function/variable names showing consent management intent
            if (/(?:handleConsent|acceptCookies|declineCookies|cookieBanner|consentManager|cookiePreferences|saveCookiePreferences|showCookieNotice|getCookieConsent|setCookieConsent)\s*[=(]/i.test(lineContent) ||
                /(?:accept|decline|preferences|banner|consent)\s*[=:]/i.test(lineContent) && /cookie/i.test(lineContent)) {
              continue;
            }
            // Import-level: known consent management libraries
            if (/(?:require|import).*(?:cookieconsent|react-cookie-consent|onetrust|cookiebot|osano|cookie-notice|cookie-consent)/i.test(content.substring(0, 2000))) {
              continue;
            }

            // Seen in: Moodle submit.js — code that removes cookies flagged as if setting them
            if (/max[_-]?age\s*[=:]\s*['"]?\s*(-\d+|0)\b/i.test(lineContent) ||
                /expires\s*[=:]\s*['"]?\s*(?:Thu,\s*01\s+Jan\s+1970|new\s+Date\s*\(\s*0\s*\))/i.test(lineContent) ||
                /new\s+Date\s*\(\s*0\s*\)/.test(lineContent) && /expires/i.test(lineContent) ||
                /=\s*['"]?\s*deleted\b/i.test(lineContent) ||
                /(?:delete|remove|clear|expire|destroy)[_-]?cookie/i.test(lineContent) ||
                /\.cookie\s*=\s*['"][^'"]*;\s*expires\s*=\s*['"]?\s*Thu,\s*01/i.test(lineContent)) {
              continue;
            }
          }

          // Check if this violation already exists (avoid duplicates)
          const exists = violations.some(v =>
            v.ruleId === rule.id &&
            v.line === lineNumber &&
            v.filePath === filePath
          );

          if (!exists) {
            // Check suppression
            const suppressed = this.config.suppressions?.enabled !== false && 
                             isViolationSuppressed(
                               { ruleId: rule.id, line: lineNumber, ruleName: '', severity: 'low', filePath: '', column: 0, message: '', codeSnippet: '', fixSuggestion: '' } as Violation,
                               suppressions,
                               globalSuppressionLines
                             );
            
            // Get suppression comment if suppressed
            let suppressionComment: string | undefined;
            if (suppressed) {
              suppressionComment = suppressions.get(lineNumber);
            }


            const contextStart = Math.max(0, lineNumber - 6); // lineNumber is 1-indexed
            const contextEnd = Math.min(lines.length, lineNumber + 5);
            const surroundingLines = lines.slice(contextStart, contextEnd).map((l, i) => {
              const ln = contextStart + i + 1;
              const marker = ln === lineNumber ? '>>>' : '   ';
              return `${marker} ${ln}: ${l}`;
            });

            violations.push({
              ruleId: rule.id,
              ruleName: rule.name,
              severity: rule.severity,
              filePath,
              line: lineNumber,
              column: column + 1,
              message: `${rule.name}: ${rule.description}`,
              codeSnippet: lineContent.trim().substring(0, 100).replace(/[\x00-\x08\x0B\x0C\x0E-\x1F\x7F]/g, ''),
              fixSuggestion: rule.fixSuggestion,
              penalty: rule.penalty,
              suppressed: suppressed || false,
              suppressionComment,
              category: extractCategory(rule.id),
              language: detectLanguage(filePath),
              matchType: 'regex',
              fixability: getRemediation(rule.id).fixability,
              remediation: getRemediation(rule.id),
              authorityTier: rule.authority_tier || undefined,
              regulatorySource: rule.knowledge?.regulatory_source || undefined,

              surroundingCode: surroundingLines.join('\n'),
              fileMetadata: {
                language: classification.language,
                isVendor: classification.isVendor,
                isTest: classification.isTest,
                isAdmin: classification.isAdmin,
                isConsent: classification.isConsent,
                isDocGenerator: classification.isDocGenerator,
                detectedFramework: this.config.framework,

                isMock: classification.isMockOrFactory,
                isFixture: classification.isFixtureOrSeed,
                isCIConfig: classification.isCIConfig,
                isBuildOutput: classification.isBuildOutput,
                isTypeDefinition: classification.isTypeDefinition,
                isStorybook: classification.isStorybook,
              },
            });
          }
        }
      }
    }


    // Previously this only ran inside scanFileWithAST() for JS/TS files.
    if (this.config.framework) {
      const result = applyFrameworkOverrides(violations, this.config.framework);
      violations = result.violations;
    }


    // Filter suppressed if configured
    if (this.config.suppressions?.enabled !== false && !this.config.includeSuppressed) {
      const unsuppressed = violations.filter(v => !v.suppressed);
      // Apply .haloignore per-violation filtering
      if (ignoreConfig) {
        return unsuppressed.filter(v => !shouldIgnoreViolation(v, ignoreConfig));
      }
      return unsuppressed;
    }

    // Even when showing suppressed, still apply .haloignore
    if (ignoreConfig) {
      return violations.filter(v => !shouldIgnoreViolation(v, ignoreConfig));
    }

    return violations;
  }

  /**
   * Get all rules
   */
  getRules(): Rule[] {
    return this.rules;
  }

  /**
   * Get rule by ID
   */
  getRule(ruleId: string): Rule | undefined {
    return this.rules.find(r => r.id === ruleId) || COPPA_RULES.find(r => r.id === ruleId);
  }
  
  /**
   * Explain a rule (for MCP)
   */
  explainRule(ruleId: string): string {
    const rule = this.getRule(ruleId);
    if (!rule) {
      return `Rule ${ruleId} not found.`;
    }
    
    return `
Rule: ${rule.id}
Name: ${rule.name}
Severity: ${rule.severity.toUpperCase()}

Description: ${rule.description}

COPPA Reference: ${rule.penalty}

Fix Suggestion: ${rule.fixSuggestion}

Supported Languages: ${rule.languages.join(', ')}
    `.trim();
  }
  
  /**
   * Get fix suggestion for a rule (for MCP)
   */
  getFixSuggestion(ruleId: string): string {
    const rule = this.getRule(ruleId);
    if (!rule) {
      return `Rule ${ruleId} not found.`;
    }
    
    return rule.fixSuggestion;
  }
}

// Export REMEDIATION_MAP and getRemediation for fixer + external consumers
export { REMEDIATION_MAP, getRemediation };

// Re-export fix engine
export { FixEngine } from './fixer';
export type { FixResult, FileFixResult, FixOptions } from './fixer';
export {
  transformUrlUpgrade,
  transformRemoveDefault,
  transformSanitizeInput,
  transformSetDefault,
} from './fixer';

// Re-export compliance score engine (Track 3)
export { ComplianceScoreEngine } from './scoring';
export type { ComplianceScoreResult, LetterGrade } from './scoring';

// Re-export scaffold engine (P2)
export { ScaffoldEngine } from './scaffold-engine';
export type { GuidedFixResult, GuidedFixSummary } from './scaffold-engine';
export { detectFramework } from './framework-detect';
export type { Framework, FrameworkDetectionResult } from './framework-detect';
export { SCAFFOLD_REGISTRY } from './scaffolds/index';
export type { ScaffoldTemplate, ScaffoldFile } from './scaffolds/index';

// SDK Intelligence
export { detectSDKsFromPackageJson, generateSDKContext, detectSDKs, SDK_RISK_DATABASE } from './sdk-intelligence';
export type { SDKRiskProfile, DetectedSDK } from './sdk-intelligence';

// Tier Context — 4-tier feature gating
export { createTierContext, resolveTierFromKey, getUpgradeCTA, getTierComparison, TIER_LIMITS, TIER_FEATURES, TIER_DISPLAY_NAMES } from './tier-context';
export type { HaloTier, TierLimits, TierFeatures, TierContext } from './tier-context';

// COPPA 2.0 Countdown + Regulatory Deadlines
export { getCoppaCountdown, formatCoppaCountdownCLI, formatCoppaCountdownMarkdown, formatCoppaCountdownPDF, COPPA_2_ENFORCEMENT_DATE, PENALTY_PER_VIOLATION_PER_DAY, getNextDeadline, formatRegulatoryCountdownCLI, formatDollarExposure } from './coppa-countdown';
export type { CoppaCountdown, RegulatoryDeadline } from './coppa-countdown';

// Import Graph — cross-file import tracking for AI Review Board context
export { extractImports, buildImportGraph, summarizeImportGraph, formatImportGraphForReview } from './import-graph';
export type { ImportEdge, ImportGraph, ImportGraphSummary } from './import-graph';

// Compliance Drift — detect posture changes between scans
export { analyzeDrift, formatDriftCLI, formatDriftNotification } from './compliance-drift';
export type { ScanSnapshot, DriftAlert, DriftAnalysis } from './compliance-drift';

// Custom rules (Enterprise)
export { loadHaloConfig, compileCustomRules } from './custom-rules';
export type { CustomRule, HaloConfig } from './custom-rules';

export default HaloEngine;
