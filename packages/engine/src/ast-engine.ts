/**
 * Halo AST Rule Engine
 *
 * Takes a parsed tree-sitter AST + rule ID and returns an AST-based verdict
 * that supplements the regex scanner. AST analysis can suppress false positives
 * (e.g., a Schema that already has TTL) or confirm true positives with higher
 * confidence.
 *
 * 10 rule analyzers for JS/TS.
 * HARD SCOPE: Single-file only (via DataFlowTracer).
 */

import Parser from 'tree-sitter';
import { ScopeAnalyzer, ScopeContext, LineContext } from './scope-analyzer';
import { DataFlowTracer } from './data-flow-tracer';

// ---------------------------------------------------------------------------
// Types
// ---------------------------------------------------------------------------

export type ASTVerdict = 'confirmed' | 'suppressed' | 'regex_only';

export interface ASTResult {
  /** Whether the violation is confirmed, suppressed, or not analyzable by AST */
  verdict: ASTVerdict;
  /** Confidence in the verdict: 0.0 to 1.0 */
  confidence: number;
  /** Human-readable reason for the verdict */
  reason?: string;
}

/** Minimal violation info needed for AST analysis */
export interface ViolationInfo {
  ruleId: string;
  line: number;
  column: number;
  codeSnippet: string;
}

// ---------------------------------------------------------------------------
// AST walker helper
// ---------------------------------------------------------------------------

function walk(node: Parser.SyntaxNode | null, visitor: (n: Parser.SyntaxNode) => void): void {
  if (!node) return;
  visitor(node);
  for (let i = 0; i < node.childCount; i++) {
    walk(node.child(i), visitor);
  }
}

// ---------------------------------------------------------------------------
// ASTRuleEngine
// ---------------------------------------------------------------------------

export class ASTRuleEngine {
  private scopeAnalyzer: ScopeAnalyzer;

  constructor() {
    this.scopeAnalyzer = new ScopeAnalyzer();
  }

  /**
   * Analyze a regex-detected violation using AST context.
   *
   * @param ruleId   - The COPPA/ethical rule ID
   * @param content  - Full file content
   * @param violation - The violation from the regex scanner
   * @param tree     - Parsed tree-sitter AST
   * @returns ASTResult with verdict, confidence, and reason
   */
  analyzeViolation(
    ruleId: string,
    content: string,
    violation: ViolationInfo,
    tree: Parser.Tree,
  ): ASTResult {
    // First check scope-level suppressions that apply to all rules
    const scopeContext = this.scopeAnalyzer.analyzeFile(
      violation.codeSnippet, // We don't have filePath here, but snippet gives some hint
      content,
      tree,
    );

    // Type definition files should suppress most violations
    if (scopeContext.isTypeDefinition) {
      return {
        verdict: 'suppressed',
        confidence: 0.95,
        reason: 'File is primarily type definitions — no runtime behavior',
      };
    }

    // Test files get suppressed for most rules (test code isn't deployed)
    if (scopeContext.isTestFile) {
      return {
        verdict: 'suppressed',
        confidence: 0.90,
        reason: 'Violation is in a test file — not deployed to production',
      };
    }

    // Route to rule-specific analyzer
    const analyzer = this.getAnalyzer(ruleId);
    if (!analyzer) {
      return { verdict: 'regex_only', confidence: 0, reason: 'No AST analyzer for this rule' };
    }

    return analyzer(tree, content, violation, scopeContext);
  }

  /**
   * Analyze a violation with a known file path (used from scanFileWithAST integration).
   * This version passes the real file path for scope analysis.
   */
  analyzeViolationWithPath(
    ruleId: string,
    filePath: string,
    content: string,
    violation: ViolationInfo,
    tree: Parser.Tree,
  ): ASTResult {
    const scopeContext = this.scopeAnalyzer.analyzeFile(filePath, content, tree);

    if (scopeContext.isTypeDefinition) {
      return {
        verdict: 'suppressed',
        confidence: 0.95,
        reason: 'File is primarily type definitions — no runtime behavior',
      };
    }

    if (scopeContext.isTestFile) {
      return {
        verdict: 'suppressed',
        confidence: 0.90,
        reason: 'Violation is in a test file — not deployed to production',
      };
    }

    const analyzer = this.getAnalyzer(ruleId);
    if (!analyzer) {
      return { verdict: 'regex_only', confidence: 0, reason: 'No AST analyzer for this rule' };
    }

    return analyzer(tree, content, violation, scopeContext);
  }

  // -------------------------------------------------------------------------
  // Analyzer dispatch
  // -------------------------------------------------------------------------

  private getAnalyzer(
    ruleId: string,
  ): ((tree: Parser.Tree, content: string, v: ViolationInfo, scope: ScopeContext) => ASTResult) | null {
    const analyzers: Record<string, (tree: Parser.Tree, content: string, v: ViolationInfo, scope: ScopeContext) => ASTResult> = {
      'coppa-tracking-003': this.analyzeTracking003.bind(this),
      'coppa-retention-005': this.analyzeRetention005.bind(this),
      'coppa-ext-017': this.analyzeExtLinks017.bind(this),
      'coppa-sec-015': this.analyzeXSS015.bind(this),
      'coppa-auth-001': this.analyzeAuth001.bind(this),
      'coppa-ui-008': this.analyzeUI008.bind(this),
      'coppa-ugc-014': this.analyzeUGC014.bind(this),
      'coppa-flow-009': this.analyzeFlow009.bind(this),
      'coppa-cookies-016': this.analyzeCookies016.bind(this),
    };

    return analyzers[ruleId] ?? null;
  }

  // -------------------------------------------------------------------------
  // Rule: coppa-tracking-003 — Ad Trackers
  // Check CallExpression args for child_directed_treatment
  // -------------------------------------------------------------------------

  private analyzeTracking003(
    tree: Parser.Tree,
    content: string,
    violation: ViolationInfo,
    _scope: ScopeContext,
  ): ASTResult {
    const tracer = new DataFlowTracer(tree);

    // Check if the call at the violation line includes child_directed_treatment
    if (tracer.hasArgument(violation.line, 'child_directed_treatment')) {
      return {
        verdict: 'suppressed',
        confidence: 0.92,
        reason: 'child_directed_treatment flag detected in tracker initialization arguments',
      };
    }

    // Also check for restrictDataProcessing
    if (tracer.hasArgument(violation.line, 'restrictDataProcessing')) {
      return {
        verdict: 'suppressed',
        confidence: 0.88,
        reason: 'restrictDataProcessing flag detected in tracker initialization',
      };
    }

    // Check nearby context (within 5 lines) for the flag being set separately
    const nearbyCalls = tracer.findNearbyCallExpressions(violation.line, 5);
    for (const call of nearbyCalls) {
      if (call.name.includes('set') || call.name.includes('config')) {
        if (tracer.hasArgument(call.line, 'child_directed_treatment') ||
            tracer.hasArgument(call.line, 'restrictDataProcessing')) {
          return {
            verdict: 'suppressed',
            confidence: 0.85,
            reason: 'Child-directed flag configured near tracker initialization',
          };
        }
      }
    }

    // Check if this is in a config file (likely setting it up correctly)
    if (_scope.isConfigFile) {
      return {
        verdict: 'confirmed',
        confidence: 0.70,
        reason: 'Tracker in config file without child_directed_treatment — may need flag',
      };
    }

    return {
      verdict: 'confirmed',
      confidence: 0.85,
      reason: 'No child_directed_treatment or restrictDataProcessing flag found in tracker setup',
    };
  }

  // -------------------------------------------------------------------------
  // Rule: coppa-retention-005 — Missing Data Retention
  // Find Schema constructors, trace for TTL/expires/deletedAt in scope
  // -------------------------------------------------------------------------

  private analyzeRetention005(
    tree: Parser.Tree,
    content: string,
    violation: ViolationInfo,
    _scope: ScopeContext,
  ): ASTResult {
    const tracer = new DataFlowTracer(tree);
    const retentionFields = [
      'TTL', 'ttl', 'expires', 'expireAt', 'expireAfterSeconds',
      'deletedAt', 'deleted_at', 'expiresAt', 'expires_at',
      'retention', 'paranoid', 'expiration', 'retentionPolicy',
    ];

    // Check if there's a retention-related property in the same scope
    if (tracer.hasPropertyInScope(violation.line, retentionFields)) {
      return {
        verdict: 'suppressed',
        confidence: 0.90,
        reason: 'Data retention field (TTL/expires/deletedAt) found in same scope as schema',
      };
    }

    // Also check if there's a Mongoose index with expires
    const scope = tracer.getEnclosingScope(violation.line);
    if (scope) {
      const scopeContent = content.split('\n').slice(scope.startLine - 1, scope.endLine).join('\n');
      if (/\.index\s*\([^)]*expires/i.test(scopeContent) ||
          /expireAfterSeconds/i.test(scopeContent)) {
        return {
          verdict: 'suppressed',
          confidence: 0.90,
          reason: 'Mongoose TTL index (expireAfterSeconds) found in schema scope',
        };
      }
    }

    // Check config files — schema definitions in config might be handled elsewhere
    if (_scope.isConfigFile) {
      return {
        verdict: 'confirmed',
        confidence: 0.50,
        reason: 'Schema in config file — retention may be handled at application level',
      };
    }

    return {
      verdict: 'confirmed',
      confidence: 0.80,
      reason: 'No TTL, expires, or deletedAt field found in schema scope',
    };
  }

  // -------------------------------------------------------------------------
  // Rule: coppa-ext-017 — External Links
  // Parse JSX <a> elements, check for rel="noopener" and interstitial warning
  // -------------------------------------------------------------------------

  private analyzeExtLinks017(
    tree: Parser.Tree,
    content: string,
    violation: ViolationInfo,
    _scope: ScopeContext,
  ): ASTResult {
    // Admin routes don't need external link warnings
    if (_scope.isAdminRoute) {
      return {
        verdict: 'suppressed',
        confidence: 0.88,
        reason: 'External link in admin route — admin users don\'t need child-safety warnings',
      };
    }

    const lines = content.split('\n');
    const violationLine = lines[violation.line - 1] || '';

    // Check if the link is wrapped in a SafeLink or ExternalLink component
    // Look at surrounding lines for component wrappers
    const contextStart = Math.max(0, violation.line - 4);
    const contextEnd = Math.min(lines.length, violation.line + 3);
    const context = lines.slice(contextStart, contextEnd).join('\n');

    if (/SafeLink|ExternalLink|InterstitialLink|WarningLink/i.test(context)) {
      return {
        verdict: 'suppressed',
        confidence: 0.90,
        reason: 'External link wrapped in safety/warning component',
      };
    }

    // Check if the link has rel="noopener noreferrer" (partial mitigation)
    if (/rel\s*=\s*["'][^"']*noopener[^"']*["']/i.test(violationLine)) {
      return {
        verdict: 'confirmed',
        confidence: 0.60,
        reason: 'External link has noopener but no interstitial warning for child users',
      };
    }

    return {
      verdict: 'confirmed',
      confidence: 0.80,
      reason: 'External link with target="_blank" lacks child-facing exit warning',
    };
  }

  // -------------------------------------------------------------------------
  // Rule: coppa-sec-015 — XSS Risk (dangerouslySetInnerHTML / innerHTML)
  // Trace data flow for sanitization (DOMPurify, sanitize-html, xss, etc.)
  // -------------------------------------------------------------------------

  private analyzeXSS015(
    tree: Parser.Tree,
    content: string,
    violation: ViolationInfo,
    _scope: ScopeContext,
  ): ASTResult {
    const tracer = new DataFlowTracer(tree);

    // Check if the value passes through a sanitization function
    const sanitizers = [
      'DOMPurify.sanitize', 'sanitize', 'xss', 'sanitizeHtml',
      'purify', 'clean', 'bleach', 'escape', 'escapeHtml',
      'he.encode', 'encode', 'striptags', 'htmlEncode',
    ];

    if (tracer.passesThrough(violation.line, sanitizers)) {
      return {
        verdict: 'suppressed',
        confidence: 0.92,
        reason: 'Value passes through sanitization function before HTML insertion',
      };
    }

    // Check if the file imports a sanitizer
    const importLines = content.split('\n').slice(0, 20).join('\n');
    const hasSanitizerImport = /import.*(?:DOMPurify|sanitize-html|xss|isomorphic-dompurify|dompurify)/i.test(importLines);

    if (hasSanitizerImport) {
      // File imports a sanitizer — check if it's used in the same function scope
      const scope = tracer.getEnclosingScope(violation.line);
      if (scope) {
        const scopeContent = content.split('\n').slice(scope.startLine - 1, scope.endLine).join('\n');
        if (/sanitize|purify|clean|escape/i.test(scopeContent)) {
          return {
            verdict: 'suppressed',
            confidence: 0.85,
            reason: 'Sanitizer imported and used in same function scope',
          };
        }
      }

      // Sanitizer imported but might not be used at this violation point
      return {
        verdict: 'confirmed',
        confidence: 0.55,
        reason: 'Sanitizer library imported but not clearly applied to this HTML insertion',
      };
    }

    // Check for static content (string literal)
    const violationLine = content.split('\n')[violation.line - 1] || '';
    if (/dangerouslySetInnerHTML\s*=\s*\{\s*\{\s*__html\s*:\s*['"`]/.test(violationLine)) {
      return {
        verdict: 'suppressed',
        confidence: 0.95,
        reason: 'innerHTML set with static string literal — no XSS vector',
      };
    }

    return {
      verdict: 'confirmed',
      confidence: 0.85,
      reason: 'No sanitization detected before HTML content insertion',
    };
  }

  // -------------------------------------------------------------------------
  // Rule: coppa-auth-001 — Social Login Without Age Gate
  // Check for age verification wrapper around signInWithPopup
  // -------------------------------------------------------------------------

  private analyzeAuth001(
    tree: Parser.Tree,
    content: string,
    violation: ViolationInfo,
    _scope: ScopeContext,
  ): ASTResult {
    const tracer = new DataFlowTracer(tree);

    // Check the enclosing function scope for age-gating patterns
    const scope = tracer.getEnclosingScope(violation.line);
    if (scope) {
      const scopeContent = content.split('\n').slice(scope.startLine - 1, scope.endLine).join('\n');

      // Look for age check patterns
      const agePatterns = [
        /age\s*>=?\s*13/,
        /age\s*>\s*12/,
        /isMinor/i,
        /isChild/i,
        /ageGate/i,
        /age_gate/i,
        /verifyAge/i,
        /checkAge/i,
        /parentalConsent/i,
        /parental_consent/i,
        /isOver13/i,
        /isAdult/i,
      ];

      if (agePatterns.some(p => p.test(scopeContent))) {
        return {
          verdict: 'suppressed',
          confidence: 0.88,
          reason: 'Age verification check found in same function scope as social login',
        };
      }
    }

    // Check if there's a parent context with age gate (look 10 lines up)
    const contextStart = Math.max(0, violation.line - 11);
    const contextContent = content.split('\n').slice(contextStart, violation.line).join('\n');
    if (/age\s*>=?\s*13|isMinor|ageGate|verifyAge|parentalConsent/i.test(contextContent)) {
      return {
        verdict: 'suppressed',
        confidence: 0.80,
        reason: 'Age verification found in preceding context',
      };
    }

    return {
      verdict: 'confirmed',
      confidence: 0.85,
      reason: 'Social login without age gate verification in scope',
    };
  }

  // -------------------------------------------------------------------------
  // Rule: coppa-ui-008 — Missing Privacy Policy on Registration
  // Walk JSX tree for privacy/terms child components
  // -------------------------------------------------------------------------

  private analyzeUI008(
    tree: Parser.Tree,
    content: string,
    violation: ViolationInfo,
    _scope: ScopeContext,
  ): ASTResult {
    const tracer = new DataFlowTracer(tree);

    // Check the enclosing scope (likely a component) for privacy-related elements
    const scope = tracer.getEnclosingScope(violation.line);
    if (!scope) {
      // If no enclosing scope, check the whole file
      return this.checkPrivacyInContent(content, violation);
    }

    const scopeContent = content.split('\n').slice(scope.startLine - 1, scope.endLine).join('\n');

    // Look for privacy policy references in the component
    const privacyPatterns = [
      /privacy/i,
      /PrivacyPolicy/,
      /privacy-policy/i,
      /terms.*service/i,
      /TermsOfService/,
      /terms-of-service/i,
      /href\s*=\s*["'][^"']*privacy/i,
      /href\s*=\s*["'][^"']*terms/i,
      /<PrivacyLink/,
      /<TermsLink/,
      /PrivacyCheckbox/,
      /AcceptTerms/,
    ];

    if (privacyPatterns.some(p => p.test(scopeContent))) {
      return {
        verdict: 'suppressed',
        confidence: 0.88,
        reason: 'Privacy policy / terms of service link found in registration component',
      };
    }

    return {
      verdict: 'confirmed',
      confidence: 0.75,
      reason: 'Registration form lacks visible privacy policy link in component scope',
    };
  }

  private checkPrivacyInContent(content: string, violation: ViolationInfo): ASTResult {
    // Check a wider window (50 lines around violation)
    const lines = content.split('\n');
    const start = Math.max(0, violation.line - 25);
    const end = Math.min(lines.length, violation.line + 25);
    const window = lines.slice(start, end).join('\n');

    if (/privacy|PrivacyPolicy|terms.*service|TermsOfService/i.test(window)) {
      return {
        verdict: 'suppressed',
        confidence: 0.75,
        reason: 'Privacy/terms reference found near registration form',
      };
    }

    return {
      verdict: 'confirmed',
      confidence: 0.70,
      reason: 'No privacy policy reference found near registration form',
    };
  }

  // -------------------------------------------------------------------------
  // Rule: coppa-ugc-014 — UGC Upload Without PII Filter
  // Find submit functions, check for moderation/scrubbing calls in body
  // -------------------------------------------------------------------------

  private analyzeUGC014(
    tree: Parser.Tree,
    content: string,
    violation: ViolationInfo,
    _scope: ScopeContext,
  ): ASTResult {
    const tracer = new DataFlowTracer(tree);

    // Check the enclosing function for moderation/filter calls
    const scope = tracer.getEnclosingScope(violation.line);
    if (scope) {
      const scopeLines = content.split('\n').slice(scope.startLine - 1, scope.endLine);
      // Strip single-line comments to avoid false matches (e.g., "// Todo: add filter")
      const scopeContent = scopeLines
        .map(line => line.replace(/\/\/.*$/, '').replace(/\/\*.*?\*\//g, ''))
        .join('\n');

      const moderationPatterns = [
        /scrub|filter|sanitize|moderate|moderation/i,
        /piiFilter|PIIFilter|pii_filter/,
        /contentFilter|ContentFilter/,
        /comprehend|rekognition|detect_pii/i,
        /removePII|stripPII|redact/i,
        /textModeration|contentModeration/i,
        /profanityFilter|wordFilter/i,
      ];

      if (moderationPatterns.some(p => p.test(scopeContent))) {
        return {
          verdict: 'suppressed',
          confidence: 0.88,
          reason: 'PII scrubbing / content moderation found in submit handler',
        };
      }
    }

    // Check if the data passes through a filter before the submission point
    const filterFunctions = [
      'scrubPII', 'filterPII', 'sanitize', 'moderate', 'contentFilter',
      'textFilter', 'piiFilter', 'redact', 'filterContent',
    ];

    if (tracer.passesThrough(violation.line, filterFunctions)) {
      return {
        verdict: 'suppressed',
        confidence: 0.85,
        reason: 'UGC content passes through PII filter before storage',
      };
    }

    return {
      verdict: 'confirmed',
      confidence: 0.80,
      reason: 'No PII scrubbing or content moderation detected in submit handler',
    };
  }

  // -------------------------------------------------------------------------
  // Rule: coppa-flow-009 — Child Contact Collection
  // Distinguish InterfaceDeclaration vs VariableDeclaration
  // -------------------------------------------------------------------------

  private analyzeFlow009(
    tree: Parser.Tree,
    content: string,
    violation: ViolationInfo,
    _scope: ScopeContext,
  ): ASTResult {
    // Check line context — if we're in an interface declaration, it's a type
    // definition, not actual data collection
    const lineContext = this.scopeAnalyzer.analyzeLineContext(violation.line, tree);

    if (lineContext.inInterfaceDecl) {
      return {
        verdict: 'suppressed',
        confidence: 0.92,
        reason: 'child_email is in a TypeScript interface declaration — defines shape, not collection',
      };
    }

    // Check if the line is a type alias or similar type-level construct
    const violationLine = content.split('\n')[violation.line - 1] || '';
    if (/^\s*(export\s+)?(type|interface)\s/.test(violationLine)) {
      return {
        verdict: 'suppressed',
        confidence: 0.90,
        reason: 'child_email is in a type/interface definition — not runtime collection',
      };
    }

    // Check if there's a parent_email variable in the same scope (any context)
    const tracer = new DataFlowTracer(tree);
    const parentEmailVars = [
      'parent_email', 'parentEmail', 'guardian_email', 'guardianEmail',
      'parent_contact', 'parentContact', 'guardian_contact', 'guardianContact',
    ];

    // Use AST-aware variable detection (DataFlowTracer improvement)
    if (tracer.hasVariableInScope(violation.line, parentEmailVars)) {
      return {
        verdict: 'suppressed',
        confidence: 0.85,
        reason: 'Parent/guardian email also collected in same scope — consent flow likely in place',
      };
    }

    // Fallback: also check via regex on enclosing scope content
    const scope = tracer.getEnclosingScope(violation.line);
    if (scope) {
      const scopeContent = content.split('\n').slice(scope.startLine - 1, scope.endLine).join('\n');
      if (/parent_email|parentEmail|guardian_email|guardianEmail/i.test(scopeContent)) {
        return {
          verdict: 'suppressed',
          confidence: 0.85,
          reason: 'Parent/guardian email also collected in same scope — consent flow likely in place',
        };
      }
    }

    return {
      verdict: 'confirmed',
      confidence: 0.80,
      reason: 'Child contact information collected without visible parent consent flow',
    };
  }

  // -------------------------------------------------------------------------
  // Rule: coppa-cookies-016 — Missing Cookie Notice
  // Check setItem() key for PII vs preference strings
  // -------------------------------------------------------------------------

  private analyzeCookies016(
    tree: Parser.Tree,
    content: string,
    violation: ViolationInfo,
    _scope: ScopeContext,
  ): ASTResult {
    const violationLine = content.split('\n')[violation.line - 1] || '';

    // Check if this is setting a preference cookie (not PII/tracking)
    const preferencePatterns = [
      /theme|darkMode|dark_mode|colorScheme|color_scheme/i,
      /locale|language|lang|i18n/i,
      /viewMode|view_mode|layout|sidebar/i,
      /consent|cookieConsent|cookie_consent/i,
      /preference|pref|setting/i,
    ];

    if (preferencePatterns.some(p => p.test(violationLine))) {
      return {
        verdict: 'suppressed',
        confidence: 0.90,
        reason: 'Cookie stores user preference (theme/locale/layout) — not PII or tracking',
      };
    }

    // Check if there's a cookie consent check before this setItem
    const tracer = new DataFlowTracer(tree);
    const scope = tracer.getEnclosingScope(violation.line);
    if (scope) {
      const scopeContent = content.split('\n').slice(scope.startLine - 1, scope.endLine).join('\n');
      if (/consent|hasConsent|cookieConsent|getCookieConsent/i.test(scopeContent)) {
        return {
          verdict: 'suppressed',
          confidence: 0.85,
          reason: 'Cookie consent check found in same scope as storage operation',
        };
      }
    }

    // If it's clearly tracking/PII storage, confirm
    const trackingPatterns = [
      /analytics|track|pixel|fbq|ga\(|gtag/i,
      /userId|user_id|sessionId|session_id/i,
      /email|phone|name|dob|birthdate/i,
    ];

    if (trackingPatterns.some(p => p.test(violationLine))) {
      return {
        verdict: 'confirmed',
        confidence: 0.90,
        reason: 'Storage operation involves tracking or PII data without consent check',
      };
    }

    return {
      verdict: 'confirmed',
      confidence: 0.65,
      reason: 'Cookie/storage operation may involve tracking data — consent check recommended',
    };
  }

}

export default ASTRuleEngine;
