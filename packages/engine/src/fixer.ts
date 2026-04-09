/**
 * Halo Fix Engine
 * Tier 1 auto-fix transforms for COPPA violations
 *
 * 4 auto-fixable rules (line-targeted string transforms, no ts-morph)
 * coppa-sec-006:    HTTP → HTTPS (url-upgrade)
 * coppa-sec-010:    Remove weak passwords (remove-default)
 * coppa-sec-015:    innerHTML → textContent (sanitize-input) ⚠️ behavior change
 * coppa-default-020: Public → private (set-default)
 */

import type { Violation, Fixability, RemediationSpec } from './index';

// ==================== Types ====================

/** Result of attempting to fix a single violation */
export interface FixResult {
  ruleId: string;
  filePath: string;
  line: number;
  status: 'applied' | 'skipped' | 'failed' | 'reverted';
  original: string;
  fixed: string;
  reason?: string;
  /** True if this fix changes rendering behavior (e.g. innerHTML → textContent) */
  warning?: string;
}

/** Result of fixing an entire file */
export interface FileFixResult {
  filePath: string;
  originalContent: string;
  fixedContent: string;
  fixes: FixResult[];
  /** False until caller re-scans to verify violations are gone */
  verified: boolean;
}

/** Options for the fix operation */
export interface FixOptions {
  dryRun?: boolean;
  rules?: string[];
  verbose?: boolean;
}

// ==================== Transform Functions ====================

/**
 * Transform: url-upgrade (coppa-sec-006)
 * Replaces http:// with https:// on the violation line.
 */
export function transformUrlUpgrade(line: string, _violation: Violation): string {
  return line.replace(/http:\/\//g, 'https://');
}

/**
 * Transform: remove-default (coppa-sec-010)
 * Replaces weak hardcoded password string literals with a secure alternative.
 *
 * Guards against false positives:
 * - Enum definitions: PASSWORD = 'password' (discriminant, not a real password)
 * - Input type declarations: type: 'password' (HTML type attribute)
 * - Switch case labels: case 'password': (discriminant)
 */
export function transformRemoveDefault(line: string, _violation: Violation): string {
  // Skip enum/const member definitions (SCREAMING_CASE = 'value') — case-sensitive for identifier
  if (/^\s*[A-Z][A-Z0-9_]+\s*=\s*(['"])(123456|password|changeme|student|welcome|student123|child123|default|admin)\1/.test(line)) {
    return line;
  }
  // Skip HTML input type declarations (type: 'password', type="password", type = "password")
  if (/\btype\s*[:=]\s*(['"])password\1/i.test(line)) {
    return line;
  }
  // Skip switch/case discriminants (case 'password':)
  if (/\bcase\s+(['"])(password|admin|default)\1\s*:/i.test(line)) {
    return line;
  }
  return line.replace(
    /(['"])(123456|password|changeme|student|welcome|student123|child123|default|admin)\1/gi,
    'require("crypto").randomBytes(16).toString("hex")'
  );
}

/**
 * Transform: sanitize-input (coppa-sec-015)
 * Replaces .innerHTML assignments with .textContent.
 * ⚠️ WARNING: This changes rendering behavior. If the developer needs HTML rendering,
 * this fix will break their UI. Flagged with a warning in dry-run output.
 *
 * Guards against false positives:
 * - Already-sanitized dangerouslySetInnerHTML (content already wrapped in DOMPurify.sanitize)
 */
export function transformSanitizeInput(line: string, _violation: Violation): string {
  // Handle .innerHTML = ... → .textContent = ...
  if (/\.innerHTML\s*=/.test(line)) {
    return line.replace(/\.innerHTML\s*=/, '.textContent =');
  }
  // Handle dangerouslySetInnerHTML → wrap in DOMPurify.sanitize()
  if (/dangerouslySetInnerHTML\s*=\s*\{\s*\{\s*__html\s*:\s*([^}]+)\}\s*\}/.test(line)) {
    // Skip if the __html value is already wrapped in DOMPurify.sanitize()
    const match = line.match(/dangerouslySetInnerHTML\s*=\s*\{\s*\{\s*__html\s*:\s*([^}]+)\}\s*\}/);
    if (match && /DOMPurify\.sanitize\s*\(/.test(match[1])) {
      return line; // Already sanitized — don't double-wrap
    }
    return line.replace(
      /dangerouslySetInnerHTML\s*=\s*\{\s*\{\s*__html\s*:\s*([^}]+)\}\s*\}/,
      'dangerouslySetInnerHTML={{ __html: DOMPurify.sanitize($1) }}'
    );
  }
  return line;
}

/**
 * Transform: set-default (coppa-default-020)
 * Changes public profile defaults to private.
 *
 * Guards against false positives:
 * - TypeScript type unions: visibility: 'public' | 'private' (type definition, not runtime value)
 */
export function transformSetDefault(line: string, _violation: Violation): string {
  let result = line;

  // Detect TypeScript type union patterns involving 'public' (e.g., 'public' | 'private')
  const isTypeUnion = /['"]public['"]\s*\|/.test(line) || /\|\s*['"]public['"]/.test(line);

  result = result.replace(/isProfileVisible:\s*true/gi, 'isProfileVisible: false');
  // Only replace string literal 'public' values if NOT in a type union context
  if (!isTypeUnion) {
    result = result.replace(/visibility:\s*['"]public['"]/gi, "visibility: 'private'");
    result = result.replace(/defaultPrivacy:\s*['"]public['"]/gi, "defaultPrivacy: 'private'");
  }
  result = result.replace(/isPublic:\s*true/gi, 'isPublic: false');
  result = result.replace(/profileVisibility\s*=\s*['"]?public['"]?/gi, "profileVisibility = 'private'");
  return result;
}

// ==================== Transform Registry ====================

type TransformFn = (line: string, violation: Violation) => string;

/** Maps transformType → transform function */
const TRANSFORM_REGISTRY: Record<string, TransformFn> = {
  'url-upgrade': transformUrlUpgrade,
  'remove-default': transformRemoveDefault,
  'sanitize-input': transformSanitizeInput,
  'set-default': transformSetDefault,
};

/** Rules where the fix changes rendering behavior and needs explicit warning */
const BEHAVIOR_CHANGING_RULES = new Set(['coppa-sec-015']);

// ==================== FixEngine Class ====================

export class FixEngine {
  /**
   * Check if a violation is auto-fixable (Tier 1).
   * Uses the fixability field already populated on the violation.
   */
  isAutoFixable(violation: Violation): boolean {
    return violation.fixability === 'auto' && violation.remediation?.transformType !== undefined;
  }

  /**
   * Check if a rule ID is auto-fixable by looking at a violation's remediation metadata.
   * For use when you have a ruleId but no violation object — checks against known auto-fix transforms.
   */
  isRuleAutoFixable(ruleId: string): boolean {
    // The 4 Tier 1 auto-fix rules with known transforms
    return ['coppa-sec-006', 'coppa-sec-010', 'coppa-sec-015', 'coppa-default-020'].includes(ruleId);
  }

  /**
   * Get all auto-fixable rule IDs.
   */
  getAutoFixableRules(): string[] {
    return ['coppa-sec-006', 'coppa-sec-010', 'coppa-sec-015', 'coppa-default-020'];
  }

  /**
   * Apply fixes to file content for a set of violations.
   * Violations must all belong to the same file.
   * Processes bottom-to-top to preserve line numbers.
   * Returns the fixed content (does NOT write to disk).
   */
  applyFixes(content: string, violations: Violation[], options?: FixOptions): FileFixResult {
    const fixes: FixResult[] = [];
    const lines = content.split('\n');
    const filePath = violations[0]?.filePath || '';

    // Filter to auto-fixable violations with known transforms
    let fixable = violations.filter(v => this.isAutoFixable(v));

    // Further filter by --rules if specified
    if (options?.rules?.length) {
      fixable = fixable.filter(v => options.rules!.includes(v.ruleId));
    }

    // Sort by line number descending so edits don't shift subsequent lines
    const sorted = [...fixable].sort((a, b) => b.line - a.line);

    for (const violation of sorted) {
      const transformType = violation.remediation?.transformType;
      if (!transformType) {
        fixes.push({
          ruleId: violation.ruleId,
          filePath,
          line: violation.line,
          status: 'skipped',
          original: '',
          fixed: '',
          reason: 'No transform type defined',
        });
        continue;
      }

      const transform = TRANSFORM_REGISTRY[transformType];
      if (!transform) {
        fixes.push({
          ruleId: violation.ruleId,
          filePath,
          line: violation.line,
          status: 'skipped',
          original: '',
          fixed: '',
          reason: `Unknown transform type: ${transformType}`,
        });
        continue;
      }

      const lineIdx = violation.line - 1;
      if (lineIdx < 0 || lineIdx >= lines.length) {
        fixes.push({
          ruleId: violation.ruleId,
          filePath,
          line: violation.line,
          status: 'failed',
          original: '',
          fixed: '',
          reason: `Line ${violation.line} out of range`,
        });
        continue;
      }

      const originalLine = lines[lineIdx];
      const fixedLine = transform(originalLine, violation);

      if (fixedLine === originalLine) {
        fixes.push({
          ruleId: violation.ruleId,
          filePath,
          line: violation.line,
          status: 'skipped',
          original: originalLine,
          fixed: fixedLine,
          reason: 'Transform produced no change',
        });
        continue;
      }

      // Apply the transform
      const fixedLines = fixedLine.split('\n');
      lines.splice(lineIdx, 1, ...fixedLines);

      const fix: FixResult = {
        ruleId: violation.ruleId,
        filePath,
        line: violation.line,
        status: 'applied',
        original: originalLine,
        fixed: fixedLine,
      };

      // Add warning for behavior-changing transforms
      if (BEHAVIOR_CHANGING_RULES.has(violation.ruleId)) {
        fix.warning = 'This fix changes rendering behavior. Review before accepting.';
      }

      fixes.push(fix);
    }

    return {
      filePath,
      originalContent: content,
      fixedContent: lines.join('\n'),
      fixes,
      verified: false,
    };
  }

  /**
   * Generate a simple unified diff between original and fixed content.
   * Used for --dry-run output.
   */
  generateDiff(filePath: string, original: string, fixed: string): string {
    const origLines = original.split('\n');
    const fixedLines = fixed.split('\n');
    const output: string[] = [];

    output.push(`--- a/${filePath}`);
    output.push(`+++ b/${filePath}`);

    let i = 0;
    let j = 0;
    while (i < origLines.length || j < fixedLines.length) {
      if (i < origLines.length && j < fixedLines.length && origLines[i] === fixedLines[j]) {
        i++;
        j++;
        continue;
      }

      // Found a difference — emit a hunk
      const contextStart = Math.max(0, i - 1);

      // Collect removed lines
      const removed: string[] = [];
      const added: string[] = [];

      while (i < origLines.length && (j >= fixedLines.length || origLines[i] !== fixedLines[j])) {
        removed.push(origLines[i]);
        i++;
        // Check if we've found alignment again
        if (j < fixedLines.length && i < origLines.length && origLines[i] === fixedLines[j + added.length + 1]) {
          break;
        }
      }

      while (j < fixedLines.length && (i >= origLines.length || origLines[i] !== fixedLines[j])) {
        added.push(fixedLines[j]);
        j++;
      }

      if (removed.length > 0 || added.length > 0) {
        output.push(`@@ -${contextStart + 1} +${contextStart + 1} @@`);
        for (const line of removed) {
          output.push(`-${line}`);
        }
        for (const line of added) {
          output.push(`+${line}`);
        }
      }
    }

    return output.join('\n');
  }
}
