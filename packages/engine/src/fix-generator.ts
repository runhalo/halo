/**
 * Halo Fix Diff Generator
 * Generates unified diff previews for the top 10 most common compliance violations.
 *
 * Used by `runhalo scan . --fix-preview` to show developers suggested code changes
 * they can review and apply. Pattern-matched on code snippets — no AST parsing.
 *
 * Covers:
 *   coppa-auth-001, coppa-tracking-003, coppa-geo-004, coppa-data-002,
 *   coppa-ui-008, asaa-av-004, asaa-vpc-001, aadc-defaults-001,
 *   aadc-defaults-002, coppa-ext-017
 */

// ==================== Types ====================

export interface FixDiff {
  ruleId: string;
  file: string;
  line: number;
  description: string;
  /** Unified diff format patch */
  diff: string;
  confidence: 'high' | 'medium' | 'low';
}

export interface ViolationInput {
  ruleId: string;
  filePath: string;
  line: number;
  codeSnippet: string;
  severity: string;
}

// ==================== Internal Helpers ====================

/** Detect leading whitespace from a code line to preserve indentation in patches. */
function detectIndent(line: string): string {
  const match = line.match(/^(\s*)/);
  return match ? match[1] : '';
}

/**
 * Build a unified diff string.
 *
 * @param filePath - relative or absolute path to the file
 * @param startLine - 1-based line number where the hunk begins
 * @param removedLines - lines being replaced (empty array for pure insertions)
 * @param addedLines - lines being inserted
 * @param contextBefore - optional context lines before the change
 * @param contextAfter - optional context lines after the change
 */
function buildUnifiedDiff(
  filePath: string,
  startLine: number,
  removedLines: string[],
  addedLines: string[],
  contextBefore: string[] = [],
  contextAfter: string[] = [],
): string {
  const header = [
    `--- a/${filePath}`,
    `+++ b/${filePath}`,
  ];

  const hunkOrigStart = startLine - contextBefore.length;
  const hunkOrigCount = contextBefore.length + removedLines.length + contextAfter.length;
  const hunkNewCount = contextBefore.length + addedLines.length + contextAfter.length;

  const hunkHeader = `@@ -${hunkOrigStart},${hunkOrigCount} +${hunkOrigStart},${hunkNewCount} @@`;

  const body: string[] = [];
  for (const line of contextBefore) {
    body.push(` ${line}`);
  }
  for (const line of removedLines) {
    body.push(`-${line}`);
  }
  for (const line of addedLines) {
    body.push(`+${line}`);
  }
  for (const line of contextAfter) {
    body.push(` ${line}`);
  }

  return [...header, hunkHeader, ...body].join('\n');
}

/**
 * Extract context lines from a code snippet.
 * Returns the trimmed violation line and any surrounding lines.
 */
function parseSnippetLines(snippet: string): string[] {
  return snippet.split('\n').filter(l => l.length > 0);
}

// ==================== Fix Template Registry ====================

interface FixTemplate {
  ruleId: string;
  description: string;
  confidence: 'high' | 'medium' | 'low';
  generate: (violation: ViolationInput) => { removed: string[]; added: string[]; contextBefore: string[]; contextAfter: string[] } | null;
}

const FIX_TEMPLATES: FixTemplate[] = [
  // 1. coppa-auth-001 — Unverified social login
  {
    ruleId: 'coppa-auth-001',
    description: 'Insert age verification before social login call',
    confidence: 'medium',
    generate: (v) => {
      const lines = parseSnippetLines(v.codeSnippet);
      const triggerLine = lines.find(l =>
        /\b(socialLogin|signInWith|loginWith|OAuth|googleSignIn|facebookLogin|appleSignIn)\b/i.test(l)
      );
      if (!triggerLine) return null;

      const indent = detectIndent(triggerLine);
      return {
        removed: [],
        added: [
          `${indent}// COPPA: Age verification required before social authentication`,
          `${indent}const userAge = await verifyUserAge();`,
          `${indent}if (userAge < 13) {`,
          `${indent}  throw new Error('Users under 13 require parental consent for account creation');`,
          `${indent}}`,
        ],
        contextBefore: [],
        contextAfter: [triggerLine],
      };
    },
  },

  // 2. coppa-tracking-003 — Third-party tracker without consent
  {
    ruleId: 'coppa-tracking-003',
    description: 'Wrap analytics initialization with parental consent check',
    confidence: 'high',
    generate: (v) => {
      const lines = parseSnippetLines(v.codeSnippet);
      const triggerLine = lines.find(l =>
        /\b(analytics\.init|gtag|fbq|mixpanel\.init|amplitude\.init|segment\.load|hotjar\.init)\b/i.test(l)
      );
      if (!triggerLine) return null;

      const indent = detectIndent(triggerLine);
      return {
        removed: [triggerLine],
        added: [
          `${indent}// COPPA: Consent required before analytics collection for children`,
          `${indent}if (await hasVerifiedParentalConsent(userId)) {`,
          `${indent}  ${triggerLine.trim()}`,
          `${indent}}`,
        ],
        contextBefore: [],
        contextAfter: [],
      };
    },
  },

  // 3. coppa-geo-004 — Geolocation without consent
  {
    ruleId: 'coppa-geo-004',
    description: 'Add parental consent gate before geolocation access',
    confidence: 'high',
    generate: (v) => {
      const lines = parseSnippetLines(v.codeSnippet);
      const triggerLine = lines.find(l =>
        /\b(navigator\.geolocation\.getCurrentPosition|navigator\.geolocation\.watchPosition|Geolocation\.getCurrentPosition)\b/.test(l)
      );
      if (!triggerLine) return null;

      const indent = detectIndent(triggerLine);
      return {
        removed: [triggerLine],
        added: [
          `${indent}// COPPA: Parental consent required before geolocation access`,
          `${indent}const consent = await getParentalConsent('geolocation');`,
          `${indent}if (!consent.granted) return;`,
          triggerLine,
        ],
        contextBefore: [],
        contextAfter: [],
      };
    },
  },

  // 4. coppa-data-002 — Excessive data collection
  {
    ruleId: 'coppa-data-002',
    description: 'Add data minimization filter to restrict collected fields',
    confidence: 'medium',
    generate: (v) => {
      const lines = parseSnippetLines(v.codeSnippet);
      const triggerLine = lines.find(l =>
        /\b(userData|formData|userInfo|profileData|registrationData|collectedData)\b/.test(l)
      );
      if (!triggerLine) return null;

      const indent = detectIndent(triggerLine);
      return {
        removed: [],
        added: [
          `${indent}// COPPA: Minimize data collection — only collect what's necessary`,
          `${indent}const allowedFields = ['username', 'age_range']; // No email, DOB, or PII for children`,
          `${indent}const sanitizedData = Object.fromEntries(`,
          `${indent}  Object.entries(userData).filter(([key]) => allowedFields.includes(key))`,
          `${indent});`,
        ],
        contextBefore: [],
        contextAfter: [triggerLine],
      };
    },
  },

  // 5. coppa-ui-008 — Missing privacy policy on registration form
  {
    ruleId: 'coppa-ui-008',
    description: 'Add privacy policy link and age notice to registration form',
    confidence: 'medium',
    generate: (v) => {
      const lines = parseSnippetLines(v.codeSnippet);
      const submitLine = lines.find(l =>
        /\b(type=["']submit["']|type="submit"|<button.*submit|handleRegister|handleSignup|onSubmit)\b/i.test(l)
      );
      if (!submitLine) return null;

      const indent = detectIndent(submitLine);
      return {
        removed: [],
        added: [
          `${indent}<p className="text-xs text-gray-500 mt-2">`,
          `${indent}  By creating an account, you agree to our{' '}`,
          `${indent}  <a href="/privacy" className="text-blue-500 underline">Privacy Policy</a>.`,
          `${indent}  {' '}If you are under 13, a parent or guardian must create this account.`,
          `${indent}</p>`,
        ],
        contextBefore: [],
        contextAfter: [submitLine],
      };
    },
  },

  // 6. asaa-av-004 — Only checks under-13, not 13-17
  {
    ruleId: 'asaa-av-004',
    description: 'Expand age check to three-tier categorization (child/teen/adult)',
    confidence: 'high',
    generate: (v) => {
      const lines = parseSnippetLines(v.codeSnippet);
      // Look for the classic binary age check pattern
      const childCheckIdx = lines.findIndex(l => /age\s*<\s*13/.test(l));
      if (childCheckIdx === -1) return null;

      // Try to find the corresponding return 'adult' or else block
      const adultReturnIdx = lines.findIndex((l, i) =>
        i > childCheckIdx && /return\s+['"]adult['"]/.test(l)
      );

      const indent = detectIndent(lines[childCheckIdx]);

      // Collect all lines from the child check through the adult return as "removed"
      const endIdx = adultReturnIdx !== -1 ? adultReturnIdx + 1 : childCheckIdx + 4;
      const removed = lines.slice(childCheckIdx, Math.min(endIdx, lines.length));

      return {
        removed,
        added: [
          `${indent}// ASAA: Three-tier age categorization required`,
          `${indent}if (age < 13) {`,
          `${indent}  return 'child'; // COPPA protections apply`,
          `${indent}} else if (age < 18) {`,
          `${indent}  return 'teen'; // ASAA parental consent required`,
          `${indent}}`,
          `${indent}return 'adult';`,
        ],
        contextBefore: [],
        contextAfter: [],
      };
    },
  },

  // 7. asaa-vpc-001 — Free app without parental consent
  {
    ruleId: 'asaa-vpc-001',
    description: 'Add parental consent flow for child and teen users',
    confidence: 'medium',
    generate: (v) => {
      const lines = parseSnippetLines(v.codeSnippet);
      const triggerLine = lines.find(l =>
        /\b(activateApp|startApp|initApp|onboardUser|createAccount|registerUser)\b/i.test(l)
      );
      if (!triggerLine) return null;

      const indent = detectIndent(triggerLine);
      return {
        removed: [],
        added: [
          `${indent}// ASAA: Parental consent required even for free apps`,
          `${indent}if (user.ageCategory === 'child' || user.ageCategory === 'teen') {`,
          `${indent}  const consent = await requestParentalConsent(user.parentEmail);`,
          `${indent}  if (!consent.verified) {`,
          `${indent}    throw new Error('Parental consent required before app activation');`,
          `${indent}  }`,
          `${indent}}`,
        ],
        contextBefore: [],
        contextAfter: [triggerLine],
      };
    },
  },

  // 8. aadc-defaults-001 — Default privacy set to public
  {
    ruleId: 'aadc-defaults-001',
    description: 'Change default profile visibility from public to private',
    confidence: 'high',
    generate: (v) => {
      const lines = parseSnippetLines(v.codeSnippet);
      const triggerLine = lines.find(l =>
        /\bprofileVisibility\s*:\s*['"]public['"]/.test(l) ||
        /\bvisibility\s*:\s*['"]public['"]/.test(l) ||
        /\bdefaultVisibility\s*:\s*['"]public['"]/.test(l)
      );
      if (!triggerLine) return null;

      const fixedLine = triggerLine
        .replace(/profileVisibility\s*:\s*['"]public['"]/, "// AADC: Privacy defaults must be restrictive for children\n" + detectIndent(triggerLine) + "profileVisibility: 'private'")
        .replace(/visibility\s*:\s*['"]public['"]/, "// AADC: Privacy defaults must be restrictive for children\n" + detectIndent(triggerLine) + "visibility: 'private'")
        .replace(/defaultVisibility\s*:\s*['"]public['"]/, "// AADC: Privacy defaults must be restrictive for children\n" + detectIndent(triggerLine) + "defaultVisibility: 'private'");

      const fixedLines = fixedLine.split('\n');

      return {
        removed: [triggerLine],
        added: fixedLines,
        contextBefore: [],
        contextAfter: [],
      };
    },
  },

  // 9. aadc-defaults-002 — Tracking opt-out by default (should be opt-in)
  {
    ruleId: 'aadc-defaults-002',
    description: 'Change tracking default from opt-out (true) to opt-in (false)',
    confidence: 'high',
    generate: (v) => {
      const lines = parseSnippetLines(v.codeSnippet);
      const triggerLine = lines.find(l =>
        /\b(trackingEnabled|enableTracking|analyticsEnabled|trackUsers)\s*:\s*true\b/.test(l)
      );
      if (!triggerLine) return null;

      const indent = detectIndent(triggerLine);
      const fixedLine = triggerLine
        .replace(/trackingEnabled\s*:\s*true/, 'trackingEnabled: false')
        .replace(/enableTracking\s*:\s*true/, 'enableTracking: false')
        .replace(/analyticsEnabled\s*:\s*true/, 'analyticsEnabled: false')
        .replace(/trackUsers\s*:\s*true/, 'trackUsers: false');

      return {
        removed: [triggerLine],
        added: [
          `${indent}// AADC: Tracking must be opt-in, not opt-out, for children`,
          fixedLine,
        ],
        contextBefore: [],
        contextAfter: [],
      };
    },
  },

  // 10. coppa-ext-017 — External links without leaving warning
  {
    ruleId: 'coppa-ext-017',
    description: 'Add modal warning before navigating to external links',
    confidence: 'medium',
    generate: (v) => {
      const lines = parseSnippetLines(v.codeSnippet);
      const triggerLine = lines.find(l =>
        /\b(window\.open|window\.location\.href|location\.assign|<a\s+href=["']https?:\/\/)\b/.test(l) ||
        /\btarget=["']_blank["']/.test(l)
      );
      if (!triggerLine) return null;

      const indent = detectIndent(triggerLine);
      return {
        removed: [triggerLine],
        added: [
          `${indent}// COPPA: External links must warn users they are leaving the app`,
          `${indent}async function handleExternalLink(url: string) {`,
          `${indent}  const confirmed = await showModal(`,
          `${indent}    'You are leaving this app',`,
          `${indent}    'This link will take you to an external website. Continue?',`,
          `${indent}    ['Stay', 'Continue']`,
          `${indent}  );`,
          `${indent}  if (confirmed) window.open(url, '_blank');`,
          `${indent}}`,
        ],
        contextBefore: [],
        contextAfter: [],
      };
    },
  },
];

// Build a lookup map for O(1) template retrieval by ruleId
const TEMPLATE_MAP = new Map<string, FixTemplate>(
  FIX_TEMPLATES.map(t => [t.ruleId, t])
);

// ==================== Public API ====================

/**
 * Returns the set of rule IDs that have fix-preview templates.
 */
export function getSupportedFixRules(): string[] {
  return FIX_TEMPLATES.map(t => t.ruleId);
}

/**
 * Check whether a given ruleId has a fix-preview template.
 */
export function hasFixTemplate(ruleId: string): boolean {
  return TEMPLATE_MAP.has(ruleId);
}

/**
 * Generate a unified-diff fix preview for a single violation.
 *
 * Returns null if no fix template exists for the rule, or if the code snippet
 * does not match the expected pattern for that rule.
 *
 * @param violation - the violation to generate a fix for
 * @returns FixDiff with a unified diff string, or null
 */
export function generateFix(violation: ViolationInput): FixDiff | null {
  const template = TEMPLATE_MAP.get(violation.ruleId);
  if (!template) {
    return null;
  }

  const result = template.generate(violation);
  if (!result) {
    return null;
  }

  const diff = buildUnifiedDiff(
    violation.filePath,
    violation.line,
    result.removed,
    result.added,
    result.contextBefore,
    result.contextAfter,
  );

  return {
    ruleId: violation.ruleId,
    file: violation.filePath,
    line: violation.line,
    description: template.description,
    diff,
    confidence: template.confidence,
  };
}

/**
 * Generate fix previews for a batch of violations.
 * Skips violations without matching templates. Returns only successful diffs.
 *
 * @param violations - array of violations to generate fixes for
 * @returns array of FixDiff objects (only for violations with matching templates)
 */
export function generateFixes(violations: ViolationInput[]): FixDiff[] {
  const results: FixDiff[] = [];
  for (const v of violations) {
    const fix = generateFix(v);
    if (fix) {
      results.push(fix);
    }
  }
  return results;
}
