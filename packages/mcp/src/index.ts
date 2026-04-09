/**
 * Halo MCP Server
 * Model Context Protocol server for IDE integration
 *
 * Updated with all 20 COPPA rules, enhanced explain_rule,
 * suppression system support, and full tool definitions per spec
 */

import { Server } from '@modelcontextprotocol/sdk/server/index.js';
import { StdioServerTransport } from '@modelcontextprotocol/sdk/server/stdio.js';
import {
  CallToolRequestSchema,
  ListToolsRequestSchema,
} from '@modelcontextprotocol/sdk/types.js';
import { createRequire } from 'module';
import * as fs from 'fs';
import * as path from 'path';

// Dynamically import engine from sibling package
// When compiled, this file lives at packages/mcp/dist/index.js
// so ../../engine/dist/index.js resolves to packages/engine/dist/index.js
const require = createRequire(import.meta.url);
const { HaloEngine, COPPA_RULES, FixEngine, REMEDIATION_MAP, ScaffoldEngine, detectFramework, ComplianceScoreEngine } = require('../../engine/dist/index.js');

// MCP Server instance
const server = new Server(
  {
    name: 'runhalo-mcp',
    version: '1.0.0',
  },
  {
    capabilities: {
      tools: {},
    },
  }
);

// Store last scan results
interface ScanState {
  lastScanResult: any;
  engine: any;
}

const scanState: ScanState = {
  lastScanResult: null,
  engine: null
};

// Full rule explanations (20 rules)
const RULE_EXPLANATIONS: Record<string, string> = {
  'coppa-auth-001': 'Prohibits social login (Google, Facebook, Twitter, GitHub) without age verification. Under COPPA 2.0 (effective April 22, 2026), children under 13 require parental consent via email verification. Use age gating or COPPA-compliant signInWithParentEmail() flow.',
  
  'coppa-data-002': 'Prevents PII (email, firstName, lastName, DOB, phone) from being passed in URL query parameters. URLs are logged in server logs, browser history, and proxy caches, exposing this data. Use POST requests with body data instead.',
  
  'coppa-tracking-003': 'Restricts third-party ad trackers (Facebook Pixel, Google Analytics, AdRoll) without child_directed_treatment flag. COPPA 2.0 explicitly excludes behavioral targeting for children. Must add restrictDataProcessing or child_directed_treatment flags.',
  
  'coppa-geo-004': 'Prevents precise geolocation collection without parental consent. Geolocation data can identify a child\'s location. Must use coarse location (enableHighAccuracy: false) or explicit parental consent flow.',
  
  'coppa-retention-005': 'Requires data retention policies (TTL, deleted_at fields) in database schemas. COPPA 2.0 mandates retention limited to "reasonably necessary" duration. Add expires fields or TTL indexes.',
  
  'coppa-sec-006': 'Critical: All API endpoints handling personal information must use HTTPS. HTTP transmits data in plaintext, vulnerable to interception. Replace http:// with https:// throughout.',
  
  'coppa-audio-007': 'Audio recording requires consent. COPPA 2.0 classifies voice prints as biometric data. Wrap getUserMedia({audio:true}) in click handlers and add parental consent checks.',
  
  'coppa-ui-008': 'Registration forms must include a clear link to the privacy policy per COPPA notice requirements. Add privacy policy link to all forms collecting user data.',
  
  'coppa-flow-009': 'Forms collecting child contact info must also require parent/guardian email for consent verification. Make parent_email required when collecting child email/phone.',
  
  'coppa-sec-010': 'Weak default passwords create security vulnerabilities. Use secure random string generators for temporary credentials. Common weak passwords: "password", "123456", "changeme".',
  
  'coppa-ext-011': 'Third-party chat widgets (Intercom, Zendesk, Drift) allow children to freely disclose PII to third parties. Disable for unauthenticated or under-13 users.',
  
  'coppa-bio-012': 'Biometric data (face recognition, voice prints, gait analysis) requires explicit parental consent. COPPA 2.0 explicitly classifies biometrics as personal information. Ensure on-device processing or obtain VPC.',
  
  'coppa-notif-013': 'Push notifications are "Online Contact Info" under COPPA 2.0. Direct notifications to children require parental consent. Gate subscription behind parental dashboard settings.',
  
  'coppa-ugc-014': 'User-generated content fields (bio, about me, comments) must pass through PII scrubbing before database storage. Add regex filters or AWS Comprehend moderation.',
  
  'coppa-sec-015': 'XSS vulnerabilities (dangerouslySetInnerHTML, innerHTML=) expose users to malicious script injection. Use standard JSX rendering or DOMPurify library.',
  
  'coppa-cookies-016': 'Reading/writing cookies or localStorage requires notice. Add cookie consent banner before setting any tracking data.',
  
  'coppa-ext-017': 'External links in child-facing views should trigger "You are leaving..." warning. Use SafeLink component with modal for external URLs.',
  
  'coppa-analytics-018': 'Passing email, name, or phone to analytics.identify() exposes PII to third parties. Hash user IDs and omit PII from analytics payloads.',
  
  'coppa-edu-019': 'Teacher accounts using generic email (@gmail.com) bypass "School Official" consent exception. Restrict to verified EDU domains or require manual approval.',
  
  'coppa-default-020': 'Default profile visibility must be private. COPPA 2.0 mandates privacy by design. Change default to "private" or false.'
};

// Fix suggestions (20 rules)
const RULE_FIXES: Record<string, string> = {
  'coppa-auth-001': '// Wrap auth call in age check\nif (user.age >= 13) {\n  await auth.signInWithPopup("google");\n} else {\n  await auth.signInWithParentEmail();\n}',
  
  'coppa-data-002': '// Use POST instead of GET\naxios.post("/api/user", { email: user.email });\n// Instead of: axios.get("/api?email=" + user.email)',
  
  'coppa-tracking-003': '// Add child-directed treatment\nfbq("init", "XXXXX", {}, { data_processing_options: "LDU" });\n// Google Analytics:\ngtag("config", "UA-XXXX", { child_directed_treatment: true });',
  
  'coppa-geo-004': '// Use coarse location\nnavigator.geolocation.getCurrentPosition(success, error, {\n  enableHighAccuracy: false\n});\n// Or add parental consent gate:\nif (user.hasParentalConsent) { ... }',
  
  'coppa-retention-005': '// Mongoose TTL:\nnew Schema({ createdAt: { type: Date, expires: "365d" } });\n// Sequelize:\nparanoid: true // adds deletedAt',
  
  'coppa-sec-006': '// Replace all http:// with https://\nconst API_URL = "https://api.example.com";',
  
  'coppa-audio-007': '// Wrap in user-initiated event\nbutton.addEventListener("click", async () => {\n  const stream = await navigator.mediaDevices.getUserMedia({ audio: true });\n});',
  
  'coppa-ui-008': '// Add to form footer\n<a href="/privacy">Privacy Policy</a>',
  
  'coppa-flow-009': '// Make parent email required for children\nconst schema = z.object({\n  child_email: z.string().email(),\n  parent_email: z.string().email().required()\n});',
  
  'coppa-sec-010': '// Use secure random\nimport { randomBytes } from "crypto";\nconst tempPassword = randomBytes(16).toString("hex");',
  
  'coppa-ext-011': '// Disable for under-13\nif (user.age >= 13) {\n  Intercom("boot", { ... });\n}',
  
  'coppa-bio-012': '// Ensure local-only processing\nconst faceMatcher = new FaceMatcher(descriptors, 0.6);\n// Do NOT send descriptors to server',
  
  'coppa-notif-013': '// Gate behind parental consent\nif (user.parentSettings.pushEnabled) {\n  await messaging.subscribeToTopic("updates");\n}',
  
  'coppa-ugc-014': '// Add PII scrubber\nfunction scrubPII(text) {\n  return text.replace(/\\b[\\w.-]+@[\\w.-]+\\.\\w+\\b/g, "[EMAIL]")\n             .replace(/\\b\\d{3}-\\d{3}-\\d{4}\\b/g, "[PHONE]");\n}',
  
  'coppa-sec-015': '// Use DOMPurify\nimport DOMPurify from "dompurify";\nconst clean = DOMPurify.sanitize(userInput);',
  
  'coppa-cookies-016': '// Show consent first\nif (!hasConsent()) {\n  showCookieBanner();\n} else {\n  localStorage.setItem("prefs", "...");\n}',
  
  'coppa-ext-017': '// Use SafeLink component\nimport { SafeLink } from "@runhalo/ui";\n<SafeLink href="https://external.com">Click here</SafeLink>',
  
  'coppa-analytics-018': '// Hash before sending\nconst hashedId = crypto.createHash("sha256").update(userId).digest("hex");\nanalytics.identify(hashedId, {});',
  
  'coppa-edu-019': '// Verify EDU domain\nconst EDU_DOMAINS = ["edu", "k12.edu", "school.edu"];\nconst isValidSchool = EDU_DOMAINS.some(d => email.endsWith("@" + d));',
  
  'coppa-default-020': '// Private by default\nconst UserSchema = new Schema({\n  isProfileVisible: { type: Boolean, default: false }\n});'
};

// Tool definitions per MCP spec
server.setRequestHandler(ListToolsRequestSchema, async () => {
  return {
    tools: [
      {
        name: 'audit_file',
        description: 'Scan a single file for Halo violations (COPPA 2.0). Returns violations with line numbers, severity, and fix suggestions.',
        inputSchema: {
          type: 'object',
          properties: {
            path: { 
              type: 'string', 
              description: 'Relative or absolute path to file' 
            },
            content: { 
              type: 'string', 
              description: 'Optional file content override (for dirty buffers)' 
            },
            includeSuppressed: {
              type: 'boolean',
              default: false,
              description: 'Include suppressed violations (with // halo-ignore comments)'
            }
          },
          required: ['path']
        },
      },
      {
        name: 'audit_project',
        description: 'Run a full compliance scan on the current project/repo. Returns summary and all violations.',
        inputSchema: {
          type: 'object',
          properties: {
            projectPath: { 
              type: 'string', 
              description: 'Path to project directory (default: current dir)' 
            },
            include_ignored: { 
              type: 'boolean', 
              default: false,
              description: 'Include suppressed violations' 
            }
          }
        },
      },
      {
        name: 'get_violations',
        description: 'Query active violations filtered by severity or regulation. Useful for "Show me all COPPA errors".',
        inputSchema: {
          type: 'object',
          properties: {
            severity: { 
              type: 'string', 
              enum: ['critical', 'high', 'medium', 'low'] 
            },
            regulation: { 
              type: 'string', 
              enum: ['COPPA', 'COPPA2.0', 'GDPR-K', 'AADC'],
              default: 'COPPA' 
            },
            file_pattern: { 
              type: 'string',
              description: 'Filter by file path pattern (glob)' 
            }
          },
        },
      },
      {
        name: 'explain_rule',
        description: 'Get detailed regulation text and penalty info for a specific rule ID. Explains WHY a rule exists.',
        inputSchema: {
          type: 'object',
          properties: {
            rule_id: { 
              type: 'string', 
              description: 'Rule ID (e.g., coppa-auth-001, coppa-data-002)' 
            },
          },
          required: ['rule_id']
        },
      },
      {
        name: 'suggest_fix',
        description: 'Generate an auto-fix patch for a specific violation. Returns code template for fixing the issue.',
        inputSchema: {
          type: 'object',
          properties: {
            violation_id: {
              type: 'string',
              description: 'Violation ID (ruleId) or violation object from scan'
            },
            context_lines: {
              type: 'number',
              default: 2,
              description: 'Number of context lines to include'
            },
          },
          required: ['violation_id']
        },
      },
      {
        name: 'scan_file',
        description: 'Real-time single-file scan for on-save hooks. Lightweight — returns violation count and details. Designed for AI coding assistant integration: AI writes code → save → Halo flags violations instantly.',
        inputSchema: {
          type: 'object',
          properties: {
            path: {
              type: 'string',
              description: 'File path to scan'
            },
            content: {
              type: 'string',
              description: 'File content (for unsaved buffer — takes priority over disk read)'
            },
          },
          required: ['path']
        },
      },
      {
        name: 'fix_file',
        description: 'Auto-fix COPPA violations in a single file. Applies Tier 1 deterministic transforms (http→https, public→private, weak passwords, XSS sanitization). Returns diff of changes made.',
        inputSchema: {
          type: 'object',
          properties: {
            path: {
              type: 'string',
              description: 'File path to fix'
            },
            dryRun: {
              type: 'boolean',
              default: true,
              description: 'If true (default), return diffs without writing. Set false to apply changes.'
            },
            rules: {
              type: 'array',
              items: { type: 'string' },
              description: 'Specific rule IDs to fix (default: all auto-fixable rules)'
            }
          },
          required: ['path']
        },
      },
      {
        name: 'fix_guided',
        description: 'Generate scaffold code for Tier 2 guided fixes. Creates framework-specific components (age gates, consent banners, PII sanitizers, retention policies). Detects React/Next.js/Vue/Svelte/plain-js automatically.',
        inputSchema: {
          type: 'object',
          properties: {
            projectPath: {
              type: 'string',
              description: 'Project root path for framework detection (default: current dir)'
            },
            violations: {
              type: 'array',
              items: {
                type: 'object',
                properties: { ruleId: { type: 'string' } }
              },
              description: 'Violations to generate scaffolds for (from scan results). If omitted, scans project first.'
            },
            framework: {
              type: 'string',
              enum: ['react', 'nextjs', 'vue', 'svelte', 'plain-js'],
              description: 'Override auto-detected framework'
            }
          }
        },
      },
      {
        name: 'compliance_score',
        description: 'Get the weighted compliance score (0-100, grade A-F) for a project or file. Includes score breakdown by severity and trend from scan history.',
        inputSchema: {
          type: 'object',
          properties: {
            projectPath: {
              type: 'string',
              description: 'Project path to score (default: current dir)'
            }
          }
        },
      },
    ],
  };
});

// Handle tool calls
server.setRequestHandler(CallToolRequestSchema, async (request) => {
  const { name, arguments: args } = request.params;

  try {
    switch (name) {
      case 'audit_file': {
        const filePath = args?.path as string;
        const content = args?.content as string | undefined;
        const includeSuppressed = args?.includeSuppressed as boolean || false;
        
        let fileContent = content;
        if (!fileContent && filePath) {
          try {
            fileContent = fs.readFileSync(filePath, 'utf-8');
          } catch (e) {
            return {
              content: [{ type: 'text', text: `Error reading file: ${filePath}` }],
              isError: true
            };
          }
        }
        
        const engine = new HaloEngine({ 
          suppressions: { enabled: true },
          includeSuppressed 
        });
        
        const violations = engine.scanFile(filePath, fileContent || '');
        
        scanState.lastScanResult = {
          filePath,
          violations,
          scannedAt: new Date().toISOString()
        };
        
        return {
          content: [
            {
              type: 'text',
              text: JSON.stringify({
                file: filePath,
                violationCount: violations.length,
                violations: violations.map((v: any) => ({
                  id: v.ruleId,
                  line: v.line,
                  column: v.column,
                  severity: v.severity,
                  message: v.message,
                  code: v.codeSnippet,
                  fix: v.fixSuggestion,
                  suppressed: v.suppressed
                }))
              }, null, 2)
            }
          ]
        };
      }

      case 'audit_project': {
        const projectPath = args?.projectPath as string || '.';
        const includeIgnored = args?.include_ignored as boolean || false;

        // Scan directory using engine directly (no CLI dependency)
        const projEngine = new HaloEngine({
          suppressions: { enabled: true },
          includeSuppressed: includeIgnored
        });

        const results: any[] = [];
        const scanDir = (dir: string) => {
          const entries = fs.readdirSync(dir, { withFileTypes: true });
          for (const entry of entries) {
            const fullPath = path.join(dir, entry.name);
            if (entry.isDirectory()) {
              // Skip common non-source directories
              if (['node_modules', 'dist', 'build', '.git', 'coverage'].includes(entry.name)) continue;
              scanDir(fullPath);
            } else if (entry.isFile()) {
              const ext = path.extname(entry.name);
              if (['.ts', '.js', '.tsx', '.jsx', '.py', '.swift', '.html', '.vue', '.php', '.rb', '.kt', '.java', '.go'].includes(ext)) {
                try {
                  const content = fs.readFileSync(fullPath, 'utf-8');
                  const violations = projEngine.scanFile(fullPath, content);
                  if (violations.length > 0) {
                    results.push({ filePath: fullPath, violations });
                  }
                } catch { /* skip unreadable files */ }
              }
            }
          }
        };

        try {
          scanDir(path.resolve(projectPath));
        } catch (e) {
          return {
            content: [{ type: 'text', text: `Error scanning project: ${e}` }],
            isError: true
          };
        }

        const allViolations = results.flatMap((r: any) => r.violations);
        
        scanState.lastScanResult = {
          projectPath,
          violations: allViolations,
          filesScanned: results.length,
          scannedAt: new Date().toISOString()
        };
        
        // Summary by severity
        const summary = {
          critical: allViolations.filter((v: any) => v.severity === 'critical').length,
          high: allViolations.filter((v: any) => v.severity === 'high').length,
          medium: allViolations.filter((v: any) => v.severity === 'medium').length,
          low: allViolations.filter((v: any) => v.severity === 'low').length
        };
        
        return {
          content: [
            {
              type: 'text',
              text: JSON.stringify({
                project: projectPath,
                filesScanned: results.length,
                totalViolations: allViolations.length,
                summary,
                violations: allViolations.map((v: any) => ({
                  id: v.ruleId,
                  file: v.filePath,
                  line: v.line,
                  severity: v.severity,
                  message: v.message,
                  suppressed: v.suppressed
                }))
              }, null, 2)
            }
          ]
        };
      }

      case 'get_violations': {
        if (!scanState.lastScanResult) {
          return {
            content: [{ 
              type: 'text', 
              text: 'No scan results available. Run audit_file or audit_project first.' 
            }]
          };
        }
        
        const severity = args?.severity as string | undefined;
        const filePattern = args?.file_pattern as string | undefined;
        
        let violations = scanState.lastScanResult.violations || [];
        
        // Filter by severity
        if (severity) {
          violations = violations.filter((v: any) => v.severity === severity);
        }
        
        // Filter by file pattern (glob-safe)
        if (filePattern) {
          const escaped = filePattern
            .replace(/[.+^${}()|[\]\\]/g, '\\$&')  // escape regex special chars
            .replace(/\*\*/g, '{{GLOBSTAR}}')
            .replace(/\*/g, '[^/]*')
            .replace(/\{\{GLOBSTAR\}\}/g, '.*');
          try {
            const regex = new RegExp(escaped);
            violations = violations.filter((v: any) => regex.test(v.filePath));
          } catch {
            // If regex construction fails, do simple substring match
            violations = violations.filter((v: any) =>
              v.filePath?.includes(filePattern)
            );
          }
        }
        
        return {
          content: [
            {
              type: 'text',
              text: JSON.stringify({
                count: violations.length,
                violations: violations.map((v: any) => ({
                  id: v.ruleId,
                  file: v.filePath,
                  line: v.line,
                  severity: v.severity,
                  message: v.message,
                  suppressed: v.suppressed
                }))
              }, null, 2)
            }
          ]
        };
      }

      case 'explain_rule': {
        const ruleId = args?.rule_id as string;
        
        if (!ruleId) {
          return {
            content: [{ type: 'text', text: 'rule_id is required' }],
            isError: true
          };
        }
        
        const explanation = RULE_EXPLANATIONS[ruleId];
        
        if (!explanation) {
          return {
            content: [{ 
              type: 'text', 
              text: `Rule ${ruleId} not found. Available rules: ${Object.keys(RULE_EXPLANATIONS).join(', ')}` 
            }],
            isError: true
          };
        }
        
        const rule = COPPA_RULES.find((r: any) => r.id === ruleId);
        
        return {
          content: [
            {
              type: 'text',
              text: JSON.stringify({
                ruleId,
                name: rule?.name,
                severity: rule?.severity,
                description: rule?.description,
                penalty: rule?.penalty,
                explanation,
                languages: rule?.languages
              }, null, 2)
            }
          ]
        };
      }

      case 'suggest_fix': {
        const violationId = args?.violation_id as string;
        
        if (!violationId) {
          return {
            content: [{ type: 'text', text: 'violation_id is required' }],
            isError: true
          };
        }
        
        // Handle both rule ID and full violation object
        let ruleId = violationId;
        
        // Check if it's a JSON violation object
        try {
          const parsed = JSON.parse(violationId);
          if (parsed.ruleId) {
            ruleId = parsed.ruleId;
          }
        } catch {
          // Not JSON, treat as ruleId directly
        }
        
        const fix = RULE_FIXES[ruleId];
        
        if (!fix) {
          return {
            content: [{ 
              type: 'text', 
              text: `Fix for ${ruleId} not available. Available: ${Object.keys(RULE_FIXES).join(', ')}` 
            }],
            isError: true
          };
        }
        
        const rule = COPPA_RULES.find((r: any) => r.id === ruleId);
        
        return {
          content: [
            {
              type: 'text',
              text: JSON.stringify({
                ruleId,
                name: rule?.name,
                fixSuggestion: fix,
                originalSuggestion: rule?.fixSuggestion
              }, null, 2)
            }
          ]
        };
      }

      case 'scan_file': {
        const filePath = args?.path as string;
        const content = args?.content as string | undefined;

        let fileContent = content;
        if (!fileContent && filePath) {
          try {
            fileContent = fs.readFileSync(filePath, 'utf-8');
          } catch (e) {
            return {
              content: [{ type: 'text', text: `Error reading file: ${filePath}` }],
              isError: true
            };
          }
        }

        const rtEngine = new HaloEngine({ suppressions: { enabled: true } });
        const violations = rtEngine.scanFile(filePath, fileContent || '');

        // Update scan state for get_violations
        scanState.lastScanResult = {
          filePath,
          violations,
          scannedAt: new Date().toISOString()
        };

        if (violations.length === 0) {
          return {
            content: [{ type: 'text', text: `✅ ${path.basename(filePath)}: Clean — no COPPA violations found.` }]
          };
        }

        // Compact format for real-time feedback
        const lines = violations.map((v: any) =>
          `⚠️ L${v.line}: [${v.severity.toUpperCase()}] ${v.ruleId} — ${v.message}`
        );

        return {
          content: [{
            type: 'text',
            text: `🔍 ${path.basename(filePath)}: ${violations.length} violation${violations.length > 1 ? 's' : ''}\n\n${lines.join('\n')}\n\nRun fix_file to auto-fix, or fix_guided for scaffold generation.`
          }]
        };
      }

      case 'fix_file': {
        const filePath = args?.path as string;
        const dryRun = args?.dryRun !== false; // default true
        const ruleFilter = args?.rules as string[] | undefined;

        let fileContent: string;
        try {
          fileContent = fs.readFileSync(filePath, 'utf-8');
        } catch (e) {
          return {
            content: [{ type: 'text', text: `Error reading file: ${filePath}` }],
            isError: true
          };
        }

        // Scan first to find violations
        const fixEngine = new HaloEngine();
        const violations = fixEngine.scanFile(filePath, fileContent);

        if (violations.length === 0) {
          return {
            content: [{ type: 'text', text: `✅ ${path.basename(filePath)}: No violations to fix.` }]
          };
        }

        // Apply Tier 1 auto-fixes
        const fixer = new FixEngine();
        const fixOptions = ruleFilter ? { rules: ruleFilter } : undefined;
        const fixResult = fixer.applyFixes(fileContent, violations, fixOptions);

        const appliedFixes = fixResult.fixes.filter((f: any) => f.status === 'applied');

        if (appliedFixes.length === 0) {
          const guidedCount = violations.filter((v: any) => {
            const remap = REMEDIATION_MAP[v.ruleId];
            return remap && remap.fixability === 'guided';
          }).length;

          return {
            content: [{
              type: 'text',
              text: `ℹ️ ${path.basename(filePath)}: ${violations.length} violation${violations.length > 1 ? 's' : ''}, but none are auto-fixable (Tier 1).\n${guidedCount > 0 ? `${guidedCount} can be addressed with guided scaffolds — use fix_guided.` : 'These require manual remediation.'}`
            }]
          };
        }

        // Generate diff
        const originalLines = fileContent.split('\n');
        const fixedLines = fixResult.fixedContent.split('\n');
        const diffs: string[] = [];
        for (let i = 0; i < Math.max(originalLines.length, fixedLines.length); i++) {
          if (originalLines[i] !== fixedLines[i]) {
            diffs.push(`L${i + 1}:`);
            if (originalLines[i]) diffs.push(`- ${originalLines[i]}`);
            if (fixedLines[i]) diffs.push(`+ ${fixedLines[i]}`);
          }
        }

        if (!dryRun) {
          fs.writeFileSync(filePath, fixResult.fixedContent, 'utf-8');
        }

        const rulesFixed = [...new Set(appliedFixes.map((f: any) => f.ruleId))];

        return {
          content: [{
            type: 'text',
            text: `🔧 ${path.basename(filePath)}: ${appliedFixes.length} fix${appliedFixes.length > 1 ? 'es' : ''} applied${dryRun ? ' (dry-run)' : ''}.\n\nRules fixed: ${rulesFixed.join(', ')}\n\nDiff:\n${diffs.join('\n')}${dryRun ? '\n\nSet dryRun: false to apply changes.' : '\n\n✅ Changes written to disk.'}`
          }]
        };
      }

      case 'fix_guided': {
        const projectPath = args?.projectPath as string || '.';
        const inputViolations = args?.violations as any[] | undefined;
        const frameworkOverride = args?.framework as string | undefined;

        const resolvedPath = path.resolve(projectPath);
        const scaffoldEngine = new ScaffoldEngine();

        // If no violations provided, scan the project first
        let violations = inputViolations;
        if (!violations) {
          const scanEngine = new HaloEngine();
          const allViolations: any[] = [];

          const scanDirForGuided = (dir: string) => {
            try {
              const entries = fs.readdirSync(dir, { withFileTypes: true });
              for (const entry of entries) {
                const fullPath = path.join(dir, entry.name);
                if (entry.isDirectory()) {
                  if (['node_modules', 'dist', 'build', '.git', 'coverage'].includes(entry.name)) continue;
                  scanDirForGuided(fullPath);
                } else if (entry.isFile()) {
                  const ext = path.extname(entry.name);
                  if (['.ts', '.js', '.tsx', '.jsx', '.py', '.swift', '.html', '.vue', '.php', '.rb', '.kt', '.java', '.go'].includes(ext)) {
                    try {
                      const content = fs.readFileSync(fullPath, 'utf-8');
                      const fileViolations = scanEngine.scanFile(fullPath, content);
                      allViolations.push(...fileViolations);
                    } catch { /* skip */ }
                  }
                }
              }
            } catch { /* skip */ }
          };

          scanDirForGuided(resolvedPath);
          violations = allViolations;
        }

        // Detect framework
        let frameworkInfo;
        try {
          frameworkInfo = detectFramework(resolvedPath);
        } catch {
          frameworkInfo = { framework: 'plain-js', typescript: false, confidence: 0 };
        }

        const framework = frameworkOverride || frameworkInfo.framework;

        // Get applicable scaffolds
        const applicable = scaffoldEngine.getApplicableScaffolds(violations);
        const unavailable = scaffoldEngine.getUnavailableScaffolds(violations);

        if (applicable.length === 0 && unavailable.length === 0) {
          return {
            content: [{ type: 'text', text: '✅ No guided fixes needed — no matching violations found.' }]
          };
        }

        // Generate scaffolds
        const results = scaffoldEngine.generateScaffolds(violations, resolvedPath, framework);

        const output: string[] = [];
        output.push(`🔮 Guided Fixes for ${path.basename(resolvedPath)} (${framework}${frameworkInfo.typescript ? ' + TypeScript' : ''})\n`);

        if (results.length > 0) {
          output.push(`**${results.length} scaffold${results.length > 1 ? 's' : ''} ready to generate:**\n`);
          for (const result of results) {
            output.push(`  📦 ${result.scaffoldId} (${result.ruleId})`);
            for (const file of result.files) {
              output.push(`     → ${file.path} (${file.content.split('\n').length} lines)`);
            }
          }
          output.push('');
          output.push('To generate these files, save to your project\'s halo-scaffolds/ directory.');
        }

        if (unavailable.length > 0) {
          output.push(`\n**${unavailable.length} violation${unavailable.length > 1 ? 's' : ''} need manual remediation:**`);
          const seen = new Set<string>();
          for (const v of unavailable) {
            if (!seen.has(v.ruleId)) {
              seen.add(v.ruleId);
              output.push(`  📄 ${v.ruleId} — docs: https://runhalo.dev/rules/${v.ruleId}`);
            }
          }
        }

        return {
          content: [{
            type: 'text',
            text: output.join('\n')
          }]
        };
      }

      case 'compliance_score': {
        const projectPath = args?.projectPath as string || '.';
        const resolvedPath = path.resolve(projectPath);

        const scoreEngine = new HaloEngine();
        const scorer = new ComplianceScoreEngine();
        const allViolations: any[] = [];
        let filesScanned = 0;

        const scanDirForScore = (dir: string) => {
          try {
            const entries = fs.readdirSync(dir, { withFileTypes: true });
            for (const entry of entries) {
              const fullPath = path.join(dir, entry.name);
              if (entry.isDirectory()) {
                if (['node_modules', 'dist', 'build', '.git', 'coverage'].includes(entry.name)) continue;
                scanDirForScore(fullPath);
              } else if (entry.isFile()) {
                const ext = path.extname(entry.name);
                if (['.ts', '.js', '.tsx', '.jsx', '.py', '.swift', '.html', '.vue', '.php', '.rb', '.kt', '.java', '.go'].includes(ext)) {
                  try {
                    const content = fs.readFileSync(fullPath, 'utf-8');
                    const violations = scoreEngine.scanFile(fullPath, content);
                    allViolations.push(...violations);
                    filesScanned++;
                  } catch { /* skip */ }
                }
              }
            }
          } catch { /* skip */ }
        };

        scanDirForScore(resolvedPath);

        const scoreResult = scorer.calculate(allViolations, filesScanned);

        // Check for history trend
        const historyPath = path.join(require('os').homedir(), '.halo', 'history.json');
        let trend = '';
        try {
          if (fs.existsSync(historyPath)) {
            const history = JSON.parse(fs.readFileSync(historyPath, 'utf-8'));
            const projectHistory = history.filter((h: any) => h.projectPath === resolvedPath);
            if (projectHistory.length > 0) {
              const lastScore = projectHistory[projectHistory.length - 1].score;
              const diff = scoreResult.score - lastScore;
              if (diff > 0) trend = ` ↑ from ${lastScore} (+${diff})`;
              else if (diff < 0) trend = ` ↓ from ${lastScore} (${diff})`;
              else trend = ` → unchanged from ${lastScore}`;
            }
          }
        } catch { /* no history */ }

        return {
          content: [{
            type: 'text',
            text: `📊 Compliance Score: ${scoreResult.score}/100 (${scoreResult.grade})${trend}\n\nFiles scanned: ${filesScanned}\nTotal violations: ${scoreResult.totalViolations}\n  Critical: ${scoreResult.bySeverity.critical}\n  High: ${scoreResult.bySeverity.high}\n  Medium: ${scoreResult.bySeverity.medium}\n  Low: ${scoreResult.bySeverity.low}\n\nRun scan_file or audit_project for detailed violations.`
          }]
        };
      }

      default:
        throw new Error(`Unknown tool: ${name}`);
    }
  } catch (error) {
    return {
      content: [
        {
          type: 'text',
          text: `Error: ${error instanceof Error ? error.message : String(error)}`
        }
      ],
      isError: true
    };
  }
});

// Start the server
async function main() {
  const transport = new StdioServerTransport();
  await server.connect(transport);
  console.error('Halo MCP Server running on stdio (v2.0.0 — P2.5: real-time scan + fix + guided + score)');
}

main().catch(console.error);
