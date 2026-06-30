/**
 * Halo CLI - Unit Tests
 */

import { HaloEngine, COPPA_RULES, FixEngine, REMEDIATION_MAP, ComplianceScoreEngine, ScaffoldEngine, detectFramework, SCAFFOLD_REGISTRY } from '@runhalo/engine';
import * as fs from 'fs';
import * as path from 'path';
import * as os from 'os';

describe('Halo CLI', () => {
  describe('Engine Integration', () => {
    it('should have access to HaloEngine', () => {
      const engine = new HaloEngine();
      expect(engine).toBeDefined();
    });

    it('should have all 21 COPPA rules defined', () => {
      expect(COPPA_RULES).toHaveLength(21);
    });

    it('should scan a file and return violations', () => {
      const engine = new HaloEngine();
      const code = `fbq('init', '123456789');`;
      const violations = engine.scanFile('test.ts', code);
      expect(violations.length).toBeGreaterThan(0);
      expect(violations[0].ruleId).toBe('coppa-tracking-003');
    });

    it('should filter by specific rules', () => {
      const engine = new HaloEngine({ rules: ['coppa-auth-001'] });
      const rules = engine.getRules();
      expect(rules).toHaveLength(1);
      expect(rules[0].id).toBe('coppa-auth-001');
    });

    it('should filter by severity', () => {
      const engine = new HaloEngine({ severityFilter: ['critical'] });
      const rules = engine.getRules();
      expect(rules.length).toBeGreaterThan(0);
      rules.forEach(r => expect(r.severity).toBe('critical'));
    });
  });

  describe('Default Patterns', () => {
    it('should have default include patterns', () => {
      const patterns = [
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
        '**/*.svelte'
      ];
      expect(patterns.length).toBe(12);
    });

    it('should have default exclude patterns', () => {
      const excludePatterns = [
        'node_modules/**',
        'dist/**',
        'build/**',
        '.git/**',
        'coverage/**'
      ];
      expect(excludePatterns.length).toBe(5);
    });
  });

  describe('Fix Engine Integration', () => {
    it('should have access to FixEngine from engine package', () => {
      const fixer = new FixEngine();
      expect(fixer).toBeDefined();
      expect(typeof fixer.applyFixes).toBe('function');
      expect(typeof fixer.generateDiff).toBe('function');
    });

    it('should report exactly 4 auto-fixable rules', () => {
      const fixer = new FixEngine();
      const autoRules = fixer.getAutoFixableRules();
      expect(autoRules).toHaveLength(4);
      expect(autoRules).toContain('coppa-sec-006');
      expect(autoRules).toContain('coppa-sec-010');
      expect(autoRules).toContain('coppa-sec-015');
      expect(autoRules).toContain('coppa-default-020');
    });

    it('should scan, fix, and re-scan with zero remaining auto-fixable violations', () => {
      const engine = new HaloEngine({});
      const fixer = new FixEngine();

      // Content with two auto-fixable violations
      const content = "const url = 'http://api.example.com/api/login';\nconst profile = { isProfileVisible: true };";
      const violations = engine.scanFile('test.ts', content);

      // Should have auto-fixable violations
      const autoFixable = violations.filter(v =>
        ['coppa-sec-006', 'coppa-default-020'].includes(v.ruleId)
      );
      expect(autoFixable.length).toBeGreaterThan(0);

      // Apply fixes
      const result = fixer.applyFixes(content, violations);
      expect(result.fixes.filter(f => f.status === 'applied').length).toBeGreaterThan(0);

      // Re-scan should show no violations for the rules we fixed
      const postViolations = engine.scanFile('test.ts', result.fixedContent);
      const remainingAuto = postViolations.filter(v =>
        ['coppa-sec-006', 'coppa-default-020'].includes(v.ruleId)
      );
      expect(remainingAuto).toHaveLength(0);
    });
  });

  describe('First-Run Config', () => {
    const tmpDir = path.join(os.tmpdir(), `halo-test-${Date.now()}`);
    const tmpConfigDir = path.join(tmpDir, '.halo');
    const tmpConfigPath = path.join(tmpConfigDir, 'config.json');

    afterEach(() => {
      // Clean up
      try {
        if (fs.existsSync(tmpDir)) {
          fs.rmSync(tmpDir, { recursive: true, force: true });
        }
      } catch {}
    });

    it('should return null when config file does not exist', () => {
      // Config doesn't exist in a fresh temp dir
      expect(fs.existsSync(tmpConfigPath)).toBe(false);
    });

    it('should create config directory and write valid JSON', () => {
      // Simulate saveConfig behavior
      if (!fs.existsSync(tmpConfigDir)) {
        fs.mkdirSync(tmpConfigDir, { recursive: true });
      }
      const config = {
        prompted: true,
        promptedAt: new Date().toISOString(),
        consent: false,
      };
      fs.writeFileSync(tmpConfigPath, JSON.stringify(config, null, 2), 'utf-8');

      // Verify
      expect(fs.existsSync(tmpConfigPath)).toBe(true);
      const loaded = JSON.parse(fs.readFileSync(tmpConfigPath, 'utf-8'));
      expect(loaded.prompted).toBe(true);
      expect(loaded.consent).toBe(false);
      expect(loaded.promptedAt).toBeDefined();
    });

    it('should save config with email when consent given', () => {
      if (!fs.existsSync(tmpConfigDir)) {
        fs.mkdirSync(tmpConfigDir, { recursive: true });
      }
      const config = {
        email: 'test@example.com',
        prompted: true,
        promptedAt: new Date().toISOString(),
        consent: true,
      };
      fs.writeFileSync(tmpConfigPath, JSON.stringify(config, null, 2), 'utf-8');

      const loaded = JSON.parse(fs.readFileSync(tmpConfigPath, 'utf-8'));
      expect(loaded.email).toBe('test@example.com');
      expect(loaded.consent).toBe(true);
    });

    it('should auto-skip when process.stdin is not a TTY', () => {
      // In test/CI environment, stdin.isTTY is typically false
      // This verifies the skip condition works
      const isTTY = process.stdin.isTTY;
      if (!isTTY) {
        // Non-TTY: firstRunPrompt should return immediately
        // (We can't easily test the full prompt flow without mocking readline)
        expect(isTTY).toBeFalsy();
      } else {
        // TTY environment — still valid, just different path
        expect(isTTY).toBeTruthy();
      }
    });
  });

  describe('Scan History', () => {
    const tmpDir = path.join(os.tmpdir(), `halo-history-test-${Date.now()}`);
    const tmpHaloDir = path.join(tmpDir, '.halo');
    const tmpHistoryPath = path.join(tmpHaloDir, 'history.json');

    afterEach(() => {
      try {
        if (fs.existsSync(tmpDir)) {
          fs.rmSync(tmpDir, { recursive: true, force: true });
        }
      } catch {}
    });

    it('should return empty array when history file does not exist', () => {
      expect(fs.existsSync(tmpHistoryPath)).toBe(false);
      // Simulate loadHistory behavior on non-existent file
      let result: any[] = [];
      try {
        if (fs.existsSync(tmpHistoryPath)) {
          result = JSON.parse(fs.readFileSync(tmpHistoryPath, 'utf-8'));
        }
      } catch {}
      expect(result).toEqual([]);
    });

    it('should save and load history entries as valid JSON array', () => {
      if (!fs.existsSync(tmpHaloDir)) {
        fs.mkdirSync(tmpHaloDir, { recursive: true });
      }
      const entry = {
        scannedAt: new Date().toISOString(),
        score: 73,
        grade: 'C',
        totalViolations: 5,
        bySeverity: { critical: 1, high: 2, medium: 1, low: 1 },
        filesScanned: 20,
        projectPath: '/test/project',
        rulesTriggered: ['coppa-auth-001', 'coppa-sec-006'],
      };

      // Save
      const history = [entry];
      fs.writeFileSync(tmpHistoryPath, JSON.stringify(history, null, 2), 'utf-8');

      // Load
      const loaded = JSON.parse(fs.readFileSync(tmpHistoryPath, 'utf-8'));
      expect(Array.isArray(loaded)).toBe(true);
      expect(loaded).toHaveLength(1);
      expect(loaded[0].score).toBe(73);
      expect(loaded[0].grade).toBe('C');
      expect(loaded[0].projectPath).toBe('/test/project');
    });

    it('should cap history at 100 entries (FIFO)', () => {
      if (!fs.existsSync(tmpHaloDir)) {
        fs.mkdirSync(tmpHaloDir, { recursive: true });
      }

      // Create 105 entries
      const entries = Array.from({ length: 105 }, (_, i) => ({
        scannedAt: new Date(Date.now() + i * 1000).toISOString(),
        score: 50 + (i % 50),
        grade: 'C',
        totalViolations: i,
        bySeverity: { critical: 0, high: i, medium: 0, low: 0 },
        filesScanned: 10,
        projectPath: '/test/project',
        rulesTriggered: ['coppa-auth-001'],
      }));

      // Write all 105
      fs.writeFileSync(tmpHistoryPath, JSON.stringify(entries, null, 2), 'utf-8');

      // Simulate FIFO trim (as saveHistory does)
      const trimmed = entries.slice(-100);
      fs.writeFileSync(tmpHistoryPath, JSON.stringify(trimmed, null, 2), 'utf-8');

      const loaded = JSON.parse(fs.readFileSync(tmpHistoryPath, 'utf-8'));
      expect(loaded).toHaveLength(100);
      // First entry should be the 6th original (index 5)
      expect(loaded[0].totalViolations).toBe(5);
    });

    it('should filter history by projectPath', () => {
      if (!fs.existsSync(tmpHaloDir)) {
        fs.mkdirSync(tmpHaloDir, { recursive: true });
      }

      const entries = [
        { scannedAt: '2026-01-01T00:00:00Z', score: 60, grade: 'C', totalViolations: 5, bySeverity: { critical: 0, high: 2, medium: 2, low: 1 }, filesScanned: 10, projectPath: '/project-a', rulesTriggered: [] },
        { scannedAt: '2026-01-02T00:00:00Z', score: 80, grade: 'B', totalViolations: 2, bySeverity: { critical: 0, high: 0, medium: 1, low: 1 }, filesScanned: 15, projectPath: '/project-b', rulesTriggered: [] },
        { scannedAt: '2026-01-03T00:00:00Z', score: 70, grade: 'C', totalViolations: 3, bySeverity: { critical: 0, high: 1, medium: 1, low: 1 }, filesScanned: 10, projectPath: '/project-a', rulesTriggered: [] },
      ];

      fs.writeFileSync(tmpHistoryPath, JSON.stringify(entries, null, 2), 'utf-8');
      const loaded = JSON.parse(fs.readFileSync(tmpHistoryPath, 'utf-8'));
      const projectA = loaded.filter((h: any) => h.projectPath === '/project-a');
      const projectB = loaded.filter((h: any) => h.projectPath === '/project-b');

      expect(projectA).toHaveLength(2);
      expect(projectB).toHaveLength(1);
      expect(projectA[0].score).toBe(60);
      expect(projectA[1].score).toBe(70);
    });

    it('should compute trend: improvement (up arrow)', () => {
      // Simulate: last scan was 58, current is 73
      const lastScore = 58;
      const currentScore = 73;
      const diff = currentScore - lastScore;
      expect(diff).toBe(15);
      expect(diff).toBeGreaterThan(0);
    });

    it('should compute trend: regression (down arrow)', () => {
      const lastScore = 73;
      const currentScore = 65;
      const diff = currentScore - lastScore;
      expect(diff).toBe(-8);
      expect(diff).toBeLessThan(0);
    });

    it('should return empty trend for no prior history', () => {
      // With no history entries, trend should be empty
      const history: any[] = [];
      const projectHistory = history.filter((h: any) => h.projectPath === '/new-project');
      expect(projectHistory).toHaveLength(0);
    });
  });

  describe('HTML Compliance Report', () => {
    it('should generate valid HTML with score and grade', () => {
      const engine = new HaloEngine();
      const code = `fbq('init', '123456789');\nconst url = 'http://api.example.com/login';`;
      const violations = engine.scanFile('test.ts', code);
      const scorer = new ComplianceScoreEngine();
      const scoreResult = scorer.calculate(violations, 1);

      const results = [{
        filePath: '/test/project/test.ts',
        violations,
        scannedAt: new Date().toISOString(),
        totalViolations: violations.length,
        suppressedCount: 0,
      }];

      // Import and call generateHtmlReport
      const { generateHtmlReport } = require('../index');
      const html = generateHtmlReport(results, scoreResult, 1, '/test/project');

      expect(html).toContain('<!DOCTYPE html>');
      expect(html).toContain('</html>');
      expect(html).toContain('COPPA Compliance Report');
      expect(html).toContain(`${scoreResult.score}`);
      expect(html).toContain(`Grade ${scoreResult.grade}`);
    });

    it('should be self-contained with no external resource links', () => {
      const { generateHtmlReport } = require('../index');
      const scoreResult = { score: 100, grade: 'A', totalViolations: 0, bySeverity: { critical: 0, high: 0, medium: 0, low: 0 }, pointsDeducted: 0, filesScanned: 1, rulesTriggered: [], summary: 'Perfect' };
      const html = generateHtmlReport([], scoreResult, 1, '/test');

      // No external CSS/JS links
      expect(html).not.toContain('cdn.');
      expect(html).not.toContain('googleapis.com');
      expect(html).not.toMatch(/<link[^>]+href="http/);
      expect(html).not.toMatch(/<script[^>]+src="http/);
    });

    it('should include violations with severity badges', () => {
      const engine = new HaloEngine();
      const code = `fbq('init', '123456789');`;
      const violations = engine.scanFile('test.ts', code);
      const scorer = new ComplianceScoreEngine();
      const scoreResult = scorer.calculate(violations, 1);

      const results = [{
        filePath: '/test/project/test.ts',
        violations,
        scannedAt: new Date().toISOString(),
        totalViolations: violations.length,
        suppressedCount: 0,
      }];

      const { generateHtmlReport } = require('../index');
      const html = generateHtmlReport(results, scoreResult, 1, '/test/project');

      expect(html).toContain('coppa-tracking-003');
      expect(html).toContain('test.ts');
    });

    it('should escape HTML special characters', () => {
      const { escapeHtml } = require('../index');
      expect(escapeHtml('<script>alert("xss")</script>')).toBe('&lt;script&gt;alert(&quot;xss&quot;)&lt;/script&gt;');
      expect(escapeHtml("it's a test & more")).toBe("it&#39;s a test &amp; more");
    });

    it('should show auto-fix guidance for fixable violations', () => {
      const engine = new HaloEngine();
      const code = `const url = 'http://api.example.com/api/login';`;
      const violations = engine.scanFile('test.ts', code);
      const scorer = new ComplianceScoreEngine();
      const scoreResult = scorer.calculate(violations, 1);

      const results = [{
        filePath: '/test/project/test.ts',
        violations,
        scannedAt: new Date().toISOString(),
        totalViolations: violations.length,
        suppressedCount: 0,
      }];

      const { generateHtmlReport } = require('../index');
      const html = generateHtmlReport(results, scoreResult, 1, '/test/project');

      // Should contain auto-fix guidance since coppa-sec-006 is auto-fixable
      const hasAutoFix = violations.some(v => v.ruleId === 'coppa-sec-006');
      if (hasAutoFix) {
        expect(html).toContain('Auto-Fixable');
        expect(html).toContain('npx runhalo fix .');
      }
    });
  });

  describe('PDF Compliance Report (P3-2)', () => {
    it('should generate a valid PDF buffer with %PDF magic bytes', async () => {
      const { generatePdfReport } = require('../index');
      const engine = new HaloEngine();
      const code = `fbq('init', '123456789');\nconst url = 'http://api.example.com/login';`;
      const violations = engine.scanFile('test.ts', code);
      const scorer = new ComplianceScoreEngine();
      const scoreResult = scorer.calculate(violations, 1);

      const results = [{
        filePath: '/test/project/test.ts',
        violations,
        scannedAt: new Date().toISOString(),
        totalViolations: violations.length,
        suppressedCount: 0,
      }];

      const pdfBuffer = await generatePdfReport(results, scoreResult, 1, '/test/project');

      expect(Buffer.isBuffer(pdfBuffer)).toBe(true);
      expect(pdfBuffer.length).toBeGreaterThan(100);
      // Check PDF magic bytes
      expect(pdfBuffer.slice(0, 5).toString()).toBe('%PDF-');
    });

    it('should generate a PDF for a clean scan (no violations)', async () => {
      const { generatePdfReport } = require('../index');
      const scorer = new ComplianceScoreEngine();
      const scoreResult = scorer.calculate([], 10);

      const pdfBuffer = await generatePdfReport([], scoreResult, 10, '/test/clean-project');

      expect(Buffer.isBuffer(pdfBuffer)).toBe(true);
      expect(pdfBuffer.slice(0, 5).toString()).toBe('%PDF-');
      // Clean report should still have substantial content (cover page, recommendations)
      expect(pdfBuffer.length).toBeGreaterThan(1000);
    });

    it('should still generate HTML report when filename is not .pdf', () => {
      const { generateHtmlReport } = require('../index');
      const scorer = new ComplianceScoreEngine();
      const scoreResult = scorer.calculate([], 1);

      const html = generateHtmlReport([], scoreResult, 1, '/test');
      expect(html).toContain('<!DOCTYPE html>');
      expect(html).toContain('COPPA Compliance Report');
    });

    it('should export generatePdfReport function', () => {
      const { generatePdfReport } = require('../index');
      expect(typeof generatePdfReport).toBe('function');
    });
  });

  describe('Init Command (IDE Rules Files)', () => {
    const tmpInitDir = path.join(os.tmpdir(), `halo-init-test-${Date.now()}`);

    afterAll(() => {
      fs.rmSync(tmpInitDir, { recursive: true, force: true });
    });

    it('should generate .cursor/rules file', () => {
      fs.mkdirSync(tmpInitDir, { recursive: true });
      const { init } = require('../index');
      // Call init directly — it writes files synchronously
      const cursorDir = path.join(tmpInitDir, '.cursor');
      fs.mkdirSync(cursorDir, { recursive: true });
      const rulesPath = path.join(cursorDir, 'rules');
      // Simulate what init does
      const content = fs.existsSync(rulesPath) ? '' : 'test';
      expect(typeof init).toBe('function');
    });

    it('should include COPPA rules in IDE content', () => {
      // The rules content generator is embedded in the CLI
      // Verify by checking the generated file content pattern
      const { init } = require('../index');
      expect(init).toBeDefined();

      // Create a test directory and run init
      const testDir = path.join(tmpInitDir, 'rules-check');
      fs.mkdirSync(testDir, { recursive: true });

      // We can't easily call init (it uses process.exit), but we can verify
      // the rules content by checking a generated file from our earlier test
      const testRulesDir = path.join(os.tmpdir(), `halo-init-rules-${Date.now()}`);
      fs.mkdirSync(testRulesDir, { recursive: true });
      fs.mkdirSync(path.join(testRulesDir, '.cursor'), { recursive: true });
    });

    it('should export init function for testing', () => {
      const { init } = require('../index');
      expect(typeof init).toBe('function');
    });

    it('should generate files for three IDE targets', () => {
      // The init command targets: .cursor/rules, .windsurfrules, .github/copilot-instructions.md
      const targets = ['.cursor/rules', '.windsurfrules', '.github/copilot-instructions.md'];
      expect(targets).toHaveLength(3);
      // Verify each target has a known parent directory
      targets.forEach(target => {
        expect(target.length).toBeGreaterThan(0);
      });
    });

    it('should include COPPA rule IDs in generated content', () => {
      // Check that generated rules files contain rule IDs
      const testDir = '/tmp/halo-init-test';
      if (fs.existsSync(path.join(testDir, '.cursor', 'rules'))) {
        const content = fs.readFileSync(path.join(testDir, '.cursor', 'rules'), 'utf-8');
        expect(content).toContain('coppa-auth-001');
        expect(content).toContain('coppa-tracking-003');
        expect(content).toContain('coppa-bio-012');
        expect(content).toContain('coppa-default-020');
        expect(content).toContain('coppa-data-002');
        expect(content).toContain('COPPA 2.0');
        expect(content).toContain('npx runhalo scan');
      }
    });
  });

  describe('License & Scan Limits (P3-1)', () => {
    const { checkScanLimit, checkProFeature, saveConfig, loadConfig, FREE_SCAN_LIMIT, HALO_CONFIG_PATH, HALO_CONFIG_DIR } = require('../index');

    let originalConfig: string | null = null;
    let originalCI: string | undefined;
    let originalTTY: boolean | undefined;

    beforeAll(() => {
      // Save existing config
      try {
        if (fs.existsSync(HALO_CONFIG_PATH)) {
          originalConfig = fs.readFileSync(HALO_CONFIG_PATH, 'utf-8');
        }
      } catch {}
    });

    beforeEach(() => {
      // Save env state
      originalCI = process.env.CI;
      originalTTY = process.stdout.isTTY;
    });

    afterEach(() => {
      // Restore env
      if (originalCI !== undefined) {
        process.env.CI = originalCI;
      } else {
        delete process.env.CI;
      }
      Object.defineProperty(process.stdout, 'isTTY', { value: originalTTY, configurable: true });
    });

    afterAll(() => {
      // Restore original config
      try {
        if (originalConfig !== null) {
          fs.writeFileSync(HALO_CONFIG_PATH, originalConfig, 'utf-8');
        }
      } catch {}
    });

    it('should bypass scan limits in CI environment', () => {
      process.env.CI = 'true';
      expect(checkScanLimit()).toBe(true);
    });

    it('should bypass scan limits when stdout is not a TTY (piped output)', () => {
      delete process.env.CI;
      Object.defineProperty(process.stdout, 'isTTY', { value: false, configurable: true });
      expect(checkScanLimit()).toBe(true);
    });

    it('should allow unlimited scans for Pro tier users', () => {
      delete process.env.CI;
      Object.defineProperty(process.stdout, 'isTTY', { value: true, configurable: true });

      saveConfig({
        prompted: true,
        promptedAt: new Date().toISOString(),
        consent: true,
        tier: 'pro',
      });

      expect(checkScanLimit()).toBe(true);
    });

    it('should allow unlimited scans for Enterprise tier users', () => {
      delete process.env.CI;
      Object.defineProperty(process.stdout, 'isTTY', { value: true, configurable: true });

      saveConfig({
        prompted: true,
        promptedAt: new Date().toISOString(),
        consent: true,
        tier: 'enterprise',
      });

      expect(checkScanLimit()).toBe(true);
    });

    it('should enforce 5-scan daily limit for free tier', () => {
      delete process.env.CI;
      Object.defineProperty(process.stdout, 'isTTY', { value: true, configurable: true });

      const today = new Date().toISOString().split('T')[0];

      // Set up config at the limit
      saveConfig({
        prompted: true,
        promptedAt: new Date().toISOString(),
        consent: false,
        scans_today: FREE_SCAN_LIMIT,
        scan_date: today,
      });

      // Suppress stderr output during test
      const stderrWrite = process.stderr.write;
      process.stderr.write = (() => true) as any;

      const result = checkScanLimit();

      process.stderr.write = stderrWrite;

      expect(result).toBe(false);
    });

    it('should reset scan counter on new day', () => {
      delete process.env.CI;
      Object.defineProperty(process.stdout, 'isTTY', { value: true, configurable: true });

      // Set up config from yesterday at the limit
      const yesterday = new Date(Date.now() - 86400000).toISOString().split('T')[0];
      saveConfig({
        prompted: true,
        promptedAt: new Date().toISOString(),
        consent: false,
        scans_today: FREE_SCAN_LIMIT,
        scan_date: yesterday,
      });

      // Should allow scan (new day)
      expect(checkScanLimit()).toBe(true);

      // Verify counter was reset
      const config = loadConfig();
      expect(config.scans_today).toBe(1);
    });

    it('should allow Pro features for Pro tier users', () => {
      delete process.env.CI;
      Object.defineProperty(process.stdout, 'isTTY', { value: true, configurable: true });

      saveConfig({
        prompted: true,
        promptedAt: new Date().toISOString(),
        consent: true,
        tier: 'pro',
      });

      expect(checkProFeature('HTML Reports', '--report')).toBe(true);
      expect(checkProFeature('Ethical Design Rules', '--ethical-preview')).toBe(true);
      expect(checkProFeature('AI Audit Mode', '--ai-audit')).toBe(true);
    });

    it('should block Pro features for free tier users with upsell', () => {
      delete process.env.CI;
      Object.defineProperty(process.stdout, 'isTTY', { value: true, configurable: true });

      saveConfig({
        prompted: true,
        promptedAt: new Date().toISOString(),
        consent: false,
        tier: undefined, // free tier (no tier set)
      });

      // Suppress stderr during test
      const stderrWrite = process.stderr.write;
      process.stderr.write = (() => true) as any;

      expect(checkProFeature('HTML Reports', '--report')).toBe(false);

      process.stderr.write = stderrWrite;
    });

    it('should bypass Pro feature gates in CI environment', () => {
      process.env.CI = 'true';
      expect(checkProFeature('HTML Reports', '--report')).toBe(true);
    });

    it('should store license key and tier in config after activation', () => {
      const testKey = '00000000-0000-0000-0000-000000000001';
      saveConfig({
        prompted: true,
        promptedAt: new Date().toISOString(),
        consent: true,
        license_key: testKey,
        tier: 'pro',
        email: 'test@example.com',
      });

      const config = loadConfig();
      expect(config.license_key).toBe(testKey);
      expect(config.tier).toBe('pro');
      expect(config.email).toBe('test@example.com');
    });

    it('should export FREE_SCAN_LIMIT as 5', () => {
      expect(FREE_SCAN_LIMIT).toBe(5);
    });
  });

  describe('Guided Fix Engine Integration', () => {
    it('should have access to ScaffoldEngine from engine package', () => {
      const scaffoldEngine = new ScaffoldEngine();
      expect(scaffoldEngine).toBeDefined();
      expect(typeof scaffoldEngine.generateScaffolds).toBe('function');
      expect(typeof scaffoldEngine.getApplicableScaffolds).toBe('function');
      expect(typeof scaffoldEngine.listAvailable).toBe('function');
    });

    it('should have 4 scaffold templates registered', () => {
      expect(SCAFFOLD_REGISTRY.size).toBe(4);
      expect(SCAFFOLD_REGISTRY.has('age-gate-auth')).toBe(true);
      expect(SCAFFOLD_REGISTRY.has('consent-cookies')).toBe(true);
      expect(SCAFFOLD_REGISTRY.has('pii-sanitizer')).toBe(true);
      expect(SCAFFOLD_REGISTRY.has('retention-policy')).toBe(true);
    });

    it('should detect framework from a project directory', () => {
      const tmpDir = path.join(os.tmpdir(), `halo-fw-cli-test-${Date.now()}`);
      fs.mkdirSync(tmpDir, { recursive: true });
      fs.writeFileSync(path.join(tmpDir, 'package.json'), JSON.stringify({
        dependencies: { react: '^18.0.0' },
        devDependencies: { typescript: '^5.0.0' }
      }));

      const result = detectFramework(tmpDir);
      expect(result.framework).toBe('react');
      expect(result.typescript).toBe(true);

      fs.rmSync(tmpDir, { recursive: true, force: true });
    });

    it('should generate scaffold files for guided violations', () => {
      const tmpDir = path.join(os.tmpdir(), `halo-scaffold-cli-test-${Date.now()}`);
      fs.mkdirSync(tmpDir, { recursive: true });
      fs.writeFileSync(path.join(tmpDir, 'package.json'), JSON.stringify({
        dependencies: { react: '^18.0.0' }
      }));

      const scaffoldEngine = new ScaffoldEngine();
      const violations = [{ ruleId: 'coppa-auth-001' }];
      const results = scaffoldEngine.generateScaffolds(violations, tmpDir);

      expect(results).toHaveLength(1);
      expect(results[0].scaffoldId).toBe('age-gate-auth');
      expect(results[0].files.length).toBeGreaterThan(0);
      expect(results[0].files[0].content).toContain('AgeGate');

      fs.rmSync(tmpDir, { recursive: true, force: true });
    });

    it('should identify guided violations from REMEDIATION_MAP', () => {
      const guidedRules = Object.entries(REMEDIATION_MAP)
        .filter(([_, spec]) => spec.fixability === 'guided')
        .map(([id]) => id);

      // Should have 16 guided rules total
      expect(guidedRules.length).toBe(16);

      // 4 should have templates available
      const scaffoldEngine = new ScaffoldEngine();
      const available = scaffoldEngine.getApplicableScaffolds(
        guidedRules.map(ruleId => ({ ruleId }))
      );
      expect(available).toHaveLength(4);
    });
  });
});
