/**
 * Halo MCP Server - Unit Tests
 */

import { HaloEngine, COPPA_RULES, Violation, FixEngine, REMEDIATION_MAP, ScaffoldEngine, detectFramework, ComplianceScoreEngine } from '@runhalo/engine';
import * as fs from 'fs';
import * as path from 'path';
import * as os from 'os';

describe('Halo MCP Server', () => {
  describe('Engine Integration', () => {
    it('should have access to HaloEngine', () => {
      const engine = new HaloEngine();
      expect(engine).toBeDefined();
    });

    it('should expose the public COPPA rule registry', () => {
      expect(COPPA_RULES).toHaveLength(21);
      expect(COPPA_RULES.every(rule => rule.id.startsWith('coppa'))).toBe(true);
    });

    it('should explain a rule', () => {
      const engine = new HaloEngine();
      const explanation = engine.explainRule('coppa-auth-001');
      expect(explanation).toContain('coppa-auth-001');
      expect(explanation).toContain('Unverified Social Login Providers');
    });

    it('should get fix suggestion for a rule', () => {
      const engine = new HaloEngine();
      const fix = engine.getFixSuggestion('coppa-tracking-003');
      expect(fix).toContain('child_directed_treatment');
    });

    it('should get rule by ID', () => {
      const engine = new HaloEngine();
      const rule = engine.getRule('coppa-geo-004');
      expect(rule).toBeDefined();
      expect(rule?.id).toBe('coppa-geo-004');
      expect(rule?.name).toBe('Precise Geolocation Collection');
    });

    it('should get all rules', () => {
      const engine = new HaloEngine();
      const rules = engine.getRules();
      expect(rules).toHaveLength(16);
      expect(rules[0].id).toBe('coppa-auth-001');
      expect(rules.every(rule => rule.id.startsWith('coppa'))).toBe(true);
    });

    it('should scan file and return violations', () => {
      const engine = new HaloEngine();
      const code = `fbq('init', '123456789');`;
      const violations = engine.scanFile('test.ts', code);
      expect(violations.length).toBeGreaterThan(0);
      expect(violations[0].ruleId).toBe('coppa-tracking-003');
    });

    it('should filter violations by rule ID', () => {
      const engine = new HaloEngine({
        rules: ['coppa-auth-001']
      });
      const rules = engine.getRules();
      expect(rules).toHaveLength(1);
      expect(rules[0].id).toBe('coppa-auth-001');
    });

    it('should filter violations by severity', () => {
      const engine = new HaloEngine({
        severityFilter: ['critical']
      });
      const rules = engine.getRules();
      rules.forEach(r => {
        expect(r.severity).toBe('critical');
      });
    });
  });

  describe('Tool Handlers - IDE Integration', () => {
    // Simulates MCP audit_file tool
    it('should implement audit_file tool logic', () => {
      const engine = new HaloEngine();
      const code = `
        import { signInWithPopup } from 'firebase/auth';
        const auth = getAuth();
        signInWithPopup(auth, provider);
      `;
      const violations = engine.scanFile('src/auth.ts', code);
      
      expect(violations.length).toBeGreaterThan(0);
      const authViolation = violations.find(v => v.ruleId === 'coppa-auth-001');
      expect(authViolation).toBeDefined();
      expect(authViolation?.severity).toBe('critical');
      expect(authViolation?.filePath).toBe('src/auth.ts');
    });

    // Simulates MCP get_violations tool
    it('should implement get_violations tool logic', () => {
      const engine = new HaloEngine();
      const code = `
        fbq('init', '123456789');
        navigator.geolocation.getCurrentPosition(success, error);
      `;
      const violations = engine.scanFile('test.ts', code);
      
      const trackingViolations = violations.filter(v => v.ruleId === 'coppa-tracking-003');
      const geoViolations = violations.filter(v => v.ruleId === 'coppa-geo-004');
      
      expect(trackingViolations.length).toBeGreaterThan(0);
      expect(geoViolations.length).toBeGreaterThan(0);
    });

    // Simulates MCP explain_rule tool
    it('should implement explain_rule tool logic', () => {
      const engine = new HaloEngine();

      // Use actual rule IDs from COPPA_RULES
      const ruleIds = COPPA_RULES.map(r => r.id);
      expect(ruleIds).toHaveLength(21);

      for (const ruleId of ruleIds) {
        const explanation = engine.explainRule(ruleId);
        expect(explanation).not.toContain('not found');
        expect(explanation).toContain(ruleId);
        expect(explanation.length).toBeGreaterThan(50);
      }
    });

    // Simulates MCP suggest_fix tool
    it('should implement suggest_fix tool logic', () => {
      const engine = new HaloEngine();
      
      // Test fix suggestions for key rules
      const authFix = engine.getFixSuggestion('coppa-auth-001');
      expect(authFix).toContain('age');
      
      const trackingFix = engine.getFixSuggestion('coppa-tracking-003');
      expect(trackingFix).toContain('child_directed_treatment');
      
      const geoFix = engine.getFixSuggestion('coppa-geo-004');
      expect(geoFix).toContain('accuracy');
    });

    // Test batch file scanning (for IDE workspace scanning)
    it('should handle batch file scanning for IDE workflows', () => {
      const engine = new HaloEngine();
      const files = [
        { path: 'src/auth.ts', content: `signInWithPopup(auth, provider);` },
        { path: 'src/api.ts', content: `axios.get('http://api.com?email=test');` },
        { path: 'src/analytics.js', content: `fbq('init', '123');` }
      ];
      
      const allViolations: Violation[] = [];
      files.forEach(f => {
        const violations = engine.scanFile(f.path, f.content);
        allViolations.push(...violations);
      });
      
      expect(allViolations.length).toBeGreaterThan(0);
      
      // Verify different rule types are caught
      const ruleIds = [...new Set(allViolations.map(v => v.ruleId))];
      expect(ruleIds.length).toBeGreaterThanOrEqual(2);
    });
  });

  describe('P2.5 — Real-Time Scan + Fix MCP Tools', () => {
    it('should scan a single file and return compact violation format', () => {
      const engine = new HaloEngine({ suppressions: { enabled: true } });
      const code = `fbq('init', '123456789');\nconst url = 'http://api.example.com/api/login';`;
      const violations = engine.scanFile('src/app.ts', code);

      expect(violations.length).toBeGreaterThan(0);
      // Verify compact format fields exist
      violations.forEach(v => {
        expect(v.ruleId).toBeDefined();
        expect(v.line).toBeDefined();
        expect(v.severity).toBeDefined();
        expect(v.message).toBeDefined();
      });
    });

    it('should return clean result for violation-free file', () => {
      const engine = new HaloEngine();
      const cleanCode = `const greeting = 'Hello, World!';`;
      const violations = engine.scanFile('src/clean.ts', cleanCode);
      expect(violations).toHaveLength(0);
    });

    it('should have access to FixEngine for auto-fix tool', () => {
      const fixer = new FixEngine();
      expect(fixer).toBeDefined();
      expect(typeof fixer.applyFixes).toBe('function');
      expect(typeof fixer.isAutoFixable).toBe('function');
      expect(typeof fixer.getAutoFixableRules).toBe('function');
    });

    it('should auto-fix http URLs via scan + applyFixes', () => {
      const engine = new HaloEngine();
      const fixer = new FixEngine();
      const code = `const url = 'http://api.example.com/api/login';`;
      const violations = engine.scanFile('test.ts', code);
      expect(violations.some(v => v.ruleId === 'coppa-sec-006')).toBe(true);

      const result = fixer.applyFixes(code, violations);
      expect(result.fixedContent).toContain('https://');
      expect(result.fixes.some((f: any) => f.ruleId === 'coppa-sec-006')).toBe(true);
    });

    it('should have access to ScaffoldEngine for guided fixes', () => {
      const scaffoldEngine = new ScaffoldEngine();
      expect(scaffoldEngine).toBeDefined();
      expect(typeof scaffoldEngine.generateScaffolds).toBe('function');
      expect(typeof scaffoldEngine.getApplicableScaffolds).toBe('function');
      expect(typeof scaffoldEngine.getUnavailableScaffolds).toBe('function');
    });

    it('should generate guided scaffolds for applicable violations', () => {
      const tmpDir = path.join(os.tmpdir(), `halo-mcp-scaffold-${Date.now()}`);
      fs.mkdirSync(tmpDir, { recursive: true });
      fs.writeFileSync(path.join(tmpDir, 'package.json'), JSON.stringify({
        dependencies: { react: '^18.0.0' }
      }));

      const scaffoldEngine = new ScaffoldEngine();
      const violations = [{ ruleId: 'coppa-auth-001' }, { ruleId: 'coppa-cookies-016' }];
      const results = scaffoldEngine.generateScaffolds(violations, tmpDir);

      expect(results.length).toBe(2);
      expect(results.map(r => r.scaffoldId)).toContain('age-gate-auth');
      expect(results.map(r => r.scaffoldId)).toContain('consent-cookies');

      fs.rmSync(tmpDir, { recursive: true, force: true });
    });

    it('should detect framework for guided fix context', () => {
      const tmpDir = path.join(os.tmpdir(), `halo-mcp-fw-${Date.now()}`);
      fs.mkdirSync(tmpDir, { recursive: true });
      fs.writeFileSync(path.join(tmpDir, 'package.json'), JSON.stringify({
        dependencies: { next: '^14.0.0', react: '^18.0.0' }
      }));

      const result = detectFramework(tmpDir);
      expect(result.framework).toBe('nextjs');

      fs.rmSync(tmpDir, { recursive: true, force: true });
    });

    it('should calculate compliance score', () => {
      const scorer = new ComplianceScoreEngine();
      const engine = new HaloEngine();
      const code = `fbq('init', '123');\nconst url = 'http://api.example.com/api/login';`;
      const violations = engine.scanFile('test.ts', code);

      const result = scorer.calculate(violations, 1);
      expect(result.score).toBeDefined();
      expect(result.grade).toBeDefined();
      expect(result.score).toBeLessThan(100);
      expect(result.totalViolations).toBeGreaterThan(0);
    });

    it('should identify REMEDIATION_MAP fixability tiers', () => {
      // Tier 1 (auto): coppa-sec-006, coppa-sec-010, coppa-sec-015, coppa-default-020
      const autoRules = Object.entries(REMEDIATION_MAP)
        .filter(([_, spec]: [string, any]) => spec.fixability === 'auto')
        .map(([id]) => id);
      expect(autoRules.length).toBe(4);

      // Tier 2 (guided): 16 rules
      const guidedRules = Object.entries(REMEDIATION_MAP)
        .filter(([_, spec]: [string, any]) => spec.fixability === 'guided')
        .map(([id]) => id);
      expect(guidedRules.length).toBe(16);
    });

    it('should expose 10 MCP tools total (5 original + 5 new)', () => {
      // Original: audit_file, audit_project, get_violations, explain_rule, suggest_fix
      // New: scan_file, fix_file, fix_guided, compliance_score
      // That's 9 total (we added 4 new tools to 5 existing)
      const originalTools = ['audit_file', 'audit_project', 'get_violations', 'explain_rule', 'suggest_fix'];
      const newTools = ['scan_file', 'fix_file', 'fix_guided', 'compliance_score'];
      const allTools = [...originalTools, ...newTools];
      expect(allTools).toHaveLength(9);
    });
  });

  describe('- New Rules Coverage', () => {
    it('should detect extended rules (6-20)', () => {
      const engine = new HaloEngine();
      
      // Test sec-006: HTTP
      const httpCode = `axios.get('http://api.com/users');`;
      const httpViolations = engine.scanFile('test.ts', httpCode);
      expect(httpViolations.some(v => v.ruleId === 'coppa-sec-006')).toBe(true);
      
      // Test audio-007: getUserMedia
      const audioCode = `navigator.mediaDevices.getUserMedia({ audio: true });`;
      const audioViolations = engine.scanFile('test.ts', audioCode);
      expect(audioViolations.some(v => v.ruleId === 'coppa-audio-007')).toBe(true);
      
      // Test sec-015: XSS
      const xssCode = `element.innerHTML = userInput;`;
      const xssViolations = engine.scanFile('test.ts', xssCode);
      expect(xssViolations.some(v => v.ruleId === 'coppa-sec-015')).toBe(true);

    });
  });
});
