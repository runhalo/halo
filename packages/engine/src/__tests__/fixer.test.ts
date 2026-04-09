/**
 * Halo Fix Engine — Unit Tests
 * Tests for Tier 1 auto-fix transforms + FixEngine class
 */

import {
  FixEngine,
  transformUrlUpgrade,
  transformRemoveDefault,
  transformSanitizeInput,
  transformSetDefault,
  REMEDIATION_MAP,
} from '../index';
import { HaloEngine } from '../index';
import type { Violation } from '../index';

// Helper to create a minimal violation for transform testing
function makeViolation(overrides: Partial<Violation>): Violation {
  return {
    ruleId: '',
    ruleName: '',
    severity: 'medium',
    filePath: 'test.ts',
    line: 1,
    column: 1,
    message: '',
    codeSnippet: '',
    fixSuggestion: '',
    ...overrides,
  };
}

// ==================== REMEDIATION_MAP ====================

describe('REMEDIATION_MAP', () => {
  it('should have exactly 4 auto-fixable rules', () => {
    const autoRules = Object.values(REMEDIATION_MAP).filter(s => s.fixability === 'auto');
    expect(autoRules).toHaveLength(4);
  });

  it('should classify coppa-sec-006 as auto with url-upgrade', () => {
    const spec = REMEDIATION_MAP['coppa-sec-006'];
    expect(spec.fixability).toBe('auto');
    expect(spec.transformType).toBe('url-upgrade');
  });

  it('should classify coppa-sec-015 as auto with sanitize-input', () => {
    const spec = REMEDIATION_MAP['coppa-sec-015'];
    expect(spec.fixability).toBe('auto');
    expect(spec.transformType).toBe('sanitize-input');
  });

  it('should classify coppa-cookies-016 as guided (not auto)', () => {
    const spec = REMEDIATION_MAP['coppa-cookies-016'];
    expect(spec.fixability).toBe('guided');
    expect(spec.scaffoldId).toBe('consent-cookies');
  });

  it('should classify coppa-auth-001 as guided', () => {
    expect(REMEDIATION_MAP['coppa-auth-001'].fixability).toBe('guided');
  });

  it('should have all 5 ethical rules as flag-only', () => {
    const flagOnly = Object.entries(REMEDIATION_MAP)
      .filter(([id]) => id.startsWith('ETHICAL'))
      .every(([, spec]) => spec.fixability === 'flag-only');
    expect(flagOnly).toBe(true);
  });
});

// ==================== FixEngine Class ====================

describe('FixEngine', () => {
  let fixer: FixEngine;

  beforeEach(() => {
    fixer = new FixEngine();
  });

  describe('isRuleAutoFixable', () => {
    it('should return true for the 4 Tier 1 rules', () => {
      expect(fixer.isRuleAutoFixable('coppa-sec-006')).toBe(true);
      expect(fixer.isRuleAutoFixable('coppa-sec-010')).toBe(true);
      expect(fixer.isRuleAutoFixable('coppa-sec-015')).toBe(true);
      expect(fixer.isRuleAutoFixable('coppa-default-020')).toBe(true);
    });

    it('should return false for guided rules', () => {
      expect(fixer.isRuleAutoFixable('coppa-auth-001')).toBe(false);
      expect(fixer.isRuleAutoFixable('coppa-cookies-016')).toBe(false);
    });

    it('should return false for unknown rules', () => {
      expect(fixer.isRuleAutoFixable('coppa-fake-999')).toBe(false);
    });
  });

  describe('getAutoFixableRules', () => {
    it('should return exactly 4 rule IDs', () => {
      const rules = fixer.getAutoFixableRules();
      expect(rules).toHaveLength(4);
      expect(rules).toContain('coppa-sec-006');
      expect(rules).toContain('coppa-sec-010');
      expect(rules).toContain('coppa-sec-015');
      expect(rules).toContain('coppa-default-020');
    });

    it('should NOT contain coppa-cookies-016', () => {
      expect(fixer.getAutoFixableRules()).not.toContain('coppa-cookies-016');
    });
  });
});

// ==================== Transform: url-upgrade (coppa-sec-006) ====================

describe('Transform: url-upgrade (coppa-sec-006)', () => {
  const v = makeViolation({ ruleId: 'coppa-sec-006' });

  it('should replace http:// with https://', () => {
    expect(transformUrlUpgrade("const url = 'http://api.example.com/users';", v))
      .toBe("const url = 'https://api.example.com/users';");
  });

  it('should replace multiple http:// on same line', () => {
    const result = transformUrlUpgrade("const a = 'http://a.com'; const b = 'http://b.com';", v);
    expect(result).toContain('https://a.com');
    expect(result).toContain('https://b.com');
    expect(result).not.toContain('http://');
  });

  it('should not change https:// URLs', () => {
    const line = "const url = 'https://api.example.com';";
    expect(transformUrlUpgrade(line, v)).toBe(line);
  });

  it('should handle axios.get with http URL', () => {
    expect(transformUrlUpgrade("axios.get('http://api.example.com/login');", v))
      .toBe("axios.get('https://api.example.com/login');");
  });

  it('should handle fetch with http URL', () => {
    expect(transformUrlUpgrade("fetch('http://example.com/api/register');", v))
      .toBe("fetch('https://example.com/api/register');");
  });
});

// ==================== Transform: remove-default (coppa-sec-010) ====================

describe('Transform: remove-default (coppa-sec-010)', () => {
  const v = makeViolation({ ruleId: 'coppa-sec-010' });

  it('should replace "password" with secure generator', () => {
    const result = transformRemoveDefault("const defaultPassword = 'password';", v);
    expect(result).toContain('crypto');
    expect(result).toContain('randomBytes');
    expect(result).not.toContain("'password'");
  });

  it('should replace "123456" with secure generator', () => {
    const result = transformRemoveDefault('password = "123456";', v);
    expect(result).toContain('crypto');
    expect(result).not.toContain('"123456"');
  });

  it('should replace "changeme"', () => {
    const result = transformRemoveDefault("initialPassword: 'changeme'", v);
    expect(result).toContain('randomBytes');
  });

  it('should replace "admin"', () => {
    const result = transformRemoveDefault("const pass = 'admin';", v);
    expect(result).toContain('crypto');
  });

  it('should not change non-weak passwords', () => {
    const line = "const password = generateSecureRandom();";
    expect(transformRemoveDefault(line, v)).toBe(line);
  });

  // False positive guards
  it('should NOT modify enum definitions (SCREAMING_CASE = value)', () => {
    const line = "\tPASSWORD = 'password',";
    expect(transformRemoveDefault(line, v)).toBe(line);
  });

  it('should NOT modify HTML input type declarations', () => {
    const line = "type: 'password',";
    expect(transformRemoveDefault(line, v)).toBe(line);
  });

  it('should NOT modify type= attribute declarations', () => {
    const line = '<input type="password" />';
    expect(transformRemoveDefault(line, v)).toBe(line);
  });

  it('should NOT modify switch case discriminants', () => {
    const line = "    case 'password':";
    expect(transformRemoveDefault(line, v)).toBe(line);
  });

  it('should still replace weak password in assignment context', () => {
    const line = "const defaultPassword = 'password';";
    const result = transformRemoveDefault(line, v);
    expect(result).toContain('crypto');
    expect(result).not.toContain("'password'");
  });
});

// ==================== Transform: sanitize-input (coppa-sec-015) ====================

describe('Transform: sanitize-input (coppa-sec-015)', () => {
  const v = makeViolation({ ruleId: 'coppa-sec-015' });

  it('should replace innerHTML with textContent', () => {
    expect(transformSanitizeInput('element.innerHTML = userContent;', v))
      .toBe('element.textContent = userContent;');
  });

  it('should handle innerHTML with spaces around =', () => {
    expect(transformSanitizeInput('el.innerHTML  =  data;', v))
      .toBe('el.textContent =  data;');
  });

  it('should handle dangerouslySetInnerHTML', () => {
    const result = transformSanitizeInput(
      '<div dangerouslySetInnerHTML={{ __html: userInput }} />',
      v
    );
    expect(result).toContain('DOMPurify.sanitize');
  });

  it('should not change textContent assignments', () => {
    const line = 'element.textContent = safeContent;';
    expect(transformSanitizeInput(line, v)).toBe(line);
  });

  it('should not change lines without innerHTML', () => {
    const line = 'const html = "<div>safe</div>";';
    expect(transformSanitizeInput(line, v)).toBe(line);
  });

  // False positive guards
  it('should NOT double-wrap already-sanitized dangerouslySetInnerHTML', () => {
    const line = '<Box dangerouslySetInnerHTML={{ __html: DOMPurify.sanitize(content) }} />';
    expect(transformSanitizeInput(line, v)).toBe(line);
  });

  it('should still wrap unsanitized dangerouslySetInnerHTML', () => {
    const line = '<div dangerouslySetInnerHTML={{ __html: rawContent }} />';
    const result = transformSanitizeInput(line, v);
    expect(result).toContain('DOMPurify.sanitize');
    expect(result).not.toContain('DOMPurify.sanitize(DOMPurify.sanitize');
  });
});

// ==================== Transform: set-default (coppa-default-020) ====================

describe('Transform: set-default (coppa-default-020)', () => {
  const v = makeViolation({ ruleId: 'coppa-default-020' });

  it('should change isProfileVisible: true to false', () => {
    expect(transformSetDefault('const profile = { isProfileVisible: true };', v))
      .toBe('const profile = { isProfileVisible: false };');
  });

  it('should change visibility: "public" to "private"', () => {
    expect(transformSetDefault("visibility: 'public'", v))
      .toBe("visibility: 'private'");
  });

  it('should change defaultPrivacy: "public" to "private"', () => {
    expect(transformSetDefault("defaultPrivacy: 'public'", v))
      .toBe("defaultPrivacy: 'private'");
  });

  it('should change isPublic: true to false', () => {
    expect(transformSetDefault('isPublic: true', v))
      .toBe('isPublic: false');
  });

  it('should not change already-private values', () => {
    const line = "const profile = { visibility: 'private' };";
    expect(transformSetDefault(line, v)).toBe(line);
  });

  // False positive guards
  it('should NOT modify TypeScript type unions (public | private)', () => {
    const line = "\tvisibility: 'public' | 'private';";
    expect(transformSetDefault(line, v)).toBe(line);
  });

  it('should NOT modify reversed type unions (private | public)', () => {
    const line = "\tvisibility: 'private' | 'public';";
    expect(transformSetDefault(line, v)).toBe(line);
  });

  it('should still change runtime visibility: public (no union)', () => {
    const line = "visibility: 'public',";
    expect(transformSetDefault(line, v)).toBe("visibility: 'private',");
  });
});

// ==================== FixEngine.applyFixes ====================

describe('FixEngine.applyFixes', () => {
  let fixer: FixEngine;
  let engine: HaloEngine;

  beforeEach(() => {
    fixer = new FixEngine();
    engine = new HaloEngine({});
  });

  // Halo 2.0: coppa-sec-006 re-enabled
  it('should fix coppa-sec-006 in file content', () => {
    const content = "const url = 'http://api.myapp.com/api/login';";
    const violations = engine.scanFile('test.ts', content);
    const sec006 = violations.filter(v => v.ruleId === 'coppa-sec-006');
    expect(sec006.length).toBeGreaterThan(0);

    const result = fixer.applyFixes(content, sec006);
    expect(result.fixedContent).toContain('https://');
    expect(result.fixedContent).not.toContain('http://');
    expect(result.fixes.some(f => f.status === 'applied')).toBe(true);
  });

  // Halo 2.0: coppa-default-020 re-enabled
  it('should fix coppa-default-020 in file content', () => {
    const content = "const profile = { isProfileVisible: true };";
    const violations = engine.scanFile('test.ts', content);
    const def020 = violations.filter(v => v.ruleId === 'coppa-default-020');
    expect(def020.length).toBeGreaterThan(0);

    const result = fixer.applyFixes(content, def020);
    expect(result.fixedContent).toContain('isProfileVisible: false');
  });

  it('should skip non-auto-fixable violations', () => {
    const content = "navigator.geolocation.getCurrentPosition(cb);";
    const violations = engine.scanFile('test.ts', content);
    const result = fixer.applyFixes(content, violations);
    // coppa-geo-004 is guided, not auto — should have no applied fixes
    expect(result.fixes.filter(f => f.status === 'applied')).toHaveLength(0);
  });

  // Halo 2.0: coppa-sec-006 re-enabled
  it('should respect --rules filter', () => {
    const content = "const url = 'http://api.myapp.com/api/login';\nconst profile = { isProfileVisible: true };";
    const violations = engine.scanFile('test.ts', content);
    const result = fixer.applyFixes(content, violations, { rules: ['coppa-sec-006'] });
    const applied = result.fixes.filter(f => f.status === 'applied');
    expect(applied.every(f => f.ruleId === 'coppa-sec-006')).toBe(true);
  });

  // Halo 2.0: coppa-sec-006 re-enabled
  it('should process violations bottom-to-top to preserve line numbers', () => {
    const content = "const a = 'http://a.com/api/login';\nconst b = 'http://b.com/api/register';";
    const violations = engine.scanFile('test.ts', content);
    const result = fixer.applyFixes(content, violations);
    expect(result.fixedContent).toContain('https://a.com');
    expect(result.fixedContent).toContain('https://b.com');
  });

  // Halo 2.0: coppa-sec-015 re-enabled
  it('should add warning for innerHTML fixes', () => {
    const content = "element.innerHTML = userContent;";
    const violations = engine.scanFile('test.ts', content);
    const sec015 = violations.filter(v => v.ruleId === 'coppa-sec-015');
    expect(sec015.length).toBeGreaterThan(0);

    const result = fixer.applyFixes(content, sec015);
    const applied = result.fixes.filter(f => f.status === 'applied');
    expect(applied.length).toBeGreaterThan(0);
    expect(applied[0].warning).toContain('rendering behavior');
  });

  // Halo 2.0: coppa-sec-006 re-enabled
  it('should return verified: false (caller must re-scan)', () => {
    const content = "const url = 'http://api.myapp.com/api/login';";
    const violations = engine.scanFile('test.ts', content);
    const result = fixer.applyFixes(content, violations);
    expect(result.verified).toBe(false);
  });
});

// ==================== FixEngine.generateDiff ====================

describe('FixEngine.generateDiff', () => {
  it('should generate a diff showing changes', () => {
    const fixer = new FixEngine();
    const original = "const url = 'http://api.com/api/login';";
    const fixed = "const url = 'https://api.com/api/login';";
    const diff = fixer.generateDiff('test.ts', original, fixed);
    expect(diff).toContain('--- a/test.ts');
    expect(diff).toContain('+++ b/test.ts');
    expect(diff).toContain('-');
    expect(diff).toContain('+');
  });

  it('should return header-only diff for identical content', () => {
    const fixer = new FixEngine();
    const content = "const x = 1;";
    const diff = fixer.generateDiff('test.ts', content, content);
    expect(diff).toContain('--- a/test.ts');
    expect(diff).not.toContain('-const');
  });
});

// ==================== End-to-end: scan → fix → re-scan ====================

describe('End-to-end: scan → fix → re-scan validation', () => {
  // Halo 2.0: coppa-sec-006 re-enabled
  it('should eliminate coppa-sec-006 after fix', () => {
    const engine = new HaloEngine({});
    const fixer = new FixEngine();

    const content = "axios.get('http://api.myapp.com/api/users');";
    const violations = engine.scanFile('test.ts', content);
    expect(violations.filter(v => v.ruleId === 'coppa-sec-006').length).toBeGreaterThan(0);

    const result = fixer.applyFixes(content, violations);
    const postViolations = engine.scanFile('test.ts', result.fixedContent);
    expect(postViolations.filter(v => v.ruleId === 'coppa-sec-006').length).toBe(0);
  });

  // Halo 2.0: coppa-default-020 re-enabled
  it('should eliminate coppa-default-020 after fix', () => {
    const engine = new HaloEngine({});
    const fixer = new FixEngine();

    const content = "const profile = { isProfileVisible: true };";
    const violations = engine.scanFile('test.ts', content);
    expect(violations.filter(v => v.ruleId === 'coppa-default-020').length).toBeGreaterThan(0);

    const result = fixer.applyFixes(content, violations);
    const postViolations = engine.scanFile('test.ts', result.fixedContent);
    expect(postViolations.filter(v => v.ruleId === 'coppa-default-020').length).toBe(0);
  });

  // Halo 2.0: coppa-sec-015 re-enabled
  it('should eliminate coppa-sec-015 after fix', () => {
    const engine = new HaloEngine({});
    const fixer = new FixEngine();

    const content = "element.innerHTML = userContent;";
    const violations = engine.scanFile('test.ts', content);
    expect(violations.filter(v => v.ruleId === 'coppa-sec-015').length).toBeGreaterThan(0);

    const result = fixer.applyFixes(content, violations);
    const postViolations = engine.scanFile('test.ts', result.fixedContent);
    expect(postViolations.filter(v => v.ruleId === 'coppa-sec-015').length).toBe(0);
  });
});
