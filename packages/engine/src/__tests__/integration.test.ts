/**
 * Halo Engine - Integration Tests
 */

import { HaloEngine, Violation } from '../index';

// Test fixtures that should trigger violations
const testCases = [
  {
    name: 'coppa-auth-001 - Social login without age gate',
    code: `import { auth } from 'firebase/auth';
await auth.signInWithPopup('google');`,
    expectedViolations: 1,
    expectedRuleId: 'coppa-auth-001'
  },
  {
    name: 'coppa-data-002 - PII in URL params',
    code: `const url = \`https://api.example.com/register?email=\${user.email}&firstName=\${user.firstName}\`;`,
    expectedViolations: 1,
    expectedRuleId: 'coppa-data-002'
  },
  {
    name: 'coppa-tracking-003 - Facebook pixel without child flag',
    code: `fbq('init', '123456789');`,
    expectedViolations: 1,
    expectedRuleId: 'coppa-tracking-003'
  },
  {
    name: 'coppa-geo-004 - High accuracy geolocation',
    code: `navigator.geolocation.getCurrentPosition(success, error, {
  enableHighAccuracy: true
});`,
    expectedViolations: 1,
    expectedRuleId: 'coppa-geo-004'
  },
  {
    name: 'coppa-retention-005 - No retention policy in schema',
    code: `const userSchema = new Schema({
  email: String,
  name: String
});`,
    expectedViolations: 1,
    expectedRuleId: 'coppa-retention-005'
  },
];

describe('HaloEngine Integration Tests', () => {
  const engine = new HaloEngine();

  testCases.forEach((tc) => {
    it(tc.name, () => {
      const violations = engine.scanFile('test.ts', tc.code);
      expect(violations.length).toBeGreaterThanOrEqual(tc.expectedViolations);
      
      if (tc.expectedRuleId) {
        const ruleIds = violations.map(v => v.ruleId);
        expect(ruleIds).toContain(tc.expectedRuleId);
      }
    });
  });

  it('should handle empty file content', () => {
    const violations = engine.scanFile('empty.ts', '');
    expect(violations).toEqual([]);
  });

  it('should handle files with no violations', () => {
    const code = `function hello() { console.log("Hello World"); }`;
    const violations = engine.scanFile('clean.ts', code);
    expect(violations).toEqual([]);
  });
});

/**
 * Known-Clean Fixture Regression Tests
 *
 * These tests scan the deliberately COPPA-compliant mini-app at
 * test/fixtures/known-clean-app/ and verify 0 violations across all packs.
 *
 * If any test fails, it means a rule change introduced a false positive
 * against code that is genuinely compliant.
 */
import * as fs from 'fs';
import * as path from 'path';

describe('Known-Clean Fixture (Zero Violations)', () => {
  const allPacksEngine = new HaloEngine({
    packs: ['coppa', 'ethical', 'ai-audit', 'au-sbd', 'ut-sb142']
  });

  const fixtureDir = path.resolve(__dirname, '../../test/fixtures/known-clean-app/src');
  const fixtureFiles = fs.existsSync(fixtureDir)
    ? fs.readdirSync(fixtureDir).filter(f => f.endsWith('.ts'))
    : [];

  if (fixtureFiles.length === 0) {
    it('fixture directory should contain .ts files', () => {
      expect(fixtureFiles.length).toBeGreaterThan(0);
    });
    return;
  }

  fixtureFiles.forEach((file) => {
    it(`${file} should produce 0 violations`, () => {
      const filePath = path.join(fixtureDir, file);
      const content = fs.readFileSync(filePath, 'utf-8');
      const violations = allPacksEngine.scanFile(file, content);

      if (violations.length > 0) {
        const details = violations.map(v =>
          `  - ${v.ruleId} (line ${v.line}): ${v.message || v.description || 'no message'}`
        ).join('\n');
        fail(`Expected 0 violations in ${file} but found ${violations.length}:\n${details}`);
      }

      expect(violations).toEqual([]);
    });
  });

  it('should scan all 5 fixture files', () => {
    expect(fixtureFiles).toEqual(
      expect.arrayContaining(['auth.ts', 'data.ts', 'tracking.ts', 'ui.ts', 'cookies.ts'])
    );
  });

  it('should produce 0 total violations across all fixture files', () => {
    let totalViolations: Violation[] = [];
    for (const file of fixtureFiles) {
      const filePath = path.join(fixtureDir, file);
      const content = fs.readFileSync(filePath, 'utf-8');
      totalViolations = totalViolations.concat(allPacksEngine.scanFile(file, content));
    }
    expect(totalViolations).toEqual([]);
  });
});
