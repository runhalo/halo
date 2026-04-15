/**
 * Halo VS Code Extension Tests
 * Tests core extension functionality without launching VS Code.
 * For full integration tests, use @vscode/test-electron.
 */

import * as assert from 'assert';
import * as path from 'path';
import * as fs from 'fs';

// Test fixture with known violations
const TEST_FIXTURE = `
import firebase from 'firebase/app';
import 'firebase/analytics';

const analytics = firebase.analytics();
analytics.logEvent('page_view', { user_id: getUserId() });

function createAccount(email: string) {
  const user = { email, dateOfBirth: '2010-05-15' };
  db.insert('users', user);
}

const profileVisibility = 'public';
const trackingEnabled = true;
`;

describe('Halo Extension Unit Tests', () => {

  describe('Rule Loading', () => {
    it('should have rules.json available', () => {
      const rulesPath = path.resolve(__dirname, '../../../engine/rules/rules.json');
      assert.ok(fs.existsSync(rulesPath), 'rules.json should exist');
    });

    it('should load 26 COPPA rules from rules.json', () => {
      const rulesPath = path.resolve(__dirname, '../../../engine/rules/rules.json');
      const rules = JSON.parse(fs.readFileSync(rulesPath, 'utf8'));
      assert.strictEqual(rules.rules.length, 26, 'Should have 26 rules');
    });

    it('should have 1 pack defined', () => {
      const rulesPath = path.resolve(__dirname, '../../../engine/rules/rules.json');
      const rules = JSON.parse(fs.readFileSync(rulesPath, 'utf8'));
      assert.strictEqual(Object.keys(rules.packs).length, 1, 'Should have 1 pack');
    });

    it('should include COPPA pack', () => {
      const rulesPath = path.resolve(__dirname, '../../../engine/rules/rules.json');
      const rules = JSON.parse(fs.readFileSync(rulesPath, 'utf8'));
      assert.ok(rules.packs.coppa, 'COPPA pack should exist');
      const coppaRules = rules.rules.filter((r: any) => r.packs.includes('coppa'));
      assert.strictEqual(coppaRules.length, 26, 'COPPA should have 26 rules');
    });
  });

  describe('Regex Pattern Validation', () => {
    it('all rule patterns should be valid regex', () => {
      const rulesPath = path.resolve(__dirname, '../../../engine/rules/rules.json');
      const rules = JSON.parse(fs.readFileSync(rulesPath, 'utf8'));
      let invalidCount = 0;

      for (const rule of rules.rules) {
        for (const pattern of rule.patterns) {
          try {
            new RegExp(pattern.pattern, pattern.flags);
          } catch (e) {
            invalidCount++;
            console.error(`Invalid regex in ${rule.id}: ${pattern.pattern}`);
          }
        }
      }

      assert.strictEqual(invalidCount, 0, `${invalidCount} invalid regex patterns found`);
    });
  });

  describe('Test Fixture Scanning', () => {
    it('should detect violations in test fixture', () => {
      const rulesPath = path.resolve(__dirname, '../../../engine/rules/rules.json');
      const rules = JSON.parse(fs.readFileSync(rulesPath, 'utf8'));

      let matchCount = 0;
      for (const rule of rules.rules) {
        for (const pattern of rule.patterns) {
          try {
            const regex = new RegExp(pattern.pattern, pattern.flags);
            if (regex.test(TEST_FIXTURE)) {
              matchCount++;
              break; // Count each rule only once
            }
          } catch { /* skip invalid */ }
        }
      }

      assert.ok(matchCount > 0, `Should find violations in test fixture (found ${matchCount})`);
    });
  });

  describe('Package Version', () => {
    it('should have a valid version in package.json', () => {
      const pkgPath = path.resolve(__dirname, '../../package.json');
      const pkg = JSON.parse(fs.readFileSync(pkgPath, 'utf8'));
      assert.ok(pkg.version, 'Should have a version');
      assert.match(pkg.version, /^\d+\.\d+\.\d+/, 'Version should be semver');
    });

    it('should have correct publisher', () => {
      const pkgPath = path.resolve(__dirname, '../../package.json');
      const pkg = JSON.parse(fs.readFileSync(pkgPath, 'utf8'));
      assert.strictEqual(pkg.publisher, 'runhalo', 'Publisher should be runhalo');
    });
  });
});
