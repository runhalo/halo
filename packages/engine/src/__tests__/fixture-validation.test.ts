/**
 * Fixture Validation Test Suite
 *
 * Automatically scans all synthetic fixture files and validates:
 * - Every should-trigger file produces >= 1 violation for its target rule
 * - Every should-not file produces 0 violations for its target rule
 *
 * Fixture files are discovered dynamically via fs.readdirSync so new fixtures
 * are picked up without modifying this test file.
 */

import * as fs from 'fs';
import * as path from 'path';
import { HaloEngine } from '../index';

// ---------------------------------------------------------------------------
// Pack resolution: map rule-ID prefix to the engine pack(s) required
// ---------------------------------------------------------------------------
const PREFIX_TO_PACKS: Array<[string, string[]]> = [
  ['gdpr-art8-', ['gdpr-art8']],
  ['dpdp-', ['india-dpdp']],
  ['lgpd-', ['brazil-lgpd']],
  ['pipeda-', ['canada-pipeda']],
  ['pipa-', ['south-korea-pipa']],
  ['behavioral-', ['behavioral-design']],
  ['aadc-', ['uk-aadc']],
  ['AU-OSA-', ['au-osa']],
];

function packsForRule(ruleId: string): string[] {
  for (const [prefix, packs] of PREFIX_TO_PACKS) {
    if (ruleId.startsWith(prefix)) {
      return packs;
    }
  }
  // Fallback: load coppa pack (covers coppa-* rules and acts as default)
  return ['coppa'];
}

// ---------------------------------------------------------------------------
// Fixture discovery helpers
// ---------------------------------------------------------------------------
const FIXTURE_EXTENSIONS = new Set(['.ts', '.js']);

const FIXTURES_DIR = path.join(__dirname, 'fixtures');
const SHOULD_TRIGGER_DIR = path.join(FIXTURES_DIR, 'should-trigger');
const SHOULD_NOT_DIR = path.join(FIXTURES_DIR, 'should-not');

function discoverFixtures(dir: string): string[] {
  if (!fs.existsSync(dir)) return [];
  return fs.readdirSync(dir).filter((f) => {
    const ext = path.extname(f);
    return FIXTURE_EXTENSIONS.has(ext);
  });
}

function ruleIdFromFilename(filename: string): string {
  const ext = path.extname(filename);
  return path.basename(filename, ext);
}

// ---------------------------------------------------------------------------
// Engine cache — avoid re-constructing engines for the same pack set
// ---------------------------------------------------------------------------
const engineCache = new Map<string, HaloEngine>();

function getEngine(packs: string[]): HaloEngine {
  const key = packs.sort().join(',');
  if (!engineCache.has(key)) {
    engineCache.set(key, new HaloEngine({ packs }));
  }
  return engineCache.get(key)!;
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

describe('Fixture Validation', () => {
  // -- should-trigger fixtures ---------------------------------------------
  describe('should-trigger fixtures', () => {
    const files = discoverFixtures(SHOULD_TRIGGER_DIR);

    if (files.length === 0) {
      it('(no should-trigger fixtures found)', () => {
        console.warn('No should-trigger fixture files found in', SHOULD_TRIGGER_DIR);
      });
    }

    for (const file of files) {
      const ruleId = ruleIdFromFilename(file);
      const packs = packsForRule(ruleId);

      it(`${ruleId} should produce >= 1 violation (packs: ${packs.join(', ')})`, () => {
        const filePath = path.join(SHOULD_TRIGGER_DIR, file);
        const content = fs.readFileSync(filePath, 'utf-8');
        const engine = getEngine(packs);

        const violations = engine.scanFile(file, content);
        const matching = violations.filter((v) => v.ruleId === ruleId);

        expect(matching.length).toBeGreaterThanOrEqual(1);
      });
    }
  });

  // -- should-not fixtures -------------------------------------------------
  describe('should-not fixtures', () => {
    const files = discoverFixtures(SHOULD_NOT_DIR);

    if (files.length === 0) {
      it('(no should-not fixtures found)', () => {
        console.warn('No should-not fixture files found in', SHOULD_NOT_DIR);
      });
    }

    for (const file of files) {
      const ruleId = ruleIdFromFilename(file);
      const packs = packsForRule(ruleId);

      it(`${ruleId} should produce 0 violations (packs: ${packs.join(', ')})`, () => {
        const filePath = path.join(SHOULD_NOT_DIR, file);
        const content = fs.readFileSync(filePath, 'utf-8');
        const engine = getEngine(packs);

        const violations = engine.scanFile(file, content);
        const matching = violations.filter((v) => v.ruleId === ruleId);

        // Build diagnostic message for readable failure output
        const details = matching.map(
          (v) => `  line ${v.line}: ${v.message}`
        );
        expect({
          ruleId,
          violationCount: matching.length,
          violations: details,
        }).toEqual({
          ruleId,
          violationCount: 0,
          violations: [],
        });
      });
    }
  });
});
