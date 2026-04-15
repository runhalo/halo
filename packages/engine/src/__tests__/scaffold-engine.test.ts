/**
 * Scaffold Engine + Framework Detection Tests
 */

import { ScaffoldEngine, detectFramework, SCAFFOLD_REGISTRY, REMEDIATION_MAP } from '../index';
import type { Framework } from '../framework-detect';
import * as fs from 'fs';
import * as path from 'path';
import * as os from 'os';

// ── Framework Detection ──────────────────────────────────────────

describe('Framework Detection', () => {
  let tmpDir: string;

  beforeEach(() => {
    tmpDir = path.join(os.tmpdir(), `halo-fw-test-${Date.now()}`);
    fs.mkdirSync(tmpDir, { recursive: true });
  });

  afterEach(() => {
    try { fs.rmSync(tmpDir, { recursive: true, force: true }); } catch {}
  });

  it('should detect Next.js from package.json', () => {
    fs.writeFileSync(path.join(tmpDir, 'package.json'), JSON.stringify({
      dependencies: { next: '^14.0.0', react: '^18.0.0' }
    }));
    const result = detectFramework(tmpDir);
    expect(result.framework).toBe('nextjs');
    expect(result.confidence).toBeGreaterThanOrEqual(0.9);
  });

  it('should detect React from package.json', () => {
    fs.writeFileSync(path.join(tmpDir, 'package.json'), JSON.stringify({
      dependencies: { react: '^18.0.0', 'react-dom': '^18.0.0' }
    }));
    const result = detectFramework(tmpDir);
    expect(result.framework).toBe('react');
  });

  it('should detect Vue from package.json', () => {
    fs.writeFileSync(path.join(tmpDir, 'package.json'), JSON.stringify({
      dependencies: { vue: '^3.4.0' }
    }));
    const result = detectFramework(tmpDir);
    expect(result.framework).toBe('vue');
  });

  it('should detect Svelte from package.json', () => {
    fs.writeFileSync(path.join(tmpDir, 'package.json'), JSON.stringify({
      devDependencies: { svelte: '^4.0.0' }
    }));
    const result = detectFramework(tmpDir);
    expect(result.framework).toBe('svelte');
  });

  it('should fall back to plain-js when no framework found', () => {
    fs.writeFileSync(path.join(tmpDir, 'package.json'), JSON.stringify({
      dependencies: { express: '^4.18.0' }
    }));
    const result = detectFramework(tmpDir);
    expect(result.framework).toBe('plain-js');
  });

  it('should fall back to plain-js when no package.json exists', () => {
    const result = detectFramework(tmpDir);
    expect(result.framework).toBe('plain-js');
    expect(result.confidence).toBeLessThanOrEqual(0.5);
  });

  it('should detect TypeScript from devDependencies', () => {
    fs.writeFileSync(path.join(tmpDir, 'package.json'), JSON.stringify({
      dependencies: { react: '^18.0.0' },
      devDependencies: { typescript: '^5.3.0' }
    }));
    const result = detectFramework(tmpDir);
    expect(result.typescript).toBe(true);
  });

  it('should detect TypeScript from tsconfig.json when not in package.json', () => {
    fs.writeFileSync(path.join(tmpDir, 'package.json'), JSON.stringify({
      dependencies: { react: '^18.0.0' }
    }));
    fs.writeFileSync(path.join(tmpDir, 'tsconfig.json'), '{}');
    const result = detectFramework(tmpDir);
    expect(result.typescript).toBe(true);
  });

  it('should handle malformed package.json gracefully', () => {
    fs.writeFileSync(path.join(tmpDir, 'package.json'), 'not valid json {{{');
    const result = detectFramework(tmpDir);
    expect(result.framework).toBe('plain-js');
  });

  it('should prioritize Next.js over React (Next.js includes React)', () => {
    fs.writeFileSync(path.join(tmpDir, 'package.json'), JSON.stringify({
      dependencies: { next: '^14.0.0', react: '^18.0.0', vue: '^3.0.0' }
    }));
    const result = detectFramework(tmpDir);
    expect(result.framework).toBe('nextjs');
  });
});

// ── Scaffold Registry ────────────────────────────────────────────

describe('Scaffold Registry', () => {
  it('should have 4 templates registered', () => {
    expect(SCAFFOLD_REGISTRY.size).toBe(4);
  });

  it('should contain the 4 expected scaffold IDs', () => {
    expect(SCAFFOLD_REGISTRY.has('age-gate-auth')).toBe(true);
    expect(SCAFFOLD_REGISTRY.has('consent-cookies')).toBe(true);
    expect(SCAFFOLD_REGISTRY.has('pii-sanitizer')).toBe(true);
    expect(SCAFFOLD_REGISTRY.has('retention-policy')).toBe(true);
  });

  it('should have valid template metadata for each entry', () => {
    for (const [id, template] of SCAFFOLD_REGISTRY) {
      expect(template.scaffoldId).toBe(id);
      expect(template.name).toBeTruthy();
      expect(template.description).toBeTruthy();
      expect(template.ruleIds.length).toBeGreaterThan(0);
      expect(typeof template.generate).toBe('function');
    }
  });
});

// ── Scaffold Engine ──────────────────────────────────────────────

describe('ScaffoldEngine', () => {
  let engine: ScaffoldEngine;
  let tmpDir: string;

  beforeEach(() => {
    engine = new ScaffoldEngine();
    tmpDir = path.join(os.tmpdir(), `halo-scaffold-test-${Date.now()}`);
    fs.mkdirSync(tmpDir, { recursive: true });
    // Create a React + TypeScript project
    fs.writeFileSync(path.join(tmpDir, 'package.json'), JSON.stringify({
      dependencies: { react: '^18.0.0' },
      devDependencies: { typescript: '^5.3.0' }
    }));
  });

  afterEach(() => {
    try { fs.rmSync(tmpDir, { recursive: true, force: true }); } catch {}
  });

  describe('getApplicableScaffolds', () => {
    it('should return scaffold IDs for guided violations with templates', () => {
      const violations = [
        { ruleId: 'coppa-auth-001' },
        { ruleId: 'coppa-data-002' },
      ];
      const scaffolds = engine.getApplicableScaffolds(violations);
      expect(scaffolds).toContain('age-gate-auth');
      expect(scaffolds).toContain('pii-sanitizer');
    });

    it('should return empty array for auto-fix-only violations', () => {
      const violations = [
        { ruleId: 'coppa-sec-006' },
        { ruleId: 'coppa-sec-010' },
      ];
      const scaffolds = engine.getApplicableScaffolds(violations);
      expect(scaffolds).toHaveLength(0);
    });

    it('should not return scaffold IDs without registered templates', () => {
      const violations = [
        { ruleId: 'coppa-ext-011' }, // chat-moderation — no template yet
      ];
      const scaffolds = engine.getApplicableScaffolds(violations);
      expect(scaffolds).toHaveLength(0);
    });

    it('should deduplicate scaffolds from multiple violations of the same rule', () => {
      const violations = [
        { ruleId: 'coppa-auth-001' },
        { ruleId: 'coppa-auth-001' },
      ];
      const scaffolds = engine.getApplicableScaffolds(violations);
      expect(scaffolds).toHaveLength(1);
    });
  });

  describe('getUnavailableScaffolds', () => {
    it('should return scaffold IDs for guided violations WITHOUT templates', () => {
      const violations = [
        { ruleId: 'coppa-ext-011' }, // chat-moderation — no template
        { ruleId: 'coppa-auth-001' }, // age-gate-auth — has template
      ];
      const unavailable = engine.getUnavailableScaffolds(violations);
      expect(unavailable).toContain('chat-moderation');
      expect(unavailable).not.toContain('age-gate-auth');
    });
  });

  describe('generateScaffolds', () => {
    it('should generate files for applicable violations', () => {
      const violations = [{ ruleId: 'coppa-auth-001' }];
      const results = engine.generateScaffolds(violations, tmpDir);
      expect(results).toHaveLength(1);
      expect(results[0].scaffoldId).toBe('age-gate-auth');
      expect(results[0].files.length).toBeGreaterThan(0);
      expect(results[0].framework).toBe('react');
    });

    it('should detect TypeScript and generate .tsx files', () => {
      const violations = [{ ruleId: 'coppa-auth-001' }];
      const results = engine.generateScaffolds(violations, tmpDir);
      expect(results[0].files[0].relativePath).toMatch(/\.tsx$/);
    });

    it('should generate plain JS when no framework detected', () => {
      // Create a plain project
      const plainDir = path.join(os.tmpdir(), `halo-plain-test-${Date.now()}`);
      fs.mkdirSync(plainDir, { recursive: true });
      fs.writeFileSync(path.join(plainDir, 'package.json'), JSON.stringify({
        dependencies: { express: '^4.18.0' }
      }));

      const violations = [{ ruleId: 'coppa-auth-001' }];
      const results = engine.generateScaffolds(violations, plainDir);
      expect(results[0].framework).toBe('plain-js');
      expect(results[0].files[0].relativePath).toMatch(/\.js$/);

      fs.rmSync(plainDir, { recursive: true, force: true });
    });

    it('should respect framework override', () => {
      const violations = [{ ruleId: 'coppa-cookies-016' }];
      const results = engine.generateScaffolds(violations, tmpDir, 'plain-js');
      expect(results[0].framework).toBe('plain-js');
    });

    it('should deduplicate by scaffoldId', () => {
      // coppa-auth-001 maps to age-gate-auth
      const violations = [
        { ruleId: 'coppa-auth-001' },
        { ruleId: 'coppa-auth-001' },
      ];
      const results = engine.generateScaffolds(violations, tmpDir);
      expect(results).toHaveLength(1);
    });

    it('should generate multiple scaffolds for different violations', () => {
      const violations = [
        { ruleId: 'coppa-auth-001' },
        { ruleId: 'coppa-cookies-016' },
        { ruleId: 'coppa-data-002' },
        { ruleId: 'coppa-retention-005' },
      ];
      const results = engine.generateScaffolds(violations, tmpDir);
      expect(results).toHaveLength(4);
      const ids = results.map(r => r.scaffoldId);
      expect(ids).toContain('age-gate-auth');
      expect(ids).toContain('consent-cookies');
      expect(ids).toContain('pii-sanitizer');
      expect(ids).toContain('retention-policy');
    });

    it('should skip auto-fix violations', () => {
      const violations = [
        { ruleId: 'coppa-sec-006' }, // auto-fix
        { ruleId: 'coppa-auth-001' }, // guided
      ];
      const results = engine.generateScaffolds(violations, tmpDir);
      expect(results).toHaveLength(1);
      expect(results[0].scaffoldId).toBe('age-gate-auth');
    });
  });

  describe('getSummary', () => {
    it('should return a complete summary', () => {
      const violations = [
        { ruleId: 'coppa-auth-001' },
        { ruleId: 'coppa-ext-011' }, // no template
      ];
      const summary = engine.getSummary(violations, tmpDir);
      expect(summary.totalScaffolds).toBe(1);
      expect(summary.totalFiles).toBeGreaterThan(0);
      expect(summary.generatedIds).toContain('age-gate-auth');
      expect(summary.unavailableIds).toContain('chat-moderation');
      expect(summary.framework).toBe('react');
      expect(summary.typescript).toBe(true);
    });
  });

  describe('listAvailable', () => {
    it('should return 4 available scaffold IDs', () => {
      const available = engine.listAvailable();
      expect(available).toHaveLength(4);
    });
  });
});

// ── Template Content Validation ──────────────────────────────────

describe('Scaffold Templates', () => {
  describe('age-gate-auth', () => {
    const template = SCAFFOLD_REGISTRY.get('age-gate-auth')!;

    it('should generate React TSX with age verification logic', () => {
      const files = template.generate('react', true);
      expect(files).toHaveLength(1);
      expect(files[0].relativePath).toBe('components/AgeGate.tsx');
      expect(files[0].content).toContain('AgeGate');
      expect(files[0].content).toContain('minimumAge');
      expect(files[0].content).toContain('sessionStorage');
    });

    it('should generate plain JS with class-based age gate', () => {
      const files = template.generate('plain-js', false);
      expect(files).toHaveLength(1);
      expect(files[0].relativePath).toBe('age-gate.js');
      expect(files[0].content).toContain('class AgeGate');
      expect(files[0].content).not.toContain('import React');
    });
  });

  describe('consent-cookies', () => {
    const template = SCAFFOLD_REGISTRY.get('consent-cookies')!;

    it('should generate React component with accept/decline', () => {
      const files = template.generate('react', true);
      expect(files).toHaveLength(1);
      expect(files[0].content).toContain('CookieConsentBanner');
      expect(files[0].content).toContain('handleAccept');
      expect(files[0].content).toContain('handleDecline');
      expect(files[0].content).toContain('hasCookieConsent');
    });

    it('should generate plain JS with no framework imports', () => {
      const files = template.generate('plain-js', false);
      expect(files[0].content).toContain('class CookieConsentBanner');
      expect(files[0].content).not.toContain('import React');
    });
  });

  describe('pii-sanitizer', () => {
    const template = SCAFFOLD_REGISTRY.get('pii-sanitizer')!;

    it('should generate utility with PII detection functions', () => {
      const files = template.generate('react', true);
      expect(files).toHaveLength(1);
      expect(files[0].content).toContain('containsPII');
      expect(files[0].content).toContain('sanitizeUrl');
      expect(files[0].content).toContain('PII_PATTERNS');
    });

    it('should include Express middleware for plain JS', () => {
      const files = template.generate('plain-js', false);
      expect(files[0].content).toContain('piiMiddleware');
      expect(files[0].content).toContain('module.exports');
    });
  });

  describe('retention-policy', () => {
    const template = SCAFFOLD_REGISTRY.get('retention-policy')!;

    it('should generate data retention utility with 48-hour SLA', () => {
      const files = template.generate('react', true);
      expect(files).toHaveLength(1);
      expect(files[0].content).toContain('DataRetention');
      expect(files[0].content).toContain('DELETION_SLA_HOURS');
      expect(files[0].content).toContain('48');
      expect(files[0].content).toContain('RETENTION_POLICIES');
    });

    it('should include TypeScript types when typescript=true', () => {
      const files = template.generate('react', true);
      expect(files[0].content).toContain('RetentionPolicy');
      expect(files[0].content).toContain('DeletionRequest');
    });

    it('should generate plain JS without type annotations', () => {
      const files = template.generate('plain-js', false);
      expect(files[0].content).not.toContain('interface ');
      expect(files[0].content).toContain('DataRetention');
    });
  });
});
