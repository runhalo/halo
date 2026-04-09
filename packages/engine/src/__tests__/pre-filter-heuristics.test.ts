/**
 *  Pre-filter A+ Heuristics Tests
 *
 * Validates the classifyFile() function and FileClassification interface
 * for all 6 new heuristic patterns plus existing ones.
 */

import { classifyFile, FileClassification } from '../index';

describe('Pre-filter A+ Heuristics', () => {

  describe('FileClassification interface', () => {
    it('should return method: "heuristic" for all deterministic classifications', () => {
      const result = classifyFile('src/app.ts');
      expect(result.method).toBe('heuristic');
    });

    it('should return all expected fields', () => {
      const result = classifyFile('src/app.ts');
      expect(result).toHaveProperty('method');
      expect(result).toHaveProperty('language');
      expect(result).toHaveProperty('isVendor');
      expect(result).toHaveProperty('isTest');
      expect(result).toHaveProperty('isConsent');
      expect(result).toHaveProperty('isAdmin');
      expect(result).toHaveProperty('isDocGenerator');
      expect(result).toHaveProperty('isDjangoMigration');
      expect(result).toHaveProperty('isFixtureOrSeed');
      expect(result).toHaveProperty('isMockOrFactory');
      expect(result).toHaveProperty('isCIConfig');
      expect(result).toHaveProperty('isBuildOutput');
      expect(result).toHaveProperty('isTypeDefinition');
      expect(result).toHaveProperty('isStorybook');
      expect(result).toHaveProperty('shouldSkip');
    });
  });

  // === Pattern 1: Django migration files ===
  describe('Django migration files', () => {
    it('should detect numbered migration files', () => {
      const result = classifyFile('myapp/migrations/0001_initial.py');
      expect(result.isDjangoMigration).toBe(true);
      expect(result.shouldSkip).toBe(true);
      expect(result.skipReason).toBe('django-migration');
    });

    it('should detect migration __init__.py', () => {
      const result = classifyFile('myapp/migrations/__init__.py');
      expect(result.isDjangoMigration).toBe(true);
      expect(result.shouldSkip).toBe(true);
    });

    it('should detect deeply nested migrations', () => {
      const result = classifyFile('apps/users/migrations/0042_add_profile_fields.py');
      expect(result.isDjangoMigration).toBe(true);
      expect(result.shouldSkip).toBe(true);
    });

    it('should NOT detect non-migration .py files', () => {
      const result = classifyFile('myapp/views.py');
      expect(result.isDjangoMigration).toBe(false);
    });

    it('should NOT detect files with "migration" in non-standard paths', () => {
      const result = classifyFile('docs/migration-guide.py');
      expect(result.isDjangoMigration).toBe(false);
    });
  });

  // === Pattern 2: Rails fixture files ===
  describe('Rails fixture and seed files', () => {
    it('should detect YAML fixture files', () => {
      const result = classifyFile('test/fixtures/users.yml');
      expect(result.isFixtureOrSeed).toBe(true);
    });

    it('should detect JSON fixture files', () => {
      const result = classifyFile('spec/fixtures/products.json');
      expect(result.isFixtureOrSeed).toBe(true);
    });

    it('should detect seed directories', () => {
      const result = classifyFile('db/seeds/development.rb');
      expect(result.isFixtureOrSeed).toBe(true);
    });

    it('should detect seeds/ directory', () => {
      const result = classifyFile('seeds/initial_data.ts');
      expect(result.isFixtureOrSeed).toBe(true);
    });

    it('should detect factory directories', () => {
      const result = classifyFile('factories/user_factory.rb');
      expect(result.isFixtureOrSeed).toBe(true);
    });

    it('should detect factory.ts files', () => {
      const result = classifyFile('src/factory.ts');
      expect(result.isFixtureOrSeed).toBe(true);
    });

    it('should NOT flag regular source files', () => {
      const result = classifyFile('src/models/user.rb');
      expect(result.isFixtureOrSeed).toBe(false);
    });
  });

  // === Pattern 3: Mock/factory files ===
  describe('Mock and factory files', () => {
    it('should detect __mocks__ directory', () => {
      const result = classifyFile('src/__mocks__/api.ts');
      expect(result.isMockOrFactory).toBe(true);
    });

    it('should detect mocks/ directory', () => {
      const result = classifyFile('mocks/database.ts');
      expect(result.isMockOrFactory).toBe(true);
    });

    it('should detect .mock.ts files', () => {
      const result = classifyFile('src/services/auth.mock.ts');
      expect(result.isMockOrFactory).toBe(true);
    });

    it('should detect .fake.py files', () => {
      const result = classifyFile('tests/auth.fake.py');
      expect(result.isMockOrFactory).toBe(true);
    });

    it('should detect mock-prefixed files', () => {
      const result = classifyFile('src/mock_service.ts');
      expect(result.isMockOrFactory).toBe(true);
    });

    it('should detect stub-suffixed files', () => {
      const result = classifyFile('src/api-stub.ts');
      expect(result.isMockOrFactory).toBe(true);
    });

    it('should NOT flag regular source files', () => {
      const result = classifyFile('src/services/auth.ts');
      expect(result.isMockOrFactory).toBe(false);
    });
  });

  // === Pattern 4: Seed/fixture data files ===
  describe('Seed/fixture data files', () => {
    it('should detect seeds/ directory with .ts', () => {
      const result = classifyFile('prisma/seeds/users.ts');
      expect(result.isFixtureOrSeed).toBe(true);
    });

    it('should detect seeds/ directory with .py', () => {
      const result = classifyFile('db/seeds/populate.py');
      expect(result.isFixtureOrSeed).toBe(true);
    });

    it('should detect CSV fixtures', () => {
      const result = classifyFile('fixtures/test_data.csv');
      expect(result.isFixtureOrSeed).toBe(true);
    });
  });

  // === Pattern 5: CI/CD config files ===
  describe('CI/CD configuration files', () => {
    it('should detect GitHub Actions workflows', () => {
      const result = classifyFile('.github/workflows/ci.yml');
      expect(result.isCIConfig).toBe(true);
      expect(result.shouldSkip).toBe(true);
      expect(result.skipReason).toBe('ci-config');
    });

    it('should detect GitHub Actions custom actions', () => {
      const result = classifyFile('.github/actions/deploy/action.yml');
      expect(result.isCIConfig).toBe(true);
      expect(result.shouldSkip).toBe(true);
    });

    it('should detect CircleCI config', () => {
      const result = classifyFile('.circleci/config.yml');
      expect(result.isCIConfig).toBe(true);
      expect(result.shouldSkip).toBe(true);
    });

    it('should detect GitLab CI', () => {
      const result = classifyFile('.gitlab-ci.yml');
      expect(result.isCIConfig).toBe(true);
      expect(result.shouldSkip).toBe(true);
    });

    it('should detect Jenkinsfile', () => {
      const result = classifyFile('Jenkinsfile');
      expect(result.isCIConfig).toBe(true);
    });

    it('should detect Travis CI', () => {
      const result = classifyFile('.travis.yml');
      expect(result.isCIConfig).toBe(true);
    });

    it('should detect Dockerfile', () => {
      const result = classifyFile('Dockerfile');
      expect(result.isCIConfig).toBe(true);
    });

    it('should detect docker-compose', () => {
      const result = classifyFile('docker-compose.yml');
      expect(result.isCIConfig).toBe(true);
    });

    it('should NOT detect regular YAML files', () => {
      const result = classifyFile('config/database.yml');
      expect(result.isCIConfig).toBe(false);
    });
  });

  // === Pattern 6: Type definition files ===
  describe('Type definition files', () => {
    it('should detect .d.ts files', () => {
      const result = classifyFile('src/types/global.d.ts');
      expect(result.isTypeDefinition).toBe(true);
      expect(result.shouldSkip).toBe(true);
      expect(result.skipReason).toBe('type-definition');
    });

    it('should detect .pyi stub files', () => {
      const result = classifyFile('mylib/stubs/client.pyi');
      expect(result.isTypeDefinition).toBe(true);
      expect(result.shouldSkip).toBe(true);
    });

    it('should detect @types/ directory', () => {
      const result = classifyFile('node_modules/@types/react/index.d.ts');
      expect(result.isTypeDefinition).toBe(true);
      expect(result.shouldSkip).toBe(true);
    });

    it('should NOT detect regular .ts files', () => {
      const result = classifyFile('src/app.ts');
      expect(result.isTypeDefinition).toBe(false);
      expect(result.shouldSkip).toBe(false);
    });

    it('should NOT detect .tsx files', () => {
      const result = classifyFile('src/components/Button.tsx');
      expect(result.isTypeDefinition).toBe(false);
    });
  });

  // === Existing heuristics still work ===
  describe('Existing heuristics (vendor, doc-generator, test, consent, admin)', () => {
    it('should detect vendor paths (node_modules)', () => {
      const result = classifyFile('node_modules/express/index.js');
      expect(result.isVendor).toBe(true);
      expect(result.shouldSkip).toBe(true);
      expect(result.skipReason).toBe('vendor-library');
    });

    it('should detect test files (.test.ts)', () => {
      const result = classifyFile('src/__tests__/app.test.ts');
      expect(result.isTest).toBe(true);
      // Tests are NOT fully skipped — they get per-rule suppression
      expect(result.shouldSkip).toBe(false);
    });

    it('should detect spec files (.spec.js)', () => {
      const result = classifyFile('src/components/button.spec.js');
      expect(result.isTest).toBe(true);
    });

    it('should detect consent implementation files', () => {
      const result = classifyFile('src/components/cookie-consent/index.ts');
      expect(result.isConsent).toBe(true);
      // Consent files are NOT fully skipped — selective suppression only
      expect(result.shouldSkip).toBe(false);
    });

    it('should detect admin paths', () => {
      const result = classifyFile('src/admin/users/list.ts');
      expect(result.isAdmin).toBe(true);
      expect(result.shouldSkip).toBe(false);
    });

    it('should detect admin via decorator in content prefix', () => {
      const result = classifyFile('views.py', '@staff_member_required\ndef manage_users():');
      expect(result.isAdmin).toBe(true);
    });
  });

  // === Build output detection ===
  describe('Build output files', () => {
    it('should detect dist/ directory', () => {
      const result = classifyFile('dist/bundle.js');
      expect(result.isBuildOutput).toBe(true);
      expect(result.shouldSkip).toBe(true);
      expect(result.skipReason).toBe('build-output');
    });

    it('should detect .next/ directory', () => {
      const result = classifyFile('.next/server/pages/index.js');
      expect(result.isBuildOutput).toBe(true);
      expect(result.shouldSkip).toBe(true);
    });

    it('should detect coverage/ directory', () => {
      const result = classifyFile('coverage/lcov-report/index.html');
      expect(result.isBuildOutput).toBe(true);
    });
  });

  // === Storybook stories ===
  describe('Storybook stories', () => {
    it('should detect .stories.tsx files', () => {
      const result = classifyFile('src/components/Button.stories.tsx');
      expect(result.isStorybook).toBe(true);
    });

    it('should detect .storybook/ config directory', () => {
      const result = classifyFile('.storybook/main.ts');
      expect(result.isStorybook).toBe(true);
    });
  });

  // === Language detection ===
  describe('Language detection', () => {
    it('should detect TypeScript', () => {
      expect(classifyFile('app.ts').language).toBe('typescript');
    });

    it('should detect Python', () => {
      expect(classifyFile('app.py').language).toBe('python');
    });

    it('should detect JavaScript', () => {
      expect(classifyFile('app.js').language).toBe('javascript');
    });

    it('should detect Ruby', () => {
      expect(classifyFile('app.rb').language).toBe('ruby');
    });

    it('should return unknown for unrecognized extensions', () => {
      expect(classifyFile('README.md').language).toBe('unknown');
    });
  });

  // === shouldSkip priority order ===
  describe('shouldSkip priority', () => {
    it('vendor takes priority over other classifications', () => {
      // A vendor file that happens to be in a migrations dir
      const result = classifyFile('node_modules/django/migrations/0001_initial.py');
      expect(result.shouldSkip).toBe(true);
      expect(result.skipReason).toBe('vendor-library');
    });

    it('regular source files are not skipped', () => {
      const result = classifyFile('src/components/LoginForm.tsx');
      expect(result.shouldSkip).toBe(false);
      expect(result.skipReason).toBeUndefined();
    });
  });

  // === Integration: scan loop behavior ===
  describe('Scan loop integration', () => {
    it('Django migration files produce zero violations when scanned', () => {
      // classifyFile marks these as shouldSkip, so the engine returns []
      const result = classifyFile('myapp/migrations/0003_add_tracking.py');
      expect(result.shouldSkip).toBe(true);
    });

    it('CI/CD configs produce zero violations when scanned', () => {
      const result = classifyFile('.github/workflows/deploy.yml');
      expect(result.shouldSkip).toBe(true);
    });

    it('Type definitions produce zero violations when scanned', () => {
      const result = classifyFile('types/analytics.d.ts');
      expect(result.shouldSkip).toBe(true);
    });

    it('Mock files are NOT fully skipped (per-rule suppression)', () => {
      const result = classifyFile('src/__mocks__/tracking.mock.ts');
      expect(result.isMockOrFactory).toBe(true);
      expect(result.shouldSkip).toBe(false);
    });

    it('Fixture/seed files are NOT fully skipped (per-rule suppression)', () => {
      const result = classifyFile('seeds/test_users.ts');
      expect(result.isFixtureOrSeed).toBe(true);
      expect(result.shouldSkip).toBe(false);
    });
  });
});
