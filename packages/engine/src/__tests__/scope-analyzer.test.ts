/**
 * Halo Scope Analyzer - Unit Tests
 * Tests for ScopeContext (file-level) and LineContext (AST-level) analysis
 */

import { ScopeAnalyzer, ScopeContext, LineContext } from '../scope-analyzer';

describe('ScopeAnalyzer', () => {
  let analyzer: ScopeAnalyzer;

  beforeEach(() => {
    analyzer = new ScopeAnalyzer();
  });

  // =========================================================================
  // Test File Detection
  // =========================================================================

  describe('isTestFile detection', () => {
    it('should detect .test.ts files', () => {
      const ctx = analyzer.analyzeFile('src/auth.test.ts', '');
      expect(ctx.isTestFile).toBe(true);
    });

    it('should detect .test.js files', () => {
      const ctx = analyzer.analyzeFile('src/utils.test.js', '');
      expect(ctx.isTestFile).toBe(true);
    });

    it('should detect .spec.ts files', () => {
      const ctx = analyzer.analyzeFile('src/engine.spec.ts', '');
      expect(ctx.isTestFile).toBe(true);
    });

    it('should detect .spec.js files', () => {
      const ctx = analyzer.analyzeFile('src/engine.spec.js', '');
      expect(ctx.isTestFile).toBe(true);
    });

    it('should detect .spec.tsx files', () => {
      const ctx = analyzer.analyzeFile('src/Component.spec.tsx', '');
      expect(ctx.isTestFile).toBe(true);
    });

    it('should detect _test.go files', () => {
      const ctx = analyzer.analyzeFile('pkg/handler_test.go', '');
      expect(ctx.isTestFile).toBe(true);
    });

    it('should detect files inside __tests__/ directory', () => {
      const ctx = analyzer.analyzeFile('src/__tests__/engine.test.ts', '');
      expect(ctx.isTestFile).toBe(true);
    });

    it('should detect files inside test/ directory', () => {
      const ctx = analyzer.analyzeFile('test/integration.ts', '');
      expect(ctx.isTestFile).toBe(true);
    });

    it('should detect files inside tests/ directory', () => {
      const ctx = analyzer.analyzeFile('tests/unit/auth.ts', '');
      expect(ctx.isTestFile).toBe(true);
    });

    it('should detect conftest.py', () => {
      const ctx = analyzer.analyzeFile('tests/conftest.py', '');
      expect(ctx.isTestFile).toBe(true);
    });

    it('should detect Java test files (TestAuth.java)', () => {
      const ctx = analyzer.analyzeFile('src/TestAuthService.java', '');
      expect(ctx.isTestFile).toBe(true);
    });

    it('should NOT flag regular source files', () => {
      const ctx = analyzer.analyzeFile('src/auth.ts', '');
      expect(ctx.isTestFile).toBe(false);
    });

    it('should NOT flag files with "test" in the name but not as a suffix', () => {
      const ctx = analyzer.analyzeFile('src/testUtils.ts', '');
      expect(ctx.isTestFile).toBe(false);
    });
  });

  // =========================================================================
  // Admin Route Detection
  // =========================================================================

  describe('isAdminRoute detection', () => {
    it('should detect /admin/ path', () => {
      const ctx = analyzer.analyzeFile('src/admin/users.ts', '');
      expect(ctx.isAdminRoute).toBe(true);
    });

    it('should detect admin.py file', () => {
      const ctx = analyzer.analyzeFile('myapp/admin.py', '');
      expect(ctx.isAdminRoute).toBe(true);
    });

    it('should detect admin.ts file', () => {
      const ctx = analyzer.analyzeFile('src/admin.ts', '');
      expect(ctx.isAdminRoute).toBe(true);
    });

    it('should detect /dashboard/ path', () => {
      const ctx = analyzer.analyzeFile('src/dashboard/metrics.ts', '');
      expect(ctx.isAdminRoute).toBe(true);
    });

    it('should detect AdminPanel component in content', () => {
      const content = `export const AdminPanel = () => <div>Admin</div>;`;
      const ctx = analyzer.analyzeFile('src/layout.tsx', content);
      expect(ctx.isAdminRoute).toBe(true);
    });

    it('should detect AdminDashboard component in content', () => {
      const content = `function AdminDashboard() { return <div />; }`;
      const ctx = analyzer.analyzeFile('src/app.tsx', content);
      expect(ctx.isAdminRoute).toBe(true);
    });

    it('should NOT flag regular user-facing routes', () => {
      const ctx = analyzer.analyzeFile('src/pages/home.ts', '');
      expect(ctx.isAdminRoute).toBe(false);
    });
  });

  // =========================================================================
  // User-Facing Detection
  // =========================================================================

  describe('isUserFacing detection', () => {
    it('should detect /pages/ path', () => {
      const ctx = analyzer.analyzeFile('src/pages/login.tsx', '');
      expect(ctx.isUserFacing).toBe(true);
    });

    it('should detect /components/ path', () => {
      const ctx = analyzer.analyzeFile('src/components/Header.tsx', '');
      expect(ctx.isUserFacing).toBe(true);
    });

    it('should detect /views/ path', () => {
      const ctx = analyzer.analyzeFile('src/views/ProfileView.vue', '');
      expect(ctx.isUserFacing).toBe(true);
    });

    it('should detect /screens/ path', () => {
      const ctx = analyzer.analyzeFile('src/screens/HomeScreen.tsx', '');
      expect(ctx.isUserFacing).toBe(true);
    });

    it('should detect /app/ path', () => {
      const ctx = analyzer.analyzeFile('src/app/layout.tsx', '');
      expect(ctx.isUserFacing).toBe(true);
    });

    it('should detect /src/components/ path', () => {
      const ctx = analyzer.analyzeFile('src/components/Button.tsx', '');
      expect(ctx.isUserFacing).toBe(true);
    });

    it('should NOT flag utility files', () => {
      const ctx = analyzer.analyzeFile('src/utils/format.ts', '');
      expect(ctx.isUserFacing).toBe(false);
    });

    it('should NOT flag service layer files', () => {
      const ctx = analyzer.analyzeFile('src/services/api.ts', '');
      expect(ctx.isUserFacing).toBe(false);
    });
  });

  // =========================================================================
  // Type Definition Detection
  // =========================================================================

  describe('isTypeDefinition detection', () => {
    it('should detect .d.ts files', () => {
      const ctx = analyzer.analyzeFile('src/types/index.d.ts', '');
      expect(ctx.isTypeDefinition).toBe(true);
    });

    it('should detect .d.tsx files', () => {
      const ctx = analyzer.analyzeFile('src/types/components.d.tsx', '');
      expect(ctx.isTypeDefinition).toBe(true);
    });

    it('should detect files with primarily interface declarations (content heuristic)', () => {
      const content = `
export interface User {
  id: string;
  name: string;
}

export interface Post {
  title: string;
  body: string;
}

export type UserRole = 'admin' | 'user';
`;
      const ctx = analyzer.analyzeFile('src/types.ts', content);
      expect(ctx.isTypeDefinition).toBe(true);
    });

    it('should NOT flag regular implementation files', () => {
      const content = `
import { User } from './types';

export function getUser(id: string): User {
  return db.findOne({ id });
}

export function deleteUser(id: string): void {
  db.delete({ id });
}
`;
      const ctx = analyzer.analyzeFile('src/service.ts', content);
      expect(ctx.isTypeDefinition).toBe(false);
    });
  });

  // =========================================================================
  // Config File Detection
  // =========================================================================

  describe('isConfigFile detection', () => {
    it('should detect .config.ts files', () => {
      const ctx = analyzer.analyzeFile('jest.config.ts', '');
      expect(ctx.isConfigFile).toBe(true);
    });

    it('should detect .config.js files', () => {
      const ctx = analyzer.analyzeFile('webpack.config.js', '');
      expect(ctx.isConfigFile).toBe(true);
    });

    it('should detect files in /config/ directory', () => {
      const ctx = analyzer.analyzeFile('src/config/database.ts', '');
      expect(ctx.isConfigFile).toBe(true);
    });

    it('should detect settings.py', () => {
      const ctx = analyzer.analyzeFile('myapp/settings.py', '');
      expect(ctx.isConfigFile).toBe(true);
    });

    it('should detect .env files', () => {
      const ctx = analyzer.analyzeFile('.env', '');
      expect(ctx.isConfigFile).toBe(true);
    });

    it('should detect .env.local files', () => {
      const ctx = analyzer.analyzeFile('.env.local', '');
      expect(ctx.isConfigFile).toBe(true);
    });

    it('should detect tailwind.config.js', () => {
      const ctx = analyzer.analyzeFile('tailwind.config.js', '');
      expect(ctx.isConfigFile).toBe(true);
    });

    it('should NOT flag regular source files', () => {
      const ctx = analyzer.analyzeFile('src/auth.ts', '');
      expect(ctx.isConfigFile).toBe(false);
    });
  });

  // =========================================================================
  // Edge Cases: Multiple Categories
  // =========================================================================

  describe('edge cases: overlapping categories', () => {
    it('should detect test file inside admin directory', () => {
      const ctx = analyzer.analyzeFile('src/admin/__tests__/users.test.ts', '');
      expect(ctx.isTestFile).toBe(true);
      expect(ctx.isAdminRoute).toBe(true);
    });

    it('should detect config file inside test directory', () => {
      const ctx = analyzer.analyzeFile('test/jest.config.ts', '');
      expect(ctx.isTestFile).toBe(true);
      expect(ctx.isConfigFile).toBe(true);
    });

    it('should detect user-facing component in admin area', () => {
      const ctx = analyzer.analyzeFile('src/admin/components/AdminTable.tsx', '');
      expect(ctx.isAdminRoute).toBe(true);
      expect(ctx.isUserFacing).toBe(true); // /components/ triggers user-facing
    });

    it('should detect type definition in pages directory', () => {
      const ctx = analyzer.analyzeFile('src/pages/types.d.ts', '');
      expect(ctx.isUserFacing).toBe(true);
      expect(ctx.isTypeDefinition).toBe(true);
    });

    it('should handle Windows-style backslash paths', () => {
      const ctx = analyzer.analyzeFile('src\\admin\\__tests__\\users.test.ts', '');
      expect(ctx.isTestFile).toBe(true);
      expect(ctx.isAdminRoute).toBe(true);
    });

    it('should return all false for a plain source file', () => {
      const ctx = analyzer.analyzeFile('src/utils/helpers.ts', 'export function add(a: number, b: number) { return a + b; }');
      expect(ctx.isTestFile).toBe(false);
      expect(ctx.isAdminRoute).toBe(false);
      expect(ctx.isUserFacing).toBe(false);
      expect(ctx.isTypeDefinition).toBe(false);
      expect(ctx.isConfigFile).toBe(false);
    });

    it('should handle empty file path gracefully', () => {
      const ctx = analyzer.analyzeFile('', '');
      expect(ctx.isTestFile).toBe(false);
      expect(ctx.isAdminRoute).toBe(false);
      expect(ctx.isUserFacing).toBe(false);
      expect(ctx.isTypeDefinition).toBe(false);
      expect(ctx.isConfigFile).toBe(false);
    });
  });

  // =========================================================================
  // LineContext with AST (requires tree-sitter)
  // =========================================================================

  describe('analyzeLineContext (AST-based)', () => {
    // Uses shared tree-sitter-helper to avoid native module conflicts
    const { parseTS: parseCode, parseTSX, isTreeSitterAvailable } = require('./tree-sitter-helper');

    it('should detect line inside interface declaration', () => {
      const tree = parseCode(`
interface User {
  id: string;
  name: string;
}
`);
      if (!tree) return;

      // Line 3 is "  id: string;" which is inside the interface
      const ctx = analyzer.analyzeLineContext(3, tree);
      expect(ctx.inInterfaceDecl).toBe(true);
      expect(ctx.inFunctionBody).toBe(false);
    });

    it('should detect line inside function declaration', () => {
      const tree = parseCode(`
function greet(name: string) {
  console.log(name);
}
`);
      if (!tree) return;

      // Line 3 is inside the function body
      const ctx = analyzer.analyzeLineContext(3, tree);
      expect(ctx.inFunctionBody).toBe(true);
      expect(ctx.inInterfaceDecl).toBe(false);
    });

    it('should detect line inside arrow function', () => {
      const tree = parseCode(`
const greet = (name: string) => {
  console.log(name);
};
`);
      if (!tree) return;

      const ctx = analyzer.analyzeLineContext(3, tree);
      expect(ctx.inFunctionBody).toBe(true);
    });

    it('should detect line inside class method', () => {
      const tree = parseCode(`
class UserService {
  getUser(id: string) {
    return this.db.find(id);
  }
}
`);
      if (!tree) return;

      // Line 4 is inside a class method
      const ctx = analyzer.analyzeLineContext(4, tree);
      expect(ctx.inFunctionBody).toBe(true);
      expect(ctx.inClassMethod).toBe(true);
    });

    it('should detect line inside JSX element', () => {
      const tree = parseTSX(`
function App() {
  return (
    <div>
      <span>Hello</span>
    </div>
  );
}
`);
      if (!tree) return;

      // Line 5 is inside JSX
      const ctx = analyzer.analyzeLineContext(5, tree);
      expect(ctx.inJSXElement).toBe(true);
      expect(ctx.inFunctionBody).toBe(true);
    });

    it('should return all false for line outside any construct', () => {
      const tree = parseCode(`
const x = 1;
`);
      if (!tree) return;

      const ctx = analyzer.analyzeLineContext(2, tree);
      expect(ctx.inInterfaceDecl).toBe(false);
      expect(ctx.inFunctionBody).toBe(false);
      expect(ctx.inClassMethod).toBe(false);
      expect(ctx.inJSXElement).toBe(false);
    });

    it('should handle line number beyond file length', () => {
      const tree = parseCode(`const x = 1;`);
      if (!tree) return;

      // Line 999 does not exist
      const ctx = analyzer.analyzeLineContext(999, tree);
      expect(ctx.inInterfaceDecl).toBe(false);
      expect(ctx.inFunctionBody).toBe(false);
      expect(ctx.inClassMethod).toBe(false);
      expect(ctx.inJSXElement).toBe(false);
    });
  });

  // =========================================================================
  // Type Definition with AST
  // =========================================================================

  describe('isTypeDefinition with AST', () => {
    // Uses shared tree-sitter-helper to avoid native module conflicts
    const { parseTS: parseCode } = require('./tree-sitter-helper');

    it('should detect file with primarily type/interface declarations via AST', () => {
      const content = `
export interface User {
  id: string;
  name: string;
}

export type Role = 'admin' | 'user';

export interface Post {
  title: string;
}
`;
      const tree = parseCode(content);
      if (!tree) return;

      const ctx = analyzer.analyzeFile('src/types.ts', content, tree);
      expect(ctx.isTypeDefinition).toBe(true);
    });

    it('should NOT flag mixed file with functions and interfaces via AST', () => {
      const content = `
export interface User {
  id: string;
}

export function getUser(id: string): User {
  return db.find(id);
}

export function deleteUser(id: string): void {
  db.delete(id);
}

export function updateUser(id: string, data: Partial<User>): User {
  return db.update(id, data);
}
`;
      const tree = parseCode(content);
      if (!tree) return;

      const ctx = analyzer.analyzeFile('src/service.ts', content, tree);
      expect(ctx.isTypeDefinition).toBe(false);
    });
  });
});
