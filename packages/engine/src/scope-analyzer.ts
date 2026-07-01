/**
 * Halo Scope Analyzer
 * Determines the context of code being scanned to reduce false positives.
 *
 * Analyzes WHERE code lives (test file? admin route? type definition?)
 * so that rule violations can be weighted or suppressed based on context.
 */

import Parser from 'tree-sitter';

/**
 * File-level scope context derived from path heuristics and content analysis.
 */
export interface ScopeContext {
  /** File is a test: _test.go, .spec.ts, .test.js, __tests__/, test/, tests/ */
  isTestFile: boolean;
  /** File is an admin route: /admin/, admin.py, AdminPanel, AdminDashboard */
  isAdminRoute: boolean;
  /** File is user-facing: /pages/, /components/, /views/, /screens/ */
  isUserFacing: boolean;
  /** File is a type definition: .d.ts, interface{}, type alias files */
  isTypeDefinition: boolean;
  /** File is configuration: .config.ts, config/, settings.py, .env */
  isConfigFile: boolean;
}

/**
 * Line-level context derived from AST analysis.
 * Describes what construct the line is enclosed within.
 */
export interface LineContext {
  /** Line is inside an interface declaration */
  inInterfaceDecl: boolean;
  /** Line is inside a function body */
  inFunctionBody: boolean;
  /** Line is inside a class method */
  inClassMethod: boolean;
  /** Line is inside a JSX/TSX element */
  inJSXElement: boolean;
}

// ---------------------------------------------------------------------------
// File path patterns
// ---------------------------------------------------------------------------

const TEST_FILE_PATTERNS: RegExp[] = [
  /_test\.go$/i,
  /\.spec\.[tj]sx?$/i,
  /\.test\.[tj]sx?$/i,
  /(^|[/\\])__tests__[/\\]/i,
  /(^|[/\\])test[/\\]/i,
  /(^|[/\\])tests[/\\]/i,
  /conftest\.py$/i,
  /(^|[/\\])Test[A-Z][^/\\]*\.java$/,
];

const ADMIN_PATH_PATTERNS: RegExp[] = [
  /[/\\]admin[/\\]/i,
  /[/\\]admin\.[a-z]+$/i,
  /[/\\]dashboard[/\\]/i,
];

const ADMIN_CONTENT_PATTERNS: RegExp[] = [
  /\bAdminPanel\b/,
  /\bAdminDashboard\b/,
  /\bAdminLayout\b/,
  /\bAdminRoute\b/,
  /\bAdminPage\b/,
];

const USER_FACING_PATTERNS: RegExp[] = [
  /[/\\]pages[/\\]/i,
  /[/\\]components[/\\]/i,
  /[/\\]views[/\\]/i,
  /[/\\]screens[/\\]/i,
  /[/\\]app[/\\]/i,
  /[/\\]src[/\\]components[/\\]/i,
];

const TYPE_DEF_PATH_PATTERNS: RegExp[] = [
  /\.d\.tsx?$/i,
];

const CONFIG_FILE_PATTERNS: RegExp[] = [
  /\.config\.[tj]sx?$/i,
  /\.config\.[cm]?js$/i,
  /(^|[/\\])config[/\\]/i,
  /(^|[/\\])settings\.py$/i,
  /(^|[/\\])\.env(\.|$)/i,
  /\.config\./i,
];

// ---------------------------------------------------------------------------
// AST node types used for line context analysis
// ---------------------------------------------------------------------------

const INTERFACE_NODE_TYPES = new Set([
  'interface_declaration',
]);

const FUNCTION_NODE_TYPES = new Set([
  'function_declaration',
  'arrow_function',
  'function',
  'method_definition',
  'function_expression',
]);

const CLASS_NODE_TYPES = new Set([
  'class_declaration',
  'class',
]);

const METHOD_NODE_TYPES = new Set([
  'method_definition',
]);

const JSX_NODE_TYPES = new Set([
  'jsx_element',
  'jsx_self_closing_element',
]);

// ---------------------------------------------------------------------------
// ScopeAnalyzer
// ---------------------------------------------------------------------------

/**
 * Analyzes the scope/context of source files and individual lines
 * to help the engine make smarter decisions about rule applicability.
 */
export class ScopeAnalyzer {

  /**
   * Analyze file-level scope from path heuristics and optionally content/AST.
   *
   * @param filePath  - Relative or absolute path to the source file
   * @param content   - Full text content of the file
   * @param tree      - Optional tree-sitter AST (used for deeper analysis)
   * @returns ScopeContext describing the file's role
   */
  analyzeFile(filePath: string, content: string, tree?: Parser.Tree): ScopeContext {
    const normalized = filePath.replace(/\\/g, '/');

    return {
      isTestFile: this.detectTestFile(normalized),
      isAdminRoute: this.detectAdminRoute(normalized, content),
      isUserFacing: this.detectUserFacing(normalized),
      isTypeDefinition: this.detectTypeDefinition(normalized, content, tree),
      isConfigFile: this.detectConfigFile(normalized),
    };
  }

  /**
   * Analyze what AST construct encloses a given line.
   *
   * Walks the tree to find the deepest node that contains the target line,
   * then walks upward through ancestors to determine enclosing constructs.
   *
   * @param line - 1-based line number
   * @param tree - tree-sitter AST
   * @returns LineContext describing the enclosing constructs
   */
  analyzeLineContext(line: number, tree: Parser.Tree): LineContext {
    const context: LineContext = {
      inInterfaceDecl: false,
      inFunctionBody: false,
      inClassMethod: false,
      inJSXElement: false,
    };

    // tree-sitter uses 0-based row indices
    const targetRow = line - 1;

    const node = this.findDeepestNodeAtLine(tree.rootNode, targetRow);
    if (!node) {
      return context;
    }

    // Walk ancestors from the deepest node upward
    let current: Parser.SyntaxNode | null = node;
    let insideClassBody = false;

    while (current) {
      const type = current.type;

      if (INTERFACE_NODE_TYPES.has(type)) {
        context.inInterfaceDecl = true;
      }

      if (FUNCTION_NODE_TYPES.has(type)) {
        context.inFunctionBody = true;
        // If we already saw a class ancestor, this function is a class method
        if (insideClassBody || METHOD_NODE_TYPES.has(type)) {
          context.inClassMethod = true;
        }
      }

      if (CLASS_NODE_TYPES.has(type)) {
        insideClassBody = true;
      }

      if (JSX_NODE_TYPES.has(type)) {
        context.inJSXElement = true;
      }

      current = current.parent;
    }

    return context;
  }

  // -----------------------------------------------------------------------
  // Private helpers — file scope detection
  // -----------------------------------------------------------------------

  private detectTestFile(filePath: string): boolean {
    return TEST_FILE_PATTERNS.some(p => p.test(filePath));
  }

  private detectAdminRoute(filePath: string, content: string): boolean {
    // Path-based detection
    if (ADMIN_PATH_PATTERNS.some(p => p.test(filePath))) {
      return true;
    }
    // Content-based detection (e.g., AdminPanel component)
    if (ADMIN_CONTENT_PATTERNS.some(p => p.test(content))) {
      // Only count if the path also suggests dashboard/admin context
      // OR the component name is strongly admin-specific
      return true;
    }
    return false;
  }

  private detectUserFacing(filePath: string): boolean {
    return USER_FACING_PATTERNS.some(p => p.test(filePath));
  }

  private detectTypeDefinition(
    filePath: string,
    content: string,
    tree?: Parser.Tree,
  ): boolean {
    // .d.ts files are always type definitions
    if (TYPE_DEF_PATH_PATTERNS.some(p => p.test(filePath))) {
      return true;
    }

    // Heuristic: if the file content is predominantly interfaces/types
    if (tree) {
      return this.isAstPrimarilyTypes(tree);
    }

    // Fallback: content-based heuristic for non-AST path
    return this.isContentPrimarilyTypes(content);
  }

  private detectConfigFile(filePath: string): boolean {
    return CONFIG_FILE_PATTERNS.some(p => p.test(filePath));
  }

  // -----------------------------------------------------------------------
  // Private helpers — type definition heuristics
  // -----------------------------------------------------------------------

  /**
   * Check via AST whether the file consists primarily of type declarations.
   * A file is considered primarily types if >= 80% of its top-level
   * statements are interface/type declarations.
   */
  private isAstPrimarilyTypes(tree: Parser.Tree): boolean {
    const root = tree.rootNode;
    if (!root) return false;

    let totalStatements = 0;
    let typeStatements = 0;

    for (const child of this.getNodeChildren(root)) {
      if (!child) continue;

      const type = child.type;

      // Skip import/export wrapper nodes — look inside them
      if (type === 'export_statement') {
        const inner = child.namedChildren[0];
        if (inner) {
          totalStatements++;
          if (this.isTypeNode(inner.type)) {
            typeStatements++;
          }
        }
        continue;
      }

      // Skip import statements — they don't count
      if (type === 'import_statement') continue;

      totalStatements++;
      if (this.isTypeNode(type)) {
        typeStatements++;
      }
    }

    if (totalStatements === 0) return false;
    return typeStatements / totalStatements >= 0.8;
  }

  private isTypeNode(nodeType: string): boolean {
    return (
      nodeType === 'interface_declaration' ||
      nodeType === 'type_alias_declaration'
    );
  }

  /**
   * Content-based fallback: count top-level interface/type declaration blocks
   * vs total top-level statements (excluding imports and blanks).
   *
   * Uses a simple state machine: lines starting with `interface` or `type`
   * keywords begin a type block. Lines that are clearly function/class/const
   * declarations begin a non-type block. Lines inside a block (e.g., interface
   * members) are attributed to whatever block they belong to.
   */
  private isContentPrimarilyTypes(content: string): boolean {
    const lines = content.split('\n');
    let typeBlocks = 0;
    let nonTypeBlocks = 0;

    const typeStart = /^\s*(export\s+)?(interface|type)\s+\w+/;
    const nonTypeStart = /^\s*(export\s+)?(function|class|const|let|var|enum|async\s+function)\s+\w+/;
    const importPattern = /^\s*import\s/;
    const blankOrComment = /^\s*(\/\/|\/\*|\*|$)/;
    const closingBrace = /^\s*\};\s*$/;

    for (const line of lines) {
      if (blankOrComment.test(line)) continue;
      if (importPattern.test(line)) continue;
      if (closingBrace.test(line)) continue;

      if (typeStart.test(line)) {
        typeBlocks++;
      } else if (nonTypeStart.test(line)) {
        nonTypeBlocks++;
      }
      // Lines inside a block (members, etc.) are ignored for counting
    }

    const totalBlocks = typeBlocks + nonTypeBlocks;
    if (totalBlocks === 0) return false;
    return typeBlocks / totalBlocks >= 0.8;
  }

  // -----------------------------------------------------------------------
  // Private helpers — AST traversal
  // -----------------------------------------------------------------------

  /**
   * Find the deepest (most specific) AST node whose range contains the
   * target row. This gives us a starting point for ancestor walking.
   */
  private findDeepestNodeAtLine(
    node: Parser.SyntaxNode | null | undefined,
    targetRow: number,
  ): Parser.SyntaxNode | null {
    if (!node) return null;

    // If this node doesn't span the target row, skip it
    if (node.startPosition.row > targetRow || node.endPosition.row < targetRow) {
      return null;
    }

    // Try to find a more specific child
    for (const child of this.getNodeChildren(node)) {
      if (!child) continue;
      const deeper = this.findDeepestNodeAtLine(child, targetRow);
      if (deeper) {
        return deeper;
      }
    }

    // No child matched — this node is the deepest
    return node;
  }

  private getNodeChildren(node: Parser.SyntaxNode): Parser.SyntaxNode[] {
    const children = (node as any).children;
    if (Array.isArray(children)) {
      return children as Parser.SyntaxNode[];
    }

    const count = (node as any).childCount ?? 0;
    const result: Parser.SyntaxNode[] = [];
    for (let i = 0; i < count; i++) {
      const child = node.child(i);
      if (child) result.push(child);
    }
    return result;
  }
}

export default ScopeAnalyzer;
