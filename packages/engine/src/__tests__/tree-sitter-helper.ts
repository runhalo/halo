/**
 * Shared tree-sitter parser helper for tests.
 *
 * Tree-sitter's native module can only be safely initialized once per process.
 * All test files that need tree-sitter parsing should import from here to
 * avoid native module conflicts when Jest runs multiple test files.
 */

let Parser: any = null;
let TSLanguage: any = null;
let TSXLanguage: any = null;
let parserInstance: any = null;
let initialized = false;

function ensureInitialized(): void {
  if (initialized) return;
  initialized = true;

  try {
    Parser = require('tree-sitter');
    const TS = require('tree-sitter-typescript');
    TSLanguage = TS.typescript;
    TSXLanguage = TS.tsx;
    parserInstance = new Parser();
    parserInstance.setLanguage(TSLanguage);
  } catch {
    parserInstance = null;
  }
}

/**
 * Parse TypeScript code and return a tree-sitter Tree.
 * Returns null if tree-sitter is not available.
 */
export function parseTS(code: string): any {
  ensureInitialized();
  if (!parserInstance) return null;
  // Ensure we're using TypeScript grammar
  parserInstance.setLanguage(TSLanguage);
  return parserInstance.parse(code);
}

/**
 * Parse TSX code and return a tree-sitter Tree.
 * Returns null if tree-sitter is not available.
 */
export function parseTSX(code: string): any {
  ensureInitialized();
  if (!parserInstance) return null;
  parserInstance.setLanguage(TSXLanguage);
  return parserInstance.parse(code);
}

/**
 * Check if tree-sitter is available.
 */
export function isTreeSitterAvailable(): boolean {
  ensureInitialized();
  return parserInstance !== null;
}
