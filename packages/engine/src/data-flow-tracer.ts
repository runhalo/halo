/**
 * DataFlowTracer — single-file data-flow analysis using tree-sitter AST.
 *
 * Answers questions like:
 *   "Does this value pass through DOMPurify before reaching dangerouslySetInnerHTML?"
 *   "Is there a TTL field in this schema?"
 *
 * HARD SCOPE: Single-file only. No cross-file resolution.
 */

import Parser from 'tree-sitter';

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

/**
 * Recursively walk every node in a subtree, calling `visitor` on each one.
 */
function walk(node: Parser.SyntaxNode | null | undefined, visitor: (n: Parser.SyntaxNode) => void): void {
  if (!node || typeof node.type !== 'string') return;
  visitor(node);
  const count = node.childCount || 0;
  for (let i = 0; i < count; i++) {
    walk(node.child(i), visitor);
  }
}

/**
 * Resolve the full text of a call expression's function name.
 * Handles both simple identifiers (`sanitize`) and member expressions
 * (`DOMPurify.sanitize`, `a.b.c`).
 */
function resolveCallName(callNode: Parser.SyntaxNode): string | null {
  const func = callNode.childForFieldName('function');
  if (!func) return null;

  if (func.type === 'identifier') {
    return func.text;
  }

  if (func.type === 'member_expression') {
    return func.text;
  }

  return func.text;
}

/**
 * Find the deepest node whose range contains the given 0-indexed line.
 */
function nodeAtLine(root: Parser.SyntaxNode, line0: number): Parser.SyntaxNode | null {
  let best: Parser.SyntaxNode | null = null;

  walk(root, (n) => {
    if (n.startPosition.row <= line0 && n.endPosition.row >= line0) {
      best = n;
    }
  });

  return best;
}

// ---------------------------------------------------------------------------
// DataFlowTracer
// ---------------------------------------------------------------------------

export class DataFlowTracer {
  private rootNode: Parser.SyntaxNode;

  constructor(tree: Parser.Tree) {
    this.rootNode = tree.rootNode;
  }

  // -----------------------------------------------------------------------
  // passesThrough
  // -----------------------------------------------------------------------

  /**
   * Check if a value at `targetLine` (1-indexed) passes through any of the
   * specified functions before being used.  Searches backward from targetLine
   * for call expressions whose name matches one of `functionNames`.
   *
   * Example:
   *   passesThrough(42, ['DOMPurify.sanitize', 'sanitize', 'xss'])
   *   checks if the value used at line 42 was sanitized.
   */
  passesThrough(targetLine: number, functionNames: string[]): boolean {
    const target0 = targetLine - 1; // convert to 0-indexed

    // 1. Check for INLINE sanitizer calls on the target line itself.
    //    e.g., dangerouslySetInnerHTML={{ __html: DOMPurify.sanitize(content) }}
    //    or    dangerouslySetInnerHTML={{ __html: sanitize(userInput) }}
    let inlineFound = false;
    walk(this.rootNode, (node) => {
      if (inlineFound) return;
      if (node.type === 'call_expression' && node.startPosition.row === target0) {
        const name = resolveCallName(node);
        if (name && functionNames.some((fn) => name === fn || name.endsWith('.' + fn))) {
          inlineFound = true;
        }
      }
    });
    if (inlineFound) return true;

    // 2. Collect all matching call_expression nodes that occur before the target line.
    const matchingCalls: Parser.SyntaxNode[] = [];

    walk(this.rootNode, (node) => {
      if (node.type === 'call_expression' && node.startPosition.row < target0) {
        const name = resolveCallName(node);
        if (name && functionNames.some((fn) => name === fn || name.endsWith('.' + fn))) {
          matchingCalls.push(node);
        }
      }
    });

    if (matchingCalls.length === 0) return false;

    // 3. Check if any of the matching calls assign to a variable that is
    // referenced on the target line.
    const targetLineText = this.getLineText(target0);

    for (const call of matchingCalls) {
      // Walk upward to find a variable_declarator or assignment_expression
      // wrapping this call.
      let parent = call.parent;
      while (parent && parent.type !== 'variable_declarator' && parent.type !== 'assignment_expression') {
        parent = parent.parent;
      }

      if (parent) {
        let assignedName: string | null = null;

        if (parent.type === 'variable_declarator') {
          const nameNode = parent.childForFieldName('name');
          if (nameNode) assignedName = nameNode.text;
        } else if (parent.type === 'assignment_expression') {
          const left = parent.childForFieldName('left');
          if (left) assignedName = left.text;
        }

        // If the variable assigned from the sanitizer call appears on the
        // target line, the value passes through.
        if (assignedName && targetLineText.includes(assignedName)) {
          return true;
        }
      }

      // Also handle the case where the call is used inline on a line just
      // before the target (e.g., the call result is passed directly as an
      // argument or stored in a variable used on the very next statement).
      if (target0 - call.startPosition.row <= 2) {
        return true;
      }
    }

    return false;
  }

  // -----------------------------------------------------------------------
  // hasPropertyInScope
  // -----------------------------------------------------------------------

  /**
   * Check if any property with the given names exists in the same scope/block
   * as the target line (1-indexed).  Used for checking if a Schema has
   * TTL/expires fields.
   *
   * Example:
   *   hasPropertyInScope(42, ['TTL', 'expires', 'retention', 'deleted_at'])
   */
  hasPropertyInScope(targetLine: number, propertyNames: string[]): boolean {
    const target0 = targetLine - 1;
    const lowerNames = propertyNames.map((n) => n.toLowerCase());

    // Find enclosing scope node.
    const scope = this.findEnclosingScopeNode(target0);
    if (!scope) return false;

    let found = false;

    walk(scope, (node) => {
      if (found) return;

      // property_identifier: key in { key: value }
      // shorthand_property_identifier_pattern: { key } destructure
      // shorthand_property_identifier: { key } shorthand
      // pair → key child (for object literals)
      if (
        node.type === 'property_identifier' ||
        node.type === 'shorthand_property_identifier' ||
        node.type === 'shorthand_property_identifier_pattern'
      ) {
        if (lowerNames.includes(node.text.toLowerCase())) {
          found = true;
        }
      }

      // Also match string keys like 'TTL' in { 'TTL': 300 }
      if (node.type === 'string' && node.parent?.type === 'pair') {
        const raw = node.text.replace(/^['"]|['"]$/g, '');
        if (lowerNames.includes(raw.toLowerCase())) {
          found = true;
        }
      }

      // Match identifiers that look like property names in type annotations
      // or interfaces, e.g.  `deleted_at: Date`
      if (node.type === 'identifier' || node.type === 'property_identifier') {
        if (lowerNames.includes(node.text.toLowerCase())) {
          found = true;
        }
      }
    });

    return found;
  }

  // -----------------------------------------------------------------------
  // findNearbyCallExpressions
  // -----------------------------------------------------------------------

  /**
   * Find all call expressions within `range` lines of `targetLine` (1-indexed).
   * Returns function name and line number (1-indexed).
   */
  findNearbyCallExpressions(
    targetLine: number,
    range: number
  ): Array<{ name: string; line: number }> {
    const target0 = targetLine - 1;
    const results: Array<{ name: string; line: number }> = [];

    walk(this.rootNode, (node) => {
      if (node.type === 'call_expression') {
        const line0 = node.startPosition.row;
        if (Math.abs(line0 - target0) <= range) {
          const name = resolveCallName(node);
          if (name) {
            results.push({ name, line: line0 + 1 });
          }
        }
      }
    });

    return results;
  }

  // -----------------------------------------------------------------------
  // getEnclosingScope
  // -----------------------------------------------------------------------

  /**
   * Get the enclosing function/block scope for a given line (1-indexed).
   * Returns the start line (1-indexed), end line (1-indexed), and type of the
   * enclosing scope.
   */
  getEnclosingScope(
    line: number
  ): { startLine: number; endLine: number; type: string } | null {
    const scope = this.findEnclosingFunctionScope(line - 1);
    if (!scope) return null;

    return {
      startLine: scope.startPosition.row + 1,
      endLine: scope.endPosition.row + 1,
      type: scope.type,
    };
  }

  // -----------------------------------------------------------------------
  // findAssignments
  // -----------------------------------------------------------------------

  /**
   * Find all assignments to a variable name within the file.
   * Returns line (1-indexed) and the textual representation of the assigned value.
   */
  findAssignments(variableName: string): Array<{ line: number; value: string }> {
    const results: Array<{ line: number; value: string }> = [];

    walk(this.rootNode, (node) => {
      // const x = ... / let x = ... / var x = ...
      if (node.type === 'variable_declarator') {
        const nameNode = node.childForFieldName('name');
        const valueNode = node.childForFieldName('value');
        if (nameNode && nameNode.text === variableName && valueNode) {
          results.push({
            line: node.startPosition.row + 1,
            value: valueNode.text,
          });
        }
      }

      // x = ... (reassignment)
      if (node.type === 'assignment_expression') {
        const left = node.childForFieldName('left');
        const right = node.childForFieldName('right');
        if (left && left.text === variableName && right) {
          results.push({
            line: node.startPosition.row + 1,
            value: right.text,
          });
        }
      }
    });

    return results;
  }

  // -----------------------------------------------------------------------
  // hasArgument
  // -----------------------------------------------------------------------

  /**
   * Check if a specific argument text is present in a function call at a
   * given line (1-indexed).
   *
   * Handles:
   *   - Simple string/identifier args: ga('create', 'UA-X', 'auto')
   *   - Object literal properties: ga('create', 'UA-X', { child_directed_treatment: true })
   *   - new_expression args: new Analytics({ child_directed_treatment: true })
   *   - Nested object properties at any depth
   *
   * Example:
   *   hasArgument(42, 'child_directed_treatment')
   */
  hasArgument(callLine: number, argumentText: string): boolean {
    const call0 = callLine - 1;
    const lowerTarget = argumentText.toLowerCase();

    let found = false;

    walk(this.rootNode, (node) => {
      if (found) return;

      // Match both call_expression and new_expression at the target line
      const isCallOrNew = node.type === 'call_expression' || node.type === 'new_expression';
      if (isCallOrNew && node.startPosition.row === call0) {
        const args = node.childForFieldName('arguments');
        if (args) {
          // Deep walk the arguments subtree — inspect every node including
          // object literal property keys, values, and nested structures.
          walk(args, (argNode) => {
            if (found) return;

            // Check property keys in object literals: { child_directed_treatment: true }
            if (argNode.type === 'property_identifier' || argNode.type === 'shorthand_property_identifier') {
              if (argNode.text.toLowerCase().includes(lowerTarget)) {
                found = true;
                return;
              }
            }

            // Check string keys: { 'child_directed_treatment': true }
            if (argNode.type === 'string' || argNode.type === 'template_string') {
              const raw = argNode.text.replace(/^['"`]|['"`]$/g, '');
              if (raw.toLowerCase().includes(lowerTarget)) {
                found = true;
                return;
              }
            }

            // Check identifiers (variable names, boolean keywords, etc.)
            if (argNode.type === 'identifier') {
              if (argNode.text.toLowerCase().includes(lowerTarget)) {
                found = true;
                return;
              }
            }

            // Fallback: raw text check on any node
            if (argNode.text.includes(argumentText)) {
              found = true;
            }
          });
        }
      }
    });

    return found;
  }

  // -----------------------------------------------------------------------
  // hasVariableInScope (— Richard Pass 4 fix)
  // -----------------------------------------------------------------------

  /**
   * Check if a variable/constant with a matching name exists in the same
   * block scope as the target line (1-indexed).
   *
   * Searches for: variable declarations, const declarations, let declarations,
   * parameter names, and property assignments.
   *
   * This catches cases like:
   *   - parent_email declared alongside child_email → suppresses coppa-flow-009
   *   - MAX_PAGES constant near IntersectionObserver → suppresses ETHICAL-001
   */
  hasVariableInScope(targetLine: number, variableNames: string[]): boolean {
    const target0 = targetLine - 1;
    const lowerNames = variableNames.map(n => n.toLowerCase());

    // Check both the immediate block scope AND the enclosing function scope
    const blockScope = this.findNearestBlockOrScope(target0);
    const funcScope = this.findEnclosingScopeNode(target0);



    const scopesToCheck = new Set<Parser.SyntaxNode>();
    if (blockScope) scopesToCheck.add(blockScope);
    if (funcScope) scopesToCheck.add(funcScope);

    for (const scope of scopesToCheck) {
      let found = false;

      walk(scope, (node) => {
        if (found) return;

        // Variable declarators: const MAX_PAGES = 10, let parent_email = ...
        if (node.type === 'variable_declarator') {
          const nameNode = node.childForFieldName('name');
          if (nameNode && lowerNames.includes(nameNode.text.toLowerCase())) {
            found = true;
            return;
          }
        }

        // Function parameters: function handler(parent_email, child_email)
        if (node.type === 'identifier' && node.parent?.type === 'formal_parameters') {
          if (lowerNames.includes(node.text.toLowerCase())) {
            found = true;
            return;
          }
        }

        // Assignment expressions: parent_email = req.body.email
        if (node.type === 'assignment_expression') {
          const left = node.childForFieldName('left');
          if (left && lowerNames.includes(left.text.toLowerCase())) {
            found = true;
            return;
          }
        }

        // Identifier references: catches bare references like MAX_PAGES in
        // `if (page < MAX_PAGES)` — the presence of the identifier anywhere
        // in scope (even without a local declaration) is meaningful.
        // Exclude identifiers that are property accesses (member_expression object/property)
        // to avoid matching unrelated nested properties.
        if (node.type === 'identifier') {
          if (node.parent?.type !== 'formal_parameters' &&
              node.parent?.type !== 'variable_declarator' &&
              node.parent?.type !== 'property_identifier') {
            if (lowerNames.includes(node.text.toLowerCase())) {
              found = true;
              return;
            }
          }
        }
      });

      if (found) return true;
    }

    return false;
  }

  // -----------------------------------------------------------------------
  // Private helpers
  // -----------------------------------------------------------------------

  /**
   * Find the enclosing function-level scope for a 0-indexed line.
   * Used by the public getEnclosingScope() API — returns function/class/program scopes.
   */
  private findEnclosingFunctionScope(line0: number): Parser.SyntaxNode | null {
    const scopeTypes = new Set([
      'function_declaration',
      'function',
      'arrow_function',
      'method_definition',
      'class_body',
      'class_declaration',
      'program',
    ]);

    // Fall back to rootNode if nodeAtLine returns null (e.g., empty leading lines
    // where tree-sitter's program node may start at a later row)
    let node = nodeAtLine(this.rootNode, line0) ?? this.rootNode;

    while (node) {
      if (scopeTypes.has(node.type)) {
        return node;
      }
      node = node.parent;
    }

    return null;
  }

  /**
   * Find the enclosing scope node for a 0-indexed line (including block scopes).
   * Used internally by hasPropertyInScope and hasVariableInScope for fine-grained
   * variable/property resolution that respects block scoping.
   */
  private findEnclosingScopeNode(line0: number): Parser.SyntaxNode | null {
    const scopeTypes = new Set([
      'function_declaration',
      'function',
      'arrow_function',
      'method_definition',
      'class_body',
      'class_declaration',
      'program',
      // Also consider block-level scopes for variable resolution
      'statement_block',
      'if_statement',
      'for_statement',
      'for_in_statement',
      'for_of_statement',
      'while_statement',
      'switch_body',
      'export_statement',
    ]);

    // Fall back to rootNode if nodeAtLine returns null (e.g., empty leading lines)
    let node = nodeAtLine(this.rootNode, line0) ?? this.rootNode;

    while (node) {
      if (scopeTypes.has(node.type)) {
        return node;
      }
      node = node.parent;
    }

    return null;
  }

  /**
   * Find the nearest block scope containing the given line (0-indexed).
   * Falls back to the enclosing function/program scope.
   * Used for variable declaration detection — checks both block and function scope.
   */
  private findNearestBlockOrScope(line0: number): Parser.SyntaxNode | null {
    const blockTypes = new Set([
      'statement_block',
      'function_declaration',
      'function',
      'arrow_function',
      'method_definition',
      'class_body',
      'class_declaration',
      'program',
    ]);

    // Fall back to rootNode if nodeAtLine returns null (e.g., empty leading lines)
    let node = nodeAtLine(this.rootNode, line0) ?? this.rootNode;

    while (node) {
      if (blockTypes.has(node.type)) {
        return node;
      }
      node = node.parent;
    }

    return null;
  }

  /**
   * Get the source text of a 0-indexed line by slicing the root node's text.
   */
  private getLineText(line0: number): string {
    const text = this.rootNode.text;
    const lines = text.split('\n');
    return lines[line0] ?? '';
  }
}
