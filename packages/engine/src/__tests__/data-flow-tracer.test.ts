/**
 * DataFlowTracer — Unit Tests
 *
 * Tests for single-file data-flow analysis using tree-sitter AST.
 *
 * NOTE: Uses shared tree-sitter-helper to avoid native module conflicts
 * when multiple test files load tree-sitter in the same Jest process.
 */

import { DataFlowTracer } from '../data-flow-tracer';
import { parseTS as parseJS, isTreeSitterAvailable } from './tree-sitter-helper';

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

describe('DataFlowTracer', () => {
  beforeAll(() => {
    if (!isTreeSitterAvailable()) {
      console.warn('tree-sitter not available, skipping DataFlowTracer tests');
    }
  });
  // -----------------------------------------------------------------------
  // passesThrough
  // -----------------------------------------------------------------------

  describe('passesThrough', () => {
    it('should return true when value passes through a sanitizer', () => {
      const code = [
        'const raw = getUserInput();',            // line 1
        'const clean = DOMPurify.sanitize(raw);', // line 2
        'el.innerHTML = clean;',                  // line 3
      ].join('\n');

      const tree = parseJS(code);
      const tracer = new DataFlowTracer(tree);

      // Line 3 uses `clean`, which was assigned from DOMPurify.sanitize on line 2.
      expect(tracer.passesThrough(3, ['DOMPurify.sanitize', 'sanitize'])).toBe(true);
    });

    it('should return false when value does NOT pass through a sanitizer', () => {
      const code = [
        'const raw = getUserInput();',  // line 1
        'el.innerHTML = raw;',          // line 2
      ].join('\n');

      const tree = parseJS(code);
      const tracer = new DataFlowTracer(tree);

      expect(tracer.passesThrough(2, ['DOMPurify.sanitize', 'sanitize'])).toBe(false);
    });

    it('should match shortened function names', () => {
      const code = [
        'const raw = getInput();',    // line 1
        'const safe = xss(raw);',     // line 2
        'render(safe);',              // line 3
      ].join('\n');

      const tree = parseJS(code);
      const tracer = new DataFlowTracer(tree);

      expect(tracer.passesThrough(3, ['xss'])).toBe(true);
    });

    it('should return false when sanitizer is called AFTER the target line', () => {
      const code = [
        'el.innerHTML = raw;',                    // line 1
        'const clean = DOMPurify.sanitize(raw);', // line 2
      ].join('\n');

      const tree = parseJS(code);
      const tracer = new DataFlowTracer(tree);

      // The sanitizer call is on line 2, AFTER the usage on line 1.
      expect(tracer.passesThrough(1, ['DOMPurify.sanitize'])).toBe(false);
    });
  });

  // -----------------------------------------------------------------------
  // hasPropertyInScope
  // -----------------------------------------------------------------------

  describe('hasPropertyInScope', () => {
    it('should return true when schema has TTL property', () => {
      const code = [
        'const UserSchema = new Schema({', // line 1
        '  email: String,',                // line 2
        '  TTL: 86400,',                   // line 3
        '  name: String',                  // line 4
        '});',                             // line 5
      ].join('\n');

      const tree = parseJS(code);
      const tracer = new DataFlowTracer(tree);

      expect(tracer.hasPropertyInScope(2, ['TTL', 'expires', 'retention', 'deleted_at'])).toBe(true);
    });

    it('should return true when schema has deleted_at property', () => {
      const code = [
        'const UserSchema = new Schema({', // line 1
        '  email: String,',                // line 2
        '  deleted_at: Date,',             // line 3
        '});',                             // line 4
      ].join('\n');

      const tree = parseJS(code);
      const tracer = new DataFlowTracer(tree);

      expect(tracer.hasPropertyInScope(2, ['TTL', 'expires', 'deleted_at'])).toBe(true);
    });

    it('should return false when schema has no retention fields', () => {
      const code = [
        'const UserSchema = new Schema({', // line 1
        '  email: String,',                // line 2
        '  name: String',                  // line 3
        '});',                             // line 4
      ].join('\n');

      const tree = parseJS(code);
      const tracer = new DataFlowTracer(tree);

      expect(tracer.hasPropertyInScope(2, ['TTL', 'expires', 'deleted_at'])).toBe(false);
    });

    it('should be case-insensitive', () => {
      const code = [
        'const config = {',  // line 1
        '  ttl: 3600,',      // line 2
        '};',                // line 3
      ].join('\n');

      const tree = parseJS(code);
      const tracer = new DataFlowTracer(tree);

      expect(tracer.hasPropertyInScope(2, ['TTL'])).toBe(true);
    });
  });

  // -----------------------------------------------------------------------
  // findNearbyCallExpressions
  // -----------------------------------------------------------------------

  describe('findNearbyCallExpressions', () => {
    it('should find call expressions within range', () => {
      const code = [
        'console.log("start");',           // line 1
        'const data = fetchData();',       // line 2
        'const cleaned = sanitize(data);', // line 3
        'render(cleaned);',                // line 4
        'console.log("end");',             // line 5
      ].join('\n');

      const tree = parseJS(code);
      const tracer = new DataFlowTracer(tree);

      // Within 1 line of line 3 (lines 2-4)
      const calls = tracer.findNearbyCallExpressions(3, 1);

      const names = calls.map((c) => c.name);
      expect(names).toContain('fetchData');
      expect(names).toContain('sanitize');
      expect(names).toContain('render');
    });

    it('should not find call expressions outside range', () => {
      const code = [
        'init();',          // line 1
        '',                 // line 2
        '',                 // line 3
        '',                 // line 4
        'cleanup();',       // line 5
      ].join('\n');

      const tree = parseJS(code);
      const tracer = new DataFlowTracer(tree);

      // Within 1 line of line 3 — neither init (line 1) nor cleanup (line 5)
      const calls = tracer.findNearbyCallExpressions(3, 1);
      const names = calls.map((c) => c.name);
      expect(names).not.toContain('init');
      expect(names).not.toContain('cleanup');
    });

    it('should return 1-indexed line numbers', () => {
      const code = 'foo();';

      const tree = parseJS(code);
      const tracer = new DataFlowTracer(tree);

      const calls = tracer.findNearbyCallExpressions(1, 0);
      expect(calls.length).toBe(1);
      expect(calls[0].line).toBe(1);
      expect(calls[0].name).toBe('foo');
    });
  });

  // -----------------------------------------------------------------------
  // getEnclosingScope
  // -----------------------------------------------------------------------

  describe('getEnclosingScope', () => {
    it('should find enclosing function declaration', () => {
      const code = [
        'function doWork() {',  // line 1
        '  const x = 1;',      // line 2
        '  return x;',         // line 3
        '}',                   // line 4
      ].join('\n');

      const tree = parseJS(code);
      const tracer = new DataFlowTracer(tree);

      const scope = tracer.getEnclosingScope(2);
      expect(scope).not.toBeNull();
      expect(scope!.type).toBe('function_declaration');
      expect(scope!.startLine).toBe(1);
      expect(scope!.endLine).toBe(4);
    });

    it('should find enclosing arrow function', () => {
      const code = [
        'const handler = () => {', // line 1
        '  process();',            // line 2
        '};',                      // line 3
      ].join('\n');

      const tree = parseJS(code);
      const tracer = new DataFlowTracer(tree);

      const scope = tracer.getEnclosingScope(2);
      expect(scope).not.toBeNull();
      expect(scope!.type).toBe('arrow_function');
    });

    it('should find enclosing class method', () => {
      const code = [
        'class Foo {',               // line 1
        '  bar() {',                 // line 2
        '    return this.value;',    // line 3
        '  }',                       // line 4
        '}',                         // line 5
      ].join('\n');

      const tree = parseJS(code);
      const tracer = new DataFlowTracer(tree);

      const scope = tracer.getEnclosingScope(3);
      expect(scope).not.toBeNull();
      expect(scope!.type).toBe('method_definition');
    });

    it('should return program for top-level code', () => {
      const code = 'const x = 1;';

      const tree = parseJS(code);
      const tracer = new DataFlowTracer(tree);

      const scope = tracer.getEnclosingScope(1);
      expect(scope).not.toBeNull();
      expect(scope!.type).toBe('program');
    });
  });

  // -----------------------------------------------------------------------
  // findAssignments
  // -----------------------------------------------------------------------

  describe('findAssignments', () => {
    it('should find variable declarations', () => {
      const code = [
        'const data = fetchData();', // line 1
        'console.log(data);',        // line 2
      ].join('\n');

      const tree = parseJS(code);
      const tracer = new DataFlowTracer(tree);

      const assignments = tracer.findAssignments('data');
      expect(assignments.length).toBe(1);
      expect(assignments[0].line).toBe(1);
      expect(assignments[0].value).toBe('fetchData()');
    });

    it('should find reassignments', () => {
      const code = [
        'let count = 0;',    // line 1
        'count = count + 1;', // line 2
      ].join('\n');

      const tree = parseJS(code);
      const tracer = new DataFlowTracer(tree);

      const assignments = tracer.findAssignments('count');
      expect(assignments.length).toBe(2);
      expect(assignments[0].line).toBe(1);
      expect(assignments[0].value).toBe('0');
      expect(assignments[1].line).toBe(2);
      expect(assignments[1].value).toBe('count + 1');
    });

    it('should return empty array for non-existent variable', () => {
      const code = 'const x = 1;';

      const tree = parseJS(code);
      const tracer = new DataFlowTracer(tree);

      const assignments = tracer.findAssignments('nonexistent');
      expect(assignments.length).toBe(0);
    });
  });

  // -----------------------------------------------------------------------
  // hasArgument
  // -----------------------------------------------------------------------

  describe('hasArgument', () => {
    it('should return true when argument text is present', () => {
      const code = [
        "ga('create', 'UA-123', { child_directed_treatment: true });", // line 1
      ].join('\n');

      const tree = parseJS(code);
      const tracer = new DataFlowTracer(tree);

      expect(tracer.hasArgument(1, 'child_directed_treatment')).toBe(true);
    });

    it('should return false when argument text is NOT present', () => {
      const code = [
        "ga('create', 'UA-123');", // line 1
      ].join('\n');

      const tree = parseJS(code);
      const tracer = new DataFlowTracer(tree);

      expect(tracer.hasArgument(1, 'child_directed_treatment')).toBe(false);
    });

    it('should match partial argument text in nested objects', () => {
      const code = [
        "fbq('init', '123', {}, { restrictDataProcessing: true });", // line 1
      ].join('\n');

      const tree = parseJS(code);
      const tracer = new DataFlowTracer(tree);

      expect(tracer.hasArgument(1, 'restrictDataProcessing')).toBe(true);
    });

    it('should not match arguments on different lines', () => {
      const code = [
        "foo('bar');",                                  // line 1
        "baz('child_directed_treatment');",             // line 2
      ].join('\n');

      const tree = parseJS(code);
      const tracer = new DataFlowTracer(tree);

      // Looking at line 1 should not find the argument on line 2.
      expect(tracer.hasArgument(1, 'child_directed_treatment')).toBe(false);
    });
  });
});
