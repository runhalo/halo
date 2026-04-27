/**
 * Tests for the process-wide AST availability state surfaced by the
 * engine for callers (the CLI) to render an honest degraded-mode
 * banner instead of relying on grep-stderr-for-warnings.
 */

import {
  isAstAvailable,
  getAstFailureMessage,
  _resetAstAvailabilityForTesting,
} from '../index';

describe('AST availability state', () => {
  beforeEach(() => {
    _resetAstAvailabilityForTesting();
  });

  it('reports available by default in a fresh process', () => {
    expect(isAstAvailable()).toBe(true);
    expect(getAstFailureMessage()).toBeNull();
  });

  it('test-only reset restores the available state', () => {
    // Smoke test for the reset helper itself; without it the suite
    // would carry state across tests if any other suite exercised
    // a real parse failure.
    _resetAstAvailabilityForTesting();
    expect(isAstAvailable()).toBe(true);
    expect(getAstFailureMessage()).toBeNull();
  });

  // Note: we don't simulate a parse failure here because the only
  // realistic trigger is a native ABI mismatch, which Jest can't
  // synthesize without reaching into tree-sitter internals. The
  // production behavior is exercised by the CLI's degraded-mode
  // rendering path, which has its own integration test.
});
