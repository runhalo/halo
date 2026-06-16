#!/usr/bin/env bash
#
# COPPA-only rule-set guard (fail-closed).
#
# The open-source Halo scanner ships the COPPA rule pack only. This guard
# verifies that packages/engine/rules/rules.json contains exactly the expected
# COPPA rule set:
#
#   * rule count == EXPECTED_RULE_COUNT
#   * every rule id begins with "coppa"
#
# Any mismatch exits non-zero, so both CI and the pre-push hook block the
# change. This script is the single source of truth shared by
# .github/workflows/coppa-rule-guard.yml and .githooks/pre-push, keeping local
# and remote enforcement identical.
#
# If the public rule set is intentionally changing, update
# EXPECTED_RULE_COUNT below in the same change.

set -euo pipefail

EXPECTED_RULE_COUNT=26

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
RULES_JSON="${REPO_ROOT}/packages/engine/rules/rules.json"

fail() {
  echo "COPPA rule guard: $1" >&2
}

if [ ! -f "$RULES_JSON" ]; then
  fail "cannot find $RULES_JSON"
  exit 1
fi

if ! command -v jq >/dev/null 2>&1; then
  fail "jq is required to verify the rule set."
  fail "Install jq (https://jqlang.github.io/jq/) and try again."
  exit 1
fi

if ! jq empty "$RULES_JSON" >/dev/null 2>&1; then
  fail "$RULES_JSON is not valid JSON."
  exit 1
fi

rule_count="$(jq '.rules | length' "$RULES_JSON")"
if ! printf '%s' "$rule_count" | grep -Eq '^[0-9]+$'; then
  fail "could not read a numeric rule count from $RULES_JSON."
  exit 1
fi

# Coerce each id to a string (missing/non-string ids become a clear marker and
# are flagged as non-COPPA) so a malformed rule fails with a useful message
# rather than a cryptic jq crash.
non_coppa_filter='[.rules[] | (.id // "(missing)") | tostring | select(startswith("coppa") | not)]'
non_coppa_count="$(jq "${non_coppa_filter} | length" "$RULES_JSON")"
non_coppa_ids="$(jq -r "${non_coppa_filter} | join(\", \")" "$RULES_JSON")"

errors=0

if [ "$rule_count" -ne "$EXPECTED_RULE_COUNT" ]; then
  fail "unexpected rule count."
  fail "  found:    $rule_count"
  fail "  expected: $EXPECTED_RULE_COUNT"
  errors=1
fi

if [ "$non_coppa_count" -ne 0 ]; then
  fail "found $non_coppa_count non-COPPA rule id(s):"
  fail "  $non_coppa_ids"
  errors=1
fi

if [ "$errors" -ne 0 ]; then
  fail ""
  fail "The open-source scanner ships the COPPA rule pack only. This guard is"
  fail "fail-closed: fix rules.json so it contains exactly ${EXPECTED_RULE_COUNT} COPPA rules,"
  fail "or, if the public rule set is intentionally changing, update"
  fail "EXPECTED_RULE_COUNT in scripts/check-coppa-rules.sh in the same change."
  exit 1
fi

echo "COPPA rule guard: OK (${rule_count} COPPA rules)."
