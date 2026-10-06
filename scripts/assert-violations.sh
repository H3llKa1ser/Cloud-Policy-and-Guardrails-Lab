#!/usr/bin/env bash
# Regression test for the guardrails against a *real* Terraform plan:
# the set of "<level> <rule-id>" findings must exactly match
# <stack-dir>/expected-violations.txt. Catches both missed detections
# (a rule silently stopped firing) and new false positives.
# Usage: scripts/assert-violations.sh <stack-dir>
set -euo pipefail

dir="${1:?usage: scripts/assert-violations.sh <stack-dir>}"
root="$(cd "$(dirname "$0")/.." && pwd)"

# conftest exits non-zero when it finds violations, which is expected here.
report="$("$root/scripts/gate.sh" "$dir" --output json --no-color || true)"

actual="$(jq -r '
    .[]
    | ((.failures // [])[] | "deny " + .msg),
      ((.warnings // [])[] | "warn " + .msg)
  ' <<<"$report" |
  sed -E 's/^(deny|warn) \[([A-Z0-9_]+)\].*/\1 \2/' |
  sort -u)"

expected="$(grep -Ev '^[[:space:]]*(#|$)' "$dir/expected-violations.txt" | sort -u)"

if diff -u <(echo "$expected") <(echo "$actual") --label expected --label actual; then
  echo "OK: $(wc -l <<<"$actual") expected findings, no misses, no extras"
else
  echo "FAIL: guardrail findings drifted from $dir/expected-violations.txt" >&2
  exit 1
fi
