#!/usr/bin/env bash
# Evaluate a plan against the guardrails. Non-zero exit = blocked.
# Usage: scripts/gate.sh <stack-dir> [extra conftest args...]
set -euo pipefail

dir="${1:?usage: scripts/gate.sh <stack-dir>}"
shift
root="$(cd "$(dirname "$0")/.." && pwd)"

conftest test "$dir/plan.json" \
  --policy "$root/policies" \
  --data "$root/exceptions" \
  --all-namespaces \
  "$@"
