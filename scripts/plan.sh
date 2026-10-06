#!/usr/bin/env bash
# Plan a stack and export the plan as JSON for policy evaluation.
# Usage: scripts/plan.sh <stack-dir>          -> <stack-dir>/plan.json
set -euo pipefail

dir="${1:?usage: scripts/plan.sh <stack-dir>}"

terraform -chdir="$dir" init -backend=false -input=false -no-color >/dev/null
terraform -chdir="$dir" plan -input=false -lock=false -no-color -out=tfplan >/dev/null
terraform -chdir="$dir" show -json tfplan >"$dir/plan.json"

echo "plan: $dir/plan.json ($(jq '.resource_changes | length' "$dir/plan.json") resource changes)"
