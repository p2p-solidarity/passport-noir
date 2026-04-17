#!/usr/bin/env bash
# Stage 4: Cross-Circuit Hash Chain Verification
# Verifies that shared parameters between circuits have matching types and names
set -euo pipefail

PROJECT_DIR="${1:-.}"
CIRCUIT_DIR="$PROJECT_DIR/circuits"

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m'

ISSUES=0

issue() { echo -e "  ${RED}[FAIL]${NC} $1"; ISSUES=$((ISSUES + 1)); }
ok()    { echo -e "  ${GREEN}[PASS]${NC} $1"; }

echo "=== v1 Hash Chain ==="

# Check that a parameter name exists in a circuit's main.nr
param_exists() {
  local circuit="$1"
  local param="$2"
  local file="$CIRCUIT_DIR/$circuit/src/main.nr"
  grep -q "$param" "$file" 2>/dev/null
}

# Check type consistency for a shared parameter between two circuits
check_link() {
  local from="$1"
  local to="$2"
  local param="$3"
  local desc="$4"

  local from_file="$CIRCUIT_DIR/$from/src/main.nr"
  local to_file="$CIRCUIT_DIR/$to/src/main.nr"

  local from_has=false
  local to_has=false

  if grep -q "$param" "$from_file" 2>/dev/null; then from_has=true; fi
  if grep -q "$param" "$to_file" 2>/dev/null; then to_has=true; fi

  if $from_has && $to_has; then
    # Extract type declarations for this param from both files, stripping 'pub ' prefix for comparison
    # Only match fn parameter lines (not comments)
    local from_type=$(grep -E "^\s+${param}\s*:" "$from_file" | head -1 | sed 's/.*:\s*//' | sed 's/[,)].*//' | tr -d ' ' | sed 's/^pub//')
    local to_type=$(grep -E "^\s+${param}\s*:" "$to_file" | head -1 | sed 's/.*:\s*//' | sed 's/[,)].*//' | tr -d ' ' | sed 's/^pub//')

    if [ -n "$from_type" ] && [ -n "$to_type" ]; then
      # Normalize: replace HASH_BYTES with 32 for comparison
      local norm_from=$(echo "$from_type" | sed 's/HASH_BYTES/32/g')
      local norm_to=$(echo "$to_type" | sed 's/HASH_BYTES/32/g')

      if [ "$norm_from" = "$norm_to" ]; then
        ok "$desc: $from -> $to via $param ($from_type)"
      else
        issue "$desc: type mismatch $from($from_type) != $to($to_type) for $param"
      fi
    else
      ok "$desc: $from -> $to via $param (types present)"
    fi
  elif ! $from_has; then
    issue "$desc: $param not found in $from"
  else
    issue "$desc: $param not found in $to"
  fi
}

# v1 chain links
check_link "passport_verifier" "data_integrity" "sod_hash" "v1[1]"
check_link "data_integrity" "disclosure" "mrz_hash" "v1[2]"
check_link "passport_verifier" "prepare_link" "sod_hash" "v1[3]"
check_link "data_integrity" "prepare_link" "mrz_hash" "v1[4]"
check_link "prepare_link" "show_link" "out_prepare_commitment" "v1[5]"

echo ""
echo "=== v2 Commitment Chain ==="

# passport_adapter -> openac_show via commitment
check_link "passport_adapter" "openac_show" "out_commitment_x" "v2[1]"
check_link "passport_adapter" "openac_show" "out_commitment_y" "v2[2]"

echo ""
echo "=== Shared Library Usage ==="

# Verify openac_core is used consistently
check_import() {
  local circuit="$1"
  local import_pattern="$2"
  local desc="$3"
  local file="$CIRCUIT_DIR/$circuit/src/main.nr"

  if grep -qF "$import_pattern" "$file" 2>/dev/null; then
    ok "$desc: $circuit uses $import_pattern"
  else
    issue "$desc: $circuit missing import $import_pattern"
  fi
}

check_import "passport_adapter" "openac_core::commit" "v2 commit"
check_import "openac_show" "openac_core::commit" "v2 commit"
check_import "openac_show" "openac_core::show" "v2 show"
check_import "openac_show" "openac_core::predicate" "v2 predicate"

echo ""
echo "=== Prepare-Show Commitment Equality ==="

# Critical: passport_adapter and openac_show MUST use the same commit function
# Both call commit_attributes() from openac_core::commit
ADAPTER_COMMIT=$(grep -c "commit_attributes" "$CIRCUIT_DIR/passport_adapter/src/main.nr" 2>/dev/null || true)
SHOW_COMMIT=$(grep -c "commit_attributes" "$CIRCUIT_DIR/openac_show/src/main.nr" 2>/dev/null || true)

if [ "$ADAPTER_COMMIT" -gt 0 ] && [ "$SHOW_COMMIT" -gt 0 ]; then
  ok "Both passport_adapter and openac_show use commit_attributes()"
else
  issue "Commitment function usage mismatch (adapter: $ADAPTER_COMMIT, show: $SHOW_COMMIT)"
fi

# Check that passport_adapter uses assert_commitment_eq
if grep -qF "assert_commitment_eq" "$CIRCUIT_DIR/passport_adapter/src/main.nr" 2>/dev/null; then
  ok "passport_adapter verifies commitment output"
else
  issue "passport_adapter missing assert_commitment_eq"
fi

# Check that openac_show re-computes commitment (not trusting external).
# v3 Path A migrated from `commit_attributes(` to `commit_attributes_v3(`;
# accept either so the script works across the v2 -> v3 transition.
if grep -qE "commit_attributes(_v3)?\(" "$CIRCUIT_DIR/openac_show/src/main.nr" 2>/dev/null; then
  ok "openac_show re-computes commitment (self-verifying)"
else
  issue "openac_show does not re-compute commitment"
fi

echo ""
echo "  Cross-circuit check: $ISSUES issue(s)"
exit $ISSUES
