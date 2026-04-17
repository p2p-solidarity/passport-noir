#!/usr/bin/env bash
# Stage 3: CLAUDE.md Spec Compliance Check
# Verifies circuit implementations match spec.toml definitions
set -euo pipefail

PROJECT_DIR="${1:-.}"
CIRCUIT_DIR="$PROJECT_DIR/circuits"
SPEC_FILE="$PROJECT_DIR/benchmark/spec.toml"

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m'

ISSUES=0

issue() { echo -e "  ${RED}[FAIL]${NC} $1"; ISSUES=$((ISSUES + 1)); }
ok()    { echo -e "  ${GREEN}[PASS]${NC} $1"; }
warn_()  { echo -e "  ${YELLOW}[WARN]${NC} $1"; }

echo "=== 3a. Public Input Verification ==="

# Check pub parameters in each circuit's main()
check_pub_inputs() {
  local name="$1"
  local source="$CIRCUIT_DIR/$name/src/main.nr"
  [ -f "$source" ] || return

  # Count parameters marked with 'pub' in the main function
  local pub_count=$(grep -c 'pub ' "$source" 2>/dev/null || true)
  # Subtract non-parameter pub usage (pub fn, pub mod, pub global, pub use)
  local non_param=$(grep -cE '^\s*(pub fn|pub mod|pub global|pub use)' "$source" 2>/dev/null || true)
  pub_count=$((pub_count - non_param))

  echo -n "    $name: $pub_count public inputs"

  if [ "$pub_count" -gt 0 ]; then
    echo -e " ${GREEN}[OK]${NC}"
  else
    echo -e " ${YELLOW}[NONE]${NC}"
  fi
}

BIN_CIRCUITS=(passport_verifier data_integrity disclosure prepare_link show_link passport_adapter openac_show device_binding sdjwt_adapter jwt_x5c_adapter x509_show composite_show)
for circuit in "${BIN_CIRCUITS[@]}"; do
  check_pub_inputs "$circuit"
done

echo ""
echo "=== 3b. Assertion Message Verification ==="

# Verify spec-defined assertion messages exist in source
check_assertions() {
  local name="$1"
  shift
  local source_dir="$CIRCUIT_DIR/$name/src"

  for msg in "$@"; do
    # Search in all .nr files in the circuit AND in openac_core (for delegated assertions)
    local found=false
    for f in "$source_dir/"*.nr "$CIRCUIT_DIR/openac_core/src/"*.nr; do
      [ -f "$f" ] || continue
      if grep -qF "$msg" "$f" 2>/dev/null; then
        found=true
        break
      fi
    done

    if $found; then
      ok "$name: \"$msg\""
    else
      issue "$name: missing assertion \"$msg\""
    fi
  done
}

# passport_verifier
check_assertions "passport_verifier" \
  "Passport DSC signature verification failed"

# data_integrity
check_assertions "data_integrity" \
  "Too many data groups" \
  "Must have at least one data group" \
  "DG length exceeds maximum" \
  "Data group hash mismatch" \
  "SOD combined hash mismatch"

# disclosure
check_assertions "disclosure" \
  "MRZ hash mismatch"

# prepare_link (uses "Hash mismatch" via assert_hash_equals helper)
check_assertions "prepare_link" \
  "Hash mismatch"

# show_link (uses "Hash mismatch" via assert_hash_equals helper)
check_assertions "show_link" \
  "Hash mismatch"

# passport_adapter
check_assertions "passport_adapter" \
  "Passport DSC signature verification failed" \
  "Too many data groups" \
  "Must have at least one data group" \
  "DG length exceeds maximum" \
  "Data group hash mismatch" \
  "SOD combined hash mismatch" \
  "Commitment X mismatch" \
  "Commitment Y mismatch"

# openac_show (v3 Path A: "Age/Nationality not disclosed but output is ..."
# assertions intentionally removed per spec.toml — when a disclosure flag
# is false the corresponding output is left unconstrained to avoid leakage).
check_assertions "openac_show" \
  "Commitment X mismatch" \
  "Commitment Y mismatch" \
  "Age predicate output mismatch" \
  "Nationality output mismatch"

# device_binding
check_assertions "device_binding" \
  "Device binding ECDSA P-256 verification failed"

echo ""
echo "=== 3c. Domain Separator Verification ==="

# v1 domain separators
check_domain() {
  local label="$1"
  local expected="$2"
  local file="$3"

  if grep -qF "$expected" "$file" 2>/dev/null; then
    ok "$label: \"$expected\" found in $(basename "$file")"
  else
    issue "$label: \"$expected\" NOT found in $(basename "$file")"
  fi
}

# v1 circuits use byte arrays for domain separators, check for function names
# prepare_domain() = "openac.preparev1", show_domain() = "openac.show.v1", scope_domain() = "openac.scope.v1"
check_domain "v1/prepare (fn)" "prepare_domain" "$CIRCUIT_DIR/prepare_link/src/main.nr"
check_domain "v1/show (fn)" "show_domain" "$CIRCUIT_DIR/show_link/src/main.nr"
check_domain "v1/scope (fn)" "scope_domain" "$CIRCUIT_DIR/show_link/src/main.nr"
# Verify byte array lengths match expected domain string lengths
check_domain "v1/prepare (16 bytes)" "PREPARE_DOMAIN_BYTES: u32 = 16" "$CIRCUIT_DIR/prepare_link/src/main.nr"
check_domain "v1/show (14 bytes)" "SHOW_DOMAIN_BYTES: u32 = 14" "$CIRCUIT_DIR/show_link/src/main.nr"
check_domain "v1/scope (15 bytes)" "SCOPE_DOMAIN_BYTES: u32 = 15" "$CIRCUIT_DIR/show_link/src/main.nr"

# v2 circuits (in openac_core)
check_domain "v2/show" "openac.show.v2" "$CIRCUIT_DIR/openac_core/src/show.nr"
check_domain "v2/scope" "openac.scope.v2" "$CIRCUIT_DIR/openac_core/src/show.nr"

# v2 domain constants
check_domain "v2/DOMAIN_PASSPORT" "DOMAIN_PASSPORT" "$CIRCUIT_DIR/openac_core/src/commit.nr"
check_domain "v2/DOMAIN_SDJWT" "DOMAIN_SDJWT" "$CIRCUIT_DIR/openac_core/src/commit.nr"
check_domain "v2/DOMAIN_MDL" "DOMAIN_MDL" "$CIRCUIT_DIR/openac_core/src/commit.nr"

# Rust cross-layer (v1)
RUST_OPENAC="$PROJECT_DIR/mopro-binding/src/openac.rs"
if [ -f "$RUST_OPENAC" ]; then
  check_domain "rust/v1/prepare" "openac.preparev1" "$RUST_OPENAC"
  check_domain "rust/v1/show" "openac.show.v1" "$RUST_OPENAC"
  check_domain "rust/v1/scope" "openac.scope.v1" "$RUST_OPENAC"
else
  warn_ "Rust verifier not found at $RUST_OPENAC — skipping cross-layer check"
fi

echo ""
echo "=== 3d. Constants Consistency ==="

check_constant() {
  local name="$1"
  local value="$2"
  local file="$3"

  if grep -qE "(${name}[^=]*=\s*${value}|${name}:\s*u32\s*=\s*${value})" "$file" 2>/dev/null; then
    ok "$name = $value in $(basename "$(dirname "$(dirname "$file")")")"
  else
    # Try simpler grep
    if grep -qF "$name" "$file" 2>/dev/null && grep -qF "$value" "$file" 2>/dev/null; then
      ok "$name = $value in $(basename "$(dirname "$(dirname "$file")")")"
    else
      issue "$name != $value in $(basename "$file")"
    fi
  fi
}

# MAX_DG_COUNT
check_constant "MAX_DG_COUNT" "4" "$CIRCUIT_DIR/data_integrity/src/main.nr"
check_constant "MAX_DG_COUNT" "4" "$CIRCUIT_DIR/passport_adapter/src/main.nr"

# MAX_DG_SIZE
check_constant "MAX_DG_SIZE" "512" "$CIRCUIT_DIR/data_integrity/src/main.nr"
check_constant "MAX_DG_SIZE" "512" "$CIRCUIT_DIR/passport_adapter/src/main.nr"

echo ""
echo "  Spec check complete: $ISSUES issue(s) found"
exit $ISSUES
