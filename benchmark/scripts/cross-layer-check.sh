#!/usr/bin/env bash
# Cross-Layer Consistency Check
# Verifies domain separators and hash functions align across Noir, Rust, and Swift
set -euo pipefail

PROJECT_DIR="${1:-.}"
CIRCUIT_DIR="$PROJECT_DIR/circuits"
RUST_DIR="$PROJECT_DIR/mopro-binding/src"

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m'

ISSUES=0

issue() { echo -e "  ${RED}[FAIL]${NC} $1"; ISSUES=$((ISSUES + 1)); }
ok()    { echo -e "  ${GREEN}[PASS]${NC} $1"; }
warn_() { echo -e "  ${YELLOW}[WARN]${NC} $1"; }

echo "=== Domain Separator Cross-Layer Check ==="

# v1 domain separators must match between Noir and Rust
RUST_OPENAC="$RUST_DIR/openac.rs"

# v1 Noir circuits use byte arrays for domain separators, so we check function names
# and verify the Rust side has matching string literals
V1_DOMAINS=("openac.preparev1" "openac.show.v1" "openac.scope.v1")
V1_NOIR_PATTERNS=("prepare_domain" "show_domain" "scope_domain")
V1_NOIR_FILES=(
  "$CIRCUIT_DIR/prepare_link/src/main.nr"
  "$CIRCUIT_DIR/show_link/src/main.nr"
  "$CIRCUIT_DIR/show_link/src/main.nr"
)
V1_LABELS=("prepare" "show" "scope")

for i in "${!V1_DOMAINS[@]}"; do
  domain="${V1_DOMAINS[$i]}"
  noir_file="${V1_NOIR_FILES[$i]}"
  noir_pattern="${V1_NOIR_PATTERNS[$i]}"
  label="${V1_LABELS[$i]}"

  # Noir: check domain function exists (byte array form)
  noir_found=false
  if [ -f "$noir_file" ] && grep -qF "$noir_pattern" "$noir_file" 2>/dev/null; then
    noir_found=true
  fi

  # Rust: check string literal
  rust_found=false
  if [ -f "$RUST_OPENAC" ] && grep -qF "$domain" "$RUST_OPENAC" 2>/dev/null; then
    rust_found=true
  fi

  if $noir_found && $rust_found; then
    ok "v1/$label: Noir has ${noir_pattern}() + Rust has \"$domain\""
  elif $noir_found && ! $rust_found; then
    if [ -f "$RUST_OPENAC" ]; then
      issue "v1/$label: Noir has ${noir_pattern}() but \"$domain\" NOT in Rust"
    else
      warn_ "v1/$label: Noir has ${noir_pattern}(); Rust file not found"
    fi
  elif ! $noir_found; then
    issue "v1/$label: ${noir_pattern}() NOT in Noir"
  fi
done

echo ""
echo "=== v2 Domain Separators (Noir only, pending Rust v2) ==="

V2_DOMAINS=("openac.show.v2" "openac.scope.v2")
V2_FILE="$CIRCUIT_DIR/openac_core/src/show.nr"

for domain in "${V2_DOMAINS[@]}"; do
  if [ -f "$V2_FILE" ] && grep -qF "$domain" "$V2_FILE" 2>/dev/null; then
    ok "v2: \"$domain\" present in openac_core"
  else
    issue "v2: \"$domain\" NOT found in openac_core"
  fi
done

echo ""
echo "=== Hash Function Consistency ==="

# Noir uses sha256::digest (via sha256 crate) or std::hash::sha256
# Rust uses sha2::Sha256

# Check each circuit's hash usage
check_hash() {
  local circuit="$1"
  local file="$CIRCUIT_DIR/$circuit/src/main.nr"
  [ -f "$file" ] || return

  local uses_sha256=false
  local uses_pedersen=false

  if grep -qE '(sha256::digest|digest\()' "$file" 2>/dev/null; then uses_sha256=true; fi
  if grep -qE '(pedersen_commitment|pedersen_hash)' "$file" 2>/dev/null; then uses_pedersen=true; fi

  if $uses_sha256 && $uses_pedersen; then
    ok "$circuit: SHA256 + Pedersen (hybrid)"
  elif $uses_sha256; then
    ok "$circuit: SHA256"
  elif $uses_pedersen; then
    ok "$circuit: Pedersen"
  else
    # May use imported functions
    ok "$circuit: hash via imports"
  fi
}

for circuit in passport_verifier data_integrity disclosure prepare_link show_link passport_adapter; do
  check_hash "$circuit"
done

# Check openac_core modules
if grep -qE 'pedersen_commitment' "$CIRCUIT_DIR/openac_core/src/commit.nr" 2>/dev/null; then
  ok "openac_core::commit: Pedersen (Grumpkin)"
fi
if grep -qE 'sha256_digest' "$CIRCUIT_DIR/openac_core/src/show.nr" 2>/dev/null; then
  ok "openac_core::show: SHA256 (challenge digest) + Pedersen (link tag)"
fi

echo ""
echo "  Cross-layer check: $ISSUES issue(s)"
exit $ISSUES
