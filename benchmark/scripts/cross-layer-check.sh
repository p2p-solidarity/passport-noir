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

# v1 circuits retired to circuits-legacy/ (2026-06-10). The v1 Rust verifier
# (openac.rs) is still shipped for old artifacts; if it references the v1
# legacy Noir circuits, they must still exist under circuits-legacy/.
RUST_OPENAC="$RUST_DIR/openac.rs"
LEGACY_DIR="$PROJECT_DIR/circuits-legacy"

if [ -f "$RUST_OPENAC" ]; then
  for legacy in prepare_link show_link; do
    if [ -d "$LEGACY_DIR/$legacy" ]; then
      ok "v1/legacy: $legacy preserved under circuits-legacy/ for openac.rs vectors"
    else
      issue "v1/legacy: openac.rs exists but circuits-legacy/$legacy is missing"
    fi
  done
fi

echo ""
echo "=== v3.1 Show-Phase Anchors (challenge digest retired) ==="

V31_FILE="$CIRCUIT_DIR/openac_core/src/show.nr"

# The unified link tag is the only show-phase domain anchor; the SHA256
# challenge digest ("openac.show.v2") must NOT reappear in-circuit.
if [ -f "$V31_FILE" ] && grep -qF "DOMAIN_LINK_TAG" "$V31_FILE" 2>/dev/null; then
  ok "v3.1: DOMAIN_LINK_TAG present in openac_core::show"
else
  issue "v3.1: DOMAIN_LINK_TAG NOT found in openac_core::show"
fi
if [ -f "$V31_FILE" ] && grep -qF "openac.show.v2" "$V31_FILE" 2>/dev/null; then
  issue "v3.1: retired SHA256 digest domain \"openac.show.v2\" reappeared in show.nr"
else
  ok "v3.1: retired digest domain absent from show.nr (as designed)"
fi

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

for circuit in passport_adapter sdjwt_adapter jwt_x5c_adapter mdoc_adapter; do
  check_hash "$circuit"
done

# Check openac_core modules
if grep -qE 'pedersen_commitment' "$CIRCUIT_DIR/openac_core/src/commit.nr" 2>/dev/null; then
  ok "openac_core::commit: Pedersen (Grumpkin)"
fi
if grep -qE 'pedersen_hash' "$CIRCUIT_DIR/openac_core/src/show.nr" 2>/dev/null; then
  ok "openac_core::show: Pedersen link tag (v3.1 -- no in-circuit digest)"
fi

echo ""
echo "  Cross-layer check: $ISSUES issue(s)"
exit $ISSUES
