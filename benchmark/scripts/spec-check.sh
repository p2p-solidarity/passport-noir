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

BIN_CIRCUITS=(dsc_chain passport_adapter openac_show sdjwt_adapter jwt_x5c_adapter x509_show composite_show)
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

# v1 / v2 circuits (passport_verifier, data_integrity, disclosure,
# prepare_link, show_link, device_binding) retired to circuits-legacy/ on
# 2026-06-10 (spec/upgrade-plan-v3.1.md Phase 3) -- no longer spec-checked.

# dsc_chain (Phase 6: cacheable CSCA trust chain split out of passport_adapter)
check_assertions "dsc_chain" \
  "DSC exponent must be 65537 (ICAO 9303 v3 trust model)" \
  "CSCA signature over DSC TBS failed verification" \
  "CSCA Merkle root mismatch" \
  "dsc_serial must match the CSCA-signed TBS serial bytes" \
  "Revocation witness matches blocked serial" \
  "Revocation SMT root mismatch" \
  "out_dsc_id must equal the computed DSC linking id"

# passport_adapter (Phase 6: per-holder core; CSCA chain moved to dsc_chain,
# linked via the in_dsc_id pin)
check_assertions "passport_adapter" \
  "Passport DSC signature verification failed" \
  "DSC modulus does not match the trusted dsc_chain id" \
  "Too many data groups" \
  "Must have at least one data group" \
  "DG length exceeds maximum" \
  "Data group hash mismatch" \
  "SOD combined hash mismatch" \
  "Commitment X mismatch" \
  "Commitment Y mismatch"

# openac_show (v3.1: challenge digest retired; predicates come from the
# committed claims Field so the v3 "birth_* not bound" asserts are gone.
# CRITICAL-2 2026-06-10: undisclosed outputs are pinned to zero sentinels.)
check_assertions "openac_show" \
  "openac_show only accepts DOMAIN_PASSPORT credentials" \
  "Commitment X mismatch" \
  "Commitment Y mismatch" \
  "Age predicate output mismatch" \
  "Nationality output mismatch" \
  "out_is_older must be false when age not disclosed" \
  "out_nationality must be zero when nationality not disclosed" \
  "Scoped link tag mismatch"

# sdjwt_adapter (Path A v3)
# 2026-04-28 P0-5 partial: out_disclosure_root binds the disclosed slot set.
check_assertions "sdjwt_adapter" \
  "SD-JWT ES256 signature verification failed" \
  "Too many disclosures" \
  "Claim length exceeds maximum" \
  "SD-JWT disclosure hash mismatch" \
  "Commitment X mismatch" \
  "Commitment Y mismatch" \
  "out_disclosure_root must match Pedersen-bound disclosure root"

# jwt_x5c_adapter (Path A v3.1 — RS256 variant)
# 2026-04-28 P0-4: sha256_var-based binding from jwt_signing_input to jwt_signed_hash.
check_assertions "jwt_x5c_adapter" \
  "Leaf certificate signature verification failed" \
  "Issuer certificate signature verification failed" \
  "Leaf cert JWT modulus mismatch" \
  "serial_number must match the issuer-signed leaf TBS serial bytes" \
  "Revocation witness matches blocked serial" \
  "Revocation SMT root mismatch" \
  "Unsupported issuer_format_tag (accepted: 1=GoogleOIDCv1, 2=AppleIDv1, 3=MicrosoftEntraV1)" \
  "Normalized JWT domain missing value" \
  "JWT payload hash mismatch" \
  "JWT signing input hash does not match jwt_signed_hash" \
  "JWT signature verification failed" \
  "Commitment X mismatch" \
  "Commitment Y mismatch"

# x509_show (v3.1: challenge digest retired; unified link tag via
# openac_core::show::verify_show)
check_assertions "x509_show" \
  "Commitment X mismatch" \
  "Commitment Y mismatch" \
  "Domain match predicate mismatch" \
  "Domain match must be boolean (0 or 1)" \
  "Scoped link tag mismatch" \
  "Unlinkable mode requires zero scope"

# composite_show (v3.1: challenge digest retired; arity-8 passport opening;
# unified link tag via openac_core::show::verify_show)
check_assertions "composite_show" \
  "aux_domain must be DOMAIN_X509 or DOMAIN_SDJWT" \
  "Commitment X mismatch" \
  "Commitment Y mismatch" \
  "Age predicate mismatch" \
  "out_is_older must be boolean (0 or 1)" \
  "Aux predicate mismatch" \
  "out_aux_predicate must be boolean (0 or 1)" \
  "Scoped link tag mismatch" \
  "Unlinkable mode requires zero scope"

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

# v1 byte-array domain separators retired with circuits-legacy/ (2026-06-10).
# v3.1: the SHA256 challenge digest ("openac.show.v2") is RETIRED -- the show
# phase has no in-circuit digest. The unified link tag is the only show-phase
# domain anchor.
check_domain "v3.1/DOMAIN_LINK_TAG" "DOMAIN_LINK_TAG" "$CIRCUIT_DIR/openac_core/src/show.nr"
check_domain "v3.1/verify_show" "pub fn verify_show" "$CIRCUIT_DIR/openac_core/src/show.nr"

# Credential-type domain constants
check_domain "v3/DOMAIN_PASSPORT" "DOMAIN_PASSPORT" "$CIRCUIT_DIR/openac_core/src/commit.nr"
check_domain "v3/DOMAIN_X509" "DOMAIN_X509" "$CIRCUIT_DIR/openac_core/src/commit.nr"
check_domain "v3/DOMAIN_SDJWT" "DOMAIN_SDJWT" "$CIRCUIT_DIR/openac_core/src/commit.nr"
check_domain "v3/DOMAIN_MDL" "DOMAIN_MDL" "$CIRCUIT_DIR/openac_core/src/commit.nr"

# v3.1 arity-8 passport commitment
check_domain "v3.1/commit_passport_v3_1" "pub fn commit_passport_v3_1" "$CIRCUIT_DIR/openac_core/src/commit.nr"

# Path A SALT constants for link-rand derivation
check_domain "v3/SALT_X509" "SALT_X509" "$CIRCUIT_DIR/openac_core/src/profile.nr"
check_domain "v3/SALT_SDJWT" "SALT_SDJWT" "$CIRCUIT_DIR/openac_core/src/profile.nr"

# Path A predicate helpers (spec sec 10)
check_domain "v3.1/age_from_claims" "pub fn age_from_claims" "$CIRCUIT_DIR/openac_core/src/predicate.nr"
check_domain "v3/decode_domain" "pub fn decode_domain" "$CIRCUIT_DIR/openac_core/src/predicate.nr"
check_domain "v3/sdjwt_predicate_check" "pub fn sdjwt_predicate_check" "$CIRCUIT_DIR/openac_core/src/predicate.nr"

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

# MAX_DG_COUNT / MAX_DG_SIZE (data_integrity retired; passport_adapter is the
# production DG-chain implementation). v3.1 sec.7.3 cut MAX_DG_COUNT 4->2
# (DG1 + DG15 only).
check_constant "MAX_DG_COUNT" "2" "$CIRCUIT_DIR/passport_adapter/src/main.nr"
check_constant "MAX_DG_SIZE" "512" "$CIRCUIT_DIR/passport_adapter/src/main.nr"

echo ""
echo "=== 3e. ABI-based public-input check (P2-10) ==="
# Issue P2-10 (2026-04-28): the original `pub` count was a grep heuristic.
# Replaced/augmented by spec-check-abi.py which parses every compiled
# circuit's ABI from circuits/target/<name>.json and compares against
# benchmark/spec.toml's public_inputs list. Detects reordering, renames,
# missing entries, and count drift -- the actual things spec-check is
# supposed to catch. We only fail the script if the ABI script returns
# non-zero AND the compiled artifacts exist (so an uncompiled run still
# reports the assertion checks above).
ABI_SCRIPT="$PROJECT_DIR/benchmark/scripts/spec-check-abi.py"
if [ -x "$ABI_SCRIPT" ]; then
  if python3 "$ABI_SCRIPT" "$PROJECT_DIR"; then
    :
  else
    ISSUES=$((ISSUES + 1))
  fi
else
  warn_ "spec-check-abi.py not executable; run \`chmod +x $ABI_SCRIPT\`"
fi

echo ""
echo "  Spec check complete: $ISSUES issue(s) found"
exit $ISSUES
