#!/usr/bin/env bash
# Stage 1: TDD Coverage Check
# Verifies each circuit has adequate test coverage (positive + negative tests)
set -euo pipefail

PROJECT_DIR="${1:-.}"
CIRCUIT_DIR="$PROJECT_DIR/circuits"

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m'

ISSUES=0

echo "  Checking TDD coverage..."

# All workspace bin circuits
BIN_CIRCUITS=(passport_verifier data_integrity disclosure prepare_link show_link passport_adapter openac_show device_binding sdjwt_adapter jwt_x5c_adapter x509_show composite_show)
# Library modules
LIB_MODULES=(openac_core/src/commit.nr openac_core/src/show.nr openac_core/src/predicate.nr)

check_circuit() {
  local name="$1"
  local source_files=("$CIRCUIT_DIR/$name/src/"*.nr)

  local positive=0
  local negative=0

  for f in "${source_files[@]}"; do
    [ -f "$f" ] || continue
    # Count #[test] that are NOT #[test(should_fail)]
    local total=$(grep -c '#\[test' "$f" 2>/dev/null || true)
    local fails=$(grep -c '#\[test(should_fail)' "$f" 2>/dev/null || true)
    positive=$((positive + total - fails))
    negative=$((negative + fails))
  done

  echo -n "    $name: ${positive} positive, ${negative} negative"

  if [ "$positive" -eq 0 ] && [ "$negative" -eq 0 ]; then
    echo -e " ${YELLOW}[NO TESTS]${NC}"
    ISSUES=$((ISSUES + 1))
  elif [ "$positive" -eq 0 ]; then
    echo -e " ${YELLOW}[NO POSITIVE]${NC}"
    ISSUES=$((ISSUES + 1))
  elif [ "$negative" -eq 0 ]; then
    echo -e " ${YELLOW}[NO NEGATIVE]${NC}"
    # Not a hard fail for some circuits (e.g., predicate)
  else
    echo -e " ${GREEN}[OK]${NC}"
  fi
}

for circuit in "${BIN_CIRCUITS[@]}"; do
  if [ -d "$CIRCUIT_DIR/$circuit" ]; then
    check_circuit "$circuit"
  else
    echo -e "    $circuit: ${RED}[MISSING]${NC}"
    ISSUES=$((ISSUES + 1))
  fi
done

echo ""
echo "  Library modules:"
for mod in "${LIB_MODULES[@]}"; do
  local_path="$CIRCUIT_DIR/$mod"
  if [ -f "$local_path" ]; then
    mod_name=$(basename "$mod" .nr)
    positive=$(grep -c '#\[test\]' "$local_path" 2>/dev/null || true)
    negative=$(grep -c '#\[test(should_fail)' "$local_path" 2>/dev/null || true)
    # Adjust positive count (total #[test includes should_fail])
    total=$(grep -c '#\[test' "$local_path" 2>/dev/null || true)
    positive=$((total - negative))
    echo -n "    openac_core::$mod_name: ${positive} positive, ${negative} negative"
    if [ "$total" -eq 0 ]; then
      echo -e " ${YELLOW}[NO TESTS]${NC}"
      ISSUES=$((ISSUES + 1))
    else
      echo -e " ${GREEN}[OK]${NC}"
    fi
  fi
done

# Check for assertion coverage: every assertion message should have a should_fail test
echo ""
echo "  Checking assertion coverage..."
for circuit in "${BIN_CIRCUITS[@]}"; do
  main_file="$CIRCUIT_DIR/$circuit/src/main.nr"
  [ -f "$main_file" ] || continue

  assertion_count=$(grep -c 'assert(' "$main_file" 2>/dev/null || true)
  should_fail_count=0
  for f in "$CIRCUIT_DIR/$circuit/src/"*.nr; do
    [ -f "$f" ] || continue
    sf=$(grep -c '#\[test(should_fail)' "$f" 2>/dev/null || true)
    should_fail_count=$((should_fail_count + sf))
  done

  if [ "$assertion_count" -gt 0 ] && [ "$should_fail_count" -eq 0 ]; then
    echo -e "    $circuit: $assertion_count assertions, 0 should_fail tests ${YELLOW}[UNCOVERED]${NC}"
  else
    echo -e "    $circuit: $assertion_count assertions, $should_fail_count should_fail tests ${GREEN}[OK]${NC}"
  fi
done

exit $ISSUES
