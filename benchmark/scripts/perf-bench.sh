#!/usr/bin/env bash
# Stage 5: Performance Benchmarking
# Collects gate counts, artifact sizes, test counts, and outputs JSON
set -euo pipefail

PROJECT_DIR="${1:-.}"
REPORT_FILE="${2:-/dev/stdout}"
CIRCUIT_DIR="$PROJECT_DIR/circuits"

GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m'

TIMESTAMP=$(date -u +"%Y-%m-%dT%H:%M:%SZ")

# Get nargo version
NARGO_VERSION=$(nargo --version 2>/dev/null | head -1 || echo "unknown")

ALL_CIRCUITS=(passport_verifier data_integrity disclosure prepare_link show_link passport_adapter openac_show device_binding)
LIB_CIRCUITS=(openac_core)

echo "  Collecting metrics..."

# Start building JSON
JSON='{'
JSON+="\"timestamp\":\"$TIMESTAMP\","
JSON+="\"nargo_version\":\"$NARGO_VERSION\","
JSON+="\"circuits\":{"

FIRST=true
TOTAL_GATES=0
TOTAL_TESTS=0

for circuit in "${ALL_CIRCUITS[@]}"; do
  SOURCE_DIR="$CIRCUIT_DIR/$circuit/src"
  ARTIFACT="$CIRCUIT_DIR/target/$circuit.json"

  # Test counts
  TOTAL_TEST_COUNT=0
  NEGATIVE_TEST_COUNT=0
  for f in "$SOURCE_DIR/"*.nr; do
    [ -f "$f" ] || continue
    tc=$(grep -c '#\[test' "$f" 2>/dev/null || true)
    nc=$(grep -c '#\[test(should_fail)' "$f" 2>/dev/null || true)
    TOTAL_TEST_COUNT=$((TOTAL_TEST_COUNT + tc))
    NEGATIVE_TEST_COUNT=$((NEGATIVE_TEST_COUNT + nc))
  done
  POSITIVE_TEST_COUNT=$((TOTAL_TEST_COUNT - NEGATIVE_TEST_COUNT))

  # Assertion count (in main.nr only)
  MAIN_FILE="$SOURCE_DIR/main.nr"
  ASSERT_COUNT=0
  if [ -f "$MAIN_FILE" ]; then
    ASSERT_COUNT=$(grep -c 'assert(' "$MAIN_FILE" 2>/dev/null || true)
  fi

  # Public input count
  PUB_COUNT=0
  if [ -f "$MAIN_FILE" ]; then
    PUB_COUNT=$(grep -c ': pub ' "$MAIN_FILE" 2>/dev/null || true)
    # Also count 'pub [' patterns for array types at start of type
    PUB_COUNT2=$(grep -c '^[[:space:]]*[a-z_]*: pub' "$MAIN_FILE" 2>/dev/null || true)
    if [ "$PUB_COUNT2" -gt "$PUB_COUNT" ]; then
      PUB_COUNT=$PUB_COUNT2
    fi
  fi

  # Artifact size
  ARTIFACT_SIZE=0
  if [ -f "$ARTIFACT" ]; then
    ARTIFACT_SIZE=$(wc -c < "$ARTIFACT" | tr -d ' ')
  fi

  # Gate count via nargo info: extract ACIR Opcodes for main function
  GATE_COUNT=0
  GATE_OUTPUT=$(cd "$CIRCUIT_DIR" && nargo info --package "$circuit" 2>&1 || true)
  # Parse: | <package> | main | <ACIR_OPCODES> | <BRILLIG> |
  GATE_COUNT=$(echo "$GATE_OUTPUT" | grep '| main ' | head -1 | awk -F'|' '{gsub(/ /,"",$4); print $4}' || true)
  if [ -z "$GATE_COUNT" ] || [ "$GATE_COUNT" = "N/A" ]; then GATE_COUNT=0; fi

  TOTAL_GATES=$((TOTAL_GATES + GATE_COUNT))
  TOTAL_TESTS=$((TOTAL_TESTS + TOTAL_TEST_COUNT))

  echo -e "    ${GREEN}$circuit${NC}: gates=$GATE_COUNT tests=$TOTAL_TEST_COUNT(+$POSITIVE_TEST_COUNT/-$NEGATIVE_TEST_COUNT) asserts=$ASSERT_COUNT artifact=${ARTIFACT_SIZE}B"

  if $FIRST; then FIRST=false; else JSON+=","; fi
  JSON+="\"$circuit\":{"
  JSON+="\"gate_count\":$GATE_COUNT,"
  JSON+="\"artifact_size_bytes\":$ARTIFACT_SIZE,"
  JSON+="\"tests\":{\"positive\":$POSITIVE_TEST_COUNT,\"negative\":$NEGATIVE_TEST_COUNT,\"total\":$TOTAL_TEST_COUNT},"
  JSON+="\"assertions\":$ASSERT_COUNT,"
  JSON+="\"public_inputs\":$PUB_COUNT"
  JSON+="}"
done

# Library metrics (openac_core)
for lib in "${LIB_CIRCUITS[@]}"; do
  LIB_DIR="$CIRCUIT_DIR/$lib/src"
  LIB_TESTS=0
  LIB_NEGATIVE=0
  for f in "$LIB_DIR/"*.nr; do
    [ -f "$f" ] || continue
    tc=$(grep -c '#\[test' "$f" 2>/dev/null || true)
    nc=$(grep -c '#\[test(should_fail)' "$f" 2>/dev/null || true)
    LIB_TESTS=$((LIB_TESTS + tc))
    LIB_NEGATIVE=$((LIB_NEGATIVE + nc))
  done
  LIB_POSITIVE=$((LIB_TESTS - LIB_NEGATIVE))
  TOTAL_TESTS=$((TOTAL_TESTS + LIB_TESTS))

  echo -e "    ${GREEN}$lib${NC} (lib): tests=$LIB_TESTS(+$LIB_POSITIVE/-$LIB_NEGATIVE)"

  JSON+=",\"$lib\":{\"gate_count\":0,\"artifact_size_bytes\":0,\"tests\":{\"positive\":$LIB_POSITIVE,\"negative\":$LIB_NEGATIVE,\"total\":$LIB_TESTS},\"assertions\":0,\"public_inputs\":0}"
done

JSON+="},"

# Overall
JSON+="\"overall\":{"
JSON+="\"total_gates\":$TOTAL_GATES,"
JSON+="\"total_tests\":$TOTAL_TESTS"
JSON+="}"
JSON+="}"

# Write report
echo "$JSON" > "$REPORT_FILE"

echo ""
echo -e "  Total: ${TOTAL_GATES} gates, ${TOTAL_TESTS} tests"
echo "  Report written to: $REPORT_FILE"
