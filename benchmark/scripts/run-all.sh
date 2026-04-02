#!/usr/bin/env bash
# Benchmark Pipeline Orchestrator
# Flow: TDD Check → Execute → Spec Check → Test Verify → Metrics
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
BENCHMARK_DIR="$(dirname "$SCRIPT_DIR")"
PROJECT_DIR="$(dirname "$BENCHMARK_DIR")"
REPORT_DIR="$BENCHMARK_DIR/reports"
TIMESTAMP=$(date -u +"%Y-%m-%dT%H:%M:%SZ")
REPORT_FILE="$REPORT_DIR/benchmark-$(date +%Y%m%d-%H%M%S).json"

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m'

PASS=0
FAIL=0
WARN=0

stage_header() {
  echo ""
  echo -e "${BLUE}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
  echo -e "${BLUE}  Stage $1: $2${NC}"
  echo -e "${BLUE}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
}

pass() { echo -e "  ${GREEN}[PASS]${NC} $1"; PASS=$((PASS + 1)); }
fail() { echo -e "  ${RED}[FAIL]${NC} $1"; FAIL=$((FAIL + 1)); }
warn() { echo -e "  ${YELLOW}[WARN]${NC} $1"; WARN=$((WARN + 1)); }

mkdir -p "$REPORT_DIR"

# Initialize JSON report
echo '{}' > "$REPORT_FILE"

# ──────────────────────────────────────────────────────────
# Stage 1: TDD Check
# ──────────────────────────────────────────────────────────
stage_header "1" "TDD Check"

TDD_EXIT=0
"$SCRIPT_DIR/tdd-check.sh" "$PROJECT_DIR" || TDD_EXIT=$?
if [ "$TDD_EXIT" -eq 0 ]; then
  pass "TDD coverage requirements met"
else
  warn "TDD coverage: $TDD_EXIT gap(s) detected (non-blocking)"
fi

# ──────────────────────────────────────────────────────────
# Stage 2: Execute (Compile + Run)
# ──────────────────────────────────────────────────────────
stage_header "2" "Execute (Compile + Test)"

COMPILE_START=$(date +%s)
echo "  Compiling workspace..."
if cd "$PROJECT_DIR/circuits" && nargo compile --workspace 2>&1; then
  COMPILE_END=$(date +%s)
  COMPILE_TIME=$((COMPILE_END - COMPILE_START))
  pass "Compilation succeeded (${COMPILE_TIME}s)"
else
  COMPILE_END=$(date +%s)
  COMPILE_TIME=$((COMPILE_END - COMPILE_START))
  fail "Compilation failed (${COMPILE_TIME}s)"
  echo -e "\n${RED}Pipeline stopped at Stage 2. Fix compilation errors first.${NC}"
  exit 1
fi

TEST_START=$(date +%s)
echo "  Running tests..."
TEST_OUTPUT=$(cd "$PROJECT_DIR/circuits" && nargo test --workspace 2>&1) || true
TEST_END=$(date +%s)
TEST_TIME=$((TEST_END - TEST_START))

# Count pass/fail from test output
TEST_PASS=$(echo "$TEST_OUTPUT" | grep -c "ok$" || true)
TEST_FAIL=$(echo "$TEST_OUTPUT" | grep -c "FAILED" || true)

if [ "$TEST_FAIL" -eq 0 ]; then
  pass "All tests passed ($TEST_PASS tests, ${TEST_TIME}s)"
else
  fail "$TEST_FAIL test(s) failed out of $((TEST_PASS + TEST_FAIL)) (${TEST_TIME}s)"
  echo "$TEST_OUTPUT" | grep "FAILED"
fi

# ──────────────────────────────────────────────────────────
# Stage 3: CLAUDE.md Spec Check
# ──────────────────────────────────────────────────────────
stage_header "3" "CLAUDE.md Spec Check"

SPEC_EXIT=0
"$SCRIPT_DIR/spec-check.sh" "$PROJECT_DIR" || SPEC_EXIT=$?
if [ "$SPEC_EXIT" -eq 0 ]; then
  pass "All spec checks passed"
else
  fail "Spec check found $SPEC_EXIT issue(s)"
fi

# ──────────────────────────────────────────────────────────
# Stage 4: Cross-Circuit Hash Chain
# ──────────────────────────────────────────────────────────
stage_header "4" "Cross-Circuit Verification"

CROSS_EXIT=0
"$SCRIPT_DIR/cross-circuit-check.sh" "$PROJECT_DIR" || CROSS_EXIT=$?
"$SCRIPT_DIR/cross-layer-check.sh" "$PROJECT_DIR" || CROSS_EXIT=$((CROSS_EXIT + $?))
if [ "$CROSS_EXIT" -eq 0 ]; then
  pass "Cross-circuit and cross-layer checks passed"
else
  fail "Cross-circuit/layer check found $CROSS_EXIT issue(s)"
fi

# ──────────────────────────────────────────────────────────
# Stage 5: Performance Metrics
# ──────────────────────────────────────────────────────────
stage_header "5" "Performance Metrics"

"$SCRIPT_DIR/perf-bench.sh" "$PROJECT_DIR" "$REPORT_FILE"
pass "Performance metrics collected"

# ──────────────────────────────────────────────────────────
# Stage 6: Size & Compression Ratio
# ──────────────────────────────────────────────────────────
stage_header "6" "Size & Compression Ratio"

SIZE_EXIT=0
"$SCRIPT_DIR/size-bench.sh" "$PROJECT_DIR" || SIZE_EXIT=$?
if [ "$SIZE_EXIT" -eq 0 ]; then
  pass "Size analysis complete"
else
  warn "Size analysis exited with $SIZE_EXIT"
fi

# ──────────────────────────────────────────────────────────
# Stage 7: Quality Lint (9 dimensions)
# ──────────────────────────────────────────────────────────
stage_header "7" "Quality Lint (9 dimensions)"

LINT_EXIT=0
"$SCRIPT_DIR/circuit-lint.sh" "$PROJECT_DIR" || LINT_EXIT=$?
if [ "$LINT_EXIT" -eq 0 ]; then
  pass "Quality lint passed"
else
  fail "Quality lint score below threshold"
fi

# ──────────────────────────────────────────────────────────
# Summary
# ──────────────────────────────────────────────────────────
echo ""
echo -e "${BLUE}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
echo -e "${BLUE}  Benchmark Summary${NC}"
echo -e "${BLUE}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
echo -e "  ${GREEN}PASS: $PASS${NC}  ${RED}FAIL: $FAIL${NC}  ${YELLOW}WARN: $WARN${NC}"
echo -e "  Compile: ${COMPILE_TIME}s  Tests: ${TEST_TIME}s"
echo -e "  Report: $REPORT_FILE"
echo ""

# Create latest symlink
ln -sf "$(basename "$REPORT_FILE")" "$REPORT_DIR/benchmark-latest.json"

# Generate human summary
SUMMARY_FILE="$REPORT_DIR/summary.txt"
cat > "$SUMMARY_FILE" << EOF
Benchmark Summary — $TIMESTAMP
================================
Pass: $PASS | Fail: $FAIL | Warn: $WARN
Compile time: ${COMPILE_TIME}s
Test time: ${TEST_TIME}s
Tests: $TEST_PASS passed, $TEST_FAIL failed
Report: $(basename "$REPORT_FILE")
EOF

if [ "$FAIL" -gt 0 ]; then
  echo -e "${RED}BENCHMARK FAILED${NC}"
  exit 1
else
  echo -e "${GREEN}BENCHMARK PASSED${NC}"
  exit 0
fi
