#!/usr/bin/env bash
# Stage 7: Witness Generation Time Bench (nargo execute)
#
# Runs `nargo execute` on each circuit's Prover.toml and times the witness
# generation step. This is a lower bound on real prove time -- prove also
# needs barretenberg backend work that nargo doesn't do. For full prove +
# verify timings on real hardware, run the mopro-binding cargo bench tests
# (see mopro-binding/src/noir.rs `bench_prove_*` / `bench_verify_*`).
#
# Output: human-readable table on stdout, optional JSON report.
#
# Usage: bash benchmark/scripts/execute-bench.sh [PROJECT_DIR] [REPORT_FILE]

set -euo pipefail

PROJECT_DIR="${1:-.}"
REPORT_FILE="${2:-/dev/stdout}"
CIRCUIT_DIR="$PROJECT_DIR/circuits"

GREEN='\033[0;32m'
YELLOW='\033[1;33m'
RED='\033[0;31m'
CYAN='\033[0;36m'
NC='\033[0m'

ALL_CIRCUITS=(passport_verifier data_integrity disclosure prepare_link show_link passport_adapter openac_show device_binding sdjwt_adapter jwt_x5c_adapter x509_show composite_show)

TIMESTAMP=$(date -u +"%Y-%m-%dT%H:%M:%SZ")
NARGO_VERSION=$(nargo --version 2>/dev/null | head -1 || echo "unknown")

now_ms() {
  python3 -c 'import time; print(int(time.time() * 1000))'
}

echo ""
echo -e "  Witness generation time (${CYAN}nargo execute${NC}, lower bound for prove time)"
echo ""
printf "  %-22s %14s %12s\n" "Circuit" "Witness gen" "Status"
printf "  %-22s %14s %12s\n" "──────────────────────" "──────────────" "────────────"

JSON='{'
JSON+="\"timestamp\":\"$TIMESTAMP\","
JSON+="\"nargo_version\":\"$NARGO_VERSION\","
JSON+="\"circuits\":{"

FIRST=true
TOTAL_MS=0
COUNTED=0
for circuit in "${ALL_CIRCUITS[@]}"; do
  PROVER_TOML="$CIRCUIT_DIR/$circuit/Prover.toml"

  if [ ! -f "$PROVER_TOML" ]; then
    printf "  %-22s %14s ${YELLOW}%12s${NC}\n" "$circuit" "—" "no Prover.toml"
    if $FIRST; then FIRST=false; else JSON+=","; fi
    JSON+="\"$circuit\":{\"witness_gen_ms\":null,\"status\":\"missing_prover_toml\"}"
    continue
  fi

  # Detect empty/placeholder Prover.toml (all values are empty strings).
  # Heuristic: skip when every quoted value is empty AND no numeric assignment
  # is present. Note: BSD grep's [^"]+ would match commas inside list literals,
  # so we exclude commas explicitly with [^",[:space:]]+ to require real chars.
  if ! grep -qE '"[^"[:space:],]+"|=[[:space:]]*[0-9]' "$PROVER_TOML"; then
    printf "  %-22s %14s ${YELLOW}%12s${NC}\n" "$circuit" "—" "empty toml"
    if $FIRST; then FIRST=false; else JSON+=","; fi
    JSON+="\"$circuit\":{\"witness_gen_ms\":null,\"status\":\"empty_prover_toml\"}"
    continue
  fi

  START=$(now_ms)
  if (cd "$CIRCUIT_DIR" && nargo execute --package "$circuit" >/dev/null 2>&1); then
    STATUS="ok"
    STATUS_COLOR=$GREEN
  else
    STATUS="failed"
    STATUS_COLOR=$RED
  fi
  END=$(now_ms)

  ELAPSED_MS=$((END - START))
  if [ "$STATUS" = "ok" ]; then
    TOTAL_MS=$((TOTAL_MS + ELAPSED_MS))
    COUNTED=$((COUNTED + 1))
  fi

  printf "  %-22s %12sms ${STATUS_COLOR}%12s${NC}\n" "$circuit" "$ELAPSED_MS" "$STATUS"

  if $FIRST; then FIRST=false; else JSON+=","; fi
  JSON+="\"$circuit\":{\"witness_gen_ms\":$ELAPSED_MS,\"status\":\"$STATUS\"}"
done

JSON+="},"
JSON+="\"overall\":{"
JSON+="\"total_ms\":$TOTAL_MS,"
JSON+="\"counted\":$COUNTED"
JSON+="}}"

printf "  %-22s %14s %12s\n" "──────────────────────" "──────────────" "────────────"
printf "  %-22s %12sms\n" "TOTAL ($COUNTED ok)" "$TOTAL_MS"
echo ""
echo -e "  Note: witness gen ≪ real prove time. Add barretenberg time + verify"
echo -e "        time via mopro-binding cargo bench for end-to-end numbers."
echo ""

if [ "$REPORT_FILE" != "/dev/stdout" ]; then
  echo "$JSON" > "$REPORT_FILE"
  echo "  Report: $REPORT_FILE"
  echo ""
fi
