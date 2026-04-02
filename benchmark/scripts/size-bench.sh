#!/usr/bin/env bash
# Stage 6: Circuit Size & Compression Ratio Analysis
# Measures source vs artifact expansion, bytes/gate efficiency, and assigns grades
set -euo pipefail

PROJECT_DIR="${1:-.}"
CIRCUIT_DIR="$PROJECT_DIR/circuits"
BASELINE="$PROJECT_DIR/benchmark/expected/baseline.toml"

GREEN='\033[0;32m'
YELLOW='\033[1;33m'
RED='\033[0;31m'
CYAN='\033[0;36m'
NC='\033[0m'

# Grade thresholds for bytes/gate (lower = better)
# A: ≤ 10, B: ≤ 30, C: ≤ 60, D: ≤ 100, F: > 100
grade_bytes_per_gate() {
  local bpg="$1"
  if [ "$bpg" -le 10 ]; then echo "A"
  elif [ "$bpg" -le 30 ]; then echo "B"
  elif [ "$bpg" -le 60 ]; then echo "C"
  elif [ "$bpg" -le 100 ]; then echo "D"
  else echo "F"
  fi
}

# Grade color
grade_color() {
  case "$1" in
    A) echo "$GREEN" ;;
    B) echo "$GREEN" ;;
    C) echo "$YELLOW" ;;
    D) echo "$YELLOW" ;;
    F) echo "$RED" ;;
    *) echo "$NC" ;;
  esac
}

ALL_CIRCUITS=(passport_verifier data_integrity disclosure prepare_link show_link passport_adapter openac_show device_binding)

echo ""

# Table header
printf "  %-22s %8s %10s %8s %8s %10s %5s\n" \
  "Circuit" "Source" "Artifact" "Gates" "B/gate" "Expansion" "Grade"
printf "  %-22s %8s %10s %8s %8s %10s %5s\n" \
  "──────────────────────" "────────" "──────────" "────────" "────────" "──────────" "─────"

TOTAL_SOURCE=0
TOTAL_ARTIFACT=0
TOTAL_GATES=0
WORST_GRADE="A"
CIRCUIT_RESULTS=()

for circuit in "${ALL_CIRCUITS[@]}"; do
  SOURCE_DIR="$CIRCUIT_DIR/$circuit/src"
  ARTIFACT="$CIRCUIT_DIR/target/$circuit.json"

  # Source size (all .nr files)
  SRC_SIZE=0
  for f in "$SOURCE_DIR/"*.nr; do
    [ -f "$f" ] || continue
    fsize=$(wc -c < "$f" | tr -d ' ')
    SRC_SIZE=$((SRC_SIZE + fsize))
  done

  # Artifact size
  ART_SIZE=0
  if [ -f "$ARTIFACT" ]; then
    ART_SIZE=$(wc -c < "$ARTIFACT" | tr -d ' ')
  fi

  # Gate count from nargo info
  GATE_COUNT=0
  GATE_OUTPUT=$(cd "$CIRCUIT_DIR" && nargo info --package "$circuit" 2>&1 || true)
  GATE_COUNT=$(echo "$GATE_OUTPUT" | grep '| main ' | head -1 | awk -F'|' '{gsub(/ /,"",$4); print $4}' || true)
  if [ -z "$GATE_COUNT" ] || [ "$GATE_COUNT" = "N/A" ]; then GATE_COUNT=0; fi

  # Compute ratios
  BYTES_PER_GATE=0
  EXPANSION="N/A"
  GRADE="-"

  if [ "$GATE_COUNT" -gt 0 ]; then
    BYTES_PER_GATE=$((ART_SIZE / GATE_COUNT))
    GRADE=$(grade_bytes_per_gate "$BYTES_PER_GATE")
  fi

  if [ "$SRC_SIZE" -gt 0 ]; then
    EXPANSION="${ART_SIZE}/${SRC_SIZE}"
    # Integer expansion ratio
    EXP_RATIO=$((ART_SIZE / SRC_SIZE))
    EXPANSION="${EXP_RATIO}x"
  fi

  GCOLOR=$(grade_color "$GRADE")

  # Format sizes
  if [ "$ART_SIZE" -ge 1048576 ]; then
    ART_FMT="$(echo "scale=1; $ART_SIZE / 1048576" | bc)M"
  elif [ "$ART_SIZE" -ge 1024 ]; then
    ART_FMT="$(echo "scale=0; $ART_SIZE / 1024" | bc)K"
  else
    ART_FMT="${ART_SIZE}B"
  fi

  if [ "$SRC_SIZE" -ge 1024 ]; then
    SRC_FMT="$(echo "scale=1; $SRC_SIZE / 1024" | bc)K"
  else
    SRC_FMT="${SRC_SIZE}B"
  fi

  printf "  %-22s %8s %10s %8s %8s %10s ${GCOLOR}%5s${NC}\n" \
    "$circuit" "$SRC_FMT" "$ART_FMT" "$GATE_COUNT" "${BYTES_PER_GATE}" "$EXPANSION" "$GRADE"

  TOTAL_SOURCE=$((TOTAL_SOURCE + SRC_SIZE))
  TOTAL_ARTIFACT=$((TOTAL_ARTIFACT + ART_SIZE))
  TOTAL_GATES=$((TOTAL_GATES + GATE_COUNT))

  # Track worst grade
  for g in F D C B A; do
    if [ "$GRADE" = "$g" ]; then WORST_GRADE="$g"; break; fi
    if [ "$WORST_GRADE" = "$g" ]; then break; fi
  done

  CIRCUIT_RESULTS+=("$circuit:$SRC_SIZE:$ART_SIZE:$GATE_COUNT:$BYTES_PER_GATE:$GRADE")
done

# Totals
printf "  %-22s %8s %10s %8s %8s %10s %5s\n" \
  "──────────────────────" "────────" "──────────" "────────" "────────" "──────────" "─────"

TOTAL_BPG=0
if [ "$TOTAL_GATES" -gt 0 ]; then
  TOTAL_BPG=$((TOTAL_ARTIFACT / TOTAL_GATES))
fi
TOTAL_EXP=0
if [ "$TOTAL_SOURCE" -gt 0 ]; then
  TOTAL_EXP=$((TOTAL_ARTIFACT / TOTAL_SOURCE))
fi
OVERALL_GRADE=$(grade_bytes_per_gate "$TOTAL_BPG")
OCOLOR=$(grade_color "$OVERALL_GRADE")

# Format total sizes
if [ "$TOTAL_ARTIFACT" -ge 1048576 ]; then
  TOTAL_ART_FMT="$(echo "scale=1; $TOTAL_ARTIFACT / 1048576" | bc)M"
else
  TOTAL_ART_FMT="$(echo "scale=0; $TOTAL_ARTIFACT / 1024" | bc)K"
fi
if [ "$TOTAL_SOURCE" -ge 1024 ]; then
  TOTAL_SRC_FMT="$(echo "scale=1; $TOTAL_SOURCE / 1024" | bc)K"
else
  TOTAL_SRC_FMT="${TOTAL_SOURCE}B"
fi

printf "  %-22s %8s %10s %8s %8s %10s ${OCOLOR}%5s${NC}\n" \
  "TOTAL" "$TOTAL_SRC_FMT" "$TOTAL_ART_FMT" "$TOTAL_GATES" "$TOTAL_BPG" "${TOTAL_EXP}x" "$OVERALL_GRADE"

echo ""

# Baseline regression check
if [ -f "$BASELINE" ]; then
  REGRESSION=0
  for result in "${CIRCUIT_RESULTS[@]}"; do
    IFS=':' read -r name src art gates bpg grade <<< "$result"
    # Read baseline gate count
    baseline_gates=$(grep "^${name} = " "$BASELINE" | grep -v '{' | head -1 | awk '{print $3}' || true)
    if [ -n "$baseline_gates" ] && [ "$baseline_gates" -gt 0 ] && [ "$gates" -gt 0 ]; then
      threshold=$(( baseline_gates + baseline_gates / 10 ))  # 10% regression threshold
      if [ "$gates" -gt "$threshold" ]; then
        echo -e "  ${RED}[REGRESS]${NC} $name: $gates gates (baseline: $baseline_gates, +10% threshold: $threshold)"
        REGRESSION=$((REGRESSION + 1))
      fi
    fi
  done
  if [ "$REGRESSION" -eq 0 ]; then
    echo -e "  ${GREEN}[OK]${NC} No gate count regressions vs baseline"
  fi
fi

echo ""
echo -e "  Grades: ${GREEN}A${NC}(≤10 B/g) ${GREEN}B${NC}(≤30) ${YELLOW}C${NC}(≤60) ${YELLOW}D${NC}(≤100) ${RED}F${NC}(>100)"
echo -e "  Overall: ${OCOLOR}${OVERALL_GRADE}${NC} — ${TOTAL_ART_FMT} total artifacts, ${TOTAL_BPG} bytes/gate avg"
