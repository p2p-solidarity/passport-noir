#!/usr/bin/env bash
# Circuit Lint & Quality Scorer (9 dimensions)
# Evaluates Noir circuits across: FileSize, Modularity, TestCov, GateEff,
# Format, Naming, Security, Transparency, SpecTDD
# Outputs per-circuit grades + overall project score (sentrux-style).
set -euo pipefail

PROJECT_DIR="${1:-.}"
CIRCUIT_DIR="$PROJECT_DIR/circuits"
SPEC_FILE="$PROJECT_DIR/benchmark/spec.toml"

GREEN='\033[0;32m'
YELLOW='\033[1;33m'
RED='\033[0;31m'
CYAN='\033[0;36m'
BOLD='\033[1m'
NC='\033[0m'

# ── Grading helpers ─────────────────────────────────────────

letter() {
  local pct="$1"
  if   [ "$pct" -ge 90 ]; then echo "A"
  elif [ "$pct" -ge 75 ]; then echo "B"
  elif [ "$pct" -ge 60 ]; then echo "C"
  elif [ "$pct" -ge 40 ]; then echo "D"
  else echo "F"
  fi
}

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

# ── Dimension scorers ──────────────────────────────────────

# 1. FileSize: penalize files > 500 lines
score_file_size() {
  local dir="$1" total=0 count=0
  for f in "$dir/"*.nr; do
    [ -f "$f" ] || continue
    lines=$(wc -l < "$f" | tr -d ' ')
    if   [ "$lines" -le 200 ];  then s=100
    elif [ "$lines" -le 500 ];  then s=$(( 100 - (lines - 200) * 40 / 300 ))
    elif [ "$lines" -le 1000 ]; then s=$(( 60 - (lines - 500) * 60 / 500 ))
    else s=0; fi
    total=$((total + s)); count=$((count + 1))
  done
  [ "$count" -eq 0 ] && echo 0 && return
  echo $((total / count))
}

# 2. Modularity: fns per file, use of imports
score_modularity() {
  local dir="$1" total=0 count=0
  for f in "$dir/"*.nr; do
    [ -f "$f" ] || continue
    fn_count=$(grep -c '^[[:space:]]*\(pub \)\{0,1\}fn ' "$f" 2>/dev/null || true)
    test_count=$(grep -c '#\[test' "$f" 2>/dev/null || true)
    non_test_fns=$((fn_count - test_count))
    [ "$non_test_fns" -lt 1 ] && non_test_fns=1
    lines=$(wc -l < "$f" | tr -d ' ')
    lines_per_fn=$((lines / non_test_fns))
    use_count=$(grep -c '^use \|^mod ' "$f" 2>/dev/null || true)
    if   [ "$lines_per_fn" -le 30 ];  then s=100
    elif [ "$lines_per_fn" -le 60 ];  then s=80
    elif [ "$lines_per_fn" -le 100 ]; then s=60
    elif [ "$lines_per_fn" -le 200 ]; then s=40
    else s=20; fi
    bonus=$((use_count * 3)); [ "$bonus" -gt 10 ] && bonus=10
    s=$((s + bonus)); [ "$s" -gt 100 ] && s=100
    total=$((total + s)); count=$((count + 1))
  done
  [ "$count" -eq 0 ] && echo 0 && return
  echo $((total / count))
}

# 3. TestCov: test:assertion ratio + negative test coverage
score_test_coverage() {
  local dir="$1" total_tests=0 total_neg=0 total_asserts=0
  for f in "$dir/"*.nr; do
    [ -f "$f" ] || continue
    tc=$(grep -c '#\[test' "$f" 2>/dev/null || true)
    nc=$(grep -c '#\[test(should_fail)' "$f" 2>/dev/null || true)
    ac=$(grep -c 'assert(' "$f" 2>/dev/null || true)
    total_tests=$((total_tests + tc)); total_neg=$((total_neg + nc)); total_asserts=$((total_asserts + ac))
  done
  [ "$total_asserts" -eq 0 ] && echo 50 && return
  ratio=$((total_tests * 100 / total_asserts))
  [ "$ratio" -gt 200 ] && ratio=200
  s=$((ratio / 2))
  [ "$total_neg" -eq 0 ] && s=$((s * 70 / 100))
  [ "$s" -gt 100 ] && s=100
  echo "$s"
}

# 4. GateEff: bytes per gate
score_gate_efficiency() {
  local circuit="$1"
  local artifact="$CIRCUIT_DIR/target/$circuit.json"
  [ ! -f "$artifact" ] && echo 50 && return
  local art_size gate_count
  art_size=$(wc -c < "$artifact" | tr -d ' ')
  gate_output=$(cd "$CIRCUIT_DIR" && nargo info --package "$circuit" 2>&1 || true)
  gate_count=$(echo "$gate_output" | grep '| main ' | head -1 | awk -F'|' '{gsub(/ /,"",$4); print $4}' || true)
  if [ -z "$gate_count" ] || [ "$gate_count" = "N/A" ] || [ "$gate_count" -eq 0 ]; then echo 50; return; fi
  local bpg=$((art_size / gate_count))
  if   [ "$bpg" -le 10 ];  then echo 100
  elif [ "$bpg" -le 30 ];  then echo 80
  elif [ "$bpg" -le 60 ];  then echo 60
  elif [ "$bpg" -le 100 ]; then echo 40
  else echo 20; fi
}

# 5. Format: nargo fmt --check
score_format() {
  local circuit="$1"
  if cd "$CIRCUIT_DIR" && nargo fmt --check --package "$circuit" >/dev/null 2>&1; then
    echo 100
  else echo 0; fi
}

# 6. Naming: snake_case fns
score_naming() {
  local dir="$1" violations=0 total=0
  for f in "$dir/"*.nr; do
    [ -f "$f" ] || continue
    while IFS= read -r name; do
      total=$((total + 1))
      echo "$name" | grep -qE '[A-Z]' && violations=$((violations + 1))
    done < <(grep -oP '(?<=fn )\w+' "$f" 2>/dev/null || true)
  done
  [ "$total" -eq 0 ] && echo 100 && return
  echo $(( (total - violations) * 100 / total ))
}

# 7. Security: unconstrained inputs, missing assert messages, hardcoded secrets
score_security() {
  local dir="$1" penalties=0 checks=0

  for f in "$dir/"*.nr; do
    [ -f "$f" ] || continue

    # 7a. Every assert() should have a message string
    asserts_total=$(grep -c 'assert(' "$f" 2>/dev/null || true)
    asserts_with_msg=$(grep -c 'assert(.*,.*"' "$f" 2>/dev/null || true)
    asserts_no_msg=$((asserts_total - asserts_with_msg))
    penalties=$((penalties + asserts_no_msg * 5))
    checks=$((checks + asserts_total))

    # 7b. No hardcoded hex secrets (≥32 chars of hex = suspicious)
    hardcoded_hex=$(grep -cE '0x[0-9a-fA-F]{32,}' "$f" 2>/dev/null || true)
    # Exclude test functions
    hardcoded_in_tests=$(grep -A1 '#\[test' "$f" 2>/dev/null | grep -cE '0x[0-9a-fA-F]{32,}' 2>/dev/null || true)
    hardcoded_outside=$((hardcoded_hex - hardcoded_in_tests))
    [ "$hardcoded_outside" -lt 0 ] && hardcoded_outside=0
    penalties=$((penalties + hardcoded_outside * 15))
    checks=$((checks + 1))

    # 7c. Unchecked array access patterns (direct index without bounds check)
    unsafe_index=$(grep -cE '\[[a-z_]+\]' "$f" 2>/dev/null || true)
    # This is informational — just light penalty
    penalties=$((penalties + unsafe_index / 10))
    checks=$((checks + 1))
  done

  [ "$checks" -eq 0 ] && echo 80 && return
  s=$((100 - penalties))
  [ "$s" -lt 0 ] && s=0
  [ "$s" -gt 100 ] && s=100
  echo "$s"
}

# 8. Transparency: assertion messages, domain separators, public input docs
score_transparency() {
  local dir="$1" circuit="$2" s=100

  for f in "$dir/"*.nr; do
    [ -f "$f" ] || continue

    # 8a. Assert message coverage (% of asserts with descriptive messages)
    asserts_total=$(grep -c 'assert(' "$f" 2>/dev/null || true)
    asserts_with_msg=$(grep -c 'assert(.*,.*"' "$f" 2>/dev/null || true)
    if [ "$asserts_total" -gt 0 ]; then
      msg_pct=$((asserts_with_msg * 100 / asserts_total))
      # Weighted contribution
      s=$(( (s * 60 + msg_pct * 40) / 100 ))
    fi

    # 8b. Domain separator presence (for circuits that use commitments)
    uses_sha=$(grep -c 'sha256\|digest' "$f" 2>/dev/null || true)
    uses_pedersen=$(grep -c 'pedersen\|commit' "$f" 2>/dev/null || true)
    if [ "$((uses_sha + uses_pedersen))" -gt 0 ]; then
      has_domain=$(grep -c 'openac\.\|domain' "$f" 2>/dev/null || true)
      [ "$has_domain" -eq 0 ] && s=$((s - 20))
    fi
  done

  # 8c. Public inputs documented in spec.toml
  if [ -f "$SPEC_FILE" ]; then
    in_spec=$(grep -c "\[circuits\.$circuit\]" "$SPEC_FILE" 2>/dev/null || true)
    [ "$in_spec" -eq 0 ] && s=$((s - 15))
  fi

  [ "$s" -lt 0 ] && s=0
  [ "$s" -gt 100 ] && s=100
  echo "$s"
}

# 9. SpecTDD: spec.toml conformance + TDD red/green discipline
score_spec_tdd() {
  local dir="$1" circuit="$2" s=100

  # 9a. Must have both positive and negative tests
  total_tests=0 total_neg=0
  for f in "$dir/"*.nr; do
    [ -f "$f" ] || continue
    tc=$(grep -c '#\[test' "$f" 2>/dev/null || true)
    nc=$(grep -c '#\[test(should_fail)' "$f" 2>/dev/null || true)
    total_tests=$((total_tests + tc)); total_neg=$((total_neg + nc))
  done
  total_pos=$((total_tests - total_neg))

  # No positive tests = major failure
  [ "$total_pos" -eq 0 ] && s=$((s - 40))
  # No negative tests = missing red phase
  [ "$total_neg" -eq 0 ] && s=$((s - 30))

  # 9b. Spec.toml has this circuit defined
  if [ -f "$SPEC_FILE" ]; then
    in_spec=$(grep -c "\[circuits\.$circuit\]" "$SPEC_FILE" 2>/dev/null || true)
    [ "$in_spec" -eq 0 ] && s=$((s - 15))

    # 9c. Public inputs in spec match actual pub count in source
    spec_pub_count=$(grep -A20 "\[circuits\.$circuit\]" "$SPEC_FILE" 2>/dev/null \
      | grep 'public_inputs' | head -1 \
      | grep -oE '"[^"]*"' | wc -l | tr -d ' ' || true)
    actual_pub=0
    main_file="$dir/main.nr"
    if [ -f "$main_file" ]; then
      actual_pub=$(grep -c ': pub ' "$main_file" 2>/dev/null || true)
    fi
    if [ -n "$spec_pub_count" ] && [ "$spec_pub_count" -gt 0 ] && [ "$actual_pub" -gt 0 ]; then
      if [ "$spec_pub_count" -ne "$actual_pub" ]; then
        s=$((s - 15))
      fi
    fi
  else
    s=$((s - 20))
  fi

  [ "$s" -lt 0 ] && s=0
  [ "$s" -gt 100 ] && s=100
  echo "$s"
}

# ── Main ────────────────────────────────────────────────────

BIN_CIRCUITS=(passport_verifier data_integrity disclosure prepare_link show_link passport_adapter openac_show device_binding)
LIB_CIRCUITS=(openac_core sdjwt_adapter)
ALL_CIRCUITS=("${BIN_CIRCUITS[@]}" "${LIB_CIRCUITS[@]}")

DIMENSIONS=("Size" "Mod" "Test" "Gate" "Fmt" "Name" "Sec" "Trans" "Spec")
DIM_WEIGHTS=(10 10 15 10 10 5 20 10 10)  # total = 100

echo ""
echo -e "${BOLD}  Circuit Quality Report${NC}"
echo -e "  $(date -u +"%Y-%m-%d %H:%M UTC")"
echo ""

# Header
printf "  ${BOLD}%-18s" "Circuit"
for dim in "${DIMENSIONS[@]}"; do
  printf " %5s" "$dim"
done
printf " %6s %5s${NC}\n" "Score" "Grade"

SEP="  ──────────────────"
for _ in "${DIMENSIONS[@]}"; do SEP+=" ─────"; done
SEP+=" ────── ─────"
echo "$SEP"

GRAND_TOTAL=0
CIRCUIT_COUNT=0

for circuit in "${ALL_CIRCUITS[@]}"; do
  SRC_DIR="$CIRCUIT_DIR/$circuit/src"
  [ ! -d "$SRC_DIR" ] && continue

  s1=$(score_file_size "$SRC_DIR")
  s2=$(score_modularity "$SRC_DIR")
  s3=$(score_test_coverage "$SRC_DIR")

  # Gate efficiency: bin circuits only
  s4=50
  is_bin=false
  for b in "${BIN_CIRCUITS[@]}"; do [ "$b" = "$circuit" ] && is_bin=true && break; done
  $is_bin && s4=$(score_gate_efficiency "$circuit")

  s5=$(score_format "$circuit")
  s6=$(score_naming "$SRC_DIR")
  s7=$(score_security "$SRC_DIR")
  s8=$(score_transparency "$SRC_DIR" "$circuit")
  s9=$(score_spec_tdd "$SRC_DIR" "$circuit")

  scores=("$s1" "$s2" "$s3" "$s4" "$s5" "$s6" "$s7" "$s8" "$s9")

  weighted=0
  for i in "${!scores[@]}"; do
    weighted=$((weighted + scores[i] * DIM_WEIGHTS[i]))
  done
  total_score=$((weighted / 100))
  grade=$(letter "$total_score")
  gcolor=$(grade_color "$grade")

  printf "  %-18s" "$circuit"
  for i in "${!scores[@]}"; do
    sc="${scores[$i]}"
    g=$(letter "$sc")
    gc=$(grade_color "$g")
    printf " ${gc}%5s${NC}" "$sc"
  done
  printf " %6s ${gcolor}%5s${NC}\n" "$total_score" "$grade"

  GRAND_TOTAL=$((GRAND_TOTAL + total_score))
  CIRCUIT_COUNT=$((CIRCUIT_COUNT + 1))
done

echo "$SEP"

[ "$CIRCUIT_COUNT" -gt 0 ] && OVERALL=$((GRAND_TOTAL / CIRCUIT_COUNT)) || OVERALL=0
OVERALL_GRADE=$(letter "$OVERALL")
OCOLOR=$(grade_color "$OVERALL_GRADE")

printf "  ${BOLD}%-18s" "OVERALL"
for _ in "${DIMENSIONS[@]}"; do printf "      "; done
printf " %6s ${OCOLOR}%5s${NC}\n" "$OVERALL" "$OVERALL_GRADE"

echo ""
echo -e "  ${BOLD}9 Dimensions (weighted):${NC}"
echo "    Size(10%)  — Lines per source file (≤200=A, >1000=F)"
echo "    Mod(10%)   — Fn decomposition, imports, lines/fn ratio"
echo "    Test(15%)  — Test:assertion ratio + negative test coverage"
echo "    Gate(10%)  — Bytes/gate artifact efficiency"
echo "    Fmt(10%)   — nargo fmt --check compliance"
echo "    Name(5%)   — snake_case functions, naming conventions"
echo "    Sec(20%)   — Assert messages, no hardcoded secrets, safe patterns"
echo "    Trans(10%) — Domain separators, public input docs, spec.toml coverage"
echo "    Spec(10%)  — TDD red/green discipline, spec.toml conformance"
echo ""
echo -e "  ${BOLD}Grades:${NC} ${GREEN}A${NC}(≥90) ${GREEN}B${NC}(≥75) ${YELLOW}C${NC}(≥60) ${YELLOW}D${NC}(≥40) ${RED}F${NC}(<40)"
echo ""

if [ "$OVERALL" -lt 60 ]; then
  echo -e "  ${RED}LINT FAILED${NC} — score $OVERALL < 60 (minimum C)"
  exit 1
else
  echo -e "  ${GREEN}LINT PASSED${NC} — score $OVERALL ($OVERALL_GRADE)"
  exit 0
fi
