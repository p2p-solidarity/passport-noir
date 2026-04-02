# Benchmark Agent Instructions

This file provides dynamic instructions for any AI agent (or human) running the benchmark suite.
The benchmark validates that all Noir ZK circuits conform to the spec defined in `CLAUDE.md` and `spec.toml`.

## Pipeline Overview

```
TDD Check ──► Execute ──► CLAUDE.md Spec Check ──► Test Verify ──► Benchmark Metrics
   (1)          (2)              (3)                    (4)              (5)
```

Each stage gates the next. If any stage fails, the pipeline stops and reports the failure.

---

## Stage 1: TDD Check (Red/Green Confirmation)

**Goal:** Confirm every circuit has inline `#[test]` and `#[test(should_fail)]` coverage for all constraints.

**Checks:**
- [ ] Each circuit in `spec.toml` has at least 1 positive test and 1 negative test
- [ ] Every assertion message string in `main.nr` has a corresponding `should_fail` test
- [ ] Cross-circuit integration tests exist (hash chain linkage between circuits)
- [ ] `openac_core` library modules (`commit`, `show`, `predicate`) each have unit tests

**How to verify:**
```bash
# Count tests per circuit
for pkg in passport_verifier data_integrity disclosure prepare_link show_link openac_core passport_adapter; do
  echo "$pkg: $(grep -c '#\[test' circuits/$pkg/src/*.nr 2>/dev/null || echo 0) tests"
done
```

**Pass criteria:** Every circuit listed in `spec.toml` must have `min_positive_tests` and `min_negative_tests` met.

---

## Stage 2: Execute (Compile + Run)

**Goal:** All circuits compile and all tests pass.

**Commands:**
```bash
cd circuits && nargo compile --workspace
cd circuits && nargo test --workspace
```

**Pass criteria:**
- Zero compilation errors
- Zero test failures
- All workspace members compile successfully

**Metrics collected:**
- Compile time per circuit (wall clock)
- Total compile time
- Test execution time

---

## Stage 3: CLAUDE.md Spec Check

**Goal:** Verify circuit implementations match the spec defined in `CLAUDE.md` and `spec.toml`.

### 3a. Public Input Verification
For each circuit, verify that `fn main()` signature matches `spec.toml`:
- Count of `pub` parameters matches `expected_public_inputs`
- Parameter names match `public_input_names`
- Parameter types match `public_input_types`

### 3b. Assertion Message Verification
Every assertion in `spec.toml[circuit].assertions` must exist verbatim in the circuit source:
```bash
grep -F "assertion message here" circuits/<circuit>/src/main.nr
```

### 3c. Domain Separator Verification
Check that domain separator strings match across layers:

| Domain | Noir (v1) | Noir (v2/openac_core) | Rust (mopro) |
|--------|-----------|----------------------|--------------|
| Prepare | `"openac.preparev1"` | N/A (Pedersen) | `"openac.preparev1"` |
| Show | `"openac.show.v1"` | `"openac.show.v2"` | `"openac.show.v1"` |
| Scope | `"openac.scope.v1"` | `"openac.scope.v2"` | `"openac.scope.v1"` |

**Version alignment rule:**
- v1 circuits (`prepare_link`, `show_link`) use SHA256-based commitments with v1 domain separators
- v2 circuits (`openac_core`, `passport_adapter`) use Pedersen commitments with v2 domain separators
- Rust verifier must support both versions or specify which version it targets

### 3d. Cross-Circuit Hash Chain Verification
The most critical spec check. Verify that shared values are consistent:

```
passport_verifier.sod_hash ══► data_integrity.sod_hash ══► prepare_link.sod_hash
                                                                    │
data_integrity.mrz_hash ══► disclosure.mrz_hash ══► prepare_link.mrz_hash
                                                                    │
                                          prepare_link.out_prepare_commitment
                                                    ══► show_link.out_prepare_commitment
```

**For v2 (Pedersen) path:**
```
passport_adapter (combines passport_verifier + data_integrity + openac_core.commit)
    └── out_commitment_x/y ══► openac_core.show.verify_show(commitment_x/y)
```

**Verification method:**
1. Parse each circuit's `fn main()` parameters
2. Build a dependency graph of shared parameter names
3. Assert type equality for linked parameters
4. Assert no orphaned public inputs (every public input consumed by at least one other circuit or verifier)

### 3e. Constants Consistency
Verify shared constants match across circuits:
- `MAX_DG_COUNT = 4` (data_integrity, passport_adapter)
- `MAX_DG_SIZE = 512` (data_integrity, passport_adapter)
- `MRZ_LINE_LEN = 44`, `MRZ_TOTAL_LEN = 88` (disclosure)
- `HASH_LEN = 32` (openac_core/show)

---

## Stage 4: Test Verification

**Goal:** Run all tests and validate results against expected outcomes.

**Commands:**
```bash
cd circuits && nargo test --workspace 2>&1
```

**Analysis:**
- Parse test output for pass/fail counts per circuit
- Compare against `spec.toml` expected test counts
- Flag any new tests not in baseline (good) or missing tests (bad)
- Ensure `should_fail` tests actually fail for the right reason

**Pass criteria:**
- All tests pass
- Test count >= baseline in `expected/baseline.toml`

---

## Stage 5: Benchmark Metrics

**Goal:** Collect quantitative metrics and output a JSON report.

### Metrics to Collect

| Metric | Source | Unit |
|--------|--------|------|
| `compile_time` | `nargo compile` wall clock | seconds |
| `test_time` | `nargo test` wall clock | seconds |
| `gate_count` | `nargo info --package <pkg>` | integer |
| `artifact_size` | `ls -la target/<pkg>.json` | bytes |
| `test_count_positive` | grep `#[test]` (non-should_fail) | integer |
| `test_count_negative` | grep `#[test(should_fail)]` | integer |
| `assertion_count` | grep `assert(` in main.nr | integer |
| `public_input_count` | grep `pub` params in main() | integer |
| `spec_compliance` | Stage 3 pass/fail | boolean |
| `cross_circuit_links` | Stage 3d verification | pass/fail per link |

### Output Format

Reports are written to `benchmark/reports/`:
- `benchmark-<timestamp>.json` — Full machine-readable report
- `benchmark-latest.json` — Symlink to latest
- `summary.txt` — Human-readable summary

### JSON Schema
```json
{
  "timestamp": "2026-04-01T12:00:00Z",
  "nargo_version": "1.0.0-beta.19",
  "circuits": {
    "<circuit_name>": {
      "compile_time_s": 12.3,
      "gate_count": 45000,
      "artifact_size_bytes": 123456,
      "tests": { "positive": 11, "negative": 8, "total": 19 },
      "assertions": 9,
      "public_inputs": 2,
      "spec_compliant": true
    }
  },
  "cross_circuit": {
    "hash_chain_valid": true,
    "domain_separators_consistent": true,
    "constants_consistent": true
  },
  "overall": {
    "all_compile": true,
    "all_tests_pass": true,
    "spec_compliant": true,
    "total_gates": 150000,
    "total_tests": 54
  }
}
```

---

## Regression Detection

Compare `benchmark-latest.json` against `expected/baseline.toml`:
- Gate count regression: warn if > 10% increase
- Test count regression: fail if any tests removed
- Spec compliance regression: fail if any circuit becomes non-compliant
- New circuits: flag as "unbaselined"

---

## Dynamic Agent Behavior

When running as an AI agent:

1. **Before running:** Read `spec.toml` to understand expected state
2. **On failure:** Don't just report — diagnose root cause:
   - Compile error → read the failing circuit source
   - Test failure → read the failing test and its assertion
   - Spec mismatch → show diff between expected and actual
3. **On success:** Compare against baseline and flag regressions
4. **Always:** Output structured JSON + human summary
5. **Update baseline:** After confirmed improvements, update `expected/baseline.toml`

---

## Usage

```bash
# Full pipeline
make benchmark

# Individual stages
make spec-check        # Stage 3 only
make bench-report      # Stage 5 only (assumes compiled)

# From scripts directly
./benchmark/scripts/run-all.sh
./benchmark/scripts/spec-check.sh
./benchmark/scripts/perf-bench.sh
```
