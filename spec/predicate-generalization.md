# Generic Predicate Evaluator (SD-JWT / X.509 only) — Deferred

> Status: **Deferred** (recorded 2026-04-26).
> Owner: TBD. Trigger to revisit: see §5.

## 1. What it is

A `(claim_index, op, operand)` + postfix-AND/OR/NOT expression evaluator, mounted **only** on the SD-JWT / X.509 / generic-credential path. Passport (`disclosure`, `openac_show` MRZ path) keeps the current hard-coded flags.

This is "Direction B" from the 2026-04-26 zkID design review. Directions C (SDK unify), D (mDoc adapter), E (Passport-AC spec) take priority.

## 2. Why we defer

- Passport's MRZ is ICAO 9303-fixed. Generalised predicates would cost constraints without expressivity gain.
- Path A's commitment scheme (`commit_attributes_v3`) already binds attribute hashes; predicate generality is orthogonal.
- C + D + E together close most of the elegance / EUDI-alignment gap without rewriting `disclosure.nr` or `openac_show.nr`.
- Noir lacks Circom-style cheap selector multiplexers (`IsZero`, `IsEqual`); a postfix evaluator with stack management has unknown constraint blow-up risk that needs prototyping before commitment.

## 3. Why we still want it eventually

- Generic SD-JWT / X.509 credentials can carry arbitrary schemas; hard-coding disclose flags doesn't scale past `nationality / age / name`.
- Verifier currently learns **individual predicate results** (`out_is_older`, `out_nationality`); a generic evaluator can hide intermediates and only reveal the final boolean. This is a privacy upgrade we should ship if the use case demands it.
- Claim-to-claim comparison (`expiry_date >= today`, `loan_amount <= account_balance`) is expressible only with a generic operand mechanism.
- Aligns with zkID's (PSE) post-April 2026 architecture — useful for ecosystem interop / mutual citation.

## 4. Design sketch

### 4.1 Scope boundary

| Path | Predicate model |
|---|---|
| `disclosure`, `openac_show` (passport) | **Unchanged** — hard-coded flags |
| New `generic_predicate` (SD-JWT / X.509 / future credentials) | **Generalised** — see §4.2 |
| `composite_show` | Mix-and-match — passport side hard-coded, aux side generalised |

### 4.2 Public input shape (proposed)

```noir
fn main(
    // ... existing commitment / proof-of-knowledge inputs ...
    pub claim_count: u32,
    pub claim_values: [Field; MAX_CLAIMS],          // already normalised
    pub predicate_count: u32,
    pub predicate_claim_refs: [u32; MAX_PREDICATES],
    pub predicate_ops: [u8; MAX_PREDICATES],         // 0=LE, 1=GE, 2=EQ
    pub predicate_rhs_is_ref: [u8; MAX_PREDICATES],  // 0=const, 1=claim ref
    pub predicate_rhs_values: [Field; MAX_PREDICATES],
    pub expr_count: u32,
    pub expr_tokens: [u8; MAX_EXPR_TOKENS],          // mixed REF / AND / OR / NOT
    pub expr_token_args: [u32; MAX_EXPR_TOKENS],     // predicate index when token=REF
    pub final_result: bool,                          // public output
) { ... }
```

### 4.3 Implementation order

1. **Normaliser layer** (`circuits/openac_core/src/normaliser.nr`): port zkID's `claim-value-normalizer.circom` semantics — formats `bool / uint / iso_date / roc_date / string`. Re-usable across credentials.
2. **Atomic predicate eval** (`circuits/openac_core/src/predicate_eval.nr`): evaluate a single predicate tuple over a claim-value array. Mirrors zkID `eval-predicate.circom`.
3. **Postfix expression eval** (`circuits/openac_core/src/expr_eval.nr`): stack-based AND / OR / NOT over predicate results. Mirrors zkID `logical-expressions.circom`. Needs careful selector design — see §4.4.
4. **Generic adapter** (`circuits/generic_predicate/src/main.nr`): wires (1)-(3) onto an existing commitment from `sdjwt_adapter` / `jwt_x5c_adapter` / `x509_adapter`.
5. **Rust verifier** (`mopro-binding/src/generic_predicate.rs`): policy + expression validator, returns final boolean + verify time.
6. **Swift wrapper** under unified `OpenAC` class (depends on Direction C landing first).

### 4.4 Risks / open questions

- **Constraint cost**: stack-based postfix evaluator in Noir without `IsZero` / `IsEqual` blackbox — first build a 2-token / 4-token PoC and measure gates before committing to MAX_EXPR_TOKENS = 32 / 64.
- **Encoding**: should `predicate_rhs_values` be `Field` (256-bit) or split hi/lo `u128` like our existing `attr_hi/attr_lo`? Field is simpler but verifier-side validation more careful.
- **Reusability of `disclosure` test vectors**: zero — generic adapter has independent inputs. Plan for new test vector batch.
- **Composite interaction**: `composite_show` currently calls `evaluate_predicates` directly. If aux side becomes generic, need a router or split into `composite_show_passport_x_generic`.

## 5. Trigger conditions to revisit

Revisit (and assign owner) when **any one** of these is true:

- A real SD-JWT or X.509 use case requires `(P0 AND P1) OR (NOT P2)` style composition that today forces us to ship a new bespoke circuit.
- A privacy-conscious counterparty raises the "verifier learns individual predicate results" concern as a deal-breaker.
- We need claim-to-claim comparison (e.g., expiry_date relative to today, balance vs threshold from same credential).
- zkID lands a stable v1+ predicate spec we want to be wire-compatible with.
- Direction D (mDoc) is in progress and we discover mDoc would benefit from sharing the predicate evaluator.

## 6. References

- zkID PSE generalised-predicates spec: `../zkID/generalized-predicates/README.md` (566 lines, 2026-04-26 ship).
- zkID atomic predicate impl: `../zkID/wallet-unit-poc/circom/circuits/components/eval-predicates.circom`.
- zkID postfix expression evaluator: `../zkID/wallet-unit-poc/circom/circuits/components/logical-expressions.circom`.
- zkID claim normaliser: `../zkID/wallet-unit-poc/circom/circuits/components/claim-value-normalizer.circom`.
- This repo's hard-coded path: `circuits/disclosure/src/main.nr`, `circuits/openac_show/src/main.nr` (`evaluate_predicates` lines 27-57).
- Comparison context: `OPENAC_COMPARISON.md` §5 (overall paper-vs-impl gaps).
