# v3 Security Review, Size/Balance, and SD-JWT / X.509 Path Status

> Date: 2026-06-10. Scope: OpenAC v3 / v3.1 architecture (Pedersen arity-5
> commitments with `pk_digest`), the SD-JWT and X.509 credential paths, and the
> ZK circuit size/security trade-off. This document records what was audited,
> what was fixed in this pass, what is a documented verifier contract (not a
> bug), and what remains deferred.

---

## 1. Security — soundness bugs fixed this pass

All three were verified against source, fixed, and covered by negative
regression tests. Full circuit suite: 287 tests pass; Rust lib: 58 pass.

| ID | Circuit | Bug | Fix | Regression test |
|----|---------|-----|-----|-----------------|
| **CRITICAL-2** | `openac_show` | `out_is_older` / `out_nationality` were free witnesses when the matching `disclose_*` flag was `false`. A prover could publish `out_is_older = true` for an underage holder, or an arbitrary nationality, and the proof verified. | `evaluate_predicates` now pins both outputs to a zero sentinel in the `else` branch (mirrors `show_link`'s unlinkable-mode zeroing). | `test_show_rejects_forged_is_older_when_age_undisclosed`, `test_show_rejects_forged_nationality_when_undisclosed` |
| **HIGH-2** | `openac_core::predicate::check_age_above` | `age -= 1` on a `u32` wrapped to ~4.29e9 when `age == 0` (born this calendar year, birthday still ahead), so a newborn satisfied any positive age threshold. Affects every circuit using `age_from_attr` (`openac_show`, `composite_show`). | Subtract only when `age > 0`; an effectively-negative age stays at 0 and fails any positive threshold. | `test_age_same_year_future_birthday_no_underflow`, `test_age_same_year_birthday_passed` |
| **HIGH-5** | `sdjwt_adapter` | `disclosure_count == 0` skipped the entire disclosure loop, so the commitment bound to `SHA256([0; N])`. A prover with a validly-signed JWT could commit to zero real claims. | `verify_disclosure_hashes` now asserts `disclosure_count > 0` (matches `mdoc_adapter`'s `claim_count > 0`). | `test_disclosure_count_zero_rejected` |

Also fixed (Rust binding, X.509 path correctness):

| ID | File | Bug | Fix | Test |
|----|------|-----|-----|------|
| **X509-RUST** | `mopro-binding/src/openac_v3.rs` | `verify_openac_v3` always recomputed a **SHA256** challenge digest (step 7). `x509_show` / `composite_show` emit a **Pedersen** digest, so every X.509/composite proof was rejected with `invalid_challenge_digest`. | Added `ChallengeDigestCheck` to `ShowLayoutV3`. Passport (`show_layout_openac`) keeps `Sha256`; x509/composite builders use `PinnedInProof`, where the digest is enforced via the pinned public input and the SHA256 recompute is skipped. | `test_pinned_challenge_digest_skips_sha256_recompute`, `test_sha256_challenge_digest_still_enforced` |

---

## 2. Security — documented verifier contracts (by design, not bugs)

These were flagged by the audit but are intentional properties of an
anonymous-credential system. They were previously undocumented; explicit
`VERIFIER CONTRACT` comments were added in-circuit so relying parties cannot
misuse them.

- **HIGH-1 — `x509_show` `out_domain_match`.** A proof with
  `out_domain_match == 0` is valid (the holder's domain simply did not match).
  A verifier wanting "domain matched" semantics MUST check
  `out_domain_match == 1` (equality to 1, never `!= 0`, since the boolean
  constraint only guarantees 0-or-1). Comment added at `x509_show/src/main.nr`.

- **HIGH-3 — `jwt_x5c_adapter` `issuer_modulus` trust anchor.** `issuer_modulus`
  is a public input that is NOT proven to chain to any root in-circuit (unlike
  `passport_adapter`, which proves CSCA Merkle inclusion). The circuit proves
  the leaf was signed by `issuer_modulus` and that the modulus is
  self-consistent — NOT that it is trusted. The verifier MUST pin
  `issuer_modulus` against its Mozilla-Root snapshot (`x509-contract.md §5`)
  out-of-circuit. Comment added at `jwt_x5c_adapter/src/main.nr`.

- **HIGH-4 — link-tag namespaces.** `show::compute_link_tag` (passport) keys on
  commitment coordinates; `profile::compute_link_tag` (X.509 / SD-JWT) keys on
  `link_rand`. The two tag spaces are disjoint by construction and never
  cross-comparable. Comment added at `openac_core/src/show.nr`.

- **MEDIUM-4 — `composite_show` prepare/show composition.** The show circuit
  proves the re-opened commitment matches the public `in_commitment_aux_*`, but
  does not re-prove that commitment came from an adapter circuit. Security
  relies on the verifier also verifying the matching prepare proof
  (`out_commitment_* == in_commitment_*`). This is the standard UltraPlonk
  composition pattern; the Rust `verify_openac_v3` already enforces
  `prepare.commitment == show.commitment`.

### Items reviewed and found SOUND (coverage note)

pk_digest binding into the arity-5 commitment; ECDSA nonce → pk_digest →
commitment link (replay-across-session closure); challenge digest folds
commitment coordinates; epoch consistency; unlinkable-mode zero-scope/zero-tag
enforcement; P0-3 RSA exponent pinning (`e == 65537`); serial→TBS byte binding
(revocation-bypass closure); SMT key includes full 20-byte serial + issuer;
CSCA Merkle `path_index < 256`; predicate binding to committed attrs (P0-B);
credential_type pinned to DOMAIN_PASSPORT (P1-8); SD-JWT disclosure inclusion
proof (P0-5); JWS payload binding (P1-4); base64url round-trip.

---

## 3. ZK circuit size / security balance

Gate counts from `benchmark/expected/baseline.toml` (nargo 1.0.0-beta.19).

| Circuit | ACIR opcodes | Artifact | B/gate | Gate budget | Role |
|---------|-------------:|---------:|:------:|:-----------:|------|
| `passport_adapter` | 36,247 | 1.33 MB | B | ≤50k (28% headroom) | prepare (once) |
| `sdjwt_adapter` | 35,885 | 0.80 MB | B | ≤40k (10% headroom) | prepare (once) |
| `jwt_x5c_adapter` | 136,440 | 3.24 MB | B | ≤200k (32% headroom) | prepare (once) |
| `mdoc_adapter` | 692,381 | 10.1 MB | B | — | **not mobile-feasible** |
| `openac_show` | 1,802 | 0.19 MB | D | ≤3k | show |
| `x509_show` | 549 | 0.13 MB | F* | ≤5k | show |
| `composite_show` | 815 | 0.15 MB | F* | ≤8k | show |
| `passport_verifier` | 11,736 | 0.65 MB | C | — | v1 |
| `data_integrity` | 13,643 | 0.41 MB | B | — | v1 |

\* The F bytes/gate grade on the show circuits is a **metric artifact**: ACIR
JSON has a ~100 KB fixed floor that doesn't amortize under ~1k gates. These
circuits are correct and efficient; no action needed.

### Where the balance is right

All show circuits and the passport/sdjwt adapters are within budget with
healthy headroom. The recent soundness closures cost gates that are **not**
negotiable:

- **P0-5** (`sdjwt_adapter`, ~30k gates) — in-circuit base64url disclosure
  inclusion. Rolling it back re-opens the "commit to attacker-chosen hashes"
  gap. Keep.
- **P1-4** (`jwt_x5c_adapter`, ~115k gates) — in-circuit base64url payload
  decode binding JWS signing input to the committed payload. Rolling it back
  re-opens the payload-swap gap. Keep.
- **P0-3 / P1-7** (`passport_adapter`) — exponent pinning + CSCA leaf v2 bind
  modulus/exponent/TBS. ~300 gates, large security value. Keep.

### Where to rebalance (recommendations, with security cost)

1. **`jwt_x5c_adapter` is the single bundle-budget breaker (3.24 MB > the
   ~2.3 MB total budget).** The dominant cost is the b64url decode over
   `JWT_PAYLOAD_LEN = 1024`. **Recommended:** reduce `JWT_PAYLOAD_LEN` to 512
   after measuring real Google/Apple/Microsoft id_token payload sizes
   (typically 400–600 bytes post-normalization). Saves ~55–60k gates / ~1.6 MB.
   **Security cost:** none to soundness; the only risk is locking out issuers
   whose normalized payload exceeds 512 bytes — must be gated by app-layer
   canonicalization that strips non-essential claims first. **Do NOT cut
   blindly** — confirm the payload-size distribution before changing the
   constant, otherwise valid issuers fail to prove.

2. **`mdoc_adapter` (692k gates, 10.1 MB) is not mobile-feasible** and is out of
   scope for the SD-JWT/X.509 paths. The O(N×K) substring selector over
   `MAX_MSG_LEN = 512` dominates. If mDoc ships later, the realistic options are
   (a) drop `MAX_MSG_LEN` to the real ICAO mso size (~256) — saves ~350k gates,
   no soundness cost if real payloads fit; (b) replace the direct selector with
   a polynomial-evaluation substring check — saves ~500k gates at the cost of a
   negligible (~2^-254) Schwartz-Zippel soundness term. Until then, exclude
   `mdoc_adapter` from the iOS bundle.

3. **Bundle budget reality.** Core passport + SD-JWT flow
   (`passport_adapter` + `openac_show` + `sdjwt_adapter`) = ~2.3 MB, exactly on
   budget. Adding `jwt_x5c_adapter` requires recommendation #1 first.

### Do NOT do (would shave gates at a real security cost)

- Moving the CSCA chain or issuer RSA verify off-circuit (reverts to v1 trust
  model — verifier can no longer prove government/CA issuance).
- Replacing SHA256 with Pedersen on externally-verifiable hashes (`sod_hash`,
  JWT payload hash) — breaks the iOS NFC reader / verifier's ability to
  independently recompute the value.

---

## 4. SD-JWT path status

| Stage | Status | Note |
|-------|--------|------|
| `sdjwt_adapter` circuit | DONE | ES256 sig + disclosure hash chain + P0-5 inclusion + arity-5 commitment; now also rejects `disclosure_count == 0` (HIGH-5). 23 tests. |
| Show — passport+SD-JWT bundle | DONE | `composite_show` accepts `aux_domain == DOMAIN_SDJWT`. |
| Show — SD-JWT standalone | **MISSING (decision needed)** | No `sdjwt_show`; SD-JWT can only be shown bundled with a passport via `composite_show`. See §6. |
| Predicates | PARTIAL | `sdjwt_predicate_check` (Pedersen hash equality). Generic predicate evaluator deferred (`predicate-generalization.md`). |
| Rust `prepare_layout_sdjwt` | DONE | All public-input pins correct. |
| Rust `show_layout_composite` | DONE + FIXED | Challenge-digest mode fix (X509-RUST) makes composite verification actually pass. |
| Test vectors | DONE | `sdjwt_adapter.json`, `composite_show.json` current. |
| Cargo prove+verify roundtrip | MISSING | `noir.rs::test_proof_roundtrip_all_circuits` still only runs `disclosure`. Needs real witness fixtures. |
| `Prover.toml` | STALE | Missing 7 v3.2 fields; `nargo execute` would fail (does not affect `nargo test`). |
| Rust `derive_sdjwt_link_rand` | MISSING (blocked) | Needs a Grumpkin Pedersen impl in Rust (same gap that leaves `rerandomize_commitment` unimplemented). |

## 5. X.509 path status

| Stage | Status | Note |
|-------|--------|------|
| `jwt_x5c_adapter` circuit | DONE (RS256) | RSA leaf+issuer verify, P0-4/P1-4 payload binding, P0-G issuer offset dispatch, revocation SMT. Trust anchor documented (HIGH-3). 26 tests. |
| `x509_show` circuit | DONE | Commitment open + ECDSA device binding + domain predicate + challenge/link tag. Domain-match contract documented (HIGH-1). 11 tests. |
| `composite_show` (X509 branch) | DONE | Shares pk_digest across both commitments. 14 tests. |
| Rust verify (x509/composite) | FIXED | X509-RUST challenge-digest fix. |
| Test vectors | DONE | `jwt_x5c_adapter.json`, `x509_show.json`, `composite_show.json` current. |
| Full `main()` happy-path Noir test for `jwt_x5c_adapter` | MISSING | Existing positive tests exercise sub-functions, not a full valid RSA-2048 fixture through `main()`. |
| Cargo prove+verify roundtrip | MISSING | Same as SD-JWT. |
| Rust JWT/x5c witness builder | MISSING | No typed `build_jwt_x5c_witnesses`; caller must assemble the witness map manually. |
| ES256 (ECDSA) JWT variant | DEFERRED | `jwt_x5c_ecdsa_adapter` not implemented (`x509-circuits.md:305`). Phase 5. |
| In-circuit Mozilla Root Merkle | DEFERRED (research) | P0-F Phase 7; off-chain snapshot policy is the v1 contract. |

## 6. Remaining work, prioritized

**P0 — needed for end-to-end prove+verify in CI/integration:**
1. Refresh stale `Prover.toml` for `sdjwt_adapter`, `composite_show`,
   `jwt_x5c_adapter` (block `nargo execute` / `make bench-execute`).
2. Add cargo prove+verify roundtrip tests for `sdjwt_adapter`, `x509_show`,
   `composite_show` (exercise the compiled artifacts through noir-rs). Requires
   building valid RSA/ES256 witness fixtures.
3. Add a full `main()` happy-path Noir test for `jwt_x5c_adapter` with a real
   RSA-2048 fixture.

**P1 — production completeness:**
4. **Decide the SD-JWT standalone show path.** Either build `sdjwt_show`
   (mirror `x509_show`, accept DOMAIN_SDJWT) if SD-JWT-only presentation
   (no passport) is a real use case, or update `x509-design.md:16` to drop the
   `sdjwt_show` label and document that SD-JWT always routes through
   `composite_show`. Also remove the broken `sdjwt_adapter → openac_show`
   cross-link from `spec.toml` (openac_show hard-asserts DOMAIN_PASSPORT).
5. Rust JWT/x5c witness builder (`build_jwt_x5c_witnesses`) for iOS integration.
6. `jwt_x5c_adapter` size: measure real payload sizes, then reduce
   `JWT_PAYLOAD_LEN` 1024 → 512 (see §3.1).

**P2 — deferred research / cleanup:**
7. ES256 JWT variant (`jwt_x5c_ecdsa_adapter`).
8. In-circuit Mozilla Root Merkle (P0-F).
9. Rust `derive_{sdjwt,x509}_link_rand` (blocked on Grumpkin Pedersen in Rust;
   same blocker as `openac_v2::rerandomize_commitment`).
10. Update stale docs: `x509-multi-agent-review.md:45` (P0-E now closed),
    `x509-migration.md §10.1` (openac_v3.rs now exists).
