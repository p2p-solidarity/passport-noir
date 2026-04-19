# OpenAC Implementation Analysis

> Mapping between the [OpenAC paper](https://github.com/privacy-ethereum/zkID/blob/main/paper/zkID.pdf) (zkID Team @ PSE, Ethereum Foundation, Nov 2025) and this repository's Noir circuit implementation.

## Paper Reference

**Title:** OpenAC: Open Design for Transparent and Lightweight Anonymous Credentials
**Authors:** The zkID Team @ PSE (Ethereum Foundation)
**Core idea:** Two-phase (Prepare + Show) anonymous credential scheme using ZK proofs, no trusted setup, no issuer modification, compatible with EUDI ARF.

## Architecture Overview

### Paper's Design

```
┌─────────────────────────────────────────────────────────┐
│  Prepare (offline, once per credential)                 │
│  ┌─────────────────────────────────────────────┐        │
│  │ C₁: parse SD-JWT → verify issuer signature  │        │
│  │     → compute message hashes h_i            │        │
│  │     → output Pedersen commitment C^(j)      │        │
│  └─────────────────────────────────────────────┘        │
│                         │                               │
│              C^(j) links both phases                    │
│                         │                               │
│  Show (online, per presentation)                        │
│  ┌─────────────────────────────────────────────┐        │
│  │ C₂: evaluate predicates f_i over messages   │        │
│  │     → verify device ECDSA nonce signature    │        │
│  │     → bind to verifier challenge             │        │
│  └─────────────────────────────────────────────┘        │
└─────────────────────────────────────────────────────────┘
Backend: Spartan + Hyrax Pedersen polynomial commitments
Linking: Commitment equality between C₁ and C₂
```

### Our Implementation

```
┌──────────────────────────────────────────────────────────┐
│  Prepare phase (offline)                                 │
│  ┌──────────────────┐  ┌──────────────────┐              │
│  │ passport_verifier │  │ data_integrity   │              │
│  │ RSA-2048 sig      │  │ DG hash chain    │              │
│  │ verify DSC→SOD    │  │ SOD→DG1..DG4     │              │
│  └────────┬─────────┘  └────────┬─────────┘              │
│           │ sod_hash            │ mrz_hash               │
│           └────────┬────────────┘                        │
│                    ▼                                     │
│           ┌──────────────────┐                           │
│           │ prepare_link     │                           │
│           │ SHA256 commitment│                           │
│           │ = H(domain ‖     │                           │
│           │   sod_hash ‖     │                           │
│           │   mrz_hash ‖     │                           │
│           │   link_rand)     │                           │
│           └────────┬─────────┘                           │
│                    │ prepare_commitment                  │
│                    ▼                                     │
│  Show phase (online, per presentation)                   │
│  ┌──────────────────┐  ┌──────────────────┐              │
│  │ disclosure        │  │ show_link        │              │
│  │ selective reveal  │  │ challenge bind   │              │
│  │ nationality/age/  │  │ scoped link tag  │              │
│  │ name from MRZ     │  │ epoch control    │              │
│  └──────────────────┘  └──────────────────┘              │
└──────────────────────────────────────────────────────────┘
Backend: Noir → mopro (UltraPlonk/Honk)
Linking: SHA256-based prepare_commitment match
```

## Circuit-by-Circuit Mapping

### prepare_link ↔ Paper's Prepare Relation (C₁)

| Paper (C₁) | Our prepare_link | Notes |
|-------------|-----------------|-------|
| Parse SD-JWT → {m_i, s_i, h_i, σ_I} | N/A (handled by passport_verifier + data_integrity) | Credential parsing split into dedicated circuits |
| Assert h_i = SHA256(m_i, s_i) | N/A (handled by data_integrity) | Hash chain verified separately |
| Assert ECDSA.verify(σ_I, PK_I) | N/A (RSA verify in passport_verifier) | Passport uses RSA-2048, not ECDSA |
| Pedersen commitment C = ∏ g_i^{m_i} · h^r | SHA256(domain ‖ sod_hash ‖ mrz_hash ‖ link_rand) | Hash-based commitment (see Design Decision D1) |
| prepareBatch re-randomization | Fresh link_rand per session | No batch needed with hash-based scheme |

**Domain separation:** `"openac.preparev1"` (16 bytes) — matches across Noir, Swift, and Rust.

**Public inputs:** `out_prepare_commitment`
**Private inputs:** `sod_hash`, `mrz_hash`, `link_rand`

### show_link ↔ Paper's Show Relation (C₂)

| Paper (C₂) | Our show_link | Notes |
|-------------|--------------|-------|
| Assert p_i = f_i(m_1,...,m_n) predicates | N/A (handled by disclosure circuit) | Predicate evaluation in separate circuit |
| Assert ECDSA.verify(σ_nonce, m_1[1]) device binding | Not implemented | See Design Decision D2 |
| Challenge binding via commitment | SHA256(show_domain ‖ challenge ‖ prepare_commitment ‖ epoch) | Binds verifier challenge to session |
| Scoped link tag | SHA256(scope_domain ‖ prepare_commitment ‖ link_scope ‖ epoch) | Deterministic within scope+epoch |
| Unlinkable mode | link_mode=false → zero link_scope, zero link_tag | Enforced by circuit assertion |

**Domain separation:**
- Show: `"openac.show.v1"` (14 bytes)
- Scope: `"openac.scope.v1"` (15 bytes)

**Public inputs:** `link_mode`, `link_scope`, `epoch`, `out_prepare_commitment`, `out_challenge_digest`, `out_link_tag`
**Private inputs:** `sod_hash`, `mrz_hash`, `link_rand`, `challenge`

### disclosure ↔ Paper's Predicate Evaluation

The disclosure circuit handles the paper's "predicate functions f_i" over MRZ data:

| Paper predicate | disclosure implementation |
|----------------|-------------------------|
| f_i(m) = m_i (disclosure) | Nationality: `mrz[54..56]`, Name: `mrz[5..43]` |
| f_i(m) ∈ {0,1} (range check) | Age: `age >= threshold` with century rollover |
| Non-disclosed fields zeroed | Enforced per-field when flag=false |

**OpenAC extension:** `main_with_challenge()` adds challenge binding:
`SHA256(show_domain ‖ challenge ‖ mrz_hash ‖ epoch)`

This composes with the base `main()` — call `main()` for basic disclosure, `main_with_challenge()` for OpenAC-mode with session binding.

## Design Decisions

### D1: Hash-based vs Pedersen Commitments

**Decision:** SHA256 hash commitment (current), Pedersen commitment planned for v2.

**Rationale:**
- SHA256 commitment `H(domain ‖ sod_hash ‖ mrz_hash ‖ link_rand)` is computationally binding (collision resistance) and hiding (random `link_rand`)
- Noir/mopro backend doesn't natively support Hyrax commitment equality checking
- Pedersen would require EC scalar multiplication in Noir — significant circuit overhead
- Hash-based approach is sufficient for the current threat model (mobile passport wallet)

**Trade-off:**
- No re-randomization → each session needs fresh `link_rand` and fresh prepare proof
- No batch preparation → cannot amortize prepare work across multiple sessions
- Paper's unlinkability via commitment re-randomization is replaced by fresh randomness

**Migration path:** When Noir gains native Pedersen/EC support or we switch to a Hyrax-compatible backend, replace `compute_prepare_commitment` with Pedersen and add a re-randomization function.

### D2: Device Binding — Out-of-band

**Decision:** Device binding via envelope-layer signature, not in-circuit.

**Rationale:**
- ECDSA P-256 verification in Noir is expensive (~100k+ constraints)
- Paper targets Spartan on T256 curve where ECDSA is natural; our backend is UltraPlonk
- mopro FFI isn't linked yet — device binding is premature to implement in-circuit
- Out-of-band approach: device signs the challenge with Secure Enclave key, verifier checks signature alongside ZK proof

**Implementation plan (v2):**
1. Add `deviceSignature: Data?` and `devicePublicKey: Data?` to `OpenACShowPresentation`
2. Verification: if present, verify ECDSA(challenge, devicePublicKey) using CryptoKit P256
3. Optional — does not break existing flow

**Security note:** Without device binding, proofs are **transferable**. The verifier must trust that the prover is the credential holder. This is acceptable for the current L3 trust model where the passport scan happens on the user's device in a controlled flow.

### D3: Proof Backend — Noir/mopro vs Spartan/Hyrax

**Decision:** Document divergence. "OpenAC-inspired design adapted for Noir/mopro backend."

| Property | Paper (Spartan+Hyrax) | Our impl (Noir/mopro) |
|----------|----------------------|----------------------|
| Setup | Transparent (no trusted setup) | SRS-based (universal, updatable) |
| Commitment | Pedersen vector (homomorphic) | SHA256 hash (one-way) |
| Linking | Native commitment equality | Hash output match |
| Field | T256 (P-256 scalar field) | bn254 (UltraPlonk default) |
| Proving | Spartan sumcheck IOP | UltraPlonk/Honk |

**Security properties preserved:**
- **Soundness** ✅ — Both backends provide computational soundness
- **Zero-knowledge** ✅ — Both backends provide ZK (Noir via UltraPlonk ZK)
- **Unlinkability** ✅ — Fresh `link_rand` per session (vs re-randomization)
- **Non-transferability** ⚠️ — Requires device binding (D2, planned v2)
- **Correctness** ✅ — Circuit constraints enforce correct computation

### D4: disclosure Circuit Integration

**Decision:** Keep `main()` and `main_with_challenge()` as separate entry points.

**Rationale:**
- `main()` is the Noir circuit entry point — it defines the base disclosure circuit
- `main_with_challenge()` composes on top — adds OpenAC challenge binding
- Merging would increase circuit size for non-OpenAC use cases
- Clean composition: callers choose which level of binding they need

**Usage:**
- Basic disclosure (no session binding): use `main()`
- OpenAC mode (with verifier challenge): use `main_with_challenge()`

## Security Properties

| Property | Paper | Our Implementation | Status |
|----------|-------|-------------------|--------|
| **Unforgeability** | Issuer signature verified in C₁ | RSA-2048 verified in passport_verifier | ✅ |
| **Correctness** | Predicate evaluation in C₂ | MRZ parsing + disclosure in disclosure circuit | ✅ |
| **Zero-Knowledge** | Spartan ZK | UltraPlonk ZK via Noir | ✅ |
| **Unlinkability** | Pedersen re-randomization | Fresh link_rand per session | ✅ |
| **Non-transferability** | Device ECDSA in C₂ | Not implemented (planned v2) | ⚠️ |
| **Revocation** | Out of scope | Out of scope | N/A |
| **Collusion resistance** | Simulator-based argument | Fresh randomness prevents linking | ✅ |

## Hash Function Consistency

All layers use identical domain-separated SHA256:

| Function | Domain | Preimage | Used in |
|----------|--------|----------|---------|
| prepare_commitment | `openac.preparev1` | domain ‖ sod_hash ‖ mrz_hash ‖ link_rand | Noir, Swift, Rust |
| challenge_digest | `openac.show.v1` | domain ‖ challenge ‖ prepare_commitment ‖ epoch | Noir, Swift, Rust |
| scoped_link_tag | `openac.scope.v1` | domain ‖ prepare_commitment ‖ link_scope ‖ epoch | Noir, Swift, Rust |

Cross-layer consistency is verified by matching test vectors across all three implementations.

## Test Coverage

| Component | Tests | Coverage |
|-----------|-------|---------|
| prepare_link (Noir) | 3 | Commitment determinism, randomness sensitivity, wrong output rejection |
| show_link (Noir) | 5 | Challenge binding, scoped tag determinism, cross-scope difference, unlinkable mode, tampered challenge |
| disclosure challenge binding (Noir) | 2 | Challenge pass, replay detection |
| Swift OpenAC helpers | 5 | Hash determinism, scoped linking flow, scope mismatch |
| Rust OpenAC verification | 12 | Full prepare+show verification, all error paths, linkability properties |
| **Total OpenAC tests** | **27** | |

## Implementation Status

```
✅ prepare_link circuit        — SHA256 commitment, 3 tests passing
✅ show_link circuit           — Challenge binding + scoped linking, 5 tests passing
✅ disclosure challenge ext    — main_with_challenge composable wrapper, 2 tests passing
✅ Swift OpenAC helpers        — Commitment/digest/tag computation + verification
✅ Rust OpenAC verification    — Full prepare+show verify with error handling
⚠️ Device binding             — Planned v2 (out-of-band ECDSA)
⚠️ Pedersen commitments       — Planned v2 (when Noir EC support matures)
❌ mopro FFI integration      — Not linked yet (app falls back to SD-JWT)
```

## Roadmap

### v1 (current) — Hash-based OpenAC
- [x] prepare_link circuit with SHA256 commitment
- [x] show_link circuit with challenge binding + scoped linkability
- [x] disclosure circuit with optional challenge binding
- [x] Swift helper functions (hash computation + linking verification)
- [x] Rust verification layer (prepare+show cross-checks)
- [ ] mopro FFI linking (blocked on mopro iOS build)

### v2 — Device Binding
- [ ] Add `deviceSignature` / `devicePublicKey` to show envelope
- [ ] CryptoKit P256 verification in Swift `verifyOpenACLinking`
- [ ] Rust p256 crate verification in `verify_openac_prepare_show`
- [ ] End-to-end test with Secure Enclave signed challenge

### v3 — Full OpenAC Compliance
- [ ] Pedersen vector commitments (replace SHA256 hash commitment)
- [ ] Batch prepare with re-randomization
- [ ] Migrate to transparent backend if/when Noir supports Spartan
- [ ] In-circuit device binding (ECDSA P-256 in Noir)
