# OpenAC Extensions for Passports — passport-noir Spec

> Status: **Draft v0.1** (2026-04-26)
> Scope: Documents four design extensions in this repo that go beyond the
> OpenAC paper (zkID PSE, November 2025) and the zkID PoC. Each extension is
> motivated, specified, and security-argued so external auditors and
> downstream integrators can reason about them without reading source.
>
> Companion docs:
> - `openAC.md` — paper-to-impl mapping
> - `OPENAC_COMPARISON.md` — gap analysis vs zkID v1.0/v2.0/v3.0 (2026-04-26)
> - `spec/x509-design.md` — full Path A architecture incl. JWT/SD-JWT adapters

---

## 1. Position statement

The OpenAC paper defines a generic anonymous-credential framework with four
modules: issuer-signature verification, attribute commitment, predicate proofs,
device binding. The paper's PoC (`zkID/wallet-unit-poc/`) implements these for
SD-JWT (ES256) and JWT (RS256), targeted at EUDI generic identity wallets.

passport-noir implements the same four modules for **ICAO 9303 e-passports**
(plus SD-JWT and X.509 OIDC paths sharing the commitment + show layer), and
adds four extensions the paper places out of scope:

| # | Extension | One-line summary | Paper position |
|---|-----------|-----------------|---------------|
| E1 | Path A — `pk_digest` folded into commitment | Device binding becomes a linking property, not an extra constraint | Out of scope (§C₂ keeps device binding as a separate constraint) |
| E2 | `composite_show` — multi-credential bundle | One device signature links N credentials in a single show | Single-credential only (§zkID_construction.tex) |
| E3 | CSCA Master List Merkle inclusion | Issuer trust root proven in-circuit via depth-8 Merkle tree | Trust root is a public constant (§security.tex) |
| E4 | DSC revocation SMT non-membership | Revocation proven in-circuit via sparse Merkle tree | Explicitly out of scope (§security.tex) |

These are **compatible** with the paper's modularity — they extend the
issuer-sig and attribute-commit modules without modifying the predicate or
proof-system layers.

The remainder of this document specifies each extension.

---

## 2. Architecture context

```
                         ┌────────────────────────────────────────┐
ICAO 9303 e-passport ──► │ passport_verifier (RSA-2048 + SHA-256) │
(NFC: SOD, DG1, DSC,     └──┬─────────────────────────────────────┘
 CSCA cert, DG hashes)      │ sod_hash, mrz_hash
                            ▼
              ┌──────────────────────────────────────────┐
              │ passport_adapter (Path A v3)              │
              │   - Verify CSCA → DSC RSA chain           │  ◄── E3, E4
              │   - Merkle inclusion in CSCA MasterList   │
              │   - SMT non-membership in DSC revocation  │
              │   - Pedersen commit with pk_digest        │  ◄── E1
              └──────────────┬───────────────────────────┘
                             │ commitment, pk_digest
                             ▼
                ┌────────────────────────────────┐
                │ openac_show / composite_show    │  ◄── E2
                │   - Re-open commitment          │
                │   - In-circuit ECDSA-P256       │
                │   - Re-derive link tag          │
                └────────────────────────────────┘
```

`pk_digest = Poseidon(enclave_pk_x, enclave_pk_y)` is shared across all three
adapters (passport / SD-JWT / X.509). `enclave_pk` stays a private witness so
presentations remain unlinkable across verifiers.

---

## 3. E1 — Path A: pk_digest in Pedersen commitment

### 3.1 Paper baseline (C₂ in `zkID_construction.tex:80`)

```
ECDSA.verify(σ_nonce, m_1[1]) = 1     // device binding
com(m_1, ..., m_N; r_1) = c            // commitment open
```

Two independent constraints. The verifier separately checks:
1. The commitment `c` matches the prepare phase
2. The ECDSA signature is valid against `m_1[1]` (the device pk extracted from
   credential attribute slot 1)

The paper relies on `m_1[1]` itself being part of the committed witness
column, so tampering with the device pk breaks the commitment. But the linking
relation (commitment equality) and the device binding (ECDSA verify) are
spelled out separately.

### 3.2 Path A construction

We commit one extra field:

```noir
commit_attributes_v3(credential_type, attr_hi, attr_lo, pk_digest, link_rand)
  = pedersen_commitment_with_separator(
      [credential_type, attr_hi, attr_lo, pk_digest, link_rand],
      DOMAIN_PASSPORT,
    )
```

Both prepare and show recompute this commitment with the same `pk_digest`.
The show circuit also runs `std::ecdsa_secp256r1::verify_signature` against
`(enclave_pk_x, enclave_pk_y)`, asserting `Poseidon(enclave_pk_x, enclave_pk_y)
== pk_digest`.

### 3.3 What this buys

| Property | Paper baseline | Path A |
|---|---|---|
| Commitment open ⇒ device binding | Independent check | **Folded** — same commitment relation |
| Verifier metadata to align | `(commitment, device_pk_metadata)` | `(commitment)` only |
| Adversary swapping device pk between phases | Caught by C₂ | Caught by commitment mismatch |

Net effect: one less out-of-circuit alignment surface. The verifier no longer
asks "is this ECDSA signature actually on the device pk this credential was
issued for?" — that property is implied by commitment equality.

### 3.4 Security argument (informal)

- **Binding**: Pedersen commitment over Grumpkin is binding under DLP. To make
  two commitments with different `pk_digest` collide, an adversary must break
  DLP on Grumpkin.
- **Hiding**: `link_rand` is sampled fresh per session; commitment is
  perfectly hiding as long as `link_rand` has full entropy.
- **Soundness of show**: ECDSA verify in-circuit forces the prover to know an
  `enclave_sk` whose corresponding `enclave_pk` Poseidon-hashes to `pk_digest`.
  Under ECDSA-P256 unforgeability + Poseidon collision resistance, no
  adversary without the enclave key can complete a show.

### 3.5 Implementation

- Commit primitive: `circuits/openac_core/src/commit.nr::commit_attributes_v3`
- Show ECDSA: `circuits/openac_core/src/device.nr::verify_device_binding`
- Verifier (Rust): `mopro-binding/src/openac_v3.rs:166` (`verify_openac_v3_with_verifier`)
- Verifier (Swift): `Sources/OpenPassportSwift.swift:899` (`verifyOpenACv3`)

---

## 4. E2 — composite_show: multi-credential bundle

### 4.1 Motivation

A user who holds **passport + X.509 corporate cert** wants to prove "I am over
18 (passport) AND I work at $COMPANY (X.509)" in a single online interaction.
The paper's model would require:
1. Two independent show proofs
2. A third proof linking the two device-binding ECDSAs to the same key
3. Verifier-side coordination of three transcripts

This is expensive both in proving time and in protocol surface.

### 4.2 Construction

`composite_show` runs **once** with two prepare commitments as private inputs:

```
inputs (private):  C_passport, C_x509,
                   passport attrs (attr_hi_p, attr_lo_p, link_rand_p),
                   x509 attrs (attr_hi_x, attr_lo_x, link_rand_x),
                   enclave_pk_x, enclave_pk_y, ecdsa_sig, ecdsa_msg

inputs (public):   C_passport, C_x509,
                   pk_digest, nonce_hash, link_tag, age_predicate_result

assertions:
  1. pk_digest == Poseidon(enclave_pk_x, enclave_pk_y)
  2. C_passport == commit_attributes_v3(0x01, attr_hi_p, attr_lo_p, pk_digest, link_rand_p)
  3. C_x509     == commit_attributes_v3(0x02, attr_hi_x, attr_lo_x, pk_digest, link_rand_x)
  4. ECDSA.verify((enclave_pk_x, enclave_pk_y), ecdsa_sig, ecdsa_msg) = 1
  5. ecdsa_msg ∋ nonce_hash    (verifier-bound)
  6. link_rand_x == derive_x509_link_rand(link_rand_p, SALT_X509)
  7. link_tag == pedersen_hash([link_rand_p, link_scope, epoch])
  8. age_predicate_result == age_at_least(birth_attrs, threshold, today)
```

Constraints 2-3 reuse the same `pk_digest`. Constraint 6 forces the X.509
randomness to be a deterministic Poseidon-derivation of the passport
randomness — a wallet-side property, not an issuer-side one — preserving
unlinkability across composites by sampling fresh `link_rand_p` per session
when desired.

### 4.3 What this buys

- One ECDSA verify covers N credentials (∼320 gates for ECDSA dominate).
- One `link_tag` covers all credentials in the bundle (verifier sees a single
  scoped tag, not N).
- Cross-credential linkability is **explicit and bounded**: the verifier
  knows two credentials were presented together; nothing leaks beyond that.

### 4.4 Soundness considerations

The deterministic `link_rand` derivation (constraint 6) is the load-bearing
piece. If `derive_x509_link_rand` were predictable from public values, the
verifier could pre-compute X.509 commitments for arbitrary users. We use
Poseidon over a private root randomness `link_rand_p`, so commitments remain
hiding as long as `link_rand_p` is unsampled by the verifier.

### 4.5 Implementation

- Circuit: `circuits/composite_show/src/main.nr`
- Helper: `circuits/openac_core/src/commit.nr::derive_x509_link_rand`
- Tests: 4 tests (1 positive, 3 negative) including the 2026-04-19 binding
  proof tests (ab6add8) for age predicate and link_scope.
- Current cost (2026-04-26 measurement): 815 ACIR gates, 133 KB artifact.

---

## 5. E3 — CSCA Master List Merkle inclusion

### 5.1 Why this matters for passports

The paper assumes "verifier checks against an online registry of trusted
issuer keys" (`security.tex`). For passports, this registry is the **ICAO
Master List** — a published set of CSCA (Country Signing Certificate
Authority) certificates, one per country, signing DSCs (Document Signers) that
in turn sign the SOD on each passport.

Trust root verification at the verifier side leaks:
1. **Which CSCA** signed the user's DSC (i.e., country)
2. **Which DSC** signed the SOD (i.e., issuance batch / time window)

Both leak nationality and approximate issuance epoch. We push the trust root
check into the prover's circuit, so the verifier only sees the Master List
**root hash**.

### 5.2 Construction

```
public input:   csca_merkle_root      (Pedersen-hash of Master List)

private input:  csca_pk_modulus_limbs[18]
                csca_merkle_path[8]    (depth-8 binary Merkle proof)
                csca_merkle_path_index (0..255)

assertion:      verify_inclusion_depth_8(
                  leaf = poseidon_hash(csca_pk_modulus_limbs),
                  path = csca_merkle_path,
                  index = csca_merkle_path_index,
                  root = csca_merkle_root,
                ) = 1
```

Depth-8 supports 256 distinct CSCAs — enough for current ICAO membership
(~190 countries). Range-checking `path_index < 256` is enforced
(`openac_core::merkle::verify_inclusion_depth_8`, fixed by 0cd7bb7 on
2026-04-18).

### 5.3 What this buys

- Verifier sees the **Master List root**, not the per-user CSCA.
- Verifier policy is a single trusted hash, updated when ICAO publishes a new
  Master List.
- Cross-country presentations are unlinkable at the trust-root layer.

### 5.4 Threat model

- **Adversary forges CSCA chain**: to produce a Merkle inclusion proof for an
  attacker-generated key, the attacker must either (a) break Pedersen
  pre-image resistance on the leaf hash, or (b) be a published CSCA. The
  trust assumption reduces to ICAO's Master List integrity.
- **Adversary uses revoked CSCA**: addressed by E4 (revocation SMT). Master
  List inclusion alone does not prove non-revocation.

### 5.5 Implementation

- Merkle verify: `circuits/openac_core/src/merkle.nr::verify_inclusion_depth_8`
- Used in: `circuits/passport_adapter/src/main.nr` (CSCA chain block), and
  `circuits/jwt_x5c_adapter/src/main.nr` (Mozilla Root snapshot Merkle).

---

## 6. E4 — DSC revocation SMT non-membership

### 6.1 Why an SMT, not a Merkle tree

Revocation has different access patterns than trust roots:
- **Frequent updates** (each new revocation appends one entry).
- **Frequent reads** (every passport presentation must check non-membership).
- **Set membership semantics**, not ordered position.

Sparse Merkle trees (SMTs) over a 256-bit key space let us express
non-membership efficiently. A revoked DSC's serial number maps to a path; if
that path resolves to the empty leaf, the DSC is not revoked.

The paper places revocation **out of scope**:

> "Revocation is critical for maintaining trust ... existing revocation
> mechanisms often compromise user privacy. The goal of this work is to
> provide a framework that allows verifiers to reliably detect whether a
> credential has been revoked, while minimizing disclosure of personal data."
> — `zkID/revocation/README.md`

zkID acknowledges the problem but the paper construction does not solve it.
We embed non-membership in the prepare circuit.

### 6.2 Construction

```
public input:   dsc_revocation_root   (SMT root)

private input:  dsc_serial_number     (32 bytes)
                dsc_smt_path[160]     (sibling hashes along the path)

assertion:      verify_non_membership(
                  key = dsc_serial_number,
                  path = dsc_smt_path,
                  root = dsc_revocation_root,
                ) = 1
```

`verify_non_membership` walks the path top-down, hashing each sibling, and
asserts the resolved leaf is the empty-leaf sentinel.

### 6.3 What this buys

- Verifier sees only the SMT root — same root for all unrevoked passports.
- Adding a revocation requires regenerating the SMT (off-chain) and
  publishing a new root. Existing presentations are not invalidated unless
  the verifier rotates roots.
- Non-revocation is **proven**, not asserted out-of-band.

### 6.4 Operational considerations

- Issuer maintains the canonical SMT (off-chain) and publishes signed root
  updates. We assume issuer trust here — falsified roots bypass revocation,
  but cannot retroactively forge a specific revocation.
- Wallets must refresh their non-membership proofs when the issuer rotates
  the root; stale proofs fail verification.
- Future extension: pair with a published **append-only log** of revocations
  so verifiers can audit issuer behavior independently.

### 6.5 Implementation

- SMT verify: `circuits/openac_core/src/smt.nr::verify_non_membership`
- Used in: `circuits/passport_adapter/src/main.nr` (DSC revocation block).
- 4 tests covering positive non-membership and 3 negative cases (wrong path,
  forged sentinel, root mismatch).

---

## 7. Comparison table

| Property | OpenAC paper | zkID PoC (v3.0.0) | passport-noir (v3 Path A) |
|---|---|---|---|
| Issuer-sig — JWT ES256 | Spec'd | Implemented | Implemented (`sdjwt_adapter`) |
| Issuer-sig — JWT RS256 | Spec'd | Implemented | Implemented (`jwt_x5c_adapter`) |
| Issuer-sig — RSA-2048 ICAO 9303 | — | — | **Implemented** (`passport_verifier`) |
| Issuer-sig — full X.509 chain | — | — | **Implemented** (Mozilla Root snapshot Merkle) |
| Commitment | Hyrax Pedersen (T256) | Hyrax Pedersen (T256) | Grumpkin Pedersen (bn254 native) |
| Predicate flexibility | Generic | Generalised tuples + postfix expr (4/26 ship) | **Hard-coded per credential** (deferred — see `spec/predicate-generalization.md`) |
| Device binding | Out-of-circuit by default; in-circuit possible | In-circuit ECDSA-P256 over T256 | **In-circuit ECDSA-P256 + folded into commitment (E1)** |
| Multi-credential bundle | Not in spec | Not in PoC | **Implemented (E2)** |
| Trust root | Verifier-side public constant | Verifier-side public constant | **In-circuit Merkle inclusion (E3)** |
| Revocation | Out of scope | Separate research stream | **In-circuit SMT non-membership (E4)** |
| Backend | Spartan + Hyrax | Spartan + Hyrax (WASM) | Noir → mopro UltraHonk |
| Mobile bench | Documented (iPhone 17 ~2.1s prepare) | Documented | Pending — mopro FFI not yet linked into iOS app |

---

## 8. Limitations

1. **Predicate model is rigid** — `disclose_nationality / disclose_older_than
   / disclose_name` flags. Generalised predicates (zkID-style) are deferred to
   `spec/predicate-generalization.md`.
2. **No prepareBatch / online reblind** — every session re-runs prepare prove.
   Mobile prepare cost is therefore higher than zkID's reblind path.
3. **Mobile FFI gap** — `MoproProofService.swift` falls back to Semaphore /
   SD-JWT until mopro xcframework is linked. Real on-device timing is not
   measured.
4. **CSCA Master List depth fixed at 8** — extension to depth-9+ requires
   recompiling `passport_adapter`; current cap is 256 CSCAs.
5. **DSC SMT root rotation is operational** — wallets must refresh
   non-membership proofs when issuer rotates the root; we do not specify the
   refresh transport.

---

## 9. Future work

| Priority | Item |
|---|------|
| High | Wire mopro FFI into iOS app; produce real iPhone bench numbers comparable to zkID's iPhone 17 / Pixel 10 Pro publication |
| High | Add prove + verify time bench for v2/v3 in `mopro-binding/src/openac_v{2,3}.rs` |
| High | Direction D — mDoc / mDL adapter for EUDI compliance |
| Medium | Direction C — unify Swift SDK (`OpenAC` class, `Credential` type, `.serialize()` on proof structs, automatic field detection) |
| Medium | Append-only revocation log for E4 verifier-side audit |
| Low | Direction B — generalised predicate evaluator on SD-JWT/X.509 path (see `spec/predicate-generalization.md`) |
| Low | Master List depth-9 extension if ICAO membership exceeds 256 CSCAs |

---

## 10. References

### This repo
- `circuits/openac_core/src/{commit,device,merkle,smt,show,predicate}.nr` — module impls
- `circuits/passport_adapter/src/main.nr` — RSA + Merkle + SMT + Pedersen integration
- `circuits/composite_show/src/main.nr` — E2 implementation
- `mopro-binding/src/openac_v3.rs` — Rust verifier
- `Sources/OpenPassportSwift.swift` — Swift verifier
- `spec/x509-design.md` — Path A architecture for SD-JWT/X.509 paths
- `OPENAC_COMPARISON.md` — full gap analysis vs zkID

### External
- OpenAC paper — `../zkID/paper/{main,zkID_construction,ac_framework,security}.tex`
- zkID PoC — `../zkID/wallet-unit-poc/`
- zkID generalised predicates — `../zkID/generalized-predicates/README.md` (2026-04-26)
- zkID revocation research — `../zkID/revocation/README.md` + PSE blog "Revocation in zkID: Merkle Tree-based Approaches"
- ICAO 9303 — Doc 9303 Part 11 (Security Mechanisms for MRTDs)
- ICAO Master List — https://www.icao.int/Security/FAL/PKD/Pages/icao-master-list.aspx
