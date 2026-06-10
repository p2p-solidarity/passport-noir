# AirMeishi (Solidarity) — ZK Passport Circuits + mopro Binding

## Rules

- **禁止建立重複的功能**：修改前先確認是否已有相同功能存在，優先複用或擴充現有程式碼。
- **不要加假資料**：禁止在正式程式碼中使用 hardcoded sample/mock/dummy data。
- **先讀再改**：修改任何檔案前必須先讀取該檔案，了解現有邏輯再動手。

## Project Overview

This repo contains the **Noir ZK circuits** and **mopro mobile binding** for the AirMeishi (Solidarity) iOS app's passport verification pipeline. These circuits implement the OpenPassport architecture for ICAO 9303 e-passport ZKP verification.

**Proof pipeline (target):**
```
Passport → MRZ OCR → NFC chip read → CSCA passive auth → OpenPassport Noir circuit (this repo) → W3C VC
```

**Current iOS app status:** MRZ + NFC pipeline is REAL. Mopro FFI not yet linked — app falls back to Semaphore → SD-JWT. This repo's goal is to complete the Noir circuits + mopro binding so the iOS app can generate real passport ZK proofs.

## Project Structure

```
circuits/                   # Noir workspace (Nargo.toml at root) — 8 production circuits (v3.1)
├── openac_core/            # v3.1: Shared Pedersen library (commit/show/predicate/profile/smt/merkle/base64)
├── passport_adapter/       # v3.1: Passport prepare (CSCA root + DSC SMT + arity-8 commitment)
├── openac_show/            # v3.1: Passport show (digest-free; nonce_hash freshness + unified link tag)
├── sdjwt_adapter/          # v3.2: SD-JWT (ES256) → Pedersen commitment
├── jwt_x5c_adapter/        # v3.1: JWT x5c (RSA + JWT payload) → X.509 commitment
├── x509_show/              # v3.1: X.509 show (commitment opening + ECDSA device binding)
├── composite_show/         # v3.1: Multi-credential show (passport + X.509 OR SD-JWT)
├── mdoc_adapter/           # v3: mDoc/mDL prepare adapter (Direction D, ES256 issuer)
└── target/                 # Compiled circuit JSON artifacts
circuits-legacy/            # RETIRED v1/v2 circuits (standalone workspace; built on demand
│                           # only — nargo cannot nest workspaces, hence top-level):
│                           #   passport_verifier, data_integrity, disclosure,
│                           #   prepare_link, show_link, device_binding
mopro-binding/              # Mobile prover integration via mopro
├── src/openac.rs           # v1 SHA256 OpenAC verifier (Rust, legacy artifacts only)
├── src/openac_v2.rs        # v2 Pedersen OpenAC verifier (Rust, legacy)
├── src/openac_v3.rs        # v3.1 Pedersen verifier (nonce_hash pinning, no digest)
├── src/noir.rs             # noir_rs prove/verify entry points
└── test-vectors/noir/      # Compiled circuit JSONs for cargo tests
benchmark/                  # Circuit benchmark & spec compliance suite
├── spec.toml               # Machine-readable circuit spec (source of truth)
├── expected/baseline.toml  # Gate count, test count, artifact size baselines
├── scripts/                # Benchmark, lint, size analysis scripts
└── reports/                # Generated reports (gitignored)
spec/                       # Human-readable design docs
├── upgrade-plan-v3.1.md    # v3.1 show-path unification plan (digest removal rationale)
├── x509-circuits.md        # X.509 / JWT-x5c circuit spec
├── x509-benchmark.md       # X.509 gate-count benchmarks
└── x509-migration.md       # X.509 migration notes
scripts/                    # Project tooling
├── pre-commit              # Git pre-commit hook (install via: make install-hooks)
├── release.sh              # Auto-version + tag creation
└── patch_mopro_fallback.sh # Post-build Swift FFI wrapper
.github/workflows/          # CI/CD
├── ci.yml                  # Lint → test → spec → mopro → integration
├── release.yml             # Tag → circuits → xcframework → GitHub Release
└── swift.yml               # iOS Swift Package test
```

## Toolchain

- **Noir**: `nargo 1.0.0-beta.19` / `noirc 1.0.0-beta.19`
- **Dependencies**:
  - `noir_rsa v0.10.0` from `zkpassport/noir_rsa` (passport_adapter, jwt_x5c_adapter) — uses `u128` limbs, `RuntimeBigNum<18, 2048>`
  - `sha256 v0.3.0` from `noir-lang/sha256` (adapters) — `sha256::digest<N>(input: [u8; N]) -> [u8; 32]`

## Common Commands

```bash
# Build (lint gate enforced: format → quality score → compile → test)
make all

# Format & lint
make fmt              # Auto-format all Noir files
make fmt-check        # Check formatting (CI uses this)
make lint             # Format check + 9-dimension quality score (must pass ≥ C)
make score            # Quality score only (informational, no gate)

# Compile & test
make circuits         # fmt-check → compile → test
make compile-circuits # Compile only
make test-circuits    # Test only

# iOS build
make build-ios        # Full pipeline: lint → circuits → mopro → xcframework

# Benchmark
make benchmark        # Full pipeline: TDD → spec → cross-circuit → perf → size
make spec-check       # Spec compliance only
make bench-report     # Performance metrics (assumes compiled)
make bench-size       # Artifact size & compression ratio (gate count + bytes/gate)
make bench-execute    # Witness gen time (lower bound for prove time, via nargo execute)
make bench-prove-verify  # Real prove + verify time via mopro-binding cargo bench (~10 min first run)

# Release (auto-version + tag → triggers GitHub Actions release)
make release-patch    # v0.1.0 → v0.1.1
make release-minor    # v0.1.0 → v0.2.0
make release-major    # v0.1.0 → v1.0.0

# Setup
make install-hooks    # Install git pre-commit hook
make clean            # Remove all build artifacts
```

## Lint & Quality Scoring

All builds (`make all`, `make circuits`) enforce lint as a gate. CI blocks PRs that fail lint.

### 9 Scoring Dimensions (weighted)

| Dim | Weight | What it checks |
|-----|--------|---------------|
| **Size** | 10% | Lines per source file (≤200=A, >1000=F) |
| **Mod** | 10% | Function decomposition, imports, lines/fn ratio |
| **Test** | 15% | Test:assertion ratio + negative test coverage |
| **Gate** | 10% | Bytes/gate artifact efficiency |
| **Fmt** | 10% | `nargo fmt --check` compliance |
| **Name** | 5% | snake_case functions, naming conventions |
| **Sec** | 20% | Assert messages present, no hardcoded secrets, safe patterns |
| **Trans** | 10% | Domain separators, public input docs, spec.toml coverage |
| **Spec** | 10% | TDD red/green discipline, spec.toml conformance |

Grades: A(≥90) B(≥75) C(≥60) D(≥40) F(<40). Must pass ≥ C (60) to build.

### Size & Compression Grades

Each circuit is graded by **bytes/gate** (artifact bytes ÷ ACIR gate count).

| Grade | B/gate | Meaning |
|-------|--------|---------|
| A | ≤ 10 | Excellent — minimal overhead |
| B | ≤ 30 | Good — efficient representation |
| C | ≤ 60 | Acceptable — room to optimize |
| D | ≤ 100 | Bloated — review artifact structure |
| F | > 100 | Critical — likely low gate count inflating ratio |

Total artifact size: **~15.9 MB** across the 7 production bin circuits (2026-06-10). `mdoc_adapter` dominates (~10.1 MB), followed by `jwt_x5c_adapter` (~3.2 MB) and `passport_adapter` (~1.3 MB); the three show circuits are <150 KB each. For exact per-circuit sizes, run `make bench-size` or check `benchmark/expected/baseline.toml`.

## Benchmark

```bash
# Individual scripts (run from project root)
bash benchmark/scripts/tdd-check.sh           # TDD coverage per circuit
bash benchmark/scripts/spec-check.sh          # CLAUDE.md ↔ spec.toml consistency
bash benchmark/scripts/cross-circuit-check.sh  # Hash chain linkage
bash benchmark/scripts/cross-layer-check.sh    # Cross-layer integration
bash benchmark/scripts/perf-bench.sh           # Gate count & compile time
bash benchmark/scripts/size-bench.sh           # Artifact size & compression ratio
bash benchmark/scripts/circuit-lint.sh         # 9-dimension quality lint
```

- **spec.toml** — Machine-readable circuit spec (public/private inputs, types, constants)
- **expected/baseline.toml** — Gate count, test count, artifact size baselines; update after confirmed improvements
- **reports/** — Generated JSON/text reports (gitignored)

### Architecture Versions

`benchmark/spec.toml` is the source of truth for per-circuit `version =` fields.

| Version | Commitment | Arity | Key feature | Circuits |
|---------|-----------|-------|-------------|----------|
| v1 | SHA256 | n/a | Hash-based prepare/show links — **RETIRED 2026-06-10** to `circuits-legacy/` | passport_verifier, data_integrity, disclosure, prepare_link, show_link |
| v2 | Pedersen | 4 | Out-of-band device binding — **RETIRED 2026-06-10** to `circuits-legacy/` | device_binding |
| v3 | Pedersen | 5 | `pk_digest` baked into commitment via `commit_attributes_v3()` — still used for non-passport (aux) commitments | sdjwt_adapter, mdoc_adapter aux layer |
| v3.1 | Pedersen | 5 / 8 | **Show-path unification** (2026-06-10, `spec/upgrade-plan-v3.1.md`): in-circuit challenge digest RETIRED (freshness = pinned public `nonce_hash`, also the ECDSA device-binding message); unified link tag `pedersen([DOMAIN_LINK_TAG, credential_type, link_rand, scope, epoch])`; passport commitment is arity-8 `commit_passport_v3_1()` with full-width SOD/DG1 hashes (no truncation); epoch is a single Field. Plus trust-anchor model (CSCA root / DSC SMT). | openac_core, passport_adapter, openac_show, x509_show, composite_show, jwt_x5c_adapter |

## CI / CD

### GitHub Actions Pipelines

| Workflow | Trigger | What it does |
|----------|---------|-------------|
| `ci.yml` | push/PR to main | lint gate → circuit tests → spec checks → mopro build → integration |
| `release.yml` | `v*` tag push | circuits → mopro xcframework → GitHub Release + checksum |
| `swift.yml` | push/PR to main | iOS Swift Package build & test |

### CI Pipeline (ci.yml)
```
lint (format + 9-dim score) ──► noir-circuits (compile + test) ──► integration (circuits + mopro)
                             ├► spec-check (TDD + cross-circuit)
                             └► mopro-binding (cargo build + test)
```
Lint is a **hard gate** — all other jobs wait for it to pass.

### Release Flow
```bash
make release-patch   # Bump version, create tag
git push origin main --tags  # Trigger release workflow
```
Release workflow: compile circuits → build xcframework on macOS → zip + upload to GitHub Release → print Package.swift checksum.

## Circuit Details

### passport_adapter (v3.1 Prepare Phase — combined, offline once)
Single prepare circuit replacing the old v1 trio: RSA-2048 (PKCS#1 v1.5) DSC→SOD verify + CSCA→DSC chain (depth-8 Master List Merkle) + depth-32 DSC revocation SMT + DG hash chain + arity-8 Pedersen commitment.
- **Public inputs**: `csca_root`, `dsc_smt_root`, `exponent` (=65537), `out_commitment_x/y`
- Commitment: `commit_passport_v3_1(claims, sod_hash_hi/lo, dg1_hash_hi/lo, pk_digest, link_rand)` — full-width hashes, no truncation; `claims` = 9-byte packed birth date + nationality
- **SOD hash format (hard constraint)**: `sod_hash = SHA256(dg0_hash || dg1_hash || dg2_hash || dg3_hash)` with **zero-padding** for unused DG slots (each slot is 32 bytes regardless of `dg_count`). This is **NOT** the ICAO 9303 LDS Security Object's TLV-encoded `signedAttrs` structure. The iOS app pipeline must normalize NFC chip data into this raw-concatenation layout before feeding the circuit.

### openac_show (v3.1 Show Phase — mobile hot path, per presentation)
- **No in-circuit challenge digest** (v3.1): freshness/replay protection = the public `nonce_hash`, which the verifier pins against the nonce it issued AND which is the ECDSA-P256 message of the in-circuit device binding. UltraHonk's public-input binding makes a separate transcript digest redundant — removing it cut openac_show from 1,802 to 647 ACIR opcodes and deleted 2 SHA256 blocks from every presentation.
- Re-opens the arity-8 passport commitment; predicates (age ≥ threshold, nationality) evaluate directly from the committed `claims` Field.
- Undisclosed outputs are pinned to zero sentinels in-circuit (CRITICAL-2).
- Link tag (all show circuits): `pedersen_hash([DOMAIN_LINK_TAG, credential_type, link_rand, link_scope, epoch])`; `link_mode=false` enforces zero scope + zero tag.

### x509_show / composite_show (v3.1)
Same digest-free pattern: ECDSA-P256 over pinned `nonce_hash` + commitment re-open + predicate + unified link tag. composite_show opens the arity-8 passport commitment AND an arity-5 aux commitment (X.509 or SD-JWT) under one shared `pk_digest`; its link tag is keyed on `(DOMAIN_PASSPORT, link_rand_p)` so a scoped verifier recognises the holder across solo and bundle presentations.

### OpenAC Flow (v3.1 composition)
```
passport_adapter ──(out_commitment_x/y)──► openac_show        (passport-only presentation)
                └─(out_commitment_x/y)──► composite_show ◄──(aux commitment)── jwt_x5c_adapter / sdjwt_adapter
jwt_x5c_adapter ──(out_commitment_x/y)──► x509_show           (X.509-only presentation)
```
- **Paper reference**: OpenAC (zkID Team @ PSE, Nov 2025) — see `openAC.md`; v3.1 design rationale in `spec/upgrade-plan-v3.1.md`
- **Device binding**: in-circuit ECDSA-P256 over `nonce_hash`; `pk_digest` bound inside every commitment (Path A)
- **Domain separation** (Noir / Rust / Swift consistent):
  - v3.1 show-phase: `DOMAIN_LINK_TAG` (`0x6c746167`, ASCII "ltag") — the ONLY in-circuit show anchor; the v2 SHA256 digest domains (`openac.show.v2` / `openac.scope.v2`) are RETIRED and must not be reused
  - Per-credential: `DOMAIN_PASSPORT` / `DOMAIN_X509` / `DOMAIN_SDJWT` / `DOMAIN_MDL` + `SALT_X509` / `SALT_SDJWT` link_rand derivation
  - v1 hash domains (`openac.preparev1`, `openac.show.v1`, `openac.scope.v1`, `openac.disclosure.v1`) only live on in `mopro-binding/src/openac.rs` for legacy artifacts
- **Legacy (circuits-legacy/)**: the v1 5-circuit composition (passport_verifier → prepare_link → show_link + data_integrity + disclosure) and v2 device_binding are retired; build on demand with `cd circuits-legacy && nargo compile --workspace`

## Conventions

- Noir source files: `<circuit>/src/main.nr`
- Each circuit has its own `Nargo.toml`; workspace config at `circuits/Nargo.toml`
- Tests are inline using `#[test]`
- RSA values use 18 `u128` limbs (120-bit limbs for 2048-bit BigNum)
- Public inputs marked with `pub` keyword in `fn main()` signatures
- All assertions include descriptive error messages

## Integration Context — iOS App (AirMeishi)

The iOS app lives in a separate repo. Key integration points:

### How Circuits Connect to the App

1. **MoproProofService.swift** — Fallback chain:
   - `generateWithMopro()`: Loads `openpassport_circuit.json` + `openpassport_srs.bin` via moproFFI → **requires this repo's compiled circuits**
   - `generateWithSemaphore()`: Semaphore group membership proof (current v1 fallback)
   - `generateSDJWTFallback()`: No cryptographic proof, trust level "blue" 🔵

2. **NFCPassportReaderService.swift** — Reads DG1/DG2/DG14/DG15/SOD from passport NFC chip (BAC/PACE auth). Provides the raw data that feeds into these circuits.

3. **PassportPipelineService.swift** — Orchestrates: MRZ → NFC → ZKP → VC. Creates `IdentityCardEntity` (type "passport") + `ProvableClaimEntity` (age_over_18, is_human).

### Trust Model
| Level | Badge | Source | Verification |
|-------|-------|--------|-------------|
| L3 政府級 | 🟢 | 護照 NFC + ZKP (this repo) | CSCA 簽章 + mopro proof |
| L2 機構級 | 🔵 | TLSNotary (v2) | TLS transcript proof |
| L1 自發行 | ⚪ | 用戶自填 | 無第三方驗證 |

### Three Proof Systems in the App
1. **MoproProofService** — Passport ZK proofs via OpenPassport Noir circuit (**this repo**). Falls back to Semaphore → SD-JWT.
2. **SemaphoreIdentityManager** — Real Semaphore ZK proofs (group membership, mopro-based). Used by proximity exchange.
3. **ProofGenerationManager** — Custom selective disclosure (SHA256 + ECDSA-P256, NOT true ZK). Used by QR code generation.

### mopro Binding Requirements
The mopro-binding directory needs to:
- Compile Noir circuits to R1CS/ACIR artifacts
- Generate SRS (Structured Reference String) files
- Produce Swift FFI bindings via mopro for iOS integration
- Output: `openpassport_circuit.json` + `openpassport_srs.bin` for app bundle

### Remaining Gaps (from iOS app side)
- `MoproProofService.swift`: moproFFI not linked; circuit files missing from bundle → always falls to SD-JWT
- No standalone CSCA certificate store for offline verification
- Passport scan flow only in Developer Mode, not main onboarding
- `SemaphoreGroupManager`: network sync methods stubbed (local-only groups)

## iOS App Dependencies (for reference)

| Package | Purpose |
|---------|---------|
| SemaphoreSwift (zkmopro) | ZK proof protocol (mopro) |
| SpruceKit Mobile (0.12.11) | VC/DID handling |
| WebRTC (125.0.0) | P2P data channel |

## iOS App Build (for reference)

```bash
xcodebuild -project airmeishi.xcodeproj -scheme airmeishi \
  -destination 'platform=iOS Simulator,name=iPhone 17 Pro' \
  build -skipPackagePluginValidation
```
- Must add `-skipPackagePluginValidation` (SwiftLint plugin issue)
- iOS Deployment Target: 18.6 (main app) / 17.0 (tests)
- Bundle ID: `kidneyweakx.airmeishi`
