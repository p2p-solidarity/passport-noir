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
circuits/                   # Noir workspace (Nargo.toml at root)
├── passport_verifier/      # RSA-SHA256 signature verification (DSC → SOD)
├── data_integrity/         # DG hash chain verification (SOD hash matching)
├── disclosure/             # Selective disclosure (nationality, age, name from MRZ)
├── prepare_link/           # OpenAC prepare-phase commitment (offline, v1 SHA256)
├── show_link/              # OpenAC show-phase challenge binding (online, v1 SHA256)
├── openac_core/            # Shared Pedersen commitment library (v2)
├── passport_adapter/       # Passport → OpenAC adapter (v2 Pedersen)
├── openac_show/            # Show-phase with Pedersen commitments (v2)
├── device_binding/         # Device binding circuit (v2, planned)
├── sdjwt_adapter/          # SD-JWT credential adapter
└── target/                 # Compiled circuit JSON artifacts
mopro-binding/              # Mobile prover integration via mopro (WIP)
├── src/bin/
├── src/openac.rs           # Rust OpenAC verification layer
├── src/openac_v2.rs        # Rust OpenAC v2 (Pedersen) verification
└── test-vectors/noir/
benchmark/                  # Circuit benchmark & spec compliance suite
├── spec.toml               # Machine-readable circuit spec definition
├── expected/baseline.toml  # Gate count, test count, artifact size baselines
├── scripts/                # Benchmark, lint, size analysis scripts
└── reports/                # Generated reports (gitignored)
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
  - `noir_rsa v0.10.0` from `zkpassport/noir_rsa` (passport_verifier) — uses `u128` limbs, `RuntimeBigNum<18, 2048>`
  - `sha256 v0.3.0` from `noir-lang/sha256` (data_integrity, disclosure) — `sha256::digest<N>(input: [u8; N]) -> [u8; 32]`

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

Total artifact budget: ~2.3 MB (all 8 circuits). Passport_adapter is the largest at ~1 MB.

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
| Version | Commitment | Circuits |
|---------|-----------|----------|
| v1 | SHA256 | passport_verifier, data_integrity, disclosure, prepare_link, show_link |
| v2 | Pedersen | openac_core, passport_adapter, openac_show, device_binding |

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

### passport_verifier
Verifies RSA-2048 + SHA-256 (PKCS#1 v1.5) signature on a passport's SOD, proving it was signed by a valid DSC.
- **Public inputs**: `modulus_limbs` (DSC public key — verifier checks against trusted CSCA list)
- **Private inputs**: `sod_hash`, `signature_limbs`, `redc_limbs`, `exponent`
- Uses `noir_rsa` for RSA BigNum operations (18 limbs for 2048-bit values)

### data_integrity
Verifies that passport data groups (DG1–DG4) hash correctly into the SOD.
- **Public inputs**: `expected_dg_hashes`, `sod_hash`
- **Private inputs**: `dg_count`, `dg_contents`, `dg_lengths`
- Constants: `MAX_DG_COUNT = 4`, `MAX_DG_SIZE = 512` bytes
- Uses `std::hash::sha256`

### disclosure
Selective disclosure over MRZ data — proves nationality, age ≥ threshold, or name without revealing the full MRZ.
- **Public inputs**: `mrz_hash`, `disclose_nationality`, `disclose_older_than`, `disclose_name`, `age_threshold`, `current_date`, `out_nationality`, `out_name`, `out_is_older`
- **Private inputs**: `mrz_data` (88-byte TD3 MRZ)
- MRZ offsets: nationality at line2[10..12], DOB at line2[13..18] (YYMMDD), name at line1[5..43]
- Uses `sha256::digest` to bind MRZ to data_integrity proof chain

### prepare_link (OpenAC Prepare Phase)
Computes a SHA256-based commitment binding sod_hash, mrz_hash, and link randomness. Run offline, once per credential session.
- **Public inputs**: `out_prepare_commitment`
- **Private inputs**: `sod_hash`, `mrz_hash`, `link_rand`
- Commitment: `SHA256("openac.preparev1" || sod_hash || mrz_hash || link_rand)`
- Uses `sha256::digest`

### show_link (OpenAC Show Phase)
Binds a verifier challenge to the prepare commitment and optionally computes a scoped link tag. Run online, per presentation.
- **Public inputs**: `link_mode`, `link_scope`, `epoch`, `out_prepare_commitment`, `out_challenge_digest`, `out_link_tag`
- **Private inputs**: `sod_hash`, `mrz_hash`, `link_rand`, `challenge`
- Challenge digest: `SHA256("openac.show.v1" || challenge || prepare_commitment || epoch)`
- Scoped link tag: `SHA256("openac.scope.v1" || prepare_commitment || link_scope || epoch)`
- Unlinkable mode: `link_mode=false` → enforces zero link_scope and zero link_tag
- Uses `sha256::digest`

### OpenAC Flow (5-circuit composition)
```
passport_verifier ──(sod_hash)──► prepare_link ──(prepare_commitment)──► show_link
data_integrity ──(mrz_hash)──┘                                              │
       └──(mrz_hash)──► disclosure ◄── (challenge binding via main_with_challenge)
```
- **Paper reference**: OpenAC (zkID Team @ PSE, Nov 2025) — see `openAC.md` for full mapping
- **Design**: Hash-based commitment (SHA256) instead of paper's Pedersen — pragmatic choice for Noir/mopro backend
- **Device binding**: Planned v2 (out-of-band ECDSA, not in-circuit)
- **Domain separation**: `openac.preparev1`, `openac.show.v1`, `openac.scope.v1` — consistent across Noir, Swift, Rust

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
