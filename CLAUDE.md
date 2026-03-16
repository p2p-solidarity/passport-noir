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
├── prepare_link/           # OpenAC prepare-phase commitment (offline)
└── show_link/              # OpenAC show-phase challenge binding + scoped linking (online)
mopro-binding/              # Mobile prover integration via mopro (WIP)
├── src/bin/
├── src/openac.rs           # Rust OpenAC verification layer
└── test-vectors/noir/
```

## Toolchain

- **Noir**: `nargo 1.0.0-beta.19` / `noirc 1.0.0-beta.19`
- **Dependencies**:
  - `noir_rsa v0.10.0` from `zkpassport/noir_rsa` (passport_verifier) — uses `u128` limbs, `RuntimeBigNum<18, 2048>`
  - `sha256 v0.3.0` from `noir-lang/sha256` (data_integrity, disclosure) — `sha256::digest<N>(input: [u8; N]) -> [u8; 32]`

## Common Commands

```bash
# All commands run from circuits/ directory
cd circuits

# Build all circuits
nargo compile --workspace

# Build a specific circuit
nargo compile --package passport_verifier
nargo compile --package data_integrity

# Run tests
nargo test --workspace
nargo test --package data_integrity

# Generate proof (after building)
nargo prove --package passport_verifier

# Check circuit compiles without running
nargo check --workspace
```

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
