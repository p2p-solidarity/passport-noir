# OpenPassport ZK Verification (Noir + mopro → Swift)

Zero-knowledge passport verification circuits built with [Noir](https://noir-lang.org/), exported to Swift via [mopro](https://zkmopro.org/).

## Architecture

Based on [OpenPassport](https://github.com/zk-passport/openpassport) / [ZKPassport](https://github.com/zkpassport/circuits) design:

```
┌─────────────────────┐
│  passport_verifier  │  RSA-SHA256 signature verification (DSC → SOD)
├─────────────────────┤
│  data_integrity     │  SHA-256 hash chain over data groups (DG1, DG2...)
├─────────────────────┤
│  disclosure         │  Selective disclosure: nationality, age, name
└─────────────────────┘
         │
         ▼
   mopro-binding (Rust FFI)
         │
         ▼
   Swift / iOS app
```

### Circuits

| Circuit | Purpose | Public Inputs |
|---------|---------|---------------|
| `passport_verifier` | Verifies DSC RSA-2048 signature over SOD | DSC modulus |
| `data_integrity` | Validates DG hash chain matches SOD | DG hashes, SOD hash |
| `disclosure` | Selective attribute disclosure from MRZ | Nationality, age check, name |

### Verification Flow

1. **Scan passport NFC** → extract DG1 (MRZ), DG2 (photo), SOD, DSC
2. **Base proof 1** (`passport_verifier`): Prove DSC signed the SOD correctly
3. **Base proof 2** (`data_integrity`): Prove DG hashes match the SOD
4. **Disclosure proof** (`disclosure`): Selectively reveal nationality / age / name

## Prerequisites

```bash
# Install Noir
curl -L https://raw.githubusercontent.com/noir-lang/noirup/refs/heads/main/install | bash
noirup

# Install mopro CLI
cargo install mopro-cli
```

## Build

```bash
# Compile & test all circuits
make circuits

# Build iOS Swift bindings
make build-ios

# Or step by step:
cd circuits && nargo compile --workspace
cd circuits && nargo test --workspace
cd mopro-binding && CONFIGURATION=release cargo run --bin ios
```

## Swift Integration

After `make build-ios`, import the generated `MoproiOSBindings/mopro.swift` into your Xcode project:

```swift
import MoproBindings

// Load compiled circuit
let circuitPath = Bundle.main.path(forResource: "passport_verifier", ofType: "json")!

// Generate proof
let inputs: [String: [String]] = [
    "sod_hash": sodHashValues,
    "signature_limbs": signatureLimbs,
    "modulus_limbs": modulusLimbs,
    "redc_limbs": redcLimbs,
    "exponent": ["65537"]
]
let (proof, publicInputs) = try generateNoirProof(circuitPath, nil, inputs)

// Verify proof
let isValid = try verifyNoirProof(circuitPath, nil, proof, publicInputs)
```

## References

- [mopro - Mobile Prover Toolkit](https://zkmopro.org/)
- [ZKPassport Circuits](https://github.com/zkpassport/circuits)
- [OpenPassport / Self](https://github.com/zk-passport/openpassport)
- [noir_rsa](https://github.com/noir-lang/noir_rsa)
- [Noir Documentation](https://noir-lang.org/docs/)
