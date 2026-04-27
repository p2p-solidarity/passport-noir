#!/usr/bin/env bash
set -euo pipefail

TARGET_FILE="${1:-Sources/MoproiOSBindings/mopro.swift}"

if [[ ! -f "$TARGET_FILE" ]]; then
  echo "patch_mopro_fallback: missing file: $TARGET_FILE" >&2
  exit 1
fi

if rg -q "passport_zk_moproFFI is unavailable on this platform" "$TARGET_FILE"; then
  exit 0
fi

TMP_FILE="$(mktemp)"
cat > "$TMP_FILE" <<'HEADER'
#if canImport(passport_zk_moproFFI)
HEADER

cat "$TARGET_FILE" >> "$TMP_FILE"

# Ensure the appended `#else` lands on its own line: uniffi 0.29 stopped emitting
# a trailing newline, so without this the `#else` glues onto the previous line
# and gets eaten by the trailing `// swiftlint:enable all` comment.
printf '\n' >> "$TMP_FILE"

cat >> "$TMP_FILE" <<'FALLBACK'
#else
import Foundation

public struct NoirProofResult: Sendable, Equatable, Hashable {
    public let proof: Data
    public let vk: Data

    public init(proof: Data, vk: Data) {
        self.proof = proof
        self.vk = vk
    }
}

public enum MoproError: Error, Equatable, Hashable, LocalizedError {
    case CircuitError(message: String)
    case ProofGenerationError(message: String)
    case VerificationError(message: String)
    case InvalidInput(message: String)

    public var errorDescription: String? {
        String(reflecting: self)
    }
}

private let unavailableMessage = "passport_zk_moproFFI is unavailable on this platform. Build for iOS with MoproBindings.xcframework."

public func generateNoirProof(
    circuitPath: String,
    srsPath: String?,
    inputs: [String: [String]]
) throws -> NoirProofResult {
    _ = (circuitPath, srsPath, inputs)
    throw MoproError.CircuitError(message: unavailableMessage)
}

public func getNoirVerificationKey(
    circuitPath: String,
    srsPath: String?
) throws -> Data {
    _ = (circuitPath, srsPath)
    throw MoproError.CircuitError(message: unavailableMessage)
}

public func verifyNoirProof(
    proof: Data,
    vk: Data
) throws -> Bool {
    _ = (proof, vk)
    throw MoproError.VerificationError(message: unavailableMessage)
}

public func uniffiEnsurePassportZkMoproInitialized() {
    // No-op on non-iOS fallback builds.
}
#endif
FALLBACK

mv "$TMP_FILE" "$TARGET_FILE"
