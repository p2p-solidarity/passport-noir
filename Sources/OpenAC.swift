import Foundation

/// Unified entry surface mirroring the shape of zkID's `openac-sdk`. Wraps the
/// existing v3 Path A free functions (`openACPrepareV3`, `openACShowV3`,
/// `verifyOpenACv3`) into a single `OpenAC` class with a `Credential`
/// abstraction, timing baked into every result, and JSON serialization on
/// proof bundles. Adopted incrementally — legacy free functions remain.
public final class OpenAC {

    /// Currently only v3 (Path A) is exposed through the facade. v1/v2 stay
    /// available through their existing free functions.
    public enum Version: Int, Sendable {
        case v3 = 3
    }

    public struct CircuitPaths: Sendable {
        public let prepare: String
        public let show: String

        public init(prepare: String, show: String) {
            self.prepare = prepare
            self.show = show
        }
    }

    public let version: Version
    public let circuitPaths: CircuitPaths
    public let srsPath: String?

    public init(
        version: Version = .v3,
        circuitPaths: CircuitPaths,
        srsPath: String? = nil
    ) {
        self.version = version
        self.circuitPaths = circuitPaths
        self.srsPath = srsPath
    }
}

// MARK: - Credential

public struct Credential: Sendable {
    public enum Kind: String, Sendable, Codable {
        case passport
        case sdjwt
        case x509
        case mdl
    }

    public let kind: Kind
    public let credentialType: OpenACV3CredentialType
    public let commitment: PedersenPoint
    public let pkDigest: Data
    public let linkRand: Data
    public let prepareInputs: [String: [String]]
    public let showInputs: [String: [String]]

    public init(
        kind: Kind,
        commitment: PedersenPoint,
        pkDigest: Data,
        linkRand: Data,
        prepareInputs: [String: [String]],
        showInputs: [String: [String]]
    ) {
        self.kind = kind
        self.credentialType = Self.credentialType(for: kind)
        self.commitment = commitment
        self.pkDigest = pkDigest
        self.linkRand = linkRand
        self.prepareInputs = prepareInputs
        self.showInputs = showInputs
    }

    private static func credentialType(for kind: Kind) -> OpenACV3CredentialType {
        switch kind {
        case .passport: return .passport
        case .sdjwt:    return .sdjwt
        case .x509:     return .x509
        case .mdl:      return .mdl
        }
    }
}

// MARK: - Timings

public struct Timings: Sendable, Codable, Equatable {
    public let prepareProveMs: UInt64
    public let showProveMs: UInt64
    public let totalProveMs: UInt64

    public init(prepareProveMs: UInt64, showProveMs: UInt64) {
        self.prepareProveMs = prepareProveMs
        self.showProveMs = showProveMs
        self.totalProveMs = prepareProveMs + showProveMs
    }
}

// MARK: - Proof request

public extension OpenAC {

    struct ProofRequest: Sendable {
        public let credential: Credential
        public let challenge: Data
        public let linkMode: OpenACLinkMode
        public let linkScope: Data?
        public let epoch: Data
        public let createdAtUnix: UInt64
        public let ttlSeconds: UInt64
        public let nonceHash: Data
        public let linkTag: Data

        public init(
            credential: Credential,
            challenge: Data,
            linkMode: OpenACLinkMode,
            linkScope: Data?,
            epoch: Data,
            createdAtUnix: UInt64,
            ttlSeconds: UInt64,
            nonceHash: Data,
            linkTag: Data
        ) {
            self.credential = credential
            self.challenge = challenge
            self.linkMode = linkMode
            self.linkScope = linkScope
            self.epoch = epoch
            self.createdAtUnix = createdAtUnix
            self.ttlSeconds = ttlSeconds
            self.nonceHash = nonceHash
            self.linkTag = linkTag
        }
    }
}

// MARK: - Proof result

public struct ProofResult: Sendable {
    public let credentialKind: Credential.Kind
    public let prepared: OpenACV3PrepareArtifact
    public let presentation: OpenACV3ShowPresentation
    public let timings: Timings

    public func toJSON() throws -> Data {
        let envelope = ProofEnvelope(result: self)
        let encoder = JSONEncoder()
        encoder.outputFormatting = [.sortedKeys]
        return try encoder.encode(envelope)
    }

    public func toBase64() throws -> String {
        try toJSON().base64EncodedString()
    }
}

// MARK: - Verification result

public struct VerificationResult: Sendable {
    public let valid: Bool
    public let verifyMs: UInt64
    public let credentialKind: Credential.Kind

    public init(valid: Bool, verifyMs: UInt64, credentialKind: Credential.Kind) {
        self.valid = valid
        self.verifyMs = verifyMs
        self.credentialKind = credentialKind
    }
}

// MARK: - Codable envelope (used for ProofResult.toJSON)

private struct ProofEnvelope: Codable {
    let proofSystem: String
    let version: Int
    let credentialKind: Credential.Kind
    let prepare: PrepareEnvelope
    let show: ShowEnvelope
    let timings: Timings

    init(result: ProofResult) {
        self.proofSystem = "openpassport_openac"
        self.version = 3
        self.credentialKind = result.credentialKind
        self.prepare = PrepareEnvelope(artifact: result.prepared)
        self.show = ShowEnvelope(presentation: result.presentation)
        self.timings = result.timings
    }
}

private struct PrepareEnvelope: Codable {
    let createdAtUnix: UInt64
    let expiresAtUnix: UInt64
    let credentialType: UInt8
    let commitmentXBase64: String
    let commitmentYBase64: String
    let pkDigestBase64: String
    let linkRandBase64: String
    let proofBase64: String
    let vkBase64: String

    init(artifact: OpenACV3PrepareArtifact) {
        self.createdAtUnix = artifact.createdAtUnix
        self.expiresAtUnix = artifact.expiresAtUnix
        self.credentialType = artifact.credentialType.rawValue
        self.commitmentXBase64 = artifact.commitmentX.base64EncodedString()
        self.commitmentYBase64 = artifact.commitmentY.base64EncodedString()
        self.pkDigestBase64 = artifact.pkDigest.base64EncodedString()
        self.linkRandBase64 = artifact.linkRand.base64EncodedString()
        self.proofBase64 = artifact.proof.base64EncodedString()
        self.vkBase64 = artifact.vk.base64EncodedString()
    }
}

private struct ShowEnvelope: Codable {
    let commitmentXBase64: String
    let commitmentYBase64: String
    let pkDigestBase64: String
    let nonceHashBase64: String
    let challengeBase64: String
    let challengeDigestBase64: String
    let linkTagBase64: String
    let proofBase64: String
    let vkBase64: String

    init(presentation: OpenACV3ShowPresentation) {
        self.commitmentXBase64 = presentation.commitmentX.base64EncodedString()
        self.commitmentYBase64 = presentation.commitmentY.base64EncodedString()
        self.pkDigestBase64 = presentation.pkDigest.base64EncodedString()
        self.nonceHashBase64 = presentation.nonceHash.base64EncodedString()
        self.challengeBase64 = presentation.challenge.base64EncodedString()
        self.challengeDigestBase64 = presentation.challengeDigest.base64EncodedString()
        self.linkTagBase64 = presentation.linkTag.base64EncodedString()
        self.proofBase64 = presentation.proof.base64EncodedString()
        self.vkBase64 = presentation.vk.base64EncodedString()
    }
}

// MARK: - High-level + low-level operations

public extension OpenAC {

    /// Run prepare and show in sequence, capturing timings for both phases.
    func createProof(_ request: ProofRequest) throws -> ProofResult {
        let prepared = try prepare(request)
        let presented = try present(request, using: prepared)
        return ProofResult(
            credentialKind: request.credential.kind,
            prepared: prepared.artifact,
            presentation: presented.presentation,
            timings: Timings(
                prepareProveMs: prepared.timing,
                showProveMs: presented.timing
            )
        )
    }

    struct PreparedHandle: Sendable {
        public let artifact: OpenACV3PrepareArtifact
        public let bundle: OpenACV3ProofBundle
        public let timing: UInt64
    }

    struct PresentedHandle: Sendable {
        public let presentation: OpenACV3ShowPresentation
        public let bundle: OpenACV3ProofBundle
        public let timing: UInt64
    }

    /// Low-level prepare. Caller controls the cache lifecycle.
    func prepare(_ request: ProofRequest) throws -> PreparedHandle {
        let cred = request.credential
        let (artifact, bundle, ms) = try measure {
            try openACPrepareV3(
                circuitPath: circuitPaths.prepare,
                srsPath: srsPath,
                inputs: cred.prepareInputs,
                credentialType: cred.credentialType,
                commitment: cred.commitment,
                pkDigest: cred.pkDigest,
                linkRand: cred.linkRand,
                createdAtUnix: request.createdAtUnix,
                ttlSeconds: request.ttlSeconds
            )
        }
        return PreparedHandle(artifact: artifact, bundle: bundle, timing: ms)
    }

    /// Low-level show. Reuses an existing PreparedHandle.
    func present(
        _ request: ProofRequest,
        using prepared: PreparedHandle
    ) throws -> PresentedHandle {
        let showRequest = OpenACShowRequest(
            challenge: request.challenge,
            linkMode: request.linkMode,
            linkScope: request.linkScope,
            epoch: request.epoch
        )
        let (presentation, bundle, ms) = try measure {
            try openACShowV3(
                circuitPath: circuitPaths.show,
                srsPath: srsPath,
                inputs: request.credential.showInputs,
                prepare: prepared.artifact,
                request: showRequest,
                nonceHash: request.nonceHash,
                linkTag: request.linkTag
            )
        }
        return PresentedHandle(presentation: presentation, bundle: bundle, timing: ms)
    }

    /// Verify a previously generated ProofResult against a policy.
    func verify(
        _ result: ProofResult,
        policy: OpenACV3Policy,
        verifier: OpenACNoirVerifier? = nil
    ) throws -> VerificationResult {
        let (valid, ms) = try measure {
            try verifyOpenACv3(
                prepare: result.prepared,
                show: result.presentation,
                policy: policy,
                verifier: verifier
            )
        }
        return VerificationResult(
            valid: valid,
            verifyMs: ms,
            credentialKind: result.credentialKind
        )
    }
}

// MARK: - Timing helper

@inline(__always)
private func measure<T>(_ block: () throws -> T) rethrows -> (T, UInt64) {
    let start = Date()
    let value = try block()
    let elapsedMs = UInt64(Date().timeIntervalSince(start) * 1000.0)
    return (value, elapsedMs)
}

@inline(__always)
private func measure<A, B>(_ block: () throws -> (A, B)) rethrows -> (A, B, UInt64) {
    let start = Date()
    let (a, b) = try block()
    let elapsedMs = UInt64(Date().timeIntervalSince(start) * 1000.0)
    return (a, b, elapsedMs)
}
