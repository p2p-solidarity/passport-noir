import Foundation
#if canImport(CryptoKit)
import CryptoKit
#endif

public enum OpenPassportSwiftInfo {
    public static let packageName = "OpenPassportSwift"
}

public enum OpenACLinkMode: String, Sendable {
    case unlinkable
    case scopedLinkable
}

public enum OpenACProofPhase: String, Sendable {
    case prepare
    case show
}

public enum OpenACError: Error, Equatable {
    case invalidLength(field: String, expected: Int, actual: Int)
    case cryptoUnavailable
    case prepareNotActive
    case expiredPrepare
    case linkMismatch
    case sodHashMismatch
    case mrzHashMismatch
    case invalidChallenge
    case scopeMismatch
}

public struct OpenACPrepareArtifact: Equatable, Sendable {
    public let createdAtUnix: UInt64
    public let expiresAtUnix: UInt64
    public let sodHash: Data
    public let mrzHash: Data
    public let prepareCommitment: Data

    public init(
        createdAtUnix: UInt64,
        expiresAtUnix: UInt64,
        sodHash: Data,
        mrzHash: Data,
        prepareCommitment: Data
    ) {
        self.createdAtUnix = createdAtUnix
        self.expiresAtUnix = expiresAtUnix
        self.sodHash = sodHash
        self.mrzHash = mrzHash
        self.prepareCommitment = prepareCommitment
    }
}

public struct OpenACShowRequest: Equatable, Sendable {
    public let challenge: Data
    public let linkMode: OpenACLinkMode
    public let linkScope: Data?
    public let epoch: Data

    public init(challenge: Data, linkMode: OpenACLinkMode, linkScope: Data?, epoch: Data) {
        self.challenge = challenge
        self.linkMode = linkMode
        self.linkScope = linkScope
        self.epoch = epoch
    }
}

public struct OpenACShowPresentation: Equatable, Sendable {
    public let sodHash: Data
    public let mrzHash: Data
    public let prepareCommitment: Data
    public let challenge: Data
    public let challengeDigest: Data
    public let linkTag: Data

    public init(
        sodHash: Data,
        mrzHash: Data,
        prepareCommitment: Data,
        challenge: Data,
        challengeDigest: Data,
        linkTag: Data
    ) {
        self.sodHash = sodHash
        self.mrzHash = mrzHash
        self.prepareCommitment = prepareCommitment
        self.challenge = challenge
        self.challengeDigest = challengeDigest
        self.linkTag = linkTag
    }
}

public struct OpenACPreparedProof: Sendable {
    public let artifact: OpenACPrepareArtifact
    public let proof: NoirProofResult

    public init(artifact: OpenACPrepareArtifact, proof: NoirProofResult) {
        self.artifact = artifact
        self.proof = proof
    }
}

public struct OpenACShowProof: Sendable {
    public let presentation: OpenACShowPresentation
    public let proof: NoirProofResult

    public init(presentation: OpenACShowPresentation, proof: NoirProofResult) {
        self.presentation = presentation
        self.proof = proof
    }
}

public struct OpenACProofEnvelope: Equatable, Sendable {
    public let proofSystem: String
    public let phase: OpenACProofPhase
    public let challenge: Data?
    public let linkMode: OpenACLinkMode
    public let linkScope: Data?
    public let linkTag: Data?
    public let prepareCommitment: Data
    public let publicOutputs: [String: String]
    public let proofPayload: Data

    public init(
        proofSystem: String = "openpassport_openac",
        phase: OpenACProofPhase,
        challenge: Data?,
        linkMode: OpenACLinkMode,
        linkScope: Data?,
        linkTag: Data?,
        prepareCommitment: Data,
        publicOutputs: [String: String],
        proofPayload: Data
    ) {
        self.proofSystem = proofSystem
        self.phase = phase
        self.challenge = challenge
        self.linkMode = linkMode
        self.linkScope = linkScope
        self.linkTag = linkTag
        self.prepareCommitment = prepareCommitment
        self.publicOutputs = publicOutputs
        self.proofPayload = proofPayload
    }
}

private enum OpenACDomain {
    static let prepare = Data("openac.preparev1".utf8)
    static let show = Data("openac.show.v1".utf8)
    static let scoped = Data("openac.scope.v1".utf8)
}

private func requireLength(_ data: Data, field: String, expected: Int = 32) throws {
    if data.count != expected {
        throw OpenACError.invalidLength(field: field, expected: expected, actual: data.count)
    }
}

private func sha256(_ chunks: [Data]) throws -> Data {
#if canImport(CryptoKit)
    if #available(iOS 13.0, macOS 10.15, *) {
        var hasher = SHA256()
        for chunk in chunks {
            hasher.update(data: chunk)
        }
        return Data(hasher.finalize())
    }
    throw OpenACError.cryptoUnavailable
#else
    _ = chunks
    throw OpenACError.cryptoUnavailable
#endif
}

public func computeOpenACPrepareCommitment(
    sodHash: Data,
    mrzHash: Data,
    linkRandomness: Data
) throws -> Data {
    try requireLength(sodHash, field: "sodHash")
    try requireLength(mrzHash, field: "mrzHash")
    try requireLength(linkRandomness, field: "linkRandomness")

    return try sha256([OpenACDomain.prepare, sodHash, mrzHash, linkRandomness])
}

public func computeOpenACChallengeDigest(
    challenge: Data,
    prepareCommitment: Data,
    epoch: Data
) throws -> Data {
    try requireLength(challenge, field: "challenge")
    try requireLength(prepareCommitment, field: "prepareCommitment")
    try requireLength(epoch, field: "epoch", expected: 4)

    return try sha256([OpenACDomain.show, challenge, prepareCommitment, epoch])
}

public func computeOpenACScopedLinkTag(
    prepareCommitment: Data,
    linkScope: Data,
    epoch: Data
) throws -> Data {
    try requireLength(prepareCommitment, field: "prepareCommitment")
    try requireLength(linkScope, field: "linkScope")
    try requireLength(epoch, field: "epoch", expected: 4)

    return try sha256([OpenACDomain.scoped, prepareCommitment, linkScope, epoch])
}

public func openACPrepare(
    circuitPath: String,
    srsPath: String? = nil,
    inputs: [String: [String]],
    sodHash: Data,
    mrzHash: Data,
    linkRandomness: Data,
    createdAtUnix: UInt64,
    ttlSeconds: UInt64
) throws -> OpenACPreparedProof {
    let commitment = try computeOpenACPrepareCommitment(
        sodHash: sodHash,
        mrzHash: mrzHash,
        linkRandomness: linkRandomness
    )

    let artifact = OpenACPrepareArtifact(
        createdAtUnix: createdAtUnix,
        expiresAtUnix: createdAtUnix + ttlSeconds,
        sodHash: sodHash,
        mrzHash: mrzHash,
        prepareCommitment: commitment
    )

    let proof = try generateNoirProof(circuitPath: circuitPath, srsPath: srsPath, inputs: inputs)
    return OpenACPreparedProof(artifact: artifact, proof: proof)
}

public func openACShow(
    circuitPath: String,
    srsPath: String? = nil,
    inputs: [String: [String]],
    prepareArtifact: OpenACPrepareArtifact,
    request: OpenACShowRequest,
    sodHash: Data,
    mrzHash: Data
) throws -> OpenACShowProof {
    let challengeDigest = try computeOpenACChallengeDigest(
        challenge: request.challenge,
        prepareCommitment: prepareArtifact.prepareCommitment,
        epoch: request.epoch
    )

    let linkTag: Data
    switch request.linkMode {
    case .unlinkable:
        linkTag = Data(repeating: 0, count: 32)
    case .scopedLinkable:
        guard let scope = request.linkScope else {
            throw OpenACError.scopeMismatch
        }
        linkTag = try computeOpenACScopedLinkTag(
            prepareCommitment: prepareArtifact.prepareCommitment,
            linkScope: scope,
            epoch: request.epoch
        )
    }

    let presentation = OpenACShowPresentation(
        sodHash: sodHash,
        mrzHash: mrzHash,
        prepareCommitment: prepareArtifact.prepareCommitment,
        challenge: request.challenge,
        challengeDigest: challengeDigest,
        linkTag: linkTag
    )

    let proof = try generateNoirProof(circuitPath: circuitPath, srsPath: srsPath, inputs: inputs)
    return OpenACShowProof(presentation: presentation, proof: proof)
}

@discardableResult
public func verifyOpenACLinking(
    prepare: OpenACPrepareArtifact,
    show: OpenACShowPresentation,
    request: OpenACShowRequest,
    nowUnix: UInt64
) throws -> Bool {
    if nowUnix < prepare.createdAtUnix {
        throw OpenACError.prepareNotActive
    }

    if nowUnix > prepare.expiresAtUnix {
        throw OpenACError.expiredPrepare
    }

    if show.prepareCommitment != prepare.prepareCommitment {
        throw OpenACError.linkMismatch
    }

    if show.sodHash != prepare.sodHash {
        throw OpenACError.sodHashMismatch
    }

    if show.mrzHash != prepare.mrzHash {
        throw OpenACError.mrzHashMismatch
    }

    let expectedChallengeDigest = try computeOpenACChallengeDigest(
        challenge: request.challenge,
        prepareCommitment: show.prepareCommitment,
        epoch: request.epoch
    )

    if show.challengeDigest != expectedChallengeDigest {
        throw OpenACError.invalidChallenge
    }

    switch request.linkMode {
    case .unlinkable:
        if request.linkScope != nil || show.linkTag != Data(repeating: 0, count: 32) {
            throw OpenACError.scopeMismatch
        }
    case .scopedLinkable:
        guard let scope = request.linkScope else {
            throw OpenACError.scopeMismatch
        }

        let expectedTag = try computeOpenACScopedLinkTag(
            prepareCommitment: show.prepareCommitment,
            linkScope: scope,
            epoch: request.epoch
        )

        if show.linkTag != expectedTag {
            throw OpenACError.scopeMismatch
        }
    }

    return true
}

public func makeOpenACEnvelope(
    phase: OpenACProofPhase,
    challenge: Data?,
    linkMode: OpenACLinkMode,
    linkScope: Data?,
    linkTag: Data?,
    prepareCommitment: Data,
    publicOutputs: [String: String],
    proofPayload: Data
) -> OpenACProofEnvelope {
    OpenACProofEnvelope(
        phase: phase,
        challenge: challenge,
        linkMode: linkMode,
        linkScope: linkScope,
        linkTag: linkTag,
        prepareCommitment: prepareCommitment,
        publicOutputs: publicOutputs,
        proofPayload: proofPayload
    )
}
