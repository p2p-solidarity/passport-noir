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

fileprivate func sha256(_ chunks: [Data]) throws -> Data {
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

// MARK: - OpenAC v2 (Pedersen)
// Mirrors mopro-binding/src/openac_v2.rs. Upgrades from SHA256 hash
// commitments (v1) to Pedersen commitments on the Grumpkin curve so
// linking between prepare and show proofs becomes point equality.

public struct PedersenPoint: Equatable, Sendable {
    public let x: Data
    public let y: Data

    public init(x: Data, y: Data) {
        self.x = x
        self.y = y
    }

    public static var zero: PedersenPoint {
        PedersenPoint(
            x: Data(repeating: 0, count: 32),
            y: Data(repeating: 0, count: 32)
        )
    }
}

public enum OpenACV2CredentialType: UInt8, Sendable {
    case passport = 0x01
    case sdjwt = 0x02
    case mdl = 0x03
}

public struct OpenACV2PrepareArtifact: Equatable, Sendable {
    public let createdAtUnix: UInt64
    public let expiresAtUnix: UInt64
    public let credentialType: OpenACV2CredentialType
    public let commitment: PedersenPoint
    public let linkRand: Data
    public let proof: Data
    public let vk: Data

    public init(
        createdAtUnix: UInt64,
        expiresAtUnix: UInt64,
        credentialType: OpenACV2CredentialType,
        commitment: PedersenPoint,
        linkRand: Data,
        proof: Data,
        vk: Data
    ) {
        self.createdAtUnix = createdAtUnix
        self.expiresAtUnix = expiresAtUnix
        self.credentialType = credentialType
        self.commitment = commitment
        self.linkRand = linkRand
        self.proof = proof
        self.vk = vk
    }
}

public struct OpenACV2ShowPresentation: Equatable, Sendable {
    public let commitment: PedersenPoint
    public let challenge: Data
    public let challengeDigest: Data
    public let linkTag: Data
    public let proof: Data
    public let vk: Data

    public init(
        commitment: PedersenPoint,
        challenge: Data,
        challengeDigest: Data,
        linkTag: Data,
        proof: Data,
        vk: Data
    ) {
        self.commitment = commitment
        self.challenge = challenge
        self.challengeDigest = challengeDigest
        self.linkTag = linkTag
        self.proof = proof
        self.vk = vk
    }
}

public struct OpenACV2Policy: Equatable, Sendable {
    public let linkMode: OpenACLinkMode
    public let linkScope: Data?
    public let epoch: Data
    public let epochField: Data
    public let nowUnix: UInt64
    public let expectedChallenge: Data
    public let prepareVkHash: Data
    public let showVkHash: Data

    public init(
        linkMode: OpenACLinkMode,
        linkScope: Data?,
        epoch: Data,
        epochField: Data,
        nowUnix: UInt64,
        expectedChallenge: Data,
        prepareVkHash: Data,
        showVkHash: Data
    ) {
        self.linkMode = linkMode
        self.linkScope = linkScope
        self.epoch = epoch
        self.epochField = epochField
        self.nowUnix = nowUnix
        self.expectedChallenge = expectedChallenge
        self.prepareVkHash = prepareVkHash
        self.showVkHash = showVkHash
    }
}

public enum OpenACV2Error: Error, Equatable {
    case invalidLength(field: String, expected: Int, actual: Int)
    case cryptoUnavailable
    case untrustedPrepareVk
    case untrustedShowVk
    case emptyPrepareBundle
    case emptyShowBundle
    case invalidPrepareProof
    case invalidShowProof
    case prepareNotActive
    case expiredPrepare
    case prepareCommitmentNotInProof
    case showCommitmentNotInProof
    case commitmentMismatch
    case invalidChallenge
    case invalidChallengeDigest
    case scopeMismatch
}

private enum OpenACV2Domain {
    static let show = Data("openac.show.v2".utf8)
}

private func requireV2Length(_ data: Data, field: String, expected: Int = 32) throws {
    if data.count != expected {
        throw OpenACV2Error.invalidLength(field: field, expected: expected, actual: data.count)
    }
}

public func computeOpenACv2ChallengeDigest(
    commitment: PedersenPoint,
    challenge: Data,
    epoch: Data
) throws -> Data {
    try requireV2Length(commitment.x, field: "commitment.x")
    try requireV2Length(commitment.y, field: "commitment.y")
    try requireV2Length(challenge, field: "challenge")
    try requireV2Length(epoch, field: "epoch", expected: 4)

    do {
        return try sha256([OpenACV2Domain.show, commitment.x, commitment.y, challenge, epoch])
    } catch {
        throw OpenACV2Error.cryptoUnavailable
    }
}

/// 32-byte aligned scan for a single Field element inside a proof byte blob.
fileprivate func containsField(proof: Data, target: Data) -> Bool {
    guard target.count == 32, proof.count >= 32 else { return false }
    let limit = proof.count - 32
    var offset = 0
    while offset <= limit {
        if proof.subdata(in: offset..<(offset + 32)) == target {
            return true
        }
        offset += 32
    }
    return false
}

/// 64-byte aligned scan for commitment (x || y) inside a proof byte blob.
fileprivate func containsCommitment(proof: Data, commitment: PedersenPoint) -> Bool {
    guard commitment.x.count == 32, commitment.y.count == 32 else { return false }
    guard proof.count >= 64 else { return false }
    var target = Data()
    target.append(commitment.x)
    target.append(commitment.y)
    let limit = proof.count - 64
    var offset = 0
    while offset <= limit {
        if proof.subdata(in: offset..<(offset + 64)) == target {
            return true
        }
        offset += 32
    }
    return false
}

/// Closure form: proof + vk -> valid. Allows tests to inject a stub without
/// requiring the mopro xcframework to be linked.
public typealias OpenACNoirVerifier = (Data, Data) throws -> Bool

fileprivate func sha256Single(_ data: Data) throws -> Data {
    try sha256([data])
}

@discardableResult
public func verifyOpenACv2(
    prepare: OpenACV2PrepareArtifact,
    show: OpenACV2ShowPresentation,
    policy: OpenACV2Policy,
    verifier: OpenACNoirVerifier? = nil
) throws -> Bool {
    // Length guards on inputs that go into downstream comparisons.
    try requireV2Length(prepare.commitment.x, field: "prepare.commitment.x")
    try requireV2Length(prepare.commitment.y, field: "prepare.commitment.y")
    try requireV2Length(show.commitment.x, field: "show.commitment.x")
    try requireV2Length(show.commitment.y, field: "show.commitment.y")
    try requireV2Length(show.challenge, field: "show.challenge")
    try requireV2Length(show.challengeDigest, field: "show.challengeDigest")
    try requireV2Length(show.linkTag, field: "show.linkTag")
    try requireV2Length(policy.epoch, field: "policy.epoch", expected: 4)
    try requireV2Length(policy.expectedChallenge, field: "policy.expectedChallenge")
    try requireV2Length(policy.prepareVkHash, field: "policy.prepareVkHash")
    try requireV2Length(policy.showVkHash, field: "policy.showVkHash")

    let runVerifier: OpenACNoirVerifier = verifier ?? { proof, vk in
        try verifyNoirProof(proof: proof, vk: vk)
    }

    // 1. VK trust
    let prepareVkHash: Data
    let showVkHash: Data
    do {
        prepareVkHash = try sha256Single(prepare.vk)
        showVkHash = try sha256Single(show.vk)
    } catch {
        throw OpenACV2Error.cryptoUnavailable
    }
    if prepareVkHash != policy.prepareVkHash {
        throw OpenACV2Error.untrustedPrepareVk
    }
    if showVkHash != policy.showVkHash {
        throw OpenACV2Error.untrustedShowVk
    }

    // 2. Noir proof verify
    if prepare.proof.isEmpty || prepare.vk.isEmpty {
        throw OpenACV2Error.emptyPrepareBundle
    }
    let prepareValid = try runVerifier(prepare.proof, prepare.vk)
    if !prepareValid {
        throw OpenACV2Error.invalidPrepareProof
    }
    if show.proof.isEmpty || show.vk.isEmpty {
        throw OpenACV2Error.emptyShowBundle
    }
    let showValid = try runVerifier(show.proof, show.vk)
    if !showValid {
        throw OpenACV2Error.invalidShowProof
    }

    // 3. TTL
    if policy.nowUnix < prepare.createdAtUnix {
        throw OpenACV2Error.prepareNotActive
    }
    if policy.nowUnix > prepare.expiresAtUnix {
        throw OpenACV2Error.expiredPrepare
    }

    // 4. Commitment in proof
    if !containsCommitment(proof: prepare.proof, commitment: prepare.commitment) {
        throw OpenACV2Error.prepareCommitmentNotInProof
    }
    if !containsCommitment(proof: show.proof, commitment: show.commitment) {
        throw OpenACV2Error.showCommitmentNotInProof
    }

    // 5. Commitment equality (the Pedersen linking check).
    if prepare.commitment != show.commitment {
        throw OpenACV2Error.commitmentMismatch
    }

    // 6. Challenge binding
    if show.challenge != policy.expectedChallenge {
        throw OpenACV2Error.invalidChallenge
    }
    let expectedDigest = try computeOpenACv2ChallengeDigest(
        commitment: show.commitment,
        challenge: policy.expectedChallenge,
        epoch: policy.epoch
    )
    if show.challengeDigest != expectedDigest {
        throw OpenACV2Error.invalidChallengeDigest
    }

    // 7. Link mode / scope
    let zero32 = Data(repeating: 0, count: 32)
    switch policy.linkMode {
    case .unlinkable:
        if policy.linkScope != nil || show.linkTag != zero32 {
            throw OpenACV2Error.scopeMismatch
        }
    case .scopedLinkable:
        guard policy.linkScope != nil else {
            throw OpenACV2Error.scopeMismatch
        }
        if show.linkTag == zero32 {
            throw OpenACV2Error.scopeMismatch
        }
    }

    return true
}

// MARK: - OpenAC v3 (Path A: Pedersen + in-circuit ECDSA device binding)
// Mirrors mopro-binding/src/openac_v3.rs. The show-phase SHA256 digest math is
// unchanged from v2 (domain "openac.show.v2"); only the commitment pre-image
// gained a pk_digest field, so a v2 artifact cannot be upgraded in place.

public enum OpenACV3CredentialType: UInt8, Sendable {
    case passport = 0x01
    case x509 = 0x02
    case sdjwt = 0x03
    case mdl = 0x04
}

public struct OpenACV3PrepareArtifact: Equatable, Sendable {
    public let createdAtUnix: UInt64
    public let expiresAtUnix: UInt64
    public let credentialType: OpenACV3CredentialType
    public let commitmentX: Data
    public let commitmentY: Data
    public let pkDigest: Data
    public let linkRand: Data
    public let proof: Data
    public let vk: Data

    public init(
        createdAtUnix: UInt64,
        expiresAtUnix: UInt64,
        credentialType: OpenACV3CredentialType,
        commitmentX: Data,
        commitmentY: Data,
        pkDigest: Data,
        linkRand: Data,
        proof: Data,
        vk: Data
    ) {
        self.createdAtUnix = createdAtUnix
        self.expiresAtUnix = expiresAtUnix
        self.credentialType = credentialType
        self.commitmentX = commitmentX
        self.commitmentY = commitmentY
        self.pkDigest = pkDigest
        self.linkRand = linkRand
        self.proof = proof
        self.vk = vk
    }
}

public struct OpenACV3ShowPresentation: Equatable, Sendable {
    public let commitmentX: Data
    public let commitmentY: Data
    public let pkDigest: Data
    public let nonceHash: Data
    public let challenge: Data
    public let challengeDigest: Data
    public let linkTag: Data
    public let proof: Data
    public let vk: Data

    public init(
        commitmentX: Data,
        commitmentY: Data,
        pkDigest: Data,
        nonceHash: Data,
        challenge: Data,
        challengeDigest: Data,
        linkTag: Data,
        proof: Data,
        vk: Data
    ) {
        self.commitmentX = commitmentX
        self.commitmentY = commitmentY
        self.pkDigest = pkDigest
        self.nonceHash = nonceHash
        self.challenge = challenge
        self.challengeDigest = challengeDigest
        self.linkTag = linkTag
        self.proof = proof
        self.vk = vk
    }
}

/// Issue P0-1 / P0-2 / Task 1+2 follow-up (2026-04-28): describes where each
/// expected public input lives in a Honk proof's public-input prefix.
/// Mirrors `mopro_binding::openac_v3::PrepareLayoutV3` so the Swift verifier
/// applies the same strict ABI-aware checks as the Rust verifier. Build via
/// the adapter-specific helpers (e.g. `OpenACPrepareLayoutV3.passport`).
public struct OpenACPrepareLayoutV3: Equatable, Sendable {
    /// Total number of public-input field elements in the proof prefix.
    public let numPublicInputs: Int
    /// Index of `out_commitment_x` in the public-input array.
    public let commitmentXIndex: Int
    /// Index of `out_commitment_y` in the public-input array.
    public let commitmentYIndex: Int
    /// Each pair `(field_index, expected_field_bytes_be32)` is enforced at
    /// its known ABI index. Includes adapter-specific trust anchors
    /// (csca_root, dsc_smt_root, exponent, expected_disclosure_root, ...).
    public let extraPinnedFields: [OpenACPinnedField]

    public init(
        numPublicInputs: Int,
        commitmentXIndex: Int,
        commitmentYIndex: Int,
        extraPinnedFields: [OpenACPinnedField]
    ) {
        self.numPublicInputs = numPublicInputs
        self.commitmentXIndex = commitmentXIndex
        self.commitmentYIndex = commitmentYIndex
        self.extraPinnedFields = extraPinnedFields
    }
}

public struct OpenACShowLayoutV3: Equatable, Sendable {
    public let numPublicInputs: Int
    public let commitmentXIndex: Int
    public let commitmentYIndex: Int
    /// Field index where `nonce_hash[0]` sits. Each subsequent byte
    /// occupies the next slot. `nil` means the layout does not bind
    /// nonce_hash bytes (only used for synthetic test layouts).
    public let nonceHashFirstByteIndex: Int?
    public let extraPinnedFields: [OpenACPinnedField]

    public init(
        numPublicInputs: Int,
        commitmentXIndex: Int,
        commitmentYIndex: Int,
        nonceHashFirstByteIndex: Int?,
        extraPinnedFields: [OpenACPinnedField]
    ) {
        self.numPublicInputs = numPublicInputs
        self.commitmentXIndex = commitmentXIndex
        self.commitmentYIndex = commitmentYIndex
        self.nonceHashFirstByteIndex = nonceHashFirstByteIndex
        self.extraPinnedFields = extraPinnedFields
    }
}

public struct OpenACPinnedField: Equatable, Sendable {
    public let fieldIndex: Int
    /// 32-byte big-endian Field encoding.
    public let expected: Data

    public init(fieldIndex: Int, expected: Data) {
        self.fieldIndex = fieldIndex
        self.expected = expected
    }
}

public struct OpenACV3Policy: Equatable, Sendable {
    public let linkMode: OpenACLinkMode
    public let linkScope: Data?
    public let epoch: Data
    public let nowUnix: UInt64
    public let expectedChallenge: Data
    public let expectedNonceHash: Data
    public let prepareVkHash: Data
    public let showVkHash: Data
    /// REQUIRED (Task 1+2 follow-up): adapter-specific layouts. The Swift
    /// verifier does ABI-aware comparison against these layouts; there is
    /// no fallback path. Build via `OpenACPrepareLayoutV3.passport(...)` /
    /// `OpenACShowLayoutV3.openacShow(...)` etc.
    public let prepareLayout: OpenACPrepareLayoutV3
    public let showLayout: OpenACShowLayoutV3

    public init(
        linkMode: OpenACLinkMode,
        linkScope: Data?,
        epoch: Data,
        nowUnix: UInt64,
        expectedChallenge: Data,
        expectedNonceHash: Data,
        prepareVkHash: Data,
        showVkHash: Data,
        prepareLayout: OpenACPrepareLayoutV3,
        showLayout: OpenACShowLayoutV3
    ) {
        self.linkMode = linkMode
        self.linkScope = linkScope
        self.epoch = epoch
        self.nowUnix = nowUnix
        self.expectedChallenge = expectedChallenge
        self.expectedNonceHash = expectedNonceHash
        self.prepareVkHash = prepareVkHash
        self.showVkHash = showVkHash
        self.prepareLayout = prepareLayout
        self.showLayout = showLayout
    }
}

public enum OpenACV3Error: Error, Equatable {
    case invalidLength(field: String, expected: Int, actual: Int)
    case cryptoUnavailable
    case prepareNotActive
    case expiredPrepare
    case commitmentMismatch
    case pkDigestMismatch
    case invalidChallenge
    case invalidNonceHash
    case invalidChallengeDigest
    case scopeMismatch
    case untrustedPrepareVk
    case untrustedShowVk
    case emptyPrepareBundle
    case emptyShowBundle
    case invalidPrepareProof
    case invalidShowProof
    case prepareCommitmentNotInProof
    case showCommitmentNotInProof
    case nonceHashNotInProof
    case proofTooShortForPublicInputs
    case preparePublicInputMismatch
    case showPublicInputMismatch
}

// MARK: - OpenAC v3 Field encoding helpers

/// Encode a single byte (0..=255) in the right-most slot of a 32-byte BE
/// Field. Used for `[u8; N]` ABI inputs where every byte occupies its own
/// Field slot.
public func openACByteAsField(_ byte: UInt8) -> Data {
    var out = Data(repeating: 0, count: 32)
    out[31] = byte
    return out
}

public func openACBoolAsField(_ value: Bool) -> Data {
    openACByteAsField(value ? 1 : 0)
}

/// Encode a UInt32 as a 32-byte BE Field with the value in the low 4 bytes.
public func openACU32AsField(_ value: UInt32) -> Data {
    var out = Data(repeating: 0, count: 32)
    out[28] = UInt8((value >> 24) & 0xFF)
    out[29] = UInt8((value >> 16) & 0xFF)
    out[30] = UInt8((value >> 8) & 0xFF)
    out[31] = UInt8(value & 0xFF)
    return out
}

/// Build (field_index, expected_field) pairs that pin every byte of a
/// `[u8; N]` ABI input into its own consecutive Field slot.
public func openACPinByteArray(baseFieldIndex: Int, bytes: Data) -> [OpenACPinnedField] {
    var out: [OpenACPinnedField] = []
    out.reserveCapacity(bytes.count)
    for (i, b) in bytes.enumerated() {
        out.append(OpenACPinnedField(fieldIndex: baseFieldIndex + i, expected: openACByteAsField(b)))
    }
    return out
}

// MARK: - OpenAC v3 Adapter-specific layout builders (Task 3)
//
// Mirror of `mopro_binding::openac_v3::*_layout_*` constructors. Each builder
// takes the off-chain policy values as required typed arguments so callers
// cannot construct a layout that silently skips a critical pin.

public extension OpenACPrepareLayoutV3 {
    /// passport_adapter v3.1 layout (5 fields, see Rust `prepare_layout_passport`).
    static func passport(
        cscaRoot: Data,
        dscSmtRoot: Data
    ) -> OpenACPrepareLayoutV3 {
        OpenACPrepareLayoutV3(
            numPublicInputs: 5,
            commitmentXIndex: 3,
            commitmentYIndex: 4,
            extraPinnedFields: [
                OpenACPinnedField(fieldIndex: 0, expected: cscaRoot),
                OpenACPinnedField(fieldIndex: 1, expected: dscSmtRoot),
                OpenACPinnedField(fieldIndex: 2, expected: openACU32AsField(65537)),
            ]
        )
    }

    /// sdjwt_adapter v3 layout (101 fields). `expectedDisclosureRoot` is
    /// REQUIRED (P0-5 off-chain policy anchor).
    static func sdjwt(
        jwtPayloadHash: Data,
        issuerPkX: Data,
        issuerPkY: Data,
        expectedSdRootHi: Data,
        expectedSdRootLo: Data,
        expectedDisclosureRoot: Data
    ) -> OpenACPrepareLayoutV3 {
        var pins: [OpenACPinnedField] = []
        pins.append(contentsOf: openACPinByteArray(baseFieldIndex: 0, bytes: jwtPayloadHash))
        pins.append(contentsOf: openACPinByteArray(baseFieldIndex: 32, bytes: issuerPkX))
        pins.append(contentsOf: openACPinByteArray(baseFieldIndex: 64, bytes: issuerPkY))
        pins.append(OpenACPinnedField(fieldIndex: 98, expected: expectedSdRootHi))
        pins.append(OpenACPinnedField(fieldIndex: 99, expected: expectedSdRootLo))
        pins.append(OpenACPinnedField(fieldIndex: 100, expected: expectedDisclosureRoot))
        return OpenACPrepareLayoutV3(
            numPublicInputs: 101,
            commitmentXIndex: 96,
            commitmentYIndex: 97,
            extraPinnedFields: pins
        )
    }

    /// jwt_x5c_adapter v3.1 layout (86 fields). `expectedJwtPayloadB64h`
    /// and `expectedJwtSignedHash` are REQUIRED (P0-4 residual gap pins).
    static func jwtX5c(
        expectedJwtPayloadB64h: Data,
        expectedJwtSignedHash: Data,
        issuerModulusLimbs: [UInt64],  // 18 limbs as low-64-bit pairs
        issuerModulusLimbsHigh: [UInt64],
        expectedSmtRoot: Data,
        expectedIssuerFormatTag: Data
    ) -> OpenACPrepareLayoutV3 {
        var pins: [OpenACPinnedField] = []
        pins.append(contentsOf: openACPinByteArray(baseFieldIndex: 0, bytes: expectedJwtPayloadB64h))
        pins.append(contentsOf: openACPinByteArray(baseFieldIndex: 32, bytes: expectedJwtSignedHash))
        // Encode each u128 limb as a 32-byte BE field with the 16-byte limb
        // packed at the LSB end.
        for i in 0..<18 {
            var field = Data(repeating: 0, count: 32)
            let high = issuerModulusLimbsHigh[i]
            let low = issuerModulusLimbs[i]
            for j in 0..<8 {
                field[16 + j] = UInt8((high >> (8 * (7 - j))) & 0xFF)
            }
            for j in 0..<8 {
                field[24 + j] = UInt8((low >> (8 * (7 - j))) & 0xFF)
            }
            pins.append(OpenACPinnedField(fieldIndex: 64 + i, expected: field))
        }
        pins.append(OpenACPinnedField(fieldIndex: 82, expected: expectedSmtRoot))
        pins.append(OpenACPinnedField(fieldIndex: 83, expected: expectedIssuerFormatTag))
        return OpenACPrepareLayoutV3(
            numPublicInputs: 86,
            commitmentXIndex: 84,
            commitmentYIndex: 85,
            extraPinnedFields: pins
        )
    }
}

public extension OpenACShowLayoutV3 {
    /// openac_show v3 (passport-only) layout (85 fields). Pins the
    /// challenge/link public outputs as well as link policy fields so
    /// metadata cannot be decoupled from proof public inputs.
    static func openacShow(
        expectedLinkMode: Bool,
        expectedLinkScope: Data,
        expectedEpoch: Data,
        expectedEpochField: Data,
        expectedChallengeDigest: Data,
        expectedLinkTag: Data
    ) -> OpenACShowLayoutV3 {
        var pins: [OpenACPinnedField] = [
            OpenACPinnedField(fieldIndex: 0, expected: openACByteAsField(0x01)),
            OpenACPinnedField(fieldIndex: 33, expected: openACBoolAsField(expectedLinkMode)),
            OpenACPinnedField(fieldIndex: 34, expected: expectedLinkScope),
            OpenACPinnedField(fieldIndex: 39, expected: expectedEpochField),
            OpenACPinnedField(fieldIndex: 80, expected: expectedLinkTag),
        ]
        pins.append(contentsOf: openACPinByteArray(baseFieldIndex: 35, bytes: expectedEpoch))
        pins.append(contentsOf: openACPinByteArray(baseFieldIndex: 48, bytes: expectedChallengeDigest))
        return OpenACShowLayoutV3(
            numPublicInputs: 85,
            commitmentXIndex: 46,
            commitmentYIndex: 47,
            nonceHashFirstByteIndex: 1,
            extraPinnedFields: pins
        )
    }

    /// x509_show v3 layout (41 fields). Pins target-domain policy plus
    /// challenge/link public outputs.
    static func x509Show(
        expectedTargetDomainHash: Data,
        expectedLinkMode: Bool,
        expectedLinkScope: Data,
        expectedEpoch: Data,
        expectedLinkTag: Data,
        expectedChallengeDigest: Data
    ) -> OpenACShowLayoutV3 {
        OpenACShowLayoutV3(
            numPublicInputs: 41,
            commitmentXIndex: 0,
            commitmentYIndex: 1,
            nonceHashFirstByteIndex: 2,
            extraPinnedFields: [
                OpenACPinnedField(fieldIndex: 34, expected: expectedTargetDomainHash),
                OpenACPinnedField(fieldIndex: 35, expected: openACBoolAsField(expectedLinkMode)),
                OpenACPinnedField(fieldIndex: 36, expected: expectedLinkScope),
                OpenACPinnedField(fieldIndex: 37, expected: expectedEpoch),
                OpenACPinnedField(fieldIndex: 38, expected: expectedLinkTag),
                OpenACPinnedField(fieldIndex: 40, expected: expectedChallengeDigest),
            ]
        )
    }

    /// composite_show v3 layout (49 fields). Pins both passport (0,1) and
    /// aux (2,3) commitments + aux_domain + target_aux_hash + challenge/link
    /// outputs.
    static func compositeShow(
        auxCommitment: PedersenPoint,
        auxDomain: Data,
        expectedTargetAuxHash: Data,
        expectedLinkMode: Bool,
        expectedLinkScope: Data,
        expectedEpoch: Data,
        expectedLinkTag: Data,
        expectedChallengeDigest: Data
    ) -> OpenACShowLayoutV3 {
        OpenACShowLayoutV3(
            numPublicInputs: 49,
            commitmentXIndex: 0,
            commitmentYIndex: 1,
            nonceHashFirstByteIndex: 5,
            extraPinnedFields: [
                OpenACPinnedField(fieldIndex: 2, expected: auxCommitment.x),
                OpenACPinnedField(fieldIndex: 3, expected: auxCommitment.y),
                OpenACPinnedField(fieldIndex: 4, expected: auxDomain),
                OpenACPinnedField(fieldIndex: 41, expected: expectedTargetAuxHash),
                OpenACPinnedField(fieldIndex: 42, expected: openACBoolAsField(expectedLinkMode)),
                OpenACPinnedField(fieldIndex: 43, expected: expectedLinkScope),
                OpenACPinnedField(fieldIndex: 44, expected: expectedEpoch),
                OpenACPinnedField(fieldIndex: 45, expected: expectedLinkTag),
                OpenACPinnedField(fieldIndex: 48, expected: expectedChallengeDigest),
            ]
        )
    }
}

// MARK: - OpenAC v3 strict public-input decoder

fileprivate func openACDecodePublicInputs(
    proof: Data,
    numFields: Int
) throws -> [Data] {
    let needed = numFields * 32
    guard proof.count >= needed else {
        throw OpenACV3Error.proofTooShortForPublicInputs
    }
    var out: [Data] = []
    out.reserveCapacity(numFields)
    for i in 0..<numFields {
        let start = proof.startIndex + i * 32
        out.append(proof.subdata(in: start..<(start + 32)))
    }
    return out
}

fileprivate func openACAssertPinned(
    publicInputs: [Data],
    pinned: [OpenACPinnedField],
    error: OpenACV3Error
) throws {
    for pin in pinned {
        guard pin.fieldIndex < publicInputs.count else {
            throw error
        }
        if publicInputs[pin.fieldIndex] != pin.expected {
            throw error
        }
    }
}

private enum OpenACV3Domain {
    // Shared with v2: v3 Path A kept the show-phase digest format unchanged.
    static let show = Data("openac.show.v2".utf8)
}

public func computeOpenACv3ChallengeDigest(
    commitmentX: Data,
    commitmentY: Data,
    challenge: Data,
    epoch: Data
) throws -> Data {
    try requireLength(commitmentX, field: "commitmentX", expected: 32)
    try requireLength(commitmentY, field: "commitmentY", expected: 32)
    try requireLength(challenge, field: "challenge", expected: 32)
    try requireLength(epoch, field: "epoch", expected: 4)
    return try sha256([OpenACV3Domain.show, commitmentX, commitmentY, challenge, epoch])
}

@discardableResult
public func verifyOpenAcV3Linking(
    prepare: OpenACV3PrepareArtifact,
    show: OpenACV3ShowPresentation,
    policy: OpenACV3Policy
) throws -> Bool {
    try requireLength(prepare.commitmentX, field: "prepare.commitmentX", expected: 32)
    try requireLength(prepare.commitmentY, field: "prepare.commitmentY", expected: 32)
    try requireLength(prepare.pkDigest, field: "prepare.pkDigest", expected: 32)
    try requireLength(show.commitmentX, field: "show.commitmentX", expected: 32)
    try requireLength(show.commitmentY, field: "show.commitmentY", expected: 32)
    try requireLength(show.pkDigest, field: "show.pkDigest", expected: 32)
    try requireLength(show.nonceHash, field: "show.nonceHash", expected: 32)
    try requireLength(show.challenge, field: "show.challenge", expected: 32)
    try requireLength(show.challengeDigest, field: "show.challengeDigest", expected: 32)
    try requireLength(show.linkTag, field: "show.linkTag", expected: 32)
    try requireLength(policy.epoch, field: "policy.epoch", expected: 4)
    try requireLength(policy.expectedChallenge, field: "policy.expectedChallenge", expected: 32)
    try requireLength(policy.expectedNonceHash, field: "policy.expectedNonceHash", expected: 32)

    if policy.nowUnix < prepare.createdAtUnix {
        throw OpenACV3Error.prepareNotActive
    }
    if policy.nowUnix > prepare.expiresAtUnix {
        throw OpenACV3Error.expiredPrepare
    }

    if prepare.commitmentX != show.commitmentX || prepare.commitmentY != show.commitmentY {
        throw OpenACV3Error.commitmentMismatch
    }

    if prepare.pkDigest != show.pkDigest {
        throw OpenACV3Error.pkDigestMismatch
    }

    if show.challenge != policy.expectedChallenge {
        throw OpenACV3Error.invalidChallenge
    }

    if show.nonceHash != policy.expectedNonceHash {
        throw OpenACV3Error.invalidNonceHash
    }

    let expectedDigest = try computeOpenACv3ChallengeDigest(
        commitmentX: show.commitmentX,
        commitmentY: show.commitmentY,
        challenge: policy.expectedChallenge,
        epoch: policy.epoch
    )
    if show.challengeDigest != expectedDigest {
        throw OpenACV3Error.invalidChallengeDigest
    }

    let zero32 = Data(repeating: 0, count: 32)
    switch policy.linkMode {
    case .unlinkable:
        if policy.linkScope != nil || show.linkTag != zero32 {
            throw OpenACV3Error.scopeMismatch
        }
    case .scopedLinkable:
        guard policy.linkScope != nil else {
            throw OpenACV3Error.scopeMismatch
        }
        if show.linkTag == zero32 {
            throw OpenACV3Error.scopeMismatch
        }
    }

    return true
}

/// Full-parity v3 verification mirroring `verify_openac_v3_with_verifier` in
/// `mopro-binding/src/openac_v3.rs`. Unlike `verifyOpenAcV3Linking`, this
/// enforces VK trust, the Noir proof check, and that commitment/nonce_hash
/// bytes appear as public inputs in the attached proofs.
@discardableResult
public func verifyOpenACv3(
    prepare: OpenACV3PrepareArtifact,
    show: OpenACV3ShowPresentation,
    policy: OpenACV3Policy,
    verifier: OpenACNoirVerifier? = nil
) throws -> Bool {
    try requireLength(prepare.commitmentX, field: "prepare.commitmentX", expected: 32)
    try requireLength(prepare.commitmentY, field: "prepare.commitmentY", expected: 32)
    try requireLength(prepare.pkDigest, field: "prepare.pkDigest", expected: 32)
    try requireLength(show.commitmentX, field: "show.commitmentX", expected: 32)
    try requireLength(show.commitmentY, field: "show.commitmentY", expected: 32)
    try requireLength(show.pkDigest, field: "show.pkDigest", expected: 32)
    try requireLength(show.nonceHash, field: "show.nonceHash", expected: 32)
    try requireLength(show.challenge, field: "show.challenge", expected: 32)
    try requireLength(show.challengeDigest, field: "show.challengeDigest", expected: 32)
    try requireLength(show.linkTag, field: "show.linkTag", expected: 32)
    try requireLength(policy.epoch, field: "policy.epoch", expected: 4)
    try requireLength(policy.expectedChallenge, field: "policy.expectedChallenge", expected: 32)
    try requireLength(policy.expectedNonceHash, field: "policy.expectedNonceHash", expected: 32)
    try requireLength(policy.prepareVkHash, field: "policy.prepareVkHash", expected: 32)
    try requireLength(policy.showVkHash, field: "policy.showVkHash", expected: 32)

    let runVerifier: OpenACNoirVerifier = verifier ?? { proof, vk in
        try verifyNoirProof(proof: proof, vk: vk)
    }

    // 1. VK trust
    let prepareVkHash: Data
    let showVkHash: Data
    do {
        prepareVkHash = try sha256([prepare.vk])
        showVkHash = try sha256([show.vk])
    } catch {
        throw OpenACV3Error.cryptoUnavailable
    }
    if prepareVkHash != policy.prepareVkHash {
        throw OpenACV3Error.untrustedPrepareVk
    }
    if showVkHash != policy.showVkHash {
        throw OpenACV3Error.untrustedShowVk
    }

    // 2. Noir proofs
    if prepare.proof.isEmpty || prepare.vk.isEmpty {
        throw OpenACV3Error.emptyPrepareBundle
    }
    if !(try runVerifier(prepare.proof, prepare.vk)) {
        throw OpenACV3Error.invalidPrepareProof
    }
    if show.proof.isEmpty || show.vk.isEmpty {
        throw OpenACV3Error.emptyShowBundle
    }
    if !(try runVerifier(show.proof, show.vk)) {
        throw OpenACV3Error.invalidShowProof
    }

    // 3. TTL
    if policy.nowUnix < prepare.createdAtUnix {
        throw OpenACV3Error.prepareNotActive
    }
    if policy.nowUnix > prepare.expiresAtUnix {
        throw OpenACV3Error.expiredPrepare
    }

    // 4. Public-input prefix checks (Task 1+2 follow-up). The Swift
    //    verifier mirrors the Rust strict-mode path: each expected value
    //    is pinned at its known ABI field index. The legacy "scan for
    //    bytes anywhere" fallback was removed.
    let preparePublicInputs = try openACDecodePublicInputs(
        proof: prepare.proof,
        numFields: policy.prepareLayout.numPublicInputs
    )
    try openACAssertPinned(
        publicInputs: preparePublicInputs,
        pinned: [
            OpenACPinnedField(
                fieldIndex: policy.prepareLayout.commitmentXIndex,
                expected: prepare.commitmentX
            ),
            OpenACPinnedField(
                fieldIndex: policy.prepareLayout.commitmentYIndex,
                expected: prepare.commitmentY
            ),
        ],
        error: .prepareCommitmentNotInProof
    )
    try openACAssertPinned(
        publicInputs: preparePublicInputs,
        pinned: policy.prepareLayout.extraPinnedFields,
        error: .preparePublicInputMismatch
    )

    let showPublicInputs = try openACDecodePublicInputs(
        proof: show.proof,
        numFields: policy.showLayout.numPublicInputs
    )
    try openACAssertPinned(
        publicInputs: showPublicInputs,
        pinned: [
            OpenACPinnedField(
                fieldIndex: policy.showLayout.commitmentXIndex,
                expected: show.commitmentX
            ),
            OpenACPinnedField(
                fieldIndex: policy.showLayout.commitmentYIndex,
                expected: show.commitmentY
            ),
        ],
        error: .showCommitmentNotInProof
    )
    if let base = policy.showLayout.nonceHashFirstByteIndex {
        try openACAssertPinned(
            publicInputs: showPublicInputs,
            pinned: openACPinByteArray(baseFieldIndex: base, bytes: show.nonceHash),
            error: .nonceHashNotInProof
        )
    }
    try openACAssertPinned(
        publicInputs: showPublicInputs,
        pinned: policy.showLayout.extraPinnedFields,
        error: .showPublicInputMismatch
    )

    // 5. Commitment equality
    if prepare.commitmentX != show.commitmentX || prepare.commitmentY != show.commitmentY {
        throw OpenACV3Error.commitmentMismatch
    }

    // 6. pk_digest equality.
    if prepare.pkDigest != show.pkDigest {
        throw OpenACV3Error.pkDigestMismatch
    }

    // 7. Challenge binding
    if show.challenge != policy.expectedChallenge {
        throw OpenACV3Error.invalidChallenge
    }
    if show.nonceHash != policy.expectedNonceHash {
        throw OpenACV3Error.invalidNonceHash
    }
    let expectedDigest = try computeOpenACv3ChallengeDigest(
        commitmentX: show.commitmentX,
        commitmentY: show.commitmentY,
        challenge: policy.expectedChallenge,
        epoch: policy.epoch
    )
    if show.challengeDigest != expectedDigest {
        throw OpenACV3Error.invalidChallengeDigest
    }

    // 8. Scope / linkability
    let zero32 = Data(repeating: 0, count: 32)
    switch policy.linkMode {
    case .unlinkable:
        if policy.linkScope != nil || show.linkTag != zero32 {
            throw OpenACV3Error.scopeMismatch
        }
    case .scopedLinkable:
        guard policy.linkScope != nil else {
            throw OpenACV3Error.scopeMismatch
        }
        if show.linkTag == zero32 {
            throw OpenACV3Error.scopeMismatch
        }
    }

    return true
}

// MARK: - OpenAC v3 high-level wrappers

public struct OpenACV3ProofBundle: Sendable {
    public let proof: Data
    public let vk: Data
    public let noirResult: NoirProofResult

    public init(proof: Data, vk: Data, noirResult: NoirProofResult) {
        self.proof = proof
        self.vk = vk
        self.noirResult = noirResult
    }
}

/// Run the prepare circuit and build a v3 prepare artifact whose commitment,
/// pk_digest, and blinding randomness are all fixed by the caller. Inputs are
/// threaded straight through to `generateNoirProof`, so the caller is
/// responsible for ensuring the Noir prover receives the same values.
public func openACPrepareV3(
    circuitPath: String,
    srsPath: String?,
    inputs: [String: [String]],
    credentialType: OpenACV3CredentialType,
    commitment: PedersenPoint,
    pkDigest: Data,
    linkRand: Data,
    createdAtUnix: UInt64,
    ttlSeconds: UInt64
) throws -> (OpenACV3PrepareArtifact, OpenACV3ProofBundle) {
    try requireLength(commitment.x, field: "commitment.x", expected: 32)
    try requireLength(commitment.y, field: "commitment.y", expected: 32)
    try requireLength(pkDigest, field: "pkDigest", expected: 32)
    try requireLength(linkRand, field: "linkRand", expected: 32)

    let noir = try generateNoirProof(
        circuitPath: circuitPath,
        srsPath: srsPath,
        inputs: inputs
    )
    let proof = Data(noir.proof)
    let vk = Data(noir.vk)

    let artifact = OpenACV3PrepareArtifact(
        createdAtUnix: createdAtUnix,
        expiresAtUnix: createdAtUnix + ttlSeconds,
        credentialType: credentialType,
        commitmentX: commitment.x,
        commitmentY: commitment.y,
        pkDigest: pkDigest,
        linkRand: linkRand,
        proof: proof,
        vk: vk
    )
    let bundle = OpenACV3ProofBundle(proof: proof, vk: vk, noirResult: noir)
    return (artifact, bundle)
}

/// Compute the v3 challenge digest for the supplied request, run the show
/// circuit, and build a `OpenACV3ShowPresentation` bound to the prepare
/// artifact's commitment + pk_digest. The caller supplies `nonceHash` and
/// `linkTag` (both 32 bytes) — these are the values the show circuit will
/// expose as public inputs.
public func openACShowV3(
    circuitPath: String,
    srsPath: String?,
    inputs: [String: [String]],
    prepare: OpenACV3PrepareArtifact,
    request: OpenACShowRequest,
    nonceHash: Data,
    linkTag: Data
) throws -> (OpenACV3ShowPresentation, OpenACV3ProofBundle) {
    try requireLength(nonceHash, field: "nonceHash", expected: 32)
    try requireLength(linkTag, field: "linkTag", expected: 32)

    let challengeDigest = try computeOpenACv3ChallengeDigest(
        commitmentX: prepare.commitmentX,
        commitmentY: prepare.commitmentY,
        challenge: request.challenge,
        epoch: request.epoch
    )

    let noir = try generateNoirProof(
        circuitPath: circuitPath,
        srsPath: srsPath,
        inputs: inputs
    )
    let proof = Data(noir.proof)
    let vk = Data(noir.vk)

    let presentation = OpenACV3ShowPresentation(
        commitmentX: prepare.commitmentX,
        commitmentY: prepare.commitmentY,
        pkDigest: prepare.pkDigest,
        nonceHash: nonceHash,
        challenge: request.challenge,
        challengeDigest: challengeDigest,
        linkTag: linkTag,
        proof: proof,
        vk: vk
    )
    let bundle = OpenACV3ProofBundle(proof: proof, vk: vk, noirResult: noir)
    return (presentation, bundle)
}
