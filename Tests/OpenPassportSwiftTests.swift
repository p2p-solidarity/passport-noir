import Foundation
import XCTest

@testable import OpenPassportSwift

final class OpenPassportSwiftTests: XCTestCase {
    func testPackageMetadata() {
        XCTAssertEqual(OpenPassportSwiftInfo.packageName, "OpenPassportSwift")
    }

    func testExportedApiSignaturesCompile() {
        let generate: (String, String?, [String: [String]]) throws -> NoirProofResult = generateNoirProof
        let getVk: (String, String?) throws -> Data = getNoirVerificationKey
        let verify: (Data, Data) throws -> Bool = verifyNoirProof
        _ = (generate, getVk, verify)
    }

    func testOpenACHashHelpersDeterministic() throws {
        let sodHash = Data(repeating: 0x11, count: 32)
        let mrzHash = Data(repeating: 0x22, count: 32)
        let linkRandomness = Data(repeating: 0x33, count: 32)
        let epoch = Data([0x20, 0x26, 0x03, 0x15])
        let challenge = Data(repeating: 0x44, count: 32)
        let linkScope = Data(repeating: 0x55, count: 32)

        let prepareCommitmentA = try computeOpenACPrepareCommitment(
            sodHash: sodHash,
            mrzHash: mrzHash,
            linkRandomness: linkRandomness
        )
        let prepareCommitmentB = try computeOpenACPrepareCommitment(
            sodHash: sodHash,
            mrzHash: mrzHash,
            linkRandomness: linkRandomness
        )

        XCTAssertEqual(prepareCommitmentA, prepareCommitmentB)

        let challengeDigest = try computeOpenACChallengeDigest(
            challenge: challenge,
            prepareCommitment: prepareCommitmentA,
            epoch: epoch
        )
        XCTAssertEqual(challengeDigest.count, 32)

        let linkTagA = try computeOpenACScopedLinkTag(
            prepareCommitment: prepareCommitmentA,
            linkScope: linkScope,
            epoch: epoch
        )
        let linkTagB = try computeOpenACScopedLinkTag(
            prepareCommitment: prepareCommitmentA,
            linkScope: linkScope,
            epoch: epoch
        )

        XCTAssertEqual(linkTagA, linkTagB)
    }

    func testOpenACScopedLinkingHappyPath() throws {
        let sodHash = Data(repeating: 0x12, count: 32)
        let mrzHash = Data(repeating: 0x23, count: 32)
        let linkRandomness = Data(repeating: 0x34, count: 32)
        let epoch = Data([0x20, 0x26, 0x03, 0x15])
        let challenge = Data(repeating: 0x45, count: 32)
        let linkScope = Data(repeating: 0x56, count: 32)

        let prepareCommitment = try computeOpenACPrepareCommitment(
            sodHash: sodHash,
            mrzHash: mrzHash,
            linkRandomness: linkRandomness
        )

        let prepare = OpenACPrepareArtifact(
            createdAtUnix: 100,
            expiresAtUnix: 200,
            sodHash: sodHash,
            mrzHash: mrzHash,
            prepareCommitment: prepareCommitment
        )

        let request = OpenACShowRequest(
            challenge: challenge,
            linkMode: .scopedLinkable,
            linkScope: linkScope,
            epoch: epoch
        )

        let challengeDigest = try computeOpenACChallengeDigest(
            challenge: challenge,
            prepareCommitment: prepareCommitment,
            epoch: epoch
        )
        let linkTag = try computeOpenACScopedLinkTag(
            prepareCommitment: prepareCommitment,
            linkScope: linkScope,
            epoch: epoch
        )

        let show = OpenACShowPresentation(
            sodHash: sodHash,
            mrzHash: mrzHash,
            prepareCommitment: prepareCommitment,
            challenge: challenge,
            challengeDigest: challengeDigest,
            linkTag: linkTag
        )

        let isValid = try verifyOpenACLinking(
            prepare: prepare,
            show: show,
            request: request,
            nowUnix: 150
        )
        XCTAssertTrue(isValid)
    }

    func testOpenACScopeMismatchThrows() throws {
        let sodHash = Data(repeating: 0x13, count: 32)
        let mrzHash = Data(repeating: 0x24, count: 32)
        let linkRandomness = Data(repeating: 0x35, count: 32)
        let epoch = Data([0x20, 0x26, 0x03, 0x15])
        let challenge = Data(repeating: 0x46, count: 32)

        let prepareCommitment = try computeOpenACPrepareCommitment(
            sodHash: sodHash,
            mrzHash: mrzHash,
            linkRandomness: linkRandomness
        )

        let prepare = OpenACPrepareArtifact(
            createdAtUnix: 100,
            expiresAtUnix: 200,
            sodHash: sodHash,
            mrzHash: mrzHash,
            prepareCommitment: prepareCommitment
        )

        let request = OpenACShowRequest(
            challenge: challenge,
            linkMode: .scopedLinkable,
            linkScope: Data(repeating: 0x66, count: 32),
            epoch: epoch
        )

        let challengeDigest = try computeOpenACChallengeDigest(
            challenge: challenge,
            prepareCommitment: prepareCommitment,
            epoch: epoch
        )
        let wrongTag = Data(repeating: 0, count: 32)

        let show = OpenACShowPresentation(
            sodHash: sodHash,
            mrzHash: mrzHash,
            prepareCommitment: prepareCommitment,
            challenge: challenge,
            challengeDigest: challengeDigest,
            linkTag: wrongTag
        )

        XCTAssertThrowsError(
            try verifyOpenACLinking(
                prepare: prepare,
                show: show,
                request: request,
                nowUnix: 150
            )
        )
    }

    // MARK: - OpenAC v3 (Path A)

    private func v3Fixture(
        linkMode: OpenACLinkMode = .scopedLinkable
    ) throws -> (OpenACV3PrepareArtifact, OpenACV3ShowPresentation, OpenACV3Policy) {
        let commitmentX = Data(repeating: 0x10, count: 32)
        let commitmentY = Data(repeating: 0x20, count: 32)
        let pkDigest = Data(repeating: 0x30, count: 32)
        let linkRand = Data(repeating: 0x40, count: 32)
        let nonceHash = Data(repeating: 0x50, count: 32)
        let challenge = Data(repeating: 0x60, count: 32)
        let epoch = Data([0x20, 0x26, 0x04, 0x01])
        let linkTag: Data
        let linkScope: Data?
        switch linkMode {
        case .scopedLinkable:
            linkTag = Data(repeating: 0x77, count: 32)
            linkScope = Data(repeating: 0x55, count: 32)
        case .unlinkable:
            linkTag = Data(repeating: 0, count: 32)
            linkScope = nil
        }

        let digest = try computeOpenACv3ChallengeDigest(
            commitmentX: commitmentX,
            commitmentY: commitmentY,
            challenge: challenge,
            epoch: epoch
        )

        let prepare = OpenACV3PrepareArtifact(
            createdAtUnix: 100,
            expiresAtUnix: 200,
            credentialType: .passport,
            commitmentX: commitmentX,
            commitmentY: commitmentY,
            pkDigest: pkDigest,
            linkRand: linkRand,
            proof: Data(),
            vk: Data()
        )

        let show = OpenACV3ShowPresentation(
            commitmentX: commitmentX,
            commitmentY: commitmentY,
            pkDigest: pkDigest,
            nonceHash: nonceHash,
            challenge: challenge,
            challengeDigest: digest,
            linkTag: linkTag,
            proof: Data(),
            vk: Data()
        )

        let policy = OpenACV3Policy(
            linkMode: linkMode,
            linkScope: linkScope,
            epoch: epoch,
            nowUnix: 150,
            expectedChallenge: challenge,
            expectedNonceHash: nonceHash,
            prepareVkHash: Data(repeating: 0, count: 32),
            showVkHash: Data(repeating: 0, count: 32)
        )

        return (prepare, show, policy)
    }

    func testOpenACV3ChallengeDigestDeterministic() throws {
        let commitmentX = Data(repeating: 0xAA, count: 32)
        let commitmentY = Data(repeating: 0xBB, count: 32)
        let challenge = Data(repeating: 0xCC, count: 32)
        let epoch = Data([0x20, 0x26, 0x04, 0x01])

        let d1 = try computeOpenACv3ChallengeDigest(
            commitmentX: commitmentX,
            commitmentY: commitmentY,
            challenge: challenge,
            epoch: epoch
        )
        let d2 = try computeOpenACv3ChallengeDigest(
            commitmentX: commitmentX,
            commitmentY: commitmentY,
            challenge: challenge,
            epoch: epoch
        )
        XCTAssertEqual(d1, d2)
        XCTAssertEqual(d1.count, 32)
    }

    func testOpenACV3HappyPathScoped() throws {
        let (prepare, show, policy) = try v3Fixture(linkMode: .scopedLinkable)
        XCTAssertTrue(try verifyOpenAcV3Linking(prepare: prepare, show: show, policy: policy))
    }

    func testOpenACV3HappyPathUnlinkable() throws {
        let (prepare, show, policy) = try v3Fixture(linkMode: .unlinkable)
        XCTAssertTrue(try verifyOpenAcV3Linking(prepare: prepare, show: show, policy: policy))
    }

    func testOpenACV3RejectsCommitmentMismatch() throws {
        let (prepare, show, policy) = try v3Fixture()
        let tamperedShow = OpenACV3ShowPresentation(
            commitmentX: Data(repeating: 0x11, count: 32),
            commitmentY: show.commitmentY,
            pkDigest: show.pkDigest,
            nonceHash: show.nonceHash,
            challenge: show.challenge,
            challengeDigest: show.challengeDigest,
            linkTag: show.linkTag,
            proof: show.proof,
            vk: show.vk
        )
        XCTAssertThrowsError(
            try verifyOpenAcV3Linking(prepare: prepare, show: tamperedShow, policy: policy)
        ) { err in
            XCTAssertEqual(err as? OpenACV3Error, .commitmentMismatch)
        }
    }

    func testOpenACV3RejectsPkDigestMismatch() throws {
        let (prepare, show, policy) = try v3Fixture()
        let tamperedShow = OpenACV3ShowPresentation(
            commitmentX: show.commitmentX,
            commitmentY: show.commitmentY,
            pkDigest: Data(repeating: 0x99, count: 32),
            nonceHash: show.nonceHash,
            challenge: show.challenge,
            challengeDigest: show.challengeDigest,
            linkTag: show.linkTag,
            proof: show.proof,
            vk: show.vk
        )
        XCTAssertThrowsError(
            try verifyOpenAcV3Linking(prepare: prepare, show: tamperedShow, policy: policy)
        ) { err in
            XCTAssertEqual(err as? OpenACV3Error, .pkDigestMismatch)
        }
    }

    func testOpenACV3RejectsWrongNonce() throws {
        let (prepare, show, policy) = try v3Fixture()
        let mutatedPolicy = OpenACV3Policy(
            linkMode: policy.linkMode,
            linkScope: policy.linkScope,
            epoch: policy.epoch,
            nowUnix: policy.nowUnix,
            expectedChallenge: policy.expectedChallenge,
            expectedNonceHash: Data(repeating: 0x00, count: 32),
            prepareVkHash: policy.prepareVkHash,
            showVkHash: policy.showVkHash
        )
        XCTAssertThrowsError(
            try verifyOpenAcV3Linking(prepare: prepare, show: show, policy: mutatedPolicy)
        ) { err in
            XCTAssertEqual(err as? OpenACV3Error, .invalidNonceHash)
        }
    }

    func testOpenACV3RejectsExpiredPrepare() throws {
        let (prepare, show, policy) = try v3Fixture()
        let latePolicy = OpenACV3Policy(
            linkMode: policy.linkMode,
            linkScope: policy.linkScope,
            epoch: policy.epoch,
            nowUnix: 500,
            expectedChallenge: policy.expectedChallenge,
            expectedNonceHash: policy.expectedNonceHash,
            prepareVkHash: policy.prepareVkHash,
            showVkHash: policy.showVkHash
        )
        XCTAssertThrowsError(
            try verifyOpenAcV3Linking(prepare: prepare, show: show, policy: latePolicy)
        ) { err in
            XCTAssertEqual(err as? OpenACV3Error, .expiredPrepare)
        }
    }

    func testOpenACV3UnlinkableRejectsNonZeroTag() throws {
        let (prepare, show, _) = try v3Fixture(linkMode: .scopedLinkable)
        let unlinkablePolicy = OpenACV3Policy(
            linkMode: .unlinkable,
            linkScope: nil,
            epoch: Data([0x20, 0x26, 0x04, 0x01]),
            nowUnix: 150,
            expectedChallenge: show.challenge,
            expectedNonceHash: show.nonceHash,
            prepareVkHash: Data(repeating: 0, count: 32),
            showVkHash: Data(repeating: 0, count: 32)
        )
        XCTAssertThrowsError(
            try verifyOpenAcV3Linking(prepare: prepare, show: show, policy: unlinkablePolicy)
        ) { err in
            XCTAssertEqual(err as? OpenACV3Error, .scopeMismatch)
        }
    }

    // MARK: - OpenAC v2 (Pedersen)

    private func v2SampleCommitment(seed: UInt8) -> PedersenPoint {
        var x = Data(count: 32)
        var y = Data(count: 32)
        for i in 0..<32 {
            x[i] = seed &+ UInt8(i)
            y[i] = seed &+ UInt8(i) &+ 100
        }
        return PedersenPoint(x: x, y: y)
    }

    private func sha256Hash(_ data: Data) -> Data {
        // Reproduce the package's SHA256 helper without exposing it.
        // Equivalent to SHA256(data).
        return Data(CryptoKitFacade.sha256(data))
    }

    private func v2Fixture(
        linkMode: OpenACLinkMode = .scopedLinkable
    ) throws -> (OpenACV2PrepareArtifact, OpenACV2ShowPresentation, OpenACV2Policy, OpenACNoirVerifier) {
        let commitment = v2SampleCommitment(seed: 10)
        let challenge = Data(repeating: 0x44, count: 32)
        let epoch = Data([0x20, 0x26, 0x04, 0x01])
        let digest = try computeOpenACv2ChallengeDigest(
            commitment: commitment,
            challenge: challenge,
            epoch: epoch
        )

        let prepareVk = Data([1, 2, 3])
        let showVk = Data([4, 5, 6])

        // Mock proofs embed commitment (x || y) as a 64-byte prefix.
        var prepareProof = Data()
        prepareProof.append(commitment.x)
        prepareProof.append(commitment.y)
        prepareProof.append(Data([10, 20, 30]))

        var showProof = Data()
        showProof.append(commitment.x)
        showProof.append(commitment.y)
        showProof.append(Data([40, 50, 60]))

        let linkTag: Data
        let linkScope: Data?
        switch linkMode {
        case .scopedLinkable:
            linkTag = Data(repeating: 0x77, count: 32)
            linkScope = Data(repeating: 0x55, count: 32)
        case .unlinkable:
            linkTag = Data(repeating: 0, count: 32)
            linkScope = nil
        }

        let prepare = OpenACV2PrepareArtifact(
            createdAtUnix: 100,
            expiresAtUnix: 200,
            credentialType: .passport,
            commitment: commitment,
            linkRand: Data(repeating: 0x33, count: 32),
            proof: prepareProof,
            vk: prepareVk
        )

        let show = OpenACV2ShowPresentation(
            commitment: commitment,
            challenge: challenge,
            challengeDigest: digest,
            linkTag: linkTag,
            proof: showProof,
            vk: showVk
        )

        let policy = OpenACV2Policy(
            linkMode: linkMode,
            linkScope: linkScope,
            epoch: epoch,
            epochField: Data(repeating: 0x20, count: 32),
            nowUnix: 150,
            expectedChallenge: challenge,
            prepareVkHash: sha256Hash(prepareVk),
            showVkHash: sha256Hash(showVk)
        )

        let verifier: OpenACNoirVerifier = { _, _ in true }
        return (prepare, show, policy, verifier)
    }

    func testOpenACv2ChallengeDigestDeterministic() throws {
        let commitment = v2SampleCommitment(seed: 10)
        let challenge = Data(repeating: 0x20, count: 32)
        let epoch = Data([0x20, 0x26, 0x04, 0x01])

        let d1 = try computeOpenACv2ChallengeDigest(
            commitment: commitment,
            challenge: challenge,
            epoch: epoch
        )
        let d2 = try computeOpenACv2ChallengeDigest(
            commitment: commitment,
            challenge: challenge,
            epoch: epoch
        )
        XCTAssertEqual(d1, d2)
        XCTAssertEqual(d1.count, 32)
    }

    func testOpenACv2HappyPathScoped() throws {
        let (prepare, show, policy, verifier) = try v2Fixture(linkMode: .scopedLinkable)
        XCTAssertTrue(try verifyOpenACv2(prepare: prepare, show: show, policy: policy, verifier: verifier))
    }

    func testOpenACv2CommitmentMismatchRejected() throws {
        let (prepare, show, policy, verifier) = try v2Fixture()
        // Rebuild show with a different commitment and matching proof embedding,
        // so the commitment-in-proof check passes but equality fails.
        var tamperedX = show.commitment.x
        tamperedX[0] ^= 0x01
        let tampered = PedersenPoint(x: tamperedX, y: show.commitment.y)

        var tamperedProof = Data()
        tamperedProof.append(tampered.x)
        tamperedProof.append(tampered.y)
        tamperedProof.append(Data([40, 50, 60]))

        let newDigest = try computeOpenACv2ChallengeDigest(
            commitment: tampered,
            challenge: policy.expectedChallenge,
            epoch: policy.epoch
        )

        let tamperedShow = OpenACV2ShowPresentation(
            commitment: tampered,
            challenge: show.challenge,
            challengeDigest: newDigest,
            linkTag: show.linkTag,
            proof: tamperedProof,
            vk: show.vk
        )

        XCTAssertThrowsError(
            try verifyOpenACv2(prepare: prepare, show: tamperedShow, policy: policy, verifier: verifier)
        ) { err in
            XCTAssertEqual(err as? OpenACV2Error, .commitmentMismatch)
        }
    }

    func testOpenACv2UntrustedVkRejected() throws {
        let (prepare, show, policy, verifier) = try v2Fixture()
        let tamperedPolicy = OpenACV2Policy(
            linkMode: policy.linkMode,
            linkScope: policy.linkScope,
            epoch: policy.epoch,
            epochField: policy.epochField,
            nowUnix: policy.nowUnix,
            expectedChallenge: policy.expectedChallenge,
            prepareVkHash: Data(repeating: 0x99, count: 32),
            showVkHash: policy.showVkHash
        )
        XCTAssertThrowsError(
            try verifyOpenACv2(prepare: prepare, show: show, policy: tamperedPolicy, verifier: verifier)
        ) { err in
            XCTAssertEqual(err as? OpenACV2Error, .untrustedPrepareVk)
        }
    }

    func testOpenACv2ExpiredPrepareRejected() throws {
        let (prepare, show, policy, verifier) = try v2Fixture()
        let latePolicy = OpenACV2Policy(
            linkMode: policy.linkMode,
            linkScope: policy.linkScope,
            epoch: policy.epoch,
            epochField: policy.epochField,
            nowUnix: 500,
            expectedChallenge: policy.expectedChallenge,
            prepareVkHash: policy.prepareVkHash,
            showVkHash: policy.showVkHash
        )
        XCTAssertThrowsError(
            try verifyOpenACv2(prepare: prepare, show: show, policy: latePolicy, verifier: verifier)
        ) { err in
            XCTAssertEqual(err as? OpenACV2Error, .expiredPrepare)
        }
    }

    func testOpenACv2UnlinkableNonZeroTagRejected() throws {
        let (prepare, show, _, verifier) = try v2Fixture(linkMode: .scopedLinkable)
        // Switch to unlinkable mode; show.linkTag is still the scoped non-zero value.
        let unlinkablePolicy = OpenACV2Policy(
            linkMode: .unlinkable,
            linkScope: nil,
            epoch: Data([0x20, 0x26, 0x04, 0x01]),
            epochField: Data(repeating: 0x20, count: 32),
            nowUnix: 150,
            expectedChallenge: show.challenge,
            prepareVkHash: sha256Hash(prepare.vk),
            showVkHash: sha256Hash(show.vk)
        )
        XCTAssertThrowsError(
            try verifyOpenACv2(prepare: prepare, show: show, policy: unlinkablePolicy, verifier: verifier)
        ) { err in
            XCTAssertEqual(err as? OpenACV2Error, .scopeMismatch)
        }
    }

    // MARK: - OpenAC v3 full verification (parity with Rust)

    private func v3FullFixture(
        linkMode: OpenACLinkMode = .scopedLinkable
    ) throws -> (OpenACV3PrepareArtifact, OpenACV3ShowPresentation, OpenACV3Policy, OpenACNoirVerifier) {
        let commitmentX = Data(repeating: 0x10, count: 32)
        let commitmentY = Data(repeating: 0x20, count: 32)
        let pkDigest = Data(repeating: 0x30, count: 32)
        let linkRand = Data(repeating: 0x40, count: 32)
        let nonceHash = Data(repeating: 0x50, count: 32)
        let challenge = Data(repeating: 0x60, count: 32)
        let epoch = Data([0x20, 0x26, 0x04, 0x01])

        let digest = try computeOpenACv3ChallengeDigest(
            commitmentX: commitmentX,
            commitmentY: commitmentY,
            challenge: challenge,
            epoch: epoch
        )

        let prepareVk = Data([0x01, 0x02, 0x03])
        let showVk = Data([0x04, 0x05, 0x06])

        var prepareProof = Data()
        prepareProof.append(commitmentX)
        prepareProof.append(commitmentY)
        prepareProof.append(Data([10, 20, 30]))

        var showProof = Data()
        showProof.append(commitmentX)
        showProof.append(commitmentY)
        showProof.append(pkDigest)
        showProof.append(nonceHash)
        showProof.append(Data([40, 50, 60]))

        let linkTag: Data
        let linkScope: Data?
        switch linkMode {
        case .scopedLinkable:
            linkTag = Data(repeating: 0x77, count: 32)
            linkScope = Data(repeating: 0x55, count: 32)
        case .unlinkable:
            linkTag = Data(repeating: 0, count: 32)
            linkScope = nil
        }

        let prepare = OpenACV3PrepareArtifact(
            createdAtUnix: 100,
            expiresAtUnix: 200,
            credentialType: .passport,
            commitmentX: commitmentX,
            commitmentY: commitmentY,
            pkDigest: pkDigest,
            linkRand: linkRand,
            proof: prepareProof,
            vk: prepareVk
        )

        let show = OpenACV3ShowPresentation(
            commitmentX: commitmentX,
            commitmentY: commitmentY,
            pkDigest: pkDigest,
            nonceHash: nonceHash,
            challenge: challenge,
            challengeDigest: digest,
            linkTag: linkTag,
            proof: showProof,
            vk: showVk
        )

        let policy = OpenACV3Policy(
            linkMode: linkMode,
            linkScope: linkScope,
            epoch: epoch,
            nowUnix: 150,
            expectedChallenge: challenge,
            expectedNonceHash: nonceHash,
            prepareVkHash: sha256Hash(prepareVk),
            showVkHash: sha256Hash(showVk)
        )

        let verifier: OpenACNoirVerifier = { _, _ in true }
        return (prepare, show, policy, verifier)
    }

    func testOpenACv3FullVerifyHappyPath() throws {
        let (prepare, show, policy, verifier) = try v3FullFixture()
        XCTAssertTrue(
            try verifyOpenACv3(prepare: prepare, show: show, policy: policy, verifier: verifier)
        )
    }

    func testOpenACv3UntrustedVkRejected() throws {
        let (prepare, show, policy, verifier) = try v3FullFixture()
        let tamperedPolicy = OpenACV3Policy(
            linkMode: policy.linkMode,
            linkScope: policy.linkScope,
            epoch: policy.epoch,
            nowUnix: policy.nowUnix,
            expectedChallenge: policy.expectedChallenge,
            expectedNonceHash: policy.expectedNonceHash,
            prepareVkHash: Data(repeating: 0x99, count: 32),
            showVkHash: policy.showVkHash
        )
        XCTAssertThrowsError(
            try verifyOpenACv3(prepare: prepare, show: show, policy: tamperedPolicy, verifier: verifier)
        ) { err in
            XCTAssertEqual(err as? OpenACV3Error, .untrustedPrepareVk)
        }
    }

    func testOpenACv3NonceHashNotInProofRejected() throws {
        let (prepare, show, policy, verifier) = try v3FullFixture()
        // Rebuild the show proof WITHOUT the nonce_hash slot to trigger the scan miss.
        var stripped = Data()
        stripped.append(show.commitmentX)
        stripped.append(show.commitmentY)
        stripped.append(show.pkDigest)
        stripped.append(Data([40, 50, 60]))

        let strippedShow = OpenACV3ShowPresentation(
            commitmentX: show.commitmentX,
            commitmentY: show.commitmentY,
            pkDigest: show.pkDigest,
            nonceHash: show.nonceHash,
            challenge: show.challenge,
            challengeDigest: show.challengeDigest,
            linkTag: show.linkTag,
            proof: stripped,
            vk: show.vk
        )

        XCTAssertThrowsError(
            try verifyOpenACv3(prepare: prepare, show: strippedShow, policy: policy, verifier: verifier)
        ) { err in
            XCTAssertEqual(err as? OpenACV3Error, .nonceHashNotInProof)
        }
    }

    func testOpenACPrepareV3WrapperThrowsWhenFFIUnavailable() throws {
        // The test host does not link the mopro xcframework, so
        // `generateNoirProof` throws a CircuitError. The wrapper must
        // propagate that error rather than swallow it.
        XCTAssertThrowsError(
            try openACPrepareV3(
                circuitPath: "/nonexistent/circuit.json",
                srsPath: nil,
                inputs: [:],
                credentialType: .passport,
                commitment: PedersenPoint(
                    x: Data(repeating: 0x01, count: 32),
                    y: Data(repeating: 0x02, count: 32)
                ),
                pkDigest: Data(repeating: 0x03, count: 32),
                linkRand: Data(repeating: 0x04, count: 32),
                createdAtUnix: 0,
                ttlSeconds: 3600
            )
        )
    }
}

/// Thin CryptoKit facade used by tests to reproduce the package's SHA256 hash.
/// Matches `fileprivate func sha256(_ chunks: [Data])` byte-for-byte for a
/// single-chunk input.
private enum CryptoKitFacade {
    static func sha256(_ data: Data) -> [UInt8] {
        #if canImport(CryptoKit)
        if #available(iOS 13.0, macOS 10.15, *) {
            var hasher = CryptoSHA256()
            hasher.update(data: data)
            return Array(hasher.finalize())
        }
        #endif
        return []
    }
}

#if canImport(CryptoKit)
import CryptoKit
private typealias CryptoSHA256 = SHA256
#else
private struct CryptoSHA256 {
    mutating func update(data: Data) {}
    func finalize() -> [UInt8] { [] }
}
#endif
