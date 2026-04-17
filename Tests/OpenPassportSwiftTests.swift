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
            linkRand: linkRand
        )

        let show = OpenACV3ShowPresentation(
            commitmentX: commitmentX,
            commitmentY: commitmentY,
            pkDigest: pkDigest,
            nonceHash: nonceHash,
            challenge: challenge,
            challengeDigest: digest,
            linkTag: linkTag
        )

        let policy = OpenACV3Policy(
            linkMode: linkMode,
            linkScope: linkScope,
            epoch: epoch,
            nowUnix: 150,
            expectedChallenge: challenge,
            expectedNonceHash: nonceHash
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
            linkTag: show.linkTag
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
            linkTag: show.linkTag
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
            expectedNonceHash: Data(repeating: 0x00, count: 32)
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
            expectedNonceHash: policy.expectedNonceHash
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
            expectedNonceHash: show.nonceHash
        )
        XCTAssertThrowsError(
            try verifyOpenAcV3Linking(prepare: prepare, show: show, policy: unlinkablePolicy)
        ) { err in
            XCTAssertEqual(err as? OpenACV3Error, .scopeMismatch)
        }
    }
}
