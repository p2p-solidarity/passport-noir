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
}
