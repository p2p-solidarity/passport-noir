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


    /// Layout helper: matches the synthetic strict-format mock proof built
    /// by `v3FullFixture`. v3Fixture (which exercises only the linking
    /// helper) does not actually use these layouts, but `OpenACV3Policy`
    /// requires them so we provide a sensible default that lines up with
    /// the v3FullFixture mock.
    private func testEmptyPrepareLayout() -> OpenACPrepareLayoutV3 {
        OpenACPrepareLayoutV3(
            numPublicInputs: 2,
            commitmentXIndex: 0,
            commitmentYIndex: 1,
            extraPinnedFields: []
        )
    }

    private func testEmptyShowLayout() -> OpenACShowLayoutV3 {
        OpenACShowLayoutV3(
            numPublicInputs: 35,
            commitmentXIndex: 0,
            commitmentYIndex: 1,
            nonceHashFirstByteIndex: 3,
            extraPinnedFields: []
        )
    }

    func testOpenACShowLayoutPinsChallengeDigestAndLinkTag() {
        let scope = Data(repeating: 0x55, count: 32)
        let epoch = Data([0x20, 0x26, 0x04, 0x28])
        let epochField = Data(repeating: 0x66, count: 32)
        let digest = Data(repeating: 0x77, count: 32)
        let tag = Data(repeating: 0x88, count: 32)

        let layout = OpenACShowLayoutV3.openacShow(
            expectedLinkMode: true,
            expectedLinkScope: scope,
            expectedEpoch: epoch,
            expectedEpochField: epochField,
            expectedChallengeDigest: digest,
            expectedLinkTag: tag
        )

        XCTAssertTrue(layout.extraPinnedFields.contains(OpenACPinnedField(fieldIndex: 33, expected: openACBoolAsField(true))))
        XCTAssertTrue(layout.extraPinnedFields.contains(OpenACPinnedField(fieldIndex: 34, expected: scope)))
        XCTAssertTrue(layout.extraPinnedFields.contains(OpenACPinnedField(fieldIndex: 39, expected: epochField)))
        XCTAssertTrue(layout.extraPinnedFields.contains(OpenACPinnedField(fieldIndex: 80, expected: tag)))
        for pin in openACPinByteArray(baseFieldIndex: 35, bytes: epoch) {
            XCTAssertTrue(layout.extraPinnedFields.contains(pin))
        }
        for pin in openACPinByteArray(baseFieldIndex: 48, bytes: digest) {
            XCTAssertTrue(layout.extraPinnedFields.contains(pin))
        }
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

        // Synthetic strict layouts that match the empty-proof test fixture.
        // Real callers build adapter-specific layouts via the
        // OpenACPrepareLayoutV3.passport/sdjwt/jwtX5c builders.
        let prepareLayout = OpenACPrepareLayoutV3(
            numPublicInputs: 0,
            commitmentXIndex: 0,
            commitmentYIndex: 1,
            extraPinnedFields: []
        )
        let showLayout = OpenACShowLayoutV3(
            numPublicInputs: 0,
            commitmentXIndex: 0,
            commitmentYIndex: 1,
            nonceHashFirstByteIndex: nil,
            extraPinnedFields: []
        )
        let policy = OpenACV3Policy(
            linkMode: linkMode,
            linkScope: linkScope,
            epoch: epoch,
            nowUnix: 150,
            expectedChallenge: challenge,
            expectedNonceHash: nonceHash,
            prepareVkHash: Data(repeating: 0, count: 32),
            showVkHash: Data(repeating: 0, count: 32),
            prepareLayout: prepareLayout,
            showLayout: showLayout
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
            showVkHash: policy.showVkHash,
            prepareLayout: testEmptyPrepareLayout(),
            showLayout: testEmptyShowLayout()
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
            showVkHash: policy.showVkHash,
            prepareLayout: policy.prepareLayout,
            showLayout: policy.showLayout
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
            showVkHash: Data(repeating: 0, count: 32),
            prepareLayout: testEmptyPrepareLayout(),
            showLayout: testEmptyShowLayout()
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

        // Strict-mode mock (Task 1+2 follow-up, 2026-04-28): the proof
        // prefix encodes each public input as a 32-byte BE Field. For the
        // synthetic test fixture we use a small layout matching real Noir
        // ABI semantics:
        //   prepare: [commitmentX | commitmentY | suffix]
        //   show:    [commitmentX | commitmentY | pkDigest | nonceHash[0..32] (each byte a Field) | suffix]
        var prepareProof = Data()
        prepareProof.append(commitmentX)
        prepareProof.append(commitmentY)
        prepareProof.append(Data([10, 20, 30]))

        var showProof = Data()
        showProof.append(commitmentX)
        showProof.append(commitmentY)
        showProof.append(pkDigest)
        for b in nonceHash {
            showProof.append(openACByteAsField(b))
        }
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

        // Layouts that match the strict-format mock above.
        let prepareLayout = OpenACPrepareLayoutV3(
            numPublicInputs: 2,
            commitmentXIndex: 0,
            commitmentYIndex: 1,
            extraPinnedFields: []
        )
        let showLayout = OpenACShowLayoutV3(
            numPublicInputs: 35,
            commitmentXIndex: 0,
            commitmentYIndex: 1,
            nonceHashFirstByteIndex: 3,
            extraPinnedFields: []
        )
        let policy = OpenACV3Policy(
            linkMode: linkMode,
            linkScope: linkScope,
            epoch: epoch,
            nowUnix: 150,
            expectedChallenge: challenge,
            expectedNonceHash: nonceHash,
            prepareVkHash: sha256Hash(prepareVk),
            showVkHash: sha256Hash(showVk),
            prepareLayout: prepareLayout,
            showLayout: showLayout
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
            showVkHash: policy.showVkHash,
            prepareLayout: testEmptyPrepareLayout(),
            showLayout: testEmptyShowLayout()
        )
        XCTAssertThrowsError(
            try verifyOpenACv3(prepare: prepare, show: show, policy: tamperedPolicy, verifier: verifier)
        ) { err in
            XCTAssertEqual(err as? OpenACV3Error, .untrustedPrepareVk)
        }
    }

    func testOpenACv3NonceHashNotInProofRejected() throws {
        let (prepare, show, policy, verifier) = try v3FullFixture()
        // Tamper a byte INSIDE the nonce-hash region (each byte of nonce
        // occupies its own 32-byte Field slot, starting at field index 3
        // == byte offset 96). Flipping the LSB of the field at index 3
        // changes nonce_hash[0] to a different byte, so the strict layout
        // check fires `nonceHashNotInProof`.
        var tampered = show.proof
        let nonceFieldStart = 3 * 32
        tampered[nonceFieldStart + 31] ^= 0x01

        let tamperedShow = OpenACV3ShowPresentation(
            commitmentX: show.commitmentX,
            commitmentY: show.commitmentY,
            pkDigest: show.pkDigest,
            nonceHash: show.nonceHash,
            challenge: show.challenge,
            challengeDigest: show.challengeDigest,
            linkTag: show.linkTag,
            proof: tampered,
            vk: show.vk
        )

        XCTAssertThrowsError(
            try verifyOpenACv3(prepare: prepare, show: tamperedShow, policy: policy, verifier: verifier)
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

    func testOpenACShowV3WrapperThrowsWhenFFIUnavailable() throws {
        // openACShowV3 also has to surface the underlying mopro FFI failure
        // as a thrown error rather than swallowing it (parity with the
        // prepare wrapper coverage above).
        let prepare = OpenACV3PrepareArtifact(
            createdAtUnix: 0,
            expiresAtUnix: 3600,
            credentialType: .passport,
            commitmentX: Data(repeating: 0x01, count: 32),
            commitmentY: Data(repeating: 0x02, count: 32),
            pkDigest: Data(repeating: 0x03, count: 32),
            linkRand: Data(repeating: 0x04, count: 32),
            proof: Data(),
            vk: Data()
        )
        let request = OpenACShowRequest(
            challenge: Data(repeating: 0x05, count: 32),
            linkMode: .scopedLinkable,
            linkScope: Data(repeating: 0x06, count: 32),
            epoch: Data([0x20, 0x26, 0x04, 0x01])
        )
        XCTAssertThrowsError(
            try openACShowV3(
                circuitPath: "/nonexistent/circuit.json",
                srsPath: nil,
                inputs: [:],
                prepare: prepare,
                request: request,
                nonceHash: Data(repeating: 0x07, count: 32),
                linkTag: Data(repeating: 0x08, count: 32)
            )
        )
    }

    // MARK: - OpenAC v1 error coverage

    private func v1Fixture(
        linkMode: OpenACLinkMode = .scopedLinkable,
        nowUnix: UInt64 = 150
    ) throws -> (OpenACPrepareArtifact, OpenACShowPresentation, OpenACShowRequest, UInt64) {
        let sodHash = Data(repeating: 0x12, count: 32)
        let mrzHash = Data(repeating: 0x23, count: 32)
        let linkRandomness = Data(repeating: 0x34, count: 32)
        let epoch = Data([0x20, 0x26, 0x03, 0x15])
        let challenge = Data(repeating: 0x45, count: 32)
        let scope: Data?
        switch linkMode {
        case .scopedLinkable: scope = Data(repeating: 0x56, count: 32)
        case .unlinkable: scope = nil
        }

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
            linkMode: linkMode,
            linkScope: scope,
            epoch: epoch
        )
        let challengeDigest = try computeOpenACChallengeDigest(
            challenge: challenge,
            prepareCommitment: prepareCommitment,
            epoch: epoch
        )
        let linkTag: Data
        switch linkMode {
        case .scopedLinkable:
            linkTag = try computeOpenACScopedLinkTag(
                prepareCommitment: prepareCommitment,
                linkScope: scope!,
                epoch: epoch
            )
        case .unlinkable:
            linkTag = Data(repeating: 0, count: 32)
        }
        let show = OpenACShowPresentation(
            sodHash: sodHash,
            mrzHash: mrzHash,
            prepareCommitment: prepareCommitment,
            challenge: challenge,
            challengeDigest: challengeDigest,
            linkTag: linkTag
        )
        return (prepare, show, request, nowUnix)
    }

    func testOpenACPrepareCommitmentRejectsBadLength() {
        // Length validation is the first defence; any mis-sized field must
        // throw `invalidLength` rather than silently truncate or hash garbage.
        XCTAssertThrowsError(
            try computeOpenACPrepareCommitment(
                sodHash: Data(repeating: 0, count: 31),
                mrzHash: Data(repeating: 0, count: 32),
                linkRandomness: Data(repeating: 0, count: 32)
            )
        ) { err in
            if case let OpenACError.invalidLength(field, expected, actual) = err {
                XCTAssertEqual(field, "sodHash")
                XCTAssertEqual(expected, 32)
                XCTAssertEqual(actual, 31)
            } else {
                XCTFail("Expected OpenACError.invalidLength, got \(err)")
            }
        }
    }

    func testOpenACChallengeDigestRequiresFourByteEpoch() {
        let prepareCommitment = Data(repeating: 0x10, count: 32)
        XCTAssertThrowsError(
            try computeOpenACChallengeDigest(
                challenge: Data(repeating: 0x20, count: 32),
                prepareCommitment: prepareCommitment,
                epoch: Data([0x01, 0x02, 0x03])
            )
        ) { err in
            if case let OpenACError.invalidLength(field, expected, _) = err {
                XCTAssertEqual(field, "epoch")
                XCTAssertEqual(expected, 4)
            } else {
                XCTFail("Expected OpenACError.invalidLength for epoch, got \(err)")
            }
        }
    }

    func testOpenACScopedLinkTagRejectsBadScope() {
        XCTAssertThrowsError(
            try computeOpenACScopedLinkTag(
                prepareCommitment: Data(repeating: 0x10, count: 32),
                linkScope: Data(repeating: 0x20, count: 16),
                epoch: Data([0x20, 0x26, 0x03, 0x15])
            )
        ) { err in
            if case let OpenACError.invalidLength(field, _, _) = err {
                XCTAssertEqual(field, "linkScope")
            } else {
                XCTFail("Expected invalidLength for linkScope, got \(err)")
            }
        }
    }

    func testOpenACVerifyRejectsPrepareNotActive() throws {
        let (prepare, show, request, _) = try v1Fixture()
        XCTAssertThrowsError(
            try verifyOpenACLinking(prepare: prepare, show: show, request: request, nowUnix: 50)
        ) { err in
            XCTAssertEqual(err as? OpenACError, .prepareNotActive)
        }
    }

    func testOpenACVerifyRejectsExpiredPrepare() throws {
        let (prepare, show, request, _) = try v1Fixture()
        XCTAssertThrowsError(
            try verifyOpenACLinking(prepare: prepare, show: show, request: request, nowUnix: 500)
        ) { err in
            XCTAssertEqual(err as? OpenACError, .expiredPrepare)
        }
    }

    func testOpenACVerifyRejectsLinkMismatch() throws {
        let (prepare, show, request, now) = try v1Fixture()
        let tampered = OpenACShowPresentation(
            sodHash: show.sodHash,
            mrzHash: show.mrzHash,
            prepareCommitment: Data(repeating: 0xAB, count: 32),
            challenge: show.challenge,
            challengeDigest: show.challengeDigest,
            linkTag: show.linkTag
        )
        XCTAssertThrowsError(
            try verifyOpenACLinking(prepare: prepare, show: tampered, request: request, nowUnix: now)
        ) { err in
            XCTAssertEqual(err as? OpenACError, .linkMismatch)
        }
    }

    func testOpenACVerifyRejectsSodHashMismatch() throws {
        let (prepare, show, request, now) = try v1Fixture()
        let tampered = OpenACShowPresentation(
            sodHash: Data(repeating: 0xFF, count: 32),
            mrzHash: show.mrzHash,
            prepareCommitment: show.prepareCommitment,
            challenge: show.challenge,
            challengeDigest: show.challengeDigest,
            linkTag: show.linkTag
        )
        XCTAssertThrowsError(
            try verifyOpenACLinking(prepare: prepare, show: tampered, request: request, nowUnix: now)
        ) { err in
            XCTAssertEqual(err as? OpenACError, .sodHashMismatch)
        }
    }

    func testOpenACVerifyRejectsMrzHashMismatch() throws {
        let (prepare, show, request, now) = try v1Fixture()
        let tampered = OpenACShowPresentation(
            sodHash: show.sodHash,
            mrzHash: Data(repeating: 0xFE, count: 32),
            prepareCommitment: show.prepareCommitment,
            challenge: show.challenge,
            challengeDigest: show.challengeDigest,
            linkTag: show.linkTag
        )
        XCTAssertThrowsError(
            try verifyOpenACLinking(prepare: prepare, show: tampered, request: request, nowUnix: now)
        ) { err in
            XCTAssertEqual(err as? OpenACError, .mrzHashMismatch)
        }
    }

    func testOpenACVerifyRejectsInvalidChallenge() throws {
        let (prepare, show, request, now) = try v1Fixture()
        let tampered = OpenACShowPresentation(
            sodHash: show.sodHash,
            mrzHash: show.mrzHash,
            prepareCommitment: show.prepareCommitment,
            challenge: show.challenge,
            challengeDigest: Data(repeating: 0xCC, count: 32),
            linkTag: show.linkTag
        )
        XCTAssertThrowsError(
            try verifyOpenACLinking(prepare: prepare, show: tampered, request: request, nowUnix: now)
        ) { err in
            XCTAssertEqual(err as? OpenACError, .invalidChallenge)
        }
    }

    func testOpenACVerifyUnlinkableHappyPath() throws {
        let (prepare, show, request, now) = try v1Fixture(linkMode: .unlinkable)
        XCTAssertTrue(try verifyOpenACLinking(prepare: prepare, show: show, request: request, nowUnix: now))
    }

    func testOpenACVerifyUnlinkableRejectsNonZeroTag() throws {
        let (prepare, _, request, now) = try v1Fixture(linkMode: .unlinkable)
        let badShow = OpenACShowPresentation(
            sodHash: prepare.sodHash,
            mrzHash: prepare.mrzHash,
            prepareCommitment: prepare.prepareCommitment,
            challenge: request.challenge,
            challengeDigest: try computeOpenACChallengeDigest(
                challenge: request.challenge,
                prepareCommitment: prepare.prepareCommitment,
                epoch: request.epoch
            ),
            linkTag: Data(repeating: 0xAA, count: 32) // unlinkable mode requires zero
        )
        XCTAssertThrowsError(
            try verifyOpenACLinking(prepare: prepare, show: badShow, request: request, nowUnix: now)
        ) { err in
            XCTAssertEqual(err as? OpenACError, .scopeMismatch)
        }
    }

    func testOpenACShowFunctionRejectsScopedWithoutScope() throws {
        // The high-level openACShow helper should refuse scoped-linkable mode
        // when the request omits a linkScope; otherwise the resulting tag
        // would be silently zero and indistinguishable from unlinkable mode.
        let sodHash = Data(repeating: 0x12, count: 32)
        let mrzHash = Data(repeating: 0x23, count: 32)
        let linkRandomness = Data(repeating: 0x34, count: 32)
        let epoch = Data([0x20, 0x26, 0x03, 0x15])
        let challenge = Data(repeating: 0x45, count: 32)
        let prepareCommitment = try computeOpenACPrepareCommitment(
            sodHash: sodHash,
            mrzHash: mrzHash,
            linkRandomness: linkRandomness
        )
        let prepare = OpenACPrepareArtifact(
            createdAtUnix: 0,
            expiresAtUnix: 1000,
            sodHash: sodHash,
            mrzHash: mrzHash,
            prepareCommitment: prepareCommitment
        )
        let request = OpenACShowRequest(
            challenge: challenge,
            linkMode: .scopedLinkable,
            linkScope: nil,
            epoch: epoch
        )
        XCTAssertThrowsError(
            try openACShow(
                circuitPath: "/nonexistent/circuit.json",
                srsPath: nil,
                inputs: [:],
                prepareArtifact: prepare,
                request: request,
                sodHash: sodHash,
                mrzHash: mrzHash
            )
        ) { err in
            // Either scopeMismatch (caught before FFI) or whatever the FFI
            // throws — but scopeMismatch should hit first.
            XCTAssertEqual(err as? OpenACError, .scopeMismatch)
        }
    }

    func testOpenACEnvelopeRoundTrip() {
        let envelope = makeOpenACEnvelope(
            phase: .prepare,
            challenge: nil,
            linkMode: .unlinkable,
            linkScope: nil,
            linkTag: nil,
            prepareCommitment: Data(repeating: 0x55, count: 32),
            publicOutputs: ["age_over_18": "true"],
            proofPayload: Data([0xDE, 0xAD, 0xBE, 0xEF])
        )
        XCTAssertEqual(envelope.proofSystem, "openpassport_openac")
        XCTAssertEqual(envelope.phase, .prepare)
        XCTAssertEqual(envelope.publicOutputs["age_over_18"], "true")
        XCTAssertEqual(envelope.proofPayload, Data([0xDE, 0xAD, 0xBE, 0xEF]))
    }

    // MARK: - OpenAC v2 — additional coverage

    func testOpenACv2HappyPathUnlinkable() throws {
        let (prepare, show, policy, verifier) = try v2Fixture(linkMode: .unlinkable)
        XCTAssertTrue(try verifyOpenACv2(prepare: prepare, show: show, policy: policy, verifier: verifier))
    }

    func testOpenACv2EmptyPrepareBundleRejected() throws {
        let (prepare, show, policy, verifier) = try v2Fixture()
        let stripped = OpenACV2PrepareArtifact(
            createdAtUnix: prepare.createdAtUnix,
            expiresAtUnix: prepare.expiresAtUnix,
            credentialType: prepare.credentialType,
            commitment: prepare.commitment,
            linkRand: prepare.linkRand,
            proof: Data(),
            vk: prepare.vk
        )
        XCTAssertThrowsError(
            try verifyOpenACv2(prepare: stripped, show: show, policy: policy, verifier: verifier)
        ) { err in
            XCTAssertEqual(err as? OpenACV2Error, .emptyPrepareBundle)
        }
    }

    func testOpenACv2EmptyShowBundleRejected() throws {
        let (prepare, show, policy, verifier) = try v2Fixture()
        let stripped = OpenACV2ShowPresentation(
            commitment: show.commitment,
            challenge: show.challenge,
            challengeDigest: show.challengeDigest,
            linkTag: show.linkTag,
            proof: Data(),
            vk: show.vk
        )
        XCTAssertThrowsError(
            try verifyOpenACv2(prepare: prepare, show: stripped, policy: policy, verifier: verifier)
        ) { err in
            XCTAssertEqual(err as? OpenACV2Error, .emptyShowBundle)
        }
    }

    func testOpenACv2InvalidPrepareProofRejected() throws {
        let (prepare, show, policy, _) = try v2Fixture()
        let alwaysFalse: OpenACNoirVerifier = { _, _ in false }
        XCTAssertThrowsError(
            try verifyOpenACv2(prepare: prepare, show: show, policy: policy, verifier: alwaysFalse)
        ) { err in
            XCTAssertEqual(err as? OpenACV2Error, .invalidPrepareProof)
        }
    }

    func testOpenACv2InvalidShowProofRejected() throws {
        let (prepare, show, policy, _) = try v2Fixture()
        // Pass prepare, fail show (matching how the runtime behaves when
        // the show circuit's proof fails verification mid-flow).
        var calls = 0
        let verifier: OpenACNoirVerifier = { _, _ in
            calls += 1
            return calls == 1
        }
        XCTAssertThrowsError(
            try verifyOpenACv2(prepare: prepare, show: show, policy: policy, verifier: verifier)
        ) { err in
            XCTAssertEqual(err as? OpenACV2Error, .invalidShowProof)
        }
    }

    func testOpenACv2PrepareCommitmentNotInProofRejected() throws {
        let (_, show, policy, verifier) = try v2Fixture()
        let other = v2SampleCommitment(seed: 99)
        // Build a prepare bundle whose proof does not contain its declared
        // commitment — exposes the field-scan defense layer.
        let prepareProof = Data([1, 2, 3, 4]) + Data(repeating: 0xFF, count: 60)
        let prepare = OpenACV2PrepareArtifact(
            createdAtUnix: 100,
            expiresAtUnix: 200,
            credentialType: .passport,
            commitment: other,
            linkRand: Data(repeating: 0x33, count: 32),
            proof: prepareProof,
            vk: Data([1, 2, 3])
        )
        let mutatedPolicy = OpenACV2Policy(
            linkMode: policy.linkMode,
            linkScope: policy.linkScope,
            epoch: policy.epoch,
            epochField: policy.epochField,
            nowUnix: policy.nowUnix,
            expectedChallenge: policy.expectedChallenge,
            prepareVkHash: sha256Hash(prepare.vk),
            showVkHash: policy.showVkHash
        )
        XCTAssertThrowsError(
            try verifyOpenACv2(prepare: prepare, show: show, policy: mutatedPolicy, verifier: verifier)
        ) { err in
            XCTAssertEqual(err as? OpenACV2Error, .prepareCommitmentNotInProof)
        }
    }

    func testOpenACv2InvalidChallengeRejected() throws {
        let (prepare, show, policy, verifier) = try v2Fixture()
        let mutated = OpenACV2Policy(
            linkMode: policy.linkMode,
            linkScope: policy.linkScope,
            epoch: policy.epoch,
            epochField: policy.epochField,
            nowUnix: policy.nowUnix,
            expectedChallenge: Data(repeating: 0xFE, count: 32),
            prepareVkHash: policy.prepareVkHash,
            showVkHash: policy.showVkHash
        )
        XCTAssertThrowsError(
            try verifyOpenACv2(prepare: prepare, show: show, policy: mutated, verifier: verifier)
        ) { err in
            XCTAssertEqual(err as? OpenACV2Error, .invalidChallenge)
        }
    }

    func testOpenACv2InvalidChallengeDigestRejected() throws {
        let (prepare, show, policy, verifier) = try v2Fixture()
        let badShow = OpenACV2ShowPresentation(
            commitment: show.commitment,
            challenge: show.challenge,
            challengeDigest: Data(repeating: 0x00, count: 32),
            linkTag: show.linkTag,
            proof: show.proof,
            vk: show.vk
        )
        XCTAssertThrowsError(
            try verifyOpenACv2(prepare: prepare, show: badShow, policy: policy, verifier: verifier)
        ) { err in
            XCTAssertEqual(err as? OpenACV2Error, .invalidChallengeDigest)
        }
    }

    func testOpenACv2UntrustedShowVkRejected() throws {
        let (prepare, show, policy, verifier) = try v2Fixture()
        let mutated = OpenACV2Policy(
            linkMode: policy.linkMode,
            linkScope: policy.linkScope,
            epoch: policy.epoch,
            epochField: policy.epochField,
            nowUnix: policy.nowUnix,
            expectedChallenge: policy.expectedChallenge,
            prepareVkHash: policy.prepareVkHash,
            showVkHash: Data(repeating: 0xAA, count: 32)
        )
        XCTAssertThrowsError(
            try verifyOpenACv2(prepare: prepare, show: show, policy: mutated, verifier: verifier)
        ) { err in
            XCTAssertEqual(err as? OpenACV2Error, .untrustedShowVk)
        }
    }

    func testOpenACv2PrepareNotActiveRejected() throws {
        let (prepare, show, policy, verifier) = try v2Fixture()
        let earlyPolicy = OpenACV2Policy(
            linkMode: policy.linkMode,
            linkScope: policy.linkScope,
            epoch: policy.epoch,
            epochField: policy.epochField,
            nowUnix: 0,
            expectedChallenge: policy.expectedChallenge,
            prepareVkHash: policy.prepareVkHash,
            showVkHash: policy.showVkHash
        )
        XCTAssertThrowsError(
            try verifyOpenACv2(prepare: prepare, show: show, policy: earlyPolicy, verifier: verifier)
        ) { err in
            XCTAssertEqual(err as? OpenACV2Error, .prepareNotActive)
        }
    }

    func testOpenACv2ScopedLinkableWithoutScopeRejected() throws {
        let (prepare, show, _, verifier) = try v2Fixture(linkMode: .scopedLinkable)
        let invalidPolicy = OpenACV2Policy(
            linkMode: .scopedLinkable,
            linkScope: nil,
            epoch: Data([0x20, 0x26, 0x04, 0x01]),
            epochField: Data(repeating: 0x20, count: 32),
            nowUnix: 150,
            expectedChallenge: show.challenge,
            prepareVkHash: sha256Hash(prepare.vk),
            showVkHash: sha256Hash(show.vk)
        )
        XCTAssertThrowsError(
            try verifyOpenACv2(prepare: prepare, show: show, policy: invalidPolicy, verifier: verifier)
        ) { err in
            XCTAssertEqual(err as? OpenACV2Error, .scopeMismatch)
        }
    }

    // MARK: - OpenAC v3 — additional coverage

    func testOpenACv3PrepareNotActiveRejected() throws {
        let (prepare, show, policy, verifier) = try v3FullFixture()
        let earlyPolicy = OpenACV3Policy(
            linkMode: policy.linkMode,
            linkScope: policy.linkScope,
            epoch: policy.epoch,
            nowUnix: 0,
            expectedChallenge: policy.expectedChallenge,
            expectedNonceHash: policy.expectedNonceHash,
            prepareVkHash: policy.prepareVkHash,
            showVkHash: policy.showVkHash,
            prepareLayout: policy.prepareLayout,
            showLayout: policy.showLayout
        )
        XCTAssertThrowsError(
            try verifyOpenACv3(prepare: prepare, show: show, policy: earlyPolicy, verifier: verifier)
        ) { err in
            XCTAssertEqual(err as? OpenACV3Error, .prepareNotActive)
        }
    }

    func testOpenACv3ExpiredPrepareRejected() throws {
        let (prepare, show, policy, verifier) = try v3FullFixture()
        let latePolicy = OpenACV3Policy(
            linkMode: policy.linkMode,
            linkScope: policy.linkScope,
            epoch: policy.epoch,
            nowUnix: 5_000,
            expectedChallenge: policy.expectedChallenge,
            expectedNonceHash: policy.expectedNonceHash,
            prepareVkHash: policy.prepareVkHash,
            showVkHash: policy.showVkHash,
            prepareLayout: policy.prepareLayout,
            showLayout: policy.showLayout
        )
        XCTAssertThrowsError(
            try verifyOpenACv3(prepare: prepare, show: show, policy: latePolicy, verifier: verifier)
        ) { err in
            XCTAssertEqual(err as? OpenACV3Error, .expiredPrepare)
        }
    }

    func testOpenACv3UntrustedShowVkRejected() throws {
        let (prepare, show, policy, verifier) = try v3FullFixture()
        let mutated = OpenACV3Policy(
            linkMode: policy.linkMode,
            linkScope: policy.linkScope,
            epoch: policy.epoch,
            nowUnix: policy.nowUnix,
            expectedChallenge: policy.expectedChallenge,
            expectedNonceHash: policy.expectedNonceHash,
            prepareVkHash: policy.prepareVkHash,
            showVkHash: Data(repeating: 0xCD, count: 32),
            prepareLayout: testEmptyPrepareLayout(),
            showLayout: testEmptyShowLayout()
        )
        XCTAssertThrowsError(
            try verifyOpenACv3(prepare: prepare, show: show, policy: mutated, verifier: verifier)
        ) { err in
            XCTAssertEqual(err as? OpenACV3Error, .untrustedShowVk)
        }
    }

    func testOpenACv3EmptyPrepareBundleRejected() throws {
        let (prepare, show, policy, verifier) = try v3FullFixture()
        let stripped = OpenACV3PrepareArtifact(
            createdAtUnix: prepare.createdAtUnix,
            expiresAtUnix: prepare.expiresAtUnix,
            credentialType: prepare.credentialType,
            commitmentX: prepare.commitmentX,
            commitmentY: prepare.commitmentY,
            pkDigest: prepare.pkDigest,
            linkRand: prepare.linkRand,
            proof: Data(),
            vk: prepare.vk
        )
        XCTAssertThrowsError(
            try verifyOpenACv3(prepare: stripped, show: show, policy: policy, verifier: verifier)
        ) { err in
            XCTAssertEqual(err as? OpenACV3Error, .emptyPrepareBundle)
        }
    }

    func testOpenACv3EmptyShowBundleRejected() throws {
        let (prepare, show, policy, verifier) = try v3FullFixture()
        let stripped = OpenACV3ShowPresentation(
            commitmentX: show.commitmentX,
            commitmentY: show.commitmentY,
            pkDigest: show.pkDigest,
            nonceHash: show.nonceHash,
            challenge: show.challenge,
            challengeDigest: show.challengeDigest,
            linkTag: show.linkTag,
            proof: Data(),
            vk: show.vk
        )
        XCTAssertThrowsError(
            try verifyOpenACv3(prepare: prepare, show: stripped, policy: policy, verifier: verifier)
        ) { err in
            XCTAssertEqual(err as? OpenACV3Error, .emptyShowBundle)
        }
    }

    func testOpenACv3InvalidPrepareProofRejected() throws {
        let (prepare, show, policy, _) = try v3FullFixture()
        let alwaysFalse: OpenACNoirVerifier = { _, _ in false }
        XCTAssertThrowsError(
            try verifyOpenACv3(prepare: prepare, show: show, policy: policy, verifier: alwaysFalse)
        ) { err in
            XCTAssertEqual(err as? OpenACV3Error, .invalidPrepareProof)
        }
    }

    func testOpenACv3InvalidShowProofRejected() throws {
        let (prepare, show, policy, _) = try v3FullFixture()
        var calls = 0
        let verifier: OpenACNoirVerifier = { _, _ in
            calls += 1
            return calls == 1 // first (prepare) ok, second (show) fails
        }
        XCTAssertThrowsError(
            try verifyOpenACv3(prepare: prepare, show: show, policy: policy, verifier: verifier)
        ) { err in
            XCTAssertEqual(err as? OpenACV3Error, .invalidShowProof)
        }
    }

    func testOpenACv3PrepareCommitmentNotInProofRejected() throws {
        let (prepare, show, policy, verifier) = try v3FullFixture()
        // Strict layout (Task 1+2 follow-up): tamper the commitment.x slot
        // bytes inside the prepare proof so the ABI-known field index 0
        // no longer matches the prepare.commitment.x. This is the precise
        // analog of the legacy "scan miss" -- now caught at the exact
        // ABI position rather than anywhere in the proof bytes.
        var tampered = prepare.proof
        tampered[0] ^= 0x01
        let tamperedPrepare = OpenACV3PrepareArtifact(
            createdAtUnix: prepare.createdAtUnix,
            expiresAtUnix: prepare.expiresAtUnix,
            credentialType: prepare.credentialType,
            commitmentX: prepare.commitmentX,
            commitmentY: prepare.commitmentY,
            pkDigest: prepare.pkDigest,
            linkRand: prepare.linkRand,
            proof: tampered,
            vk: prepare.vk
        )
        XCTAssertThrowsError(
            try verifyOpenACv3(prepare: tamperedPrepare, show: show, policy: policy, verifier: verifier)
        ) { err in
            XCTAssertEqual(err as? OpenACV3Error, .prepareCommitmentNotInProof)
        }
    }

    func testOpenACv3ShowCommitmentNotInProofRejected() throws {
        let (prepare, show, policy, verifier) = try v3FullFixture()
        // Strict layout: tamper the commitment.x slot inside the show
        // proof. The ABI-known field index 0 no longer holds the value
        // the verifier expects, so the strict check fires.
        var tampered = show.proof
        tampered[0] ^= 0x01
        let tamperedShow = OpenACV3ShowPresentation(
            commitmentX: show.commitmentX,
            commitmentY: show.commitmentY,
            pkDigest: show.pkDigest,
            nonceHash: show.nonceHash,
            challenge: show.challenge,
            challengeDigest: show.challengeDigest,
            linkTag: show.linkTag,
            proof: tampered,
            vk: show.vk
        )
        XCTAssertThrowsError(
            try verifyOpenACv3(prepare: prepare, show: tamperedShow, policy: policy, verifier: verifier)
        ) { err in
            XCTAssertEqual(err as? OpenACV3Error, .showCommitmentNotInProof)
        }
    }

    func testOpenACv3InvalidChallengeRejected() throws {
        let (prepare, show, policy, verifier) = try v3FullFixture()
        let mutated = OpenACV3Policy(
            linkMode: policy.linkMode,
            linkScope: policy.linkScope,
            epoch: policy.epoch,
            nowUnix: policy.nowUnix,
            expectedChallenge: Data(repeating: 0xFA, count: 32),
            expectedNonceHash: policy.expectedNonceHash,
            prepareVkHash: policy.prepareVkHash,
            showVkHash: policy.showVkHash,
            prepareLayout: testEmptyPrepareLayout(),
            showLayout: testEmptyShowLayout()
        )
        XCTAssertThrowsError(
            try verifyOpenACv3(prepare: prepare, show: show, policy: mutated, verifier: verifier)
        ) { err in
            XCTAssertEqual(err as? OpenACV3Error, .invalidChallenge)
        }
    }

    func testOpenACv3InvalidChallengeDigestRejected() throws {
        let (prepare, show, policy, verifier) = try v3FullFixture()
        let badShow = OpenACV3ShowPresentation(
            commitmentX: show.commitmentX,
            commitmentY: show.commitmentY,
            pkDigest: show.pkDigest,
            nonceHash: show.nonceHash,
            challenge: show.challenge,
            challengeDigest: Data(repeating: 0x77, count: 32),
            linkTag: show.linkTag,
            proof: show.proof,
            vk: show.vk
        )
        XCTAssertThrowsError(
            try verifyOpenACv3(prepare: prepare, show: badShow, policy: policy, verifier: verifier)
        ) { err in
            XCTAssertEqual(err as? OpenACV3Error, .invalidChallengeDigest)
        }
    }

    func testOpenACv3UnlinkableHappyPath() throws {
        let (prepare, show, policy, verifier) = try v3FullFixture(linkMode: .unlinkable)
        XCTAssertTrue(
            try verifyOpenACv3(prepare: prepare, show: show, policy: policy, verifier: verifier)
        )
    }

    func testOpenACv3UnlinkableNonZeroTagRejected() throws {
        let (prepare, show, _, verifier) = try v3FullFixture(linkMode: .scopedLinkable)
        let unlinkablePolicy = OpenACV3Policy(
            linkMode: .unlinkable,
            linkScope: nil,
            epoch: Data([0x20, 0x26, 0x04, 0x01]),
            nowUnix: 150,
            expectedChallenge: show.challenge,
            expectedNonceHash: show.nonceHash,
            prepareVkHash: sha256Hash(prepare.vk),
            showVkHash: sha256Hash(show.vk),
            prepareLayout: testEmptyPrepareLayout(),
            showLayout: testEmptyShowLayout()
        )
        XCTAssertThrowsError(
            try verifyOpenACv3(prepare: prepare, show: show, policy: unlinkablePolicy, verifier: verifier)
        ) { err in
            XCTAssertEqual(err as? OpenACV3Error, .scopeMismatch)
        }
    }

    func testOpenACv3ScopedLinkableMissingScopeRejected() throws {
        let (prepare, show, _, verifier) = try v3FullFixture(linkMode: .scopedLinkable)
        let invalidPolicy = OpenACV3Policy(
            linkMode: .scopedLinkable,
            linkScope: nil,
            epoch: Data([0x20, 0x26, 0x04, 0x01]),
            nowUnix: 150,
            expectedChallenge: show.challenge,
            expectedNonceHash: show.nonceHash,
            prepareVkHash: sha256Hash(prepare.vk),
            showVkHash: sha256Hash(show.vk),
            prepareLayout: testEmptyPrepareLayout(),
            showLayout: testEmptyShowLayout()
        )
        XCTAssertThrowsError(
            try verifyOpenACv3(prepare: prepare, show: show, policy: invalidPolicy, verifier: verifier)
        ) { err in
            XCTAssertEqual(err as? OpenACV3Error, .scopeMismatch)
        }
    }

    func testOpenACv3ScopedLinkableZeroTagRejected() throws {
        let (prepare, show, policy, verifier) = try v3FullFixture(linkMode: .scopedLinkable)
        let badShow = OpenACV3ShowPresentation(
            commitmentX: show.commitmentX,
            commitmentY: show.commitmentY,
            pkDigest: show.pkDigest,
            nonceHash: show.nonceHash,
            challenge: show.challenge,
            challengeDigest: show.challengeDigest,
            linkTag: Data(repeating: 0, count: 32),
            proof: show.proof,
            vk: show.vk
        )
        XCTAssertThrowsError(
            try verifyOpenACv3(prepare: prepare, show: badShow, policy: policy, verifier: verifier)
        ) { err in
            XCTAssertEqual(err as? OpenACV3Error, .scopeMismatch)
        }
    }

    func testOpenACv3LinkingHappyPathBoundaryNow() throws {
        // Boundary test: nowUnix exactly equal to expiresAtUnix is still
        // active (the check is `>` not `>=`). A regression here would
        // expire credentials a second early.
        let (prepare, show, policy) = try v3Fixture()
        let boundaryPolicy = OpenACV3Policy(
            linkMode: policy.linkMode,
            linkScope: policy.linkScope,
            epoch: policy.epoch,
            nowUnix: prepare.expiresAtUnix,
            expectedChallenge: policy.expectedChallenge,
            expectedNonceHash: policy.expectedNonceHash,
            prepareVkHash: policy.prepareVkHash,
            showVkHash: policy.showVkHash,
            prepareLayout: policy.prepareLayout,
            showLayout: policy.showLayout
        )
        XCTAssertTrue(
            try verifyOpenAcV3Linking(prepare: prepare, show: show, policy: boundaryPolicy)
        )
    }

    func testOpenACv3ChallengeDigestSensitiveToEpoch() throws {
        let cx = Data(repeating: 0x10, count: 32)
        let cy = Data(repeating: 0x20, count: 32)
        let challenge = Data(repeating: 0x30, count: 32)
        let d1 = try computeOpenACv3ChallengeDigest(
            commitmentX: cx,
            commitmentY: cy,
            challenge: challenge,
            epoch: Data([0x20, 0x26, 0x04, 0x01])
        )
        let d2 = try computeOpenACv3ChallengeDigest(
            commitmentX: cx,
            commitmentY: cy,
            challenge: challenge,
            epoch: Data([0x20, 0x26, 0x04, 0x02])
        )
        XCTAssertNotEqual(d1, d2)
    }

    func testOpenACv3ChallengeDigestRejectsWrongLength() {
        XCTAssertThrowsError(
            try computeOpenACv3ChallengeDigest(
                commitmentX: Data(repeating: 0, count: 31),
                commitmentY: Data(repeating: 0, count: 32),
                challenge: Data(repeating: 0, count: 32),
                epoch: Data([0, 0, 0, 0])
            )
        ) { err in
            if case let OpenACError.invalidLength(field, _, _) = err {
                XCTAssertEqual(field, "commitmentX")
            } else {
                XCTFail("Expected OpenACError.invalidLength, got \(err)")
            }
        }
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
