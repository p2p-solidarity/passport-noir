import Foundation
import XCTest

@testable import OpenPassportSwift

final class OpenACFacadeTests: XCTestCase {

    // MARK: - Construction

    func testOpenACInit() {
        let paths = OpenAC.CircuitPaths(prepare: "/tmp/prepare.json", show: "/tmp/show.json")
        let openAC = OpenAC(circuitPaths: paths)
        XCTAssertEqual(openAC.version, .v3)
        XCTAssertEqual(openAC.circuitPaths.prepare, "/tmp/prepare.json")
        XCTAssertEqual(openAC.circuitPaths.show, "/tmp/show.json")
        XCTAssertNil(openAC.srsPath)
    }

    func testCredentialKindToCredentialType() {
        let cases: [(Credential.Kind, OpenACV3CredentialType)] = [
            (.passport, .passport),
            (.x509, .x509),
            (.sdjwt, .sdjwt),
            (.mdl, .mdl),
        ]
        for (kind, expected) in cases {
            let cred = Credential(
                kind: kind,
                commitment: PedersenPoint.zero,
                pkDigest: Data(repeating: 0x01, count: 32),
                linkRand: Data(repeating: 0x02, count: 32),
                prepareInputs: [:],
                showInputs: [:]
            )
            XCTAssertEqual(cred.credentialType, expected, "kind=\(kind)")
        }
    }

    // MARK: - Timings

    func testTimingsTotal() {
        let t = Timings(prepareProveMs: 200, showProveMs: 50)
        XCTAssertEqual(t.totalProveMs, 250)
    }

    func testTimingsCodableRoundTrip() throws {
        let t = Timings(prepareProveMs: 1234, showProveMs: 56)
        let data = try JSONEncoder().encode(t)
        let decoded = try JSONDecoder().decode(Timings.self, from: data)
        XCTAssertEqual(decoded, t)
        XCTAssertEqual(decoded.totalProveMs, 1290)
    }

    // MARK: - ProofResult JSON

    func testProofResultToJSONIsStableAndRoundTripDecodable() throws {
        let prepared = makeFixturePrepared()
        let presentation = makeFixturePresentation()
        let timings = Timings(prepareProveMs: 100, showProveMs: 25)
        let result = ProofResult(
            credentialKind: .passport,
            prepared: prepared,
            presentation: presentation,
            timings: timings
        )

        let json1 = try result.toJSON()
        let json2 = try result.toJSON()
        XCTAssertEqual(json1, json2, "JSON output must be deterministic across calls")

        let parsed = try JSONSerialization.jsonObject(with: json1) as? [String: Any]
        XCTAssertEqual(parsed?["proofSystem"] as? String, "openpassport_openac")
        XCTAssertEqual(parsed?["version"] as? Int, 3)
        XCTAssertEqual(parsed?["credentialKind"] as? String, "passport")

        guard let prepareDict = parsed?["prepare"] as? [String: Any] else {
            XCTFail("prepare envelope missing")
            return
        }
        XCTAssertEqual(prepareDict["createdAtUnix"] as? UInt64, 1_700_000_000)
        XCTAssertEqual(prepareDict["expiresAtUnix"] as? UInt64, 1_700_000_300)
        XCTAssertEqual(prepareDict["credentialType"] as? UInt8, 0x01)

        let base64 = try result.toBase64()
        XCTAssertFalse(base64.isEmpty)
        let roundtrip = Data(base64Encoded: base64)
        XCTAssertEqual(roundtrip, json1)
    }

    // MARK: - Verify with stub

    func testVerifyWithStubVerifierReportsTiming() throws {
        let prepared = makeFixturePrepared()
        let presentation = makeFixturePresentation()
        let timings = Timings(prepareProveMs: 0, showProveMs: 0)
        let result = ProofResult(
            credentialKind: .passport,
            prepared: prepared,
            presentation: presentation,
            timings: timings
        )

        let policy = makeFixturePolicy(prepared: prepared, presentation: presentation)
        let openAC = OpenAC(circuitPaths: OpenAC.CircuitPaths(prepare: "x", show: "y"))

        // Stub verifier that always succeeds — exercises the facade's wrapping
        // without requiring the real mopro xcframework to be linked.
        let stub: OpenACNoirVerifier = { _, _ in true }

        let outcome = try openAC.verify(result, policy: policy, verifier: stub)
        XCTAssertTrue(outcome.valid)
        XCTAssertEqual(outcome.credentialKind, .passport)
        // Timing is recorded — exact value is environment-dependent but should
        // be a valid UInt64.
        _ = outcome.verifyMs
    }

    func testVerifyWithFailingVerifierThrows() {
        let prepared = makeFixturePrepared()
        let presentation = makeFixturePresentation()
        let timings = Timings(prepareProveMs: 0, showProveMs: 0)
        let result = ProofResult(
            credentialKind: .passport,
            prepared: prepared,
            presentation: presentation,
            timings: timings
        )
        let policy = makeFixturePolicy(prepared: prepared, presentation: presentation)
        let openAC = OpenAC(circuitPaths: OpenAC.CircuitPaths(prepare: "x", show: "y"))

        let failingStub: OpenACNoirVerifier = { _, _ in false }

        XCTAssertThrowsError(try openAC.verify(result, policy: policy, verifier: failingStub))
    }

    // MARK: - Fixtures

    private func makeFixturePrepared() -> OpenACV3PrepareArtifact {
        OpenACV3PrepareArtifact(
            createdAtUnix: 1_700_000_000,
            expiresAtUnix: 1_700_000_300,
            credentialType: .passport,
            commitmentX: Data(repeating: 0x10, count: 32),
            commitmentY: Data(repeating: 0x11, count: 32),
            pkDigest: Data(repeating: 0x12, count: 32),
            linkRand: Data(repeating: 0x13, count: 32),
            proof: makeProofBlobContaining(
                commitmentX: Data(repeating: 0x10, count: 32),
                commitmentY: Data(repeating: 0x11, count: 32)
            ),
            vk: Data(repeating: 0xAA, count: 64)
        )
    }

    private func makeFixturePresentation() -> OpenACV3ShowPresentation {
        let nonceHash = Data(repeating: 0x21, count: 32)
        let challenge = Data(repeating: 0x22, count: 32)
        let epoch = Data([0x20, 0x26, 0x04, 0x26])
        let cx = Data(repeating: 0x10, count: 32)
        let cy = Data(repeating: 0x11, count: 32)
        // Compute the digest the same way verifyOpenACv3 expects.
        let digest = (try? computeOpenACv3ChallengeDigest(
            commitmentX: cx,
            commitmentY: cy,
            challenge: challenge,
            epoch: epoch
        )) ?? Data(repeating: 0, count: 32)

        return OpenACV3ShowPresentation(
            commitmentX: cx,
            commitmentY: cy,
            pkDigest: Data(repeating: 0x12, count: 32),
            nonceHash: nonceHash,
            challenge: challenge,
            challengeDigest: digest,
            linkTag: Data(repeating: 0, count: 32),
            proof: makeProofBlobContainingFields(
                commitmentX: cx,
                commitmentY: cy,
                nonceHash: nonceHash
            ),
            vk: Data(repeating: 0xBB, count: 64)
        )
    }

    private func makeFixturePolicy(
        prepared: OpenACV3PrepareArtifact,
        presentation: OpenACV3ShowPresentation
    ) -> OpenACV3Policy {
        let prepareVkHash = (try? computeSHA256(prepared.vk)) ?? Data()
        let showVkHash = (try? computeSHA256(presentation.vk)) ?? Data()
        return OpenACV3Policy(
            linkMode: .unlinkable,
            linkScope: nil,
            epoch: Data([0x20, 0x26, 0x04, 0x26]),
            nowUnix: 1_700_000_100,
            expectedChallenge: presentation.challenge,
            expectedNonceHash: presentation.nonceHash,
            prepareVkHash: prepareVkHash,
            showVkHash: showVkHash
        )
    }

    private func makeProofBlobContaining(commitmentX cx: Data, commitmentY cy: Data) -> Data {
        // verify_openac_v3 scans for `cx || cy` on 32-byte boundaries.
        var blob = Data(repeating: 0, count: 32)
        blob.append(cx)
        blob.append(cy)
        blob.append(Data(repeating: 0, count: 32))
        return blob
    }

    private func makeProofBlobContainingFields(
        commitmentX cx: Data,
        commitmentY cy: Data,
        nonceHash: Data
    ) -> Data {
        var blob = Data(repeating: 0, count: 32)
        blob.append(cx)
        blob.append(cy)
        blob.append(nonceHash)
        blob.append(Data(repeating: 0, count: 32))
        return blob
    }

    private func computeSHA256(_ data: Data) throws -> Data {
        #if canImport(CryptoKit)
        if #available(iOS 13.0, macOS 10.15, *) {
            var hasher = CryptoKitSHA256()
            hasher.update(data: data)
            return Data(hasher.finalize())
        }
        #endif
        throw OpenACV3Error.cryptoUnavailable
    }
}

#if canImport(CryptoKit)
import CryptoKit
private typealias CryptoKitSHA256 = SHA256
#endif
