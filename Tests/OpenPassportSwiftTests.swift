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
}
