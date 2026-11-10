import XCTest
@testable import SerbianEIDSetup

final class MUPChainTests: XCTestCase {
    func testEmbeddedCertificatesMatchPinnedFingerprints() {
        for c in MUPCertificate.allCases {
            XCTAssertNoThrow(try MUPChain.verifiedDER(c))
        }
    }

    func testTamperedCertificateIsRejected() throws {
        var der = try MUPChain.verifiedDER(.root)
        der[der.count / 2] ^= 0xFF
        XCTAssertThrowsError(try MUPChain.verify(der: der, as: .root)) { error in
            XCTAssertEqual(error as? MUPChainError, .fingerprintMismatch(.root))
        }
    }

    func testMissingResourceIsReported() {
        XCTAssertThrowsError(try MUPChain.verifiedDER(.root, bundle: Bundle(for: MUPChainTests.self))) { error in
            XCTAssertEqual(error as? MUPChainError, .missingResource("MUPRootCA4"))
        }
    }
}
