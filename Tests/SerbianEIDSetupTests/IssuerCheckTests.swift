import XCTest
@testable import SerbianEIDSetup

final class IssuerCheckTests: XCTestCase {
    func testLeafIssuedByCA() {
        XCTAssertTrue(IssuerCheck.isIssued(SetupFixtures.fakeLeaf, by: SetupFixtures.fakeCA))
    }

    func testSelfSignedLeafNotIssuedByCA() {
        XCTAssertFalse(IssuerCheck.isIssued(SetupFixtures.selfSignedLeaf, by: SetupFixtures.fakeCA))
    }

    func testGarbageIsNotIssued() {
        XCTAssertFalse(IssuerCheck.isIssued(Data([0x30, 0x00]), by: SetupFixtures.fakeCA))
    }

    func testFakeLeafIsNotIssuedByMUPGradjaniCA4() {
        XCTAssertFalse(IssuerCheck.isIssuedByMUPGradjaniCA4(SetupFixtures.fakeLeaf))
    }
}
