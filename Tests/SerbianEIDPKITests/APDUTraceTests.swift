import XCTest
@testable import SerbianEIDPKI

final class APDUTraceTests: XCTestCase {
    func testVerifyDataIsMasked() throws {
        let apdu = Commands.verifyPIN(try PaddedPIN("1234"))
        let line = APDUTrace.format(apdu)
        XCTAssertEqual(line, "> 00 20 00 80 08 <PIN masked>")
        XCTAssertFalse(line.contains("31 32 33 34"))
    }

    func testVerifyResponseShowsOnlySW() {
        let apdu = APDU(ins: 0x20, p1: 0, p2: 0x80, data: [1, 2, 3, 4])
        XCTAssertEqual(APDUTrace.format(APDUResponse(data: [0xAA], sw: 0x63C2), for: apdu), "< SW=63C2")
    }

    func testOtherCommandsPrintData() {
        let apdu = APDU(ins: 0xA4, p1: 0, p2: 0, data: [0x3F, 0x00], le: 256)
        XCTAssertEqual(APDUTrace.format(apdu), "> 00 A4 00 00 02 3F 00 00")
        XCTAssertEqual(APDUTrace.format(APDUResponse(data: [1, 2], sw: 0x9000), for: apdu), "< 01 02 SW=9000")
    }
}
