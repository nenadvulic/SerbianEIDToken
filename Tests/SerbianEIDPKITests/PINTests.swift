import XCTest
@testable import SerbianEIDPKI

final class PINTests: XCTestCase {
    func testPadding() throws {
        XCTAssertEqual(try PaddedPIN("1234").bytes, [0x31, 0x32, 0x33, 0x34, 0, 0, 0, 0])
        XCTAssertEqual(try PaddedPIN("12345678").bytes, Array("12345678".utf8))
    }

    func testInvalidPIN() {
        for bad in ["123", "123456789", "12a4"] {
            let mock = MockTransport()
            let card = PKICard(transport: mock)
            XCTAssertThrowsError(try card.verifyPIN(bad)) { error in
                guard case APDUError.malformed = error else {
                    return XCTFail("expected malformed, got \(error)")
                }
            }
            XCTAssertTrue(mock.sent.isEmpty)
        }
    }

    func testStatusMapping() {
        XCTAssertEqual(PINResult.from(sw: 0x9000), .ok)
        XCTAssertEqual(PINResult.from(sw: 0x63C2), .wrong(retriesLeft: 2))
        XCTAssertEqual(PINResult.from(sw: 0x63C0), .blocked)
        XCTAssertEqual(PINResult.from(sw: 0x6983), .blocked)
        XCTAssertEqual(PINResult.from(sw: 0x6A80), .wrong(retriesLeft: nil))
    }

    func testVerifyApduShape() throws {
        let apdu = Commands.verifyPIN(try PaddedPIN("1234"))
        XCTAssertEqual(apdu.bytes, [0x00, 0x20, 0x00, 0x80, 0x08, 0x31, 0x32, 0x33, 0x34, 0, 0, 0, 0])
        XCTAssertEqual(Array(apdu.bytes.prefix(5)), PaddedPIN.verifyTemplate)
    }

    func testVerifySendsOnce() throws {
        let mock = MockTransport(script: [(expected: nil, response: APDUResponse(data: [], sw: 0x63C2))])
        let result = try PKICard(transport: mock).verifyPIN("1234")
        XCTAssertEqual(result, .wrong(retriesLeft: 2))
        XCTAssertEqual(mock.sent.count, 1)
        XCTAssertEqual(mock.sent[0].ins, 0x20)
    }
}
