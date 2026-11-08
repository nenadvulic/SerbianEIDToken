import XCTest
@testable import SerbianEIDPKI

final class SigningTests: XCTestCase {
    private let fid: [UInt8] = [0x60, 0x05]

    func testSignDigestInfoAPDUs() throws {
        let di = [UInt8](repeating: 0xAB, count: 51)
        let sig = [UInt8](repeating: 0xCD, count: 256)
        let mock = MockTransport(script: [
            (expected: APDU(ins: 0x22, p1: 0x41, p2: 0xB6, data: [0x80, 0x01, 0x02, 0x84, 0x02, 0x60, 0x05]),
             response: APDUResponse(data: [], sw: 0x9000)),
            (expected: nil, response: APDUResponse(data: sig, sw: 0x9000)),
        ])
        let out = try PKICard(transport: mock).sign(.digestInfo(di), keyFID: fid)
        XCTAssertEqual(out, sig)
        XCTAssertEqual(mock.sent[0].bytes, [0x00, 0x22, 0x41, 0xB6, 0x07, 0x80, 0x01, 0x02, 0x84, 0x02, 0x60, 0x05])
        XCTAssertEqual(mock.sent[1].bytes, [0x00, 0x2A, 0x9E, 0x00, UInt8(di.count)] + di + [0x00])
    }

    func testSignRawUsesP2Trick() throws {
        let block = (0..<256).map { UInt8($0) }
        let mock = MockTransport(script: [
            (expected: nil, response: APDUResponse(data: [], sw: 0x9000)),
            (expected: nil, response: APDUResponse(data: [9], sw: 0x9000)),
        ])
        _ = try PKICard(transport: mock).sign(.rawBlock(block), keyFID: fid)
        XCTAssertEqual(Array(mock.sent[0].bytes[4...6]), [0x07, 0x80, 0x01])
        XCTAssertEqual(mock.sent[0].bytes[7], 0x00)
        let pso = mock.sent[1]
        XCTAssertEqual(pso.p2, block[0])
        XCTAssertEqual(pso.data, Array(block[1...]))
        XCTAssertEqual(pso.bytes.prefix(5), [0x00, 0x2A, 0x9E, block[0], 0xFF])
        XCTAssertEqual(pso.bytes.count, 4 + 1 + 255 + 1)
    }

    func testSignStatusError() {
        let mock = MockTransport(script: [
            (expected: nil, response: APDUResponse(data: [], sw: 0x9000)),
            (expected: nil, response: APDUResponse(data: [], sw: 0x6982)),
        ])
        XCTAssertThrowsError(try PKICard(transport: mock).sign(.digestInfo([1, 2]), keyFID: fid)) { error in
            XCTAssertEqual(error as? APDUError, .status(0x6982))
        }
    }

    func testWrongSizesSendNothing() {
        let cases: [SignRequest] = [.rawBlock([UInt8](repeating: 0, count: 255)), .digestInfo([]), .digestInfo([UInt8](repeating: 0, count: 256))]
        for request in cases {
            let mock = MockTransport()
            XCTAssertThrowsError(try PKICard(transport: mock).sign(request, keyFID: fid))
            XCTAssertTrue(mock.sent.isEmpty)
        }
        let mock = MockTransport()
        XCTAssertThrowsError(try PKICard(transport: mock).sign(.digestInfo([1]), keyFID: [1]))
        XCTAssertTrue(mock.sent.isEmpty)
    }

    func testMSEFailureSkipsPSO() {
        let mock = MockTransport(script: [(expected: nil, response: APDUResponse(data: [], sw: 0x6A88))])
        XCTAssertThrowsError(try PKICard(transport: mock).sign(.digestInfo([1]), keyFID: fid))
        XCTAssertEqual(mock.sent.count, 1)
    }
}
