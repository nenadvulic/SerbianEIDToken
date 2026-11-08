import XCTest
import Security
@testable import SerbianEIDPKI

final class CardFilesTests: XCTestCase {
    private func assertMalformed<T>(_ expr: @autoclosure () throws -> T, file: StaticString = #filePath, line: UInt = #line) {
        XCTAssertThrowsError(try expr(), file: file, line: line) { error in
            guard case APDUError.malformed = error else {
                return XCTFail("expected malformed, got \(error)", file: file, line: line)
            }
        }
    }

    func testAPDUEncoding() {
        XCTAssertEqual(Commands.selectPKCS15Applet().bytes,
                       [0x00,0xA4,0x04,0x00,0x0C,0xA0,0x00,0x00,0x00,0x63,0x50,0x4B,0x43,0x53,0x2D,0x31,0x35,0xFF])
        XCTAssertEqual(Commands.readBinary(offset: 0x0123, length: 300).bytes, [0x00,0xB0,0x01,0x23,0xFF])
        XCTAssertEqual(Commands.selectFile([0x8F,0xFF], le: nil).bytes, [0x00,0xA4,0x00,0x00,0x02,0x8F,0xFF])
        XCTAssertEqual(APDU(ins: 0xB0, p1: 0, p2: 0, le: 256).bytes, [0x00,0xB0,0x00,0x00,0x00])
    }

    func testIndexValid() throws {
        XCTAssertEqual(try CardIndex([0x02,0x00,0x02,0x71,0x03,0x71]).fids, [[0x71,0x02],[0x71,0x03]])
        XCTAssertEqual(try CardIndex([0x00,0x00]).fids, [])
        XCTAssertEqual(try CardIndex([0x01,0x00,0x02,0x71,0xAA,0xBB]).fids, [[0x71,0x02]])
    }

    func testIndexInvalid() {
        for bad: [UInt8] in [[], [0x01], [0x01,0x00], [0x01,0x00,0x00], [0x02,0x00,0xFF,0xFF], [0xFF,0xFF]] {
            assertMalformed(try CardIndex(bad))
        }
    }

    func testMetaFileValid() throws {
        let id = [UInt8](repeating: 0xFF, count: 20)
        let m = try MetaFile([0x01,0xF1,0xF2,0x02,0xD1,0xD2,0x14] + id)
        XCTAssertEqual(m.class_, 1)
        XCTAssertEqual(m.fileName, [0xF1,0xF2])
        XCTAssertEqual(m.label, [0xD1,0xD2])
        XCTAssertEqual(m.id, id)
        XCTAssertNil(try MetaFile([0x01,0xF1,0xF2,0x00,0x14] + id).label)
    }

    func testMetaFileInvalid() {
        let id = [UInt8](repeating: 0xFF, count: 20)
        assertMalformed(try MetaFile([0x00,0xF1,0xF2,0x00,0x14] + id))
        assertMalformed(try MetaFile([0x04,0xF1,0xF2,0x00,0x14] + id))
        assertMalformed(try MetaFile([0x01,0xF1,0xF2,0x00,0x13] + id.dropLast()))
        assertMalformed(try MetaFile([0x01,0xF1,0xF2,0x00,0x15] + id + [0xFF]))
        assertMalformed(try MetaFile([0x01,0xF1,0xF2,0x09,0xD1,0xD2]))
    }

    func testPublicKeyFile() throws {
        let k = try PublicKeyFile([0x00,0x05,0x01,0x60,0x05,0x00,0x02,0xAA,0xBB,0x00,0x04,0xAA,0xBB,0xCC,0xDD])
        XCTAssertEqual(k.privateKeyFID, [0x60,0x05])
        XCTAssertEqual(k.modulus, [0xAA,0xBB])
        XCTAssertEqual(k.exponent, [0xAA,0xBB,0xCC,0xDD])
        assertMalformed(try PublicKeyFile([0x00,0x06,0x01,0x60,0x05,0x00,0x02,0xAA,0xBB,0x00,0x04,0xAA,0xBB,0xCC,0xDD]))
        assertMalformed(try PublicKeyFile([0x00,0x05,0x01,0x60,0x05,0x00,0x02,0xAA]))
    }

    func testCertificateDecoder() throws {
        let der = Fixtures.testCertDER
        XCTAssertNotNil(SecCertificateCreateWithData(nil, Data(der) as CFData))
        let file = Fixtures.testCertCardFile
        XCTAssertEqual([UInt8](try CertificateDecoder.decode(file)), der)
        assertMalformed(try CertificateDecoder.decode(Array(file.prefix(file.count / 2))))
        assertMalformed(try CertificateDecoder.decode([1,2,3]))
    }
}
