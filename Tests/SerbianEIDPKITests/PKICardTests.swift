import XCTest
import Compression
@testable import SerbianEIDPKI

/// In-memory card: files by FID, SELECT sets the current file, READ BINARY slices it.
private final class FileCard: APDUTransport {
    var files: [[UInt8]: [UInt8]] = [:]
    var appletSW: UInt16 = 0x9000
    private var current: [UInt8]?

    func transmit(_ apdu: APDU) throws -> APDUResponse {
        switch apdu.ins {
        case 0xA4 where apdu.p1 == 0x04:
            return APDUResponse(data: [], sw: appletSW)
        case 0xA4:
            guard let f = files[apdu.data] else { return APDUResponse(data: [], sw: 0x6A82) }
            current = apdu.data
            return APDUResponse(data: [0x6F, 0x00, UInt8(f.count >> 8), UInt8(f.count & 0xFF), 0, 0, 0, 0], sw: 0x9000)
        case 0xB0:
            guard let c = current, let f = files[c] else { return APDUResponse(data: [], sw: 0x6985) }
            let off = Int(apdu.p1) << 8 | Int(apdu.p2)
            guard off < f.count else { return APDUResponse(data: [], sw: 0x6B00) }
            return APDUResponse(data: Array(f[off..<min(f.count, off + (apdu.le ?? 256))]), sw: 0x9000)
        default:
            return APDUResponse(data: [], sw: 0x6D00)
        }
    }
}

private func cardFile(forDER der: [UInt8]) -> [UInt8] {
    var dst = [UInt8](repeating: 0, count: der.count + 1024)
    let n = der.withUnsafeBufferPointer { src in
        dst.withUnsafeMutableBufferPointer { out in
            compression_encode_buffer(out.baseAddress!, out.count, src.baseAddress!, der.count, nil, COMPRESSION_ZLIB)
        }
    }
    // 6 header bytes, zlib header, raw deflate, 4 trailing bytes (checksum is not verified).
    return [1, 2, 3, 4, 5, 6, 0x78, 0xDA] + dst[0..<n] + [0, 0, 0, 0]
}

private func meta(_ cls: UInt8, file: [UInt8], label: String = "", id: UInt8) -> [UInt8] {
    [cls] + file + [UInt8(label.utf8.count)] + Array(label.utf8) + [20] + [UInt8](repeating: id, count: 20)
}

private func pubKey(privFID: [UInt8], modulus: [UInt8]) -> [UInt8] {
    [0x00, 0x05, 0x01] + privFID + [0, UInt8(modulus.count)] + modulus + [0, 3, 1, 0, 1]
}

final class PKICardTests: XCTestCase {
    private let ok = APDUResponse(data: [], sw: 0x9000)
    private let fid: [UInt8] = [0x71, 0x02]

    func testSelectFallsBackWithoutLe() throws {
        let fci: [UInt8] = [0x6F, 0x00, 0x00, 0x03, 0, 0, 0, 0]
        let t = MockTransport(script: [
            (Commands.selectFile(fid, le: 0xFF), APDUResponse(data: [], sw: 0x6F00)),
            (Commands.selectFile(fid, le: nil), APDUResponse(data: fci, sw: 0x9000)),
            (Commands.readBinary(offset: 0, length: 3), APDUResponse(data: [1, 2, 3], sw: 0x9000)),
            // second file: remembered strategy goes straight to no-Le
            (Commands.selectFile(fid, le: nil), APDUResponse(data: fci, sw: 0x9000)),
            (Commands.readBinary(offset: 0, length: 3), APDUResponse(data: [4, 5, 6], sw: 0x9000)),
        ])
        let card = PKICard(transport: t)
        XCTAssertEqual(try card.readFile(fid), [1, 2, 3])
        XCTAssertEqual(try card.readFile(fid), [4, 5, 6])
    }

    func testSelectFallsBackToFCI() throws {
        let fci: [UInt8] = [0x6F, 0x00, 0x00, 0x01, 0, 0, 0, 0]
        let bad = APDUResponse(data: [], sw: 0x6F00)
        let t = MockTransport(script: [
            (Commands.selectFile(fid, le: 0xFF), bad),
            (Commands.selectFile(fid, le: nil), bad),
            (Commands.selectFile(fid, le: nil, p2: 0x04), APDUResponse(data: fci, sw: 0x9000)),
            (Commands.readBinary(offset: 0, length: 1), APDUResponse(data: [9], sw: 0x9000)),
        ])
        XCTAssertEqual(try PKICard(transport: t).readFile(fid), [9])
    }

    func testReadFileLoops() throws {
        let fci: [UInt8] = [0x6F, 0x00, 0x02, 0x58, 0, 0, 0, 0]  // 600
        let t = MockTransport(script: [
            (nil, APDUResponse(data: fci, sw: 0x9000)),
            (Commands.readBinary(offset: 0, length: 255), APDUResponse(data: [UInt8](repeating: 1, count: 255), sw: 0x9000)),
            (Commands.readBinary(offset: 255, length: 255), APDUResponse(data: [UInt8](repeating: 2, count: 255), sw: 0x9000)),
            (Commands.readBinary(offset: 510, length: 90), APDUResponse(data: [UInt8](repeating: 3, count: 90), sw: 0x9000)),
        ])
        XCTAssertEqual(try PKICard(transport: t).readFile(fid).count, 600)
        XCTAssertEqual(t.sent.dropFirst().map { $0.bytes[3] }, [0, 255, 254])  // P2 = offset low byte
        XCTAssertEqual(t.sent.count, 4)
    }

    func testReadFileStopsOnEmptyResponse() throws {
        let fci: [UInt8] = [0x6F, 0x00, 0x02, 0x58, 0, 0, 0, 0]
        let t = MockTransport(script: [
            (nil, APDUResponse(data: fci, sw: 0x9000)),
            (nil, APDUResponse(data: [1, 2], sw: 0x9000)),
            (nil, ok),
        ])
        XCTAssertEqual(try PKICard(transport: t).readFile(fid), [1, 2])
    }

    func testDiscoverPairsByID() throws {
        let card = FileCard()
        card.files[[0x8F, 0xFF]] = [3, 0, 0x01, 0x71, 0x02, 0x71, 0x03, 0x71, 0x04, 0x71]
        // index entries are byte-reversed: FIDs 71 01, 71 02, 71 03, 71 04
        card.files[[0x71, 0x01]] = meta(1, file: [0x41, 0x01], label: "Auth", id: 0xA)
        card.files[[0x71, 0x02]] = meta(2, file: [0x42, 0x01], id: 0xA)
        card.files[[0x71, 0x03]] = meta(1, file: [0x41, 0x02], id: 0xB)
        card.files[[0x71, 0x04]] = meta(3, file: [0x43, 0x01], id: 0xA)
        card.files[[0x41, 0x01]] = cardFile(forDER: Fixtures.certAuthOnly)
        card.files[[0x41, 0x02]] = cardFile(forDER: Fixtures.certSignature)
        card.files[[0x42, 0x01]] = pubKey(privFID: [0x60, 0x05], modulus: [0xC3, 0x01])
        card.files[[0x8F, 0xFF]] = [4, 0, 0x01, 0x71, 0x02, 0x71, 0x03, 0x71, 0x04, 0x71]
        let objects = try PKICard(transport: card).discover()
        XCTAssertEqual(objects.identities.count, 1)
        let id = objects.identities[0]
        XCTAssertEqual(id.id, [UInt8](repeating: 0xA, count: 20))
        XCTAssertEqual(id.role, .authentication)
        XCTAssertEqual(id.label, "Auth")
        XCTAssertEqual(id.privateKeyFID, [0x60, 0x05])
        XCTAssertEqual(id.exponent, [1, 0, 1])
        XCTAssertEqual(id.keySizeInBits, 16)
        XCTAssertEqual([UInt8](id.certificate), Fixtures.certAuthOnly)
        XCTAssertEqual(objects.extraCertificates.map { [UInt8]($0) }, [Fixtures.certSignature])
    }

    func testDiscoverSkipsCorruptObject() throws {
        let card = FileCard()
        card.files[[0x8F, 0xFF]] = [3, 0, 0x01, 0x71, 0x02, 0x71, 0x03, 0x71]
        card.files[[0x71, 0x01]] = [0x09, 0xFF]  // corrupt MetaFile
        card.files[[0x71, 0x02]] = meta(1, file: [0x41, 0x01], id: 0xA)
        card.files[[0x71, 0x03]] = meta(2, file: [0x42, 0x01], id: 0xA)
        card.files[[0x41, 0x01]] = cardFile(forDER: Fixtures.certAuthOnly)
        card.files[[0x42, 0x01]] = pubKey(privFID: [0x60, 0x05], modulus: [0xC3, 0x01])
        let objects = try PKICard(transport: card).discover()
        XCTAssertEqual(objects.identities.count, 1)
        XCTAssertTrue(objects.extraCertificates.isEmpty)
    }

    func testDiscoverAppletMissing() {
        let card = FileCard()
        card.appletSW = 0x6A82
        XCTAssertThrowsError(try PKICard(transport: card).discover()) {
            XCTAssertEqual($0 as? APDUError, .unsupportedCard)
        }
    }

    func testNonRSAKeySkipped() throws {
        let card = FileCard()
        card.files[[0x8F, 0xFF]] = [2, 0, 0x01, 0x71, 0x02, 0x71]
        card.files[[0x71, 0x01]] = meta(1, file: [0x41, 0x01], id: 0xA)
        card.files[[0x71, 0x02]] = meta(2, file: [0x42, 0x01], id: 0xA)
        card.files[[0x41, 0x01]] = cardFile(forDER: Fixtures.certAuthOnly)
        card.files[[0x42, 0x01]] = pubKey(privFID: [0x60, 0x05], modulus: [])
        let objects = try PKICard(transport: card).discover()
        XCTAssertTrue(objects.identities.isEmpty)
        XCTAssertEqual(objects.extraCertificates.count, 1)
    }

    func testRole() {
        XCTAssertEqual(CardIdentity.role(of: Data(Fixtures.certAuthOnly)), .authentication)
        XCTAssertEqual(CardIdentity.role(of: Data(Fixtures.certSignature)), .qualifiedSignature)
        XCTAssertEqual(CardIdentity.role(of: Data(Fixtures.certNoKeyUsage)), .other)
        XCTAssertEqual(CardIdentity.role(of: Data([1, 2, 3])), .other)
    }
}
