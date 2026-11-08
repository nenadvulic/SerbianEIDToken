import XCTest
import CryptoKit
import Security
@testable import SerbianEIDPKI

final class SignatureEncodingTests: XCTestCase {
    static var privateKey: SecKey!
    static var publicKey: SecKey!

    override class func setUp() {
        let attrs: [String: Any] = [
            kSecAttrKeyType as String: kSecAttrKeyTypeRSA,
            kSecAttrKeySizeInBits as String: 2048,
            kSecAttrIsPermanent as String: false,
        ]
        var error: Unmanaged<CFError>?
        privateKey = SecKeyCreateRandomKey(attrs as CFDictionary, &error)
        publicKey = SecKeyCopyPublicKey(privateKey)
    }

    private let message = Array("serbian eid signing test".utf8)

    private func digest(_ message: [UInt8], _ hash: HashAlgorithm) -> [UInt8] {
        switch hash {
        case .sha1: return Array(Insecure.SHA1.hash(data: message))
        case .sha256: return Array(SHA256.hash(data: message))
        case .sha384: return Array(SHA384.hash(data: message))
        case .sha512: return Array(SHA512.hash(data: message))
        }
    }

    private func rawSign(_ block: [UInt8]) throws -> Data {
        var error: Unmanaged<CFError>?
        guard let sig = SecKeyCreateSignature(Self.privateKey, .rsaSignatureRaw, Data(block) as CFData, &error) else {
            throw error!.takeRetainedValue()
        }
        return sig as Data
    }

    private func verify(_ sig: Data, _ algorithm: SecKeyAlgorithm, _ hash: HashAlgorithm) -> Bool {
        var error: Unmanaged<CFError>?
        return SecKeyVerifySignature(Self.publicKey, algorithm, Data(digest(message, hash)) as CFData, sig as CFData, &error)
    }

    func testDigestInfoVerifies() throws {
        let cases: [(HashAlgorithm, SecKeyAlgorithm)] = [
            (.sha1, .rsaSignatureDigestPKCS1v15SHA1),
            (.sha256, .rsaSignatureDigestPKCS1v15SHA256),
            (.sha384, .rsaSignatureDigestPKCS1v15SHA384),
            (.sha512, .rsaSignatureDigestPKCS1v15SHA512),
        ]
        for (hash, alg) in cases {
            let di = try SignatureEncoding.digestInfo(digest(message, hash), hash)
            let pad = [UInt8](repeating: 0xFF, count: 256 - 3 - di.count)
            let block: [UInt8] = [0x00, 0x01] + pad + [0x00] + di
            XCTAssertEqual(block.count, 256)
            XCTAssertTrue(verify(try rawSign(block), alg, hash), "\(hash)")
        }
    }

    func testPSSVerifies() throws {
        let cases: [(HashAlgorithm, SecKeyAlgorithm)] = [
            (.sha256, .rsaSignatureDigestPSSSHA256),
            (.sha384, .rsaSignatureDigestPSSSHA384),
            (.sha512, .rsaSignatureDigestPSSSHA512),
        ]
        for (hash, alg) in cases {
            let em = try SignatureEncoding.pss(digest(message, hash), hash, modulusBits: 2048)
            XCTAssertEqual(em.count, 256)
            XCTAssertTrue(verify(try rawSign(em), alg, hash), "\(hash)")
        }
    }

    func testPSSDeterministicWithSalt() throws {
        let d = digest(message, .sha256)
        let salt = [UInt8](repeating: 7, count: 32)
        let a = try SignatureEncoding.pss(d, .sha256, modulusBits: 2048, salt: salt)
        let b = try SignatureEncoding.pss(d, .sha256, modulusBits: 2048, salt: salt)
        XCTAssertEqual(a, b)
        XCTAssertThrowsError(try SignatureEncoding.pss(d, .sha256, modulusBits: 2048, salt: [1, 2, 3]))
    }

    func testWrongDigestLength() {
        XCTAssertThrowsError(try SignatureEncoding.digestInfo([UInt8](repeating: 0, count: 31), .sha256)) { error in
            guard case APDUError.malformed = error else { return XCTFail("got \(error)") }
        }
        XCTAssertThrowsError(try SignatureEncoding.pss([UInt8](repeating: 0, count: 31), .sha256, modulusBits: 2048)) { error in
            guard case APDUError.malformed = error else { return XCTFail("got \(error)") }
        }
    }

    func testRawWrongSize() {
        XCTAssertThrowsError(try CardSignatureAlgorithm.raw.request(for: [UInt8](repeating: 1, count: 255), modulusBits: 2048)) { error in
            guard case APDUError.malformed = error else { return XCTFail("got \(error)") }
        }
    }

    func testRequestKinds() throws {
        let d = digest(message, .sha256)
        XCTAssertEqual(try CardSignatureAlgorithm.pkcs1(.sha256).request(for: d, modulusBits: 2048),
                       .digestInfo(try SignatureEncoding.digestInfo(d, .sha256)))
        XCTAssertEqual(try CardSignatureAlgorithm.pkcs1DigestInfo.request(for: [1, 2, 3], modulusBits: 2048), .digestInfo([1, 2, 3]))
        let block = [UInt8](repeating: 1, count: 256)
        XCTAssertEqual(try CardSignatureAlgorithm.raw.request(for: block, modulusBits: 2048), .rawBlock(block))
        guard case .rawBlock(let em) = try CardSignatureAlgorithm.pss(.sha256).request(for: d, modulusBits: 2048) else {
            return XCTFail("expected rawBlock")
        }
        XCTAssertEqual(em.count, 256)
    }

    func testAlgorithmMapping() {
        XCTAssertEqual(CardSignatureAlgorithm(.rsaSignatureDigestPKCS1v15SHA1), .pkcs1(.sha1))
        XCTAssertEqual(CardSignatureAlgorithm(.rsaSignatureDigestPKCS1v15SHA256), .pkcs1(.sha256))
        XCTAssertEqual(CardSignatureAlgorithm(.rsaSignatureDigestPKCS1v15SHA384), .pkcs1(.sha384))
        XCTAssertEqual(CardSignatureAlgorithm(.rsaSignatureDigestPKCS1v15SHA512), .pkcs1(.sha512))
        XCTAssertEqual(CardSignatureAlgorithm(.rsaSignatureDigestPKCS1v15Raw), .pkcs1DigestInfo)
        XCTAssertEqual(CardSignatureAlgorithm(.rsaSignatureRaw), .raw)
        XCTAssertEqual(CardSignatureAlgorithm(.rsaSignatureDigestPSSSHA256), .pss(.sha256))
        XCTAssertEqual(CardSignatureAlgorithm(.rsaSignatureDigestPSSSHA384), .pss(.sha384))
        XCTAssertEqual(CardSignatureAlgorithm(.rsaSignatureDigestPSSSHA512), .pss(.sha512))
        XCTAssertNil(CardSignatureAlgorithm(.rsaEncryptionPKCS1))
    }
}
