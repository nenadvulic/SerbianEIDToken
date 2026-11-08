import Foundation
import CryptoKit
import Security

public enum HashAlgorithm: Equatable {
    case sha1, sha256, sha384, sha512

    public var digestLength: Int {
        switch self {
        case .sha1: return 20
        case .sha256: return 32
        case .sha384: return 48
        case .sha512: return 64
        }
    }

    /// DER prefix of the DigestInfo structure (RFC 8017 §9.2 note 1).
    public var digestInfoPrefix: [UInt8] {
        switch self {
        case .sha1:
            return [0x30, 0x21, 0x30, 0x09, 0x06, 0x05, 0x2B, 0x0E, 0x03, 0x02, 0x1A, 0x05, 0x00, 0x04, 0x14]
        case .sha256:
            return [0x30, 0x31, 0x30, 0x0D, 0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x01, 0x05, 0x00, 0x04, 0x20]
        case .sha384:
            return [0x30, 0x41, 0x30, 0x0D, 0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x02, 0x05, 0x00, 0x04, 0x30]
        case .sha512:
            return [0x30, 0x51, 0x30, 0x0D, 0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x03, 0x05, 0x00, 0x04, 0x40]
        }
    }

    func hash(_ data: [UInt8]) -> [UInt8] {
        switch self {
        case .sha1: return Array(Insecure.SHA1.hash(data: data))
        case .sha256: return Array(SHA256.hash(data: data))
        case .sha384: return Array(SHA384.hash(data: data))
        case .sha512: return Array(SHA512.hash(data: data))
        }
    }
}

/// What is sent to the card: `digestInfo` maps to card alg 02, `rawBlock` to card alg 00.
public enum SignRequest: Equatable {
    case digestInfo([UInt8])
    case rawBlock([UInt8])
}

public enum SignatureEncoding {
    public static func digestInfo(_ digest: [UInt8], _ hash: HashAlgorithm) throws -> [UInt8] {
        guard digest.count == hash.digestLength else {
            throw APDUError.malformed("digest length \(digest.count), expected \(hash.digestLength)")
        }
        return hash.digestInfoPrefix + digest
    }

    /// EMSA-PSS-ENCODE (RFC 8017 §9.1.1), salt length = hash length, MGF1 with the same hash.
    public static func pss(_ digest: [UInt8], _ hash: HashAlgorithm, modulusBits: Int, salt: [UInt8]? = nil) throws -> [UInt8] {
        let hLen = hash.digestLength
        guard digest.count == hLen else {
            throw APDUError.malformed("digest length \(digest.count), expected \(hLen)")
        }
        let emBits = modulusBits - 1
        let emLen = (emBits + 7) / 8
        guard emLen >= 2 * hLen + 2 else { throw APDUError.malformed("modulus too small for PSS") }
        let saltBytes: [UInt8]
        if let salt = salt {
            guard salt.count == hLen else { throw APDUError.malformed("salt length \(salt.count), expected \(hLen)") }
            saltBytes = salt
        } else {
            var random = [UInt8](repeating: 0, count: hLen)
            guard SecRandomCopyBytes(kSecRandomDefault, hLen, &random) == errSecSuccess else {
                throw APDUError.malformed("random generation failed")
            }
            saltBytes = random
        }
        let mPrime = [UInt8](repeating: 0, count: 8) + digest + saltBytes
        let h = hash.hash(mPrime)
        let dbLen = emLen - hLen - 1
        var db = [UInt8](repeating: 0, count: dbLen - hLen - 1) + [0x01] + saltBytes
        let mask = mgf1(h, length: dbLen, hash)
        for i in 0..<dbLen { db[i] ^= mask[i] }
        db[0] &= 0xFF >> UInt8(8 * emLen - emBits)
        return db + h + [0xBC]
    }

    private static func mgf1(_ seed: [UInt8], length: Int, _ hash: HashAlgorithm) -> [UInt8] {
        var out: [UInt8] = []
        var counter: UInt32 = 0
        while out.count < length {
            let c = [UInt8(counter >> 24 & 0xFF), UInt8(counter >> 16 & 0xFF), UInt8(counter >> 8 & 0xFF), UInt8(counter & 0xFF)]
            out += hash.hash(seed + c)
            counter += 1
        }
        return Array(out.prefix(length))
    }
}

public enum CardSignatureAlgorithm: Equatable {
    case pkcs1(HashAlgorithm)
    case pkcs1DigestInfo
    case raw
    case pss(HashAlgorithm)

    public init?(_ secKeyAlgorithm: SecKeyAlgorithm) {
        switch secKeyAlgorithm {
        case .rsaSignatureDigestPKCS1v15SHA1: self = .pkcs1(.sha1)
        case .rsaSignatureDigestPKCS1v15SHA256: self = .pkcs1(.sha256)
        case .rsaSignatureDigestPKCS1v15SHA384: self = .pkcs1(.sha384)
        case .rsaSignatureDigestPKCS1v15SHA512: self = .pkcs1(.sha512)
        case .rsaSignatureDigestPKCS1v15Raw: self = .pkcs1DigestInfo
        case .rsaSignatureRaw: self = .raw
        case .rsaSignatureDigestPSSSHA256: self = .pss(.sha256)
        case .rsaSignatureDigestPSSSHA384: self = .pss(.sha384)
        case .rsaSignatureDigestPSSSHA512: self = .pss(.sha512)
        default: return nil
        }
    }

    /// Builds the card request for `data` (a digest, a DigestInfo or a full block depending on the algorithm).
    public func request(for data: [UInt8], modulusBits: Int) throws -> SignRequest {
        let modulusBytes = modulusBits / 8
        switch self {
        case .pkcs1(let hash):
            return .digestInfo(try SignatureEncoding.digestInfo(data, hash))
        case .pkcs1DigestInfo:
            guard !data.isEmpty, data.count <= modulusBytes - 11 else {
                throw APDUError.malformed("DigestInfo length \(data.count) out of range")
            }
            return .digestInfo(data)
        case .raw:
            guard data.count == modulusBytes else {
                throw APDUError.malformed("raw block length \(data.count), expected \(modulusBytes)")
            }
            return .rawBlock(data)
        case .pss(let hash):
            return .rawBlock(try SignatureEncoding.pss(data, hash, modulusBits: modulusBits))
        }
    }
}
