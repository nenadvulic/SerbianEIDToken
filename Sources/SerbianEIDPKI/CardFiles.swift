import Foundation
import Compression

/// Directory file: entry count (LE16) then 2-byte file identifiers, stored low byte first.
public struct CardIndex {
    public let fids: [[UInt8]]

    public init(_ bytes: [UInt8]) throws {
        guard bytes.count >= 2 else { throw APDUError.malformed("index too short") }
        let count = Int(bytes[0]) | (Int(bytes[1]) << 8)
        guard bytes.count >= 2 + count * 2 else { throw APDUError.malformed("index truncated") }
        var out: [[UInt8]] = []
        for i in 0..<count {
            let o = 2 + i * 2
            out.append([bytes[o + 1], bytes[o]])
        }
        fids = out
    }
}

public struct MetaFile {
    public let class_: UInt8
    public let fileName: [UInt8]
    public let label: [UInt8]?
    public let id: [UInt8]

    public init(_ bytes: [UInt8]) throws {
        var pos = 0
        func take(_ n: Int) throws -> [UInt8] {
            guard n >= 0, pos + n <= bytes.count else { throw APDUError.malformed("meta file truncated") }
            defer { pos += n }
            return Array(bytes[pos..<pos + n])
        }
        let cls = try take(1)[0]
        guard (1...3).contains(cls) else { throw APDUError.malformed("bad class") }
        class_ = cls
        fileName = try take(2)
        let labelLen = Int(try take(1)[0])
        let lbl = try take(labelLen)
        label = lbl.isEmpty ? nil : lbl
        let idLen = Int(try take(1)[0])
        guard idLen == 20 else { throw APDUError.malformed("bad id length") }
        id = try take(idLen)
    }
}

public struct PublicKeyFile {
    public let privateKeyFID: [UInt8]
    public let modulus: [UInt8]
    public let exponent: [UInt8]

    public init(_ bytes: [UInt8]) throws {
        var pos = 0
        func take(_ n: Int) throws -> [UInt8] {
            guard n >= 0, pos + n <= bytes.count else { throw APDUError.malformed("public key file truncated") }
            defer { pos += n }
            return Array(bytes[pos..<pos + n])
        }
        guard try take(2) == [0x00, 0x05] else { throw APDUError.malformed("bad public key prefix") }
        _ = try take(1)
        privateKeyFID = try take(2)
        func lengthPrefixed() throws -> [UInt8] {
            let l = try take(2)
            return try take(Int(l[0]) << 8 | Int(l[1]))
        }
        modulus = try lengthPrefixed()
        exponent = try lengthPrefixed()
    }
}

public enum CertificateDecoder {
    /// File layout: 6 bytes header, zlib stream (2-byte header, raw deflate, Adler-32).
    public static func decode(_ fileBytes: [UInt8]) throws -> Data {
        guard fileBytes.count > 6 + 2 + 4 else { throw APDUError.malformed("certificate file too short") }
        let deflate = Array(fileBytes[8..<(fileBytes.count - 4)])
        var capacity = max(deflate.count * 8, 4096)
        let maxCapacity = 16 * 1024 * 1024
        while capacity <= maxCapacity {
            var dst = [UInt8](repeating: 0, count: capacity)
            let n = deflate.withUnsafeBufferPointer { src in
                dst.withUnsafeMutableBufferPointer { out in
                    compression_decode_buffer(out.baseAddress!, capacity, src.baseAddress!, deflate.count, nil, COMPRESSION_ZLIB)
                }
            }
            if n == 0 { throw APDUError.malformed("certificate decompression failed") }
            if n < capacity { return Data(dst[0..<n]) }
            capacity *= 2
        }
        throw APDUError.malformed("certificate too large")
    }
}
