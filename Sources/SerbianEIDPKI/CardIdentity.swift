import Foundation

public enum CertificateRole: Equatable {
    case authentication
    case qualifiedSignature
    case other
}

public struct CardIdentity {
    public let id: [UInt8]
    public let certificate: Data
    public let role: CertificateRole
    public let label: String?
    public let privateKeyFID: [UInt8]
    public let modulus: [UInt8]
    public let exponent: [UInt8]

    public init(id: [UInt8], certificate: Data, role: CertificateRole, label: String?,
                privateKeyFID: [UInt8], modulus: [UInt8], exponent: [UInt8]) {
        self.id = id; self.certificate = certificate; self.role = role; self.label = label
        self.privateKeyFID = privateKeyFID; self.modulus = modulus; self.exponent = exponent
    }

    /// Modulus size in bits, ignoring leading zero bytes.
    public var keySizeInBits: Int {
        guard let first = modulus.firstIndex(where: { $0 != 0 }) else { return 0 }
        let rest = modulus.count - first - 1
        return rest * 8 + (8 - modulus[first].leadingZeroBitCount)
    }

    /// Role from the keyUsage extension: nonRepudiation gives a qualified signature,
    /// digitalSignature alone gives authentication, anything else is `.other`.
    public static func role(of certificateDER: Data) -> CertificateRole {
        guard let bits = keyUsageByte(certificateDER) else { return .other }
        if bits & 0x40 != 0 { return .qualifiedSignature }
        if bits & 0x80 != 0 { return .authentication }
        return .other
    }

    /// First byte of the keyUsage BIT STRING (bit 0 = 0x80), found by walking the extension.
    private static func keyUsageByte(_ der: Data) -> UInt8? {
        let b = [UInt8](der)
        let oid: [UInt8] = [0x06, 0x03, 0x55, 0x1D, 0x0F]
        guard b.count > oid.count else { return nil }
        var i = 0
        while i + oid.count <= b.count {
            if Array(b[i..<i + oid.count]) == oid { break }
            i += 1
        }
        guard i + oid.count <= b.count else { return nil }
        var pos = i + oid.count
        func tlv(_ tag: UInt8) -> (start: Int, len: Int)? {
            guard pos + 2 <= b.count, b[pos] == tag else { return nil }
            var len = Int(b[pos + 1])
            var hdr = 2
            if len & 0x80 != 0 {
                let n = len & 0x7F
                guard n >= 1, n <= 2, pos + 2 + n <= b.count else { return nil }
                len = 0
                for k in 0..<n { len = len << 8 | Int(b[pos + 2 + k]) }
                hdr += n
            }
            guard pos + hdr + len <= b.count else { return nil }
            return (pos + hdr, len)
        }
        if let critical = tlv(0x01) { pos = critical.start + critical.len }
        guard let octets = tlv(0x04) else { return nil }
        pos = octets.start
        guard let bitString = tlv(0x03), bitString.len >= 2 else { return nil }
        return b[bitString.start + 1]
    }
}

public struct CardObjects {
    public let identities: [CardIdentity]
    /// Certificates without a matching key (for example the issuing CA).
    public let extraCertificates: [Data]
}
