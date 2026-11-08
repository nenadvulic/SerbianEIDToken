import Foundation

public final class PKICard {
    private let transport: APDUTransport
    private var selectStrategy: Int?

    public init(transport: APDUTransport) {
        self.transport = transport
    }

    public func selectApplet() throws {
        let response = try transport.transmit(Commands.selectPKCS15Applet())
        guard response.isOK else { throw APDUError.unsupportedCard }
    }

    /// SELECT strategies in order: Le=FF, no Le, no Le with P2=04 (FCI). The first that works is remembered.
    private func selectCommand(_ fid: [UInt8], strategy: Int) -> APDU {
        switch strategy {
        case 0: return Commands.selectFile(fid, le: 0xFF)
        case 1: return Commands.selectFile(fid, le: nil)
        default: return Commands.selectFile(fid, le: nil, p2: 0x04)
        }
    }

    private func select(_ fid: [UInt8]) throws -> APDUResponse {
        let candidates = selectStrategy.map { [$0] } ?? [0, 1, 2]
        var last = APDUResponse(data: [], sw: 0x6F00)
        for strategy in candidates {
            let response = try transport.transmit(selectCommand(fid, strategy: strategy))
            if response.isOK {
                selectStrategy = strategy
                return response
            }
            last = response
            if response.sw != 0x6F00 { break }
        }
        throw APDUError.status(last.sw)
    }

    public func readFile(_ fid: [UInt8]) throws -> [UInt8] {
        let fci = try select(fid).data
        var size: Int?
        if fci.count >= 6 { size = Int(fci[2]) << 8 | Int(fci[3]) }
        var out: [UInt8] = []
        while size == nil || out.count < size! {
            let want = size.map { $0 - out.count } ?? 255
            let response = try transport.transmit(Commands.readBinary(offset: out.count, length: want))
            if !response.isOK {
                if size == nil && !out.isEmpty { break }
                throw APDUError.status(response.sw)
            }
            if response.data.isEmpty { break }
            out.append(contentsOf: response.data)
        }
        return out
    }

    public func discover() throws -> CardObjects {
        try selectApplet()
        let index = try CardIndex(try readFile([0x8F, 0xFF]))
        var certs: [(id: [UInt8], der: Data, label: String?)] = []
        var keys: [[UInt8]: PublicKeyFile] = [:]
        for fid in index.fids {
            do {
                let meta = try MetaFile(try readFile(fid))
                switch meta.class_ {
                case 1:
                    let der = try CertificateDecoder.decode(try readFile(meta.fileName))
                    let label = meta.label.flatMap { String(bytes: $0, encoding: .utf8) }
                    certs.append((meta.id, der, label))
                case 2:
                    let key = try PublicKeyFile(try readFile(meta.fileName))
                    if !key.modulus.isEmpty { keys[meta.id] = key }
                default:
                    break
                }
            } catch let error as APDUError {
                if case .transport = error { throw error }
                continue
            } catch {
                continue  // corrupt or unreadable object: keep the others
            }
        }
        var identities: [CardIdentity] = []
        var extras: [Data] = []
        for cert in certs {
            if let key = keys[cert.id] {
                identities.append(CardIdentity(
                    id: cert.id, certificate: cert.der, role: CardIdentity.role(of: cert.der),
                    label: cert.label, privateKeyFID: key.privateKeyFID,
                    modulus: key.modulus, exponent: key.exponent))
            } else {
                extras.append(cert.der)
            }
        }
        return CardObjects(identities: identities, extraCertificates: extras)
    }
}
