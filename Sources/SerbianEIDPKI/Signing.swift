import Foundation

extension Commands {
    /// MANAGE SECURITY ENVIRONMENT, set the signature key and algorithm (00 raw block, 02 DigestInfo).
    public static func mseSet(keyFID: [UInt8], algorithm: UInt8) -> APDU {
        APDU(ins: 0x22, p1: 0x41, p2: 0xB6, data: [0x80, 0x01, algorithm, 0x84, 0x02] + keyFID)
    }

    /// PERFORM SECURITY OPERATION, compute digital signature. For a raw block the first byte
    /// travels in P2 so the remaining 255 bytes fit one short APDU.
    public static func pso(_ request: SignRequest) -> APDU {
        switch request {
        case .digestInfo(let data):
            return APDU(ins: 0x2A, p1: 0x9E, p2: 0x00, data: data, le: 256)
        case .rawBlock(let block):
            return APDU(ins: 0x2A, p1: 0x9E, p2: block[0], data: Array(block.dropFirst()), le: 256)
        }
    }
}

extension PKICard {
    /// MSE SET then PSO back to back. No SELECT, VERIFY or transaction: the caller owns the session.
    public func sign(_ request: SignRequest, keyFID: [UInt8]) throws -> [UInt8] {
        guard keyFID.count == 2 else { throw APDUError.malformed("key FID must be 2 bytes") }
        let algorithm: UInt8
        switch request {
        case .digestInfo(let data):
            guard !data.isEmpty, data.count <= 255 else {
                throw APDUError.malformed("DigestInfo length \(data.count) out of range")
            }
            algorithm = 0x02
        case .rawBlock(let block):
            guard block.count == 256 else {
                throw APDUError.malformed("raw block length \(block.count), expected 256")
            }
            algorithm = 0x00
        }
        let mse = try transport.transmit(Commands.mseSet(keyFID: keyFID, algorithm: algorithm))
        guard mse.isOK else { throw APDUError.status(mse.sw) }
        let pso = try transport.transmit(Commands.pso(request))
        guard pso.isOK else { throw APDUError.status(pso.sw) }
        return pso.data
    }
}
