import Foundation

public struct APDU: Equatable {
    public var cla: UInt8
    public var ins: UInt8
    public var p1: UInt8
    public var p2: UInt8
    public var data: [UInt8]
    public var le: Int?

    public init(cla: UInt8 = 0x00, ins: UInt8, p1: UInt8, p2: UInt8, data: [UInt8] = [], le: Int? = nil) {
        self.cla = cla; self.ins = ins; self.p1 = p1; self.p2 = p2
        self.data = data; self.le = le
    }

    /// ISO 7816 short encoding. `le == 256` is encoded as 00, nil means absent.
    public var bytes: [UInt8] {
        var out: [UInt8] = [cla, ins, p1, p2]
        if !data.isEmpty {
            out.append(UInt8(truncatingIfNeeded: data.count))
            out.append(contentsOf: data)
        }
        if let le = le {
            out.append(le >= 256 ? 0x00 : UInt8(truncatingIfNeeded: le))
        }
        return out
    }
}

public struct APDUResponse {
    public var data: [UInt8]
    public var sw: UInt16

    public init(data: [UInt8], sw: UInt16) {
        self.data = data; self.sw = sw
    }

    public var isOK: Bool { sw == 0x9000 }
}

public protocol APDUTransport {
    func transmit(_ apdu: APDU) throws -> APDUResponse
}

public enum APDUError: Error, Equatable {
    case status(UInt16)
    case malformed(String)
    case unsupportedCard
    case transport(String)
}
