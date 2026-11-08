import Foundation

/// A PIN of 4 to 8 ASCII digits, right-padded with 0x00 to 8 bytes.
public struct PaddedPIN {
    /// First 5 bytes of the VERIFY APDU (CLA INS P1 P2 Lc). Used to recognize and mask it in traces.
    public static let verifyTemplate: [UInt8] = [0x00, 0x20, 0x00, 0x80, 0x08]

    public private(set) var bytes: [UInt8]

    public init(_ pin: String) throws {
        let digits = Array(pin.utf8)
        guard (4...8).contains(digits.count), digits.allSatisfy({ (0x30...0x39).contains($0) }) else {
            throw APDUError.malformed("PIN must be 4 to 8 digits")
        }
        bytes = digits + [UInt8](repeating: 0x00, count: 8 - digits.count)
    }

    /// Best effort wipe. Swift arrays are value types: copies made earlier (for example inside an
    /// APDU, a String or the transport) are not reachable and are not zeroed by this call.
    mutating func wipe() {
        for i in bytes.indices { bytes[i] = 0 }
    }
}

public enum PINResult: Equatable {
    case ok
    case wrong(retriesLeft: Int?)
    case blocked

    public static func from(sw: UInt16) -> PINResult {
        switch sw {
        case 0x9000: return .ok
        case 0x6983, 0x63C0: return .blocked
        case 0x63C1...0x63CF: return .wrong(retriesLeft: Int(sw & 0x0F))
        default: return .wrong(retriesLeft: nil)
        }
    }
}

extension Commands {
    public static func verifyPIN(_ pin: PaddedPIN) -> APDU {
        APDU(ins: 0x20, p1: 0x00, p2: 0x80, data: pin.bytes)
    }
}

extension PKICard {
    /// Sends exactly one VERIFY. The applet must already be selected by the caller. Never retries.
    public func verifyPIN(_ pin: String) throws -> PINResult {
        var padded = try PaddedPIN(pin)
        defer { padded.wipe() }
        let response = try transport.transmit(Commands.verifyPIN(padded))
        return PINResult.from(sw: response.sw)
    }
}
