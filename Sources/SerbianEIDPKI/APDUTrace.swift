import Foundation

/// Human readable APDU traces. VERIFY (INS 0x20) data is never printed.
public enum APDUTrace {
    private static func hex(_ bytes: [UInt8]) -> String {
        bytes.map { String(format: "%02X", $0) }.joined(separator: " ")
    }

    public static func format(_ apdu: APDU) -> String {
        let header = hex([apdu.cla, apdu.ins, apdu.p1, apdu.p2])
        var out = "> " + header
        if !apdu.data.isEmpty {
            out += apdu.ins == 0x20
                ? " \(String(format: "%02X", apdu.data.count)) <PIN masked>"
                : " \(String(format: "%02X", apdu.data.count)) " + hex(apdu.data)
        }
        if let le = apdu.le { out += " " + String(format: "%02X", le >= 256 ? 0 : le) }
        return out
    }

    public static func format(_ response: APDUResponse, for apdu: APDU) -> String {
        let sw = String(format: "%04X", response.sw)
        if apdu.ins == 0x20 { return "< SW=\(sw)" }
        return "< " + (response.data.isEmpty ? "" : hex(response.data) + " ") + "SW=\(sw)"
    }
}
