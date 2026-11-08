import Foundation

public enum Commands {
    static let pkcs15AID: [UInt8] = [0xA0, 0x00, 0x00, 0x00, 0x63, 0x50, 0x4B, 0x43, 0x53, 0x2D, 0x31, 0x35]

    public static func selectPKCS15Applet() -> APDU {
        APDU(ins: 0xA4, p1: 0x04, p2: 0x00, data: pkcs15AID, le: 255)
    }

    public static func selectFile(_ fid: [UInt8], le: Int?, p2: UInt8 = 0x00) -> APDU {
        APDU(ins: 0xA4, p1: 0x00, p2: p2, data: fid, le: le)
    }

    public static func readBinary(offset: Int, length: Int) -> APDU {
        APDU(ins: 0xB0, p1: UInt8((offset >> 8) & 0xFF), p2: UInt8(offset & 0xFF), le: min(length, 255))
    }
}
