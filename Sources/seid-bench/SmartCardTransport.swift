import Foundation
import CryptoTokenKit
import SerbianEIDPKI

/// APDUTransport over a TKSmartCard. The caller owns the session (`card.withSession`).
final class SmartCardTransport: APDUTransport {
    private let card: TKSmartCard
    private let trace: ((String) -> Void)?

    init(card: TKSmartCard, trace: ((String) -> Void)? = nil) {
        self.card = card
        self.trace = trace
        card.cla = 0x00
    }

    func transmit(_ apdu: APDU) throws -> APDUResponse {
        trace?(APDUTrace.format(apdu))
        let le: Int?
        switch apdu.le {
        case nil: le = nil
        case 256?: le = 0  // CTK reads 0 as 256 in short APDUs
        case let value?: le = value
        }
        do {
            let (sw, data) = try card.send(ins: apdu.ins, p1: apdu.p1, p2: apdu.p2,
                                           data: apdu.data.isEmpty ? nil : Data(apdu.data), le: le)
            let response = APDUResponse(data: [UInt8](data), sw: sw)
            trace?(APDUTrace.format(response, for: apdu))
            return response
        } catch {
            throw APDUError.transport(String(describing: error))
        }
    }
}
