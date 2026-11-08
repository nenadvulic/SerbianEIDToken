import Foundation
@testable import SerbianEIDPKI

final class MockTransport: APDUTransport {
    var script: [(expected: APDU?, response: APDUResponse)]
    private(set) var sent: [APDU] = []

    init(script: [(expected: APDU?, response: APDUResponse)] = []) {
        self.script = script
    }

    func transmit(_ apdu: APDU) throws -> APDUResponse {
        sent.append(apdu)
        guard !script.isEmpty else { throw APDUError.transport("mock script exhausted") }
        let step = script.removeFirst()
        if let expected = step.expected, expected != apdu {
            throw APDUError.transport("unexpected APDU \(apdu.bytes)")
        }
        return step.response
    }
}
