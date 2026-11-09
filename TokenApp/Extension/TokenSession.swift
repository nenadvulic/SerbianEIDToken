import CryptoTokenKit
import Security
import SerbianEIDPKI

/// Session for one client of the token: PIN through the system prompt, then signing on the card.
/// The card is not relocked after a signature: the PIN stays valid until the card is removed.
final class TokenSession: TKSmartCardTokenSession, TKTokenSessionDelegate {
    /// Every SecKeyAlgorithm that CardSignatureAlgorithm knows how to map.
    private static let candidates: [SecKeyAlgorithm] = [
        .rsaSignatureDigestPKCS1v15SHA1,
        .rsaSignatureDigestPKCS1v15SHA256,
        .rsaSignatureDigestPKCS1v15SHA384,
        .rsaSignatureDigestPKCS1v15SHA512,
        .rsaSignatureDigestPKCS1v15Raw,
        .rsaSignatureRaw,
        .rsaSignatureDigestPSSSHA256,
        .rsaSignatureDigestPSSSHA384,
        .rsaSignatureDigestPSSSHA512,
    ]

    private var cardToken: Token? { token as? Token }

    private static func cardAlgorithm(for algorithm: TKTokenKeyAlgorithm) -> CardSignatureAlgorithm? {
        for candidate in candidates where algorithm.isAlgorithm(candidate) {
            if let mapped = CardSignatureAlgorithm(candidate) { return mapped }
        }
        return nil
    }

    func tokenSession(_ session: TKTokenSession, supports operation: TKTokenOperation,
                      keyObjectID: TKToken.ObjectID, algorithm: TKTokenKeyAlgorithm) -> Bool {
        guard operation == .signData, cardToken?.identity(for: keyObjectID) != nil else { return false }
        return TokenSession.cardAlgorithm(for: algorithm) != nil
    }

    /// The system shows the PIN window, fills the template and sends VERIFY itself.
    func tokenSession(_ session: TKTokenSession, beginAuthFor operation: TKTokenOperation,
                      constraint: Any) throws -> TKTokenAuthOperation {
        guard let value = constraint as? String, value == Token.pinConstraint else {
            throw TKError(.badParameter)
        }
        let auth = PINAuthOperation()
        auth.pinFormat.charset = .numeric
        auth.pinFormat.minPINLength = 4
        auth.pinFormat.maxPINLength = 8
        auth.pinFormat.encoding = .ascii
        auth.pinFormat.pinBlockByteLength = 8
        auth.pinFormat.pinJustification = .left
        auth.apduTemplate = Data(PaddedPIN.verifyTemplate) + Data(repeating: 0x00, count: 8)
        auth.pinByteOffset = 5
        auth.smartCard = smartCard
        return auth
    }

    func tokenSession(_ session: TKTokenSession, sign dataToSign: Data, keyObjectID: TKToken.ObjectID,
                      algorithm: TKTokenKeyAlgorithm) throws -> Data {
        guard let token = cardToken, let identity = token.identity(for: keyObjectID),
              let cardAlgorithm = TokenSession.cardAlgorithm(for: algorithm) else {
            throw TKError(.badParameter)
        }
        let request: SignRequest
        do {
            request = try cardAlgorithm.request(for: [UInt8](dataToSign), modulusBits: identity.keySizeInBits)
        } catch {
            throw TKError(.badParameter)
        }
        // The system already holds an exclusive session with the applet selected (the token has an
        // AID): no withSession here, and no SELECT that could reset the PIN status.
        do {
            let signature = try PKICard(transport: SmartCardTransport(card: smartCard))
                .sign(request, keyFID: identity.privateKeyFID)
            return Data(signature)
        } catch APDUError.status(0x6982) {
            throw TKError(.authenticationNeeded)  // security status not satisfied: the system asks the PIN again
        } catch APDUError.malformed {
            throw TKError(.badParameter)
        } catch {
            throw TKError(.communicationError)
        }
    }
}

/// PIN operation for readers without a pinpad: the base class only collects the PIN, so finish()
/// sends the VERIFY itself. Exactly one VERIFY per entry, never retried, PIN cleared after use.
final class PINAuthOperation: TKTokenSmartCardPINAuthOperation {
    override func finish() throws {
        let entered = pin
        pin = nil
        guard let entered = entered, (try? PaddedPIN(entered)) != nil else {
            throw TKError(.authenticationFailed)  // nothing sent to the card
        }
        guard let card = smartCard else { throw TKError(.communicationError) }
        // The token session's card already has the applet selected: no SELECT, no withSession.
        let result: PINResult
        do {
            result = try PKICard(transport: SmartCardTransport(card: card)).verifyPIN(entered)
        } catch {
            throw TKError(.communicationError)
        }
        switch result {
        case .ok:
            return
        case .wrong(let left):
            let message = left.map { "Wrong PIN, \($0) attempts left" } ?? "Wrong PIN"
            throw TKError(.authenticationFailed, userInfo: [NSLocalizedDescriptionKey: message])
        case .blocked:
            throw TKError(.authenticationFailed, userInfo: [NSLocalizedDescriptionKey: "PIN blocked"])
        }
    }
}
