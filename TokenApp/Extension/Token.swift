import CryptoKit
import CryptoTokenKit
import Security
import SerbianEIDPKI

/// Token for one inserted Serbian eID card. Exposes each certificate/key pair read from the
/// card as keychain items, plus any extra certificate (for example the issuing CA).
final class Token: TKSmartCardToken, TKTokenDelegate {
    /// Value stored in key constraints for operations that need the card PIN.
    static let pinConstraint = "PIN"

    let identities: [CardIdentity]

    /// Reads the card before registering the token. Never sends VERIFY.
    init(smartCard: TKSmartCard, aid AID: Data?, tokenDriver: TKSmartCardTokenDriver) throws {
        let objects = try Token.discover(on: smartCard)
        guard !objects.identities.isEmpty else { throw TKError(.tokenNotFound) }
        identities = objects.identities
        super.init(smartCard: smartCard, aid: AID,
                   instanceID: Token.instanceID(for: objects.identities),
                   tokenDriver: tokenDriver)
        delegate = self
        keychainContents?.fill(with: try Token.keychainItems(for: objects))
    }

    func identity(for objectID: TKToken.ObjectID) -> CardIdentity? {
        guard let data = objectID as? Data else { return nil }
        return identities.first { Data($0.id) == data }
    }

    func createSession(_ token: TKToken) throws -> TKTokenSession {
        let session = TokenSession(token: self)
        session.delegate = session
        return session
    }

    // MARK: - Discovery

    /// Maps card errors to TKError: an unknown applet becomes `tokenNotFound` so the card is left to others.
    private static func discover(on card: TKSmartCard) throws -> CardObjects {
        do {
            return try card.withSession {
                try PKICard(transport: SmartCardTransport(card: card)).discover()
            }
        } catch let error as APDUError {
            switch error {
            case .unsupportedCard: throw TKError(.tokenNotFound)
            case .transport: throw TKError(.communicationError)
            case .status, .malformed: throw TKError(.corruptedData)
            }
        } catch let error as TKError {
            throw error
        } catch {
            throw TKError(.communicationError)
        }
    }

    /// Stable per card: derived from the certificates, which do not change between insertions.
    private static func instanceID(for identities: [CardIdentity]) -> String {
        var hasher = SHA256()
        for identity in identities { hasher.update(data: identity.certificate) }
        return hasher.finalize().prefix(8).map { String(format: "%02x", $0) }.joined()
    }

    // MARK: - Keychain items

    /// Object IDs: key = id, certificate = id + 01, extra certificate = CA + index.
    private static func keychainItems(for objects: CardObjects) throws -> [TKTokenKeychainItem] {
        var items: [TKTokenKeychainItem] = []
        for identity in objects.identities {
            guard let certificate = SecCertificateCreateWithData(nil, identity.certificate as CFData),
                  let certItem = TKTokenKeychainCertificate(certificate: certificate,
                                                            objectID: Data(identity.id) + [0x01]),
                  let keyItem = TKTokenKeychainKey(certificate: certificate, objectID: Data(identity.id))
            else { throw TKError(.corruptedData) }
            certItem.label = identity.label
            keyItem.label = identity.label
            keyItem.keyType = kSecAttrKeyTypeRSA as String
            keyItem.keySizeInBits = identity.keySizeInBits
            keyItem.canSign = true
            keyItem.canDecrypt = false
            keyItem.canPerformKeyExchange = false
            keyItem.constraints = [NSNumber(value: TKTokenOperation.signData.rawValue): pinConstraint]
            items.append(certItem)
            items.append(keyItem)
        }
        for (index, der) in objects.extraCertificates.enumerated() where index <= 0xFF {
            guard let certificate = SecCertificateCreateWithData(nil, der as CFData),
                  let item = TKTokenKeychainCertificate(certificate: certificate,
                                                        objectID: Data([0xCA, UInt8(index)]))
            else { continue }  // an unparsable CA certificate must not hide the identities
            items.append(item)
        }
        return items
    }
}
