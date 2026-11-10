import CryptoTokenKit
import Foundation
import Security
import SerbianEIDPKI
import SerbianEIDSetup

/// Reads the system state the setup assistant needs. Blocking: call off the main thread.
enum SystemProbe {
    static let tokenIDPrefix = "rs.serbiandocuments.SerbianEIDToken:"

    static func inputs() -> SetupInputs {
        let isInApplications = Bundle.main.bundleURL.path.hasPrefix("/Applications/")
        let (readerCount, card, authTrusted) = probeCard()
        let chainInstalled = TrustInstaller.isInstalled() || authTrusted

        let tokenRegistered: Bool?
        if case .serbianEID = card {
            tokenRegistered = TKTokenWatcher().tokenIDs.contains { $0.hasPrefix(tokenIDPrefix) }
        } else {
            tokenRegistered = nil
        }
        return SetupInputs(isInApplicationsFolder: isInApplications, readerCount: readerCount, card: card,
                           chainInstalled: chainInstalled, tokenRegistered: tokenRegistered)
    }

    /// Walks the reader slots (no PIN, no VERIFY). Returns the reader count, the card state of the
    /// first slot holding a card, and whether that card's authentication certificate is trusted.
    private static func probeCard() -> (readers: Int, card: CardState, authTrusted: Bool) {
        guard let manager = TKSmartCardSlotManager.default else { return (0, CardState.none, false) }
        let names = manager.slotNames
        var fallback = CardState.none
        for name in names {
            guard let slot = manager.slotNamed(name) else { continue }
            switch slot.state {
            case .validCard: break
            case .muteCard:
                fallback = .unreadable
                continue
            default: continue
            }
            guard let card = slot.makeSmartCard() else {
                fallback = .unreadable
                continue
            }
            do {
                let objects = try card.withSession {
                    try PKICard(transport: SmartCardTransport(card: card)).discover()
                }
                guard let auth = objects.identities.first(where: { $0.role == .authentication })
                        ?? objects.identities.first else {
                    return (names.count, .unreadable, false)
                }
                let ca4 = IssuerCheck.isIssuedByMUPGradjaniCA4(auth.certificate)
                let trusted = isTrusted(auth.certificate, intermediates: objects.extraCertificates)
                return (names.count, .serbianEID(authIssuedByCA4: ca4), trusted)
            } catch APDUError.unsupportedCard {
                return (names.count, .notSerbianEID, false)
            } catch {
                return (names.count, .unreadable, false)
            }
        }
        return (names.count, fallback, false)
    }

    /// Evaluates the certificate with the SSL client policy, using the card's extra certificates as intermediates.
    private static func isTrusted(_ der: Data, intermediates: [Data]) -> Bool {
        let chain = ([der] + intermediates).compactMap { SecCertificateCreateWithData(nil, $0 as CFData) }
        guard !chain.isEmpty else { return false }
        var trust: SecTrust?
        guard SecTrustCreateWithCertificates(chain as CFArray, SecPolicyCreateSSL(false, nil), &trust) == errSecSuccess,
              let trust else { return false }
        SecTrustSetNetworkFetchAllowed(trust, false)  // no AIA fetch: no network besides the release check
        return SecTrustEvaluateWithError(trust, nil)
    }
}
