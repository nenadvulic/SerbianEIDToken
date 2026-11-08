import CryptoTokenKit
import Security
import SerbianEIDPKI
import SwiftUI

/// One certificate read from the card, for display only.
struct CardCertificate: Identifiable {
    let id = UUID()
    let subject: String
    let role: String
}

/// Reader and card status, read directly from the card (no PIN, no VERIFY).
@MainActor
final class CardStatusModel: ObservableObject {
    @Published var readerStatus = "Checking..."
    @Published var cardStatus = ""
    @Published var certificates: [CardCertificate] = []
    @Published var trustWarning: String?

    private struct Snapshot {
        var reader: String
        var card: String
        var certificates: [CardCertificate] = []
        var trustWarning: String?
    }

    func refresh() {
        readerStatus = "Checking..."
        Task.detached {
            let snapshot = CardStatusModel.readSnapshot()
            await MainActor.run {
                self.readerStatus = snapshot.reader
                self.cardStatus = snapshot.card
                self.certificates = snapshot.certificates
                self.trustWarning = snapshot.trustWarning
            }
        }
    }

    nonisolated private static func readSnapshot() -> Snapshot {
        guard let manager = TKSmartCardSlotManager.default else {
            return Snapshot(reader: "Smart card service unavailable", card: "")
        }
        guard !manager.slotNames.isEmpty else {
            return Snapshot(reader: "No reader connected", card: "")
        }
        for name in manager.slotNames {
            guard let slot = manager.slotNamed(name), slot.state == .validCard,
                  let card = slot.makeSmartCard() else { continue }
            do {
                let objects = try card.withSession {
                    try PKICard(transport: SmartCardTransport(card: card)).discover()
                }
                var snapshot = Snapshot(reader: "Reader: \(name)", card: "Serbian eID card detected")
                snapshot.certificates = objects.identities.map {
                    CardCertificate(subject: subject(of: $0.certificate), role: describe($0.role))
                }
                if let auth = objects.identities.first(where: { $0.role == .authentication })
                    ?? objects.identities.first,
                   !isTrusted(auth.certificate, intermediates: objects.extraCertificates) {
                    snapshot.trustWarning = "The MUP CA4 certificates seem to be missing from the keychain: "
                        + "the authentication certificate is not trusted. Install them from ca.mup.gov.rs."
                }
                return snapshot
            } catch APDUError.unsupportedCard {
                return Snapshot(reader: "Reader: \(name)", card: "The inserted card is not a Serbian eID card")
            } catch {
                return Snapshot(reader: "Reader: \(name)", card: "Could not read the card")
            }
        }
        return Snapshot(reader: "Reader: \(manager.slotNames.joined(separator: ", "))", card: "No card inserted")
    }

    nonisolated private static func subject(of der: Data) -> String {
        guard let certificate = SecCertificateCreateWithData(nil, der as CFData) else { return "Unreadable certificate" }
        return SecCertificateCopySubjectSummary(certificate) as String? ?? "Certificate"
    }

    nonisolated private static func describe(_ role: CertificateRole) -> String {
        switch role {
        case .authentication: return "Authentication"
        case .qualifiedSignature: return "Qualified signature"
        case .other: return "Other"
        }
    }

    /// Evaluates the certificate with the SSL client policy, using the card's extra certificates as intermediates.
    nonisolated private static func isTrusted(_ der: Data, intermediates: [Data]) -> Bool {
        let chain = ([der] + intermediates).compactMap { SecCertificateCreateWithData(nil, $0 as CFData) }
        guard !chain.isEmpty else { return false }
        var trust: SecTrust?
        guard SecTrustCreateWithCertificates(chain as CFArray, SecPolicyCreateSSL(false, nil), &trust) == errSecSuccess,
              let trust else { return false }
        return SecTrustEvaluateWithError(trust, nil)
    }
}

struct ContentView: View {
    @StateObject private var model = CardStatusModel()

    var body: some View {
        VStack(alignment: .leading, spacing: 12) {
            Text("This app installs a CryptoTokenKit extension that makes the certificates of the "
                 + "Serbian ID card available to macOS. Independent project, not affiliated with the Serbian State.")
                .fixedSize(horizontal: false, vertical: true)
            Divider()
            Text(model.readerStatus).font(.headline)
            if !model.cardStatus.isEmpty { Text(model.cardStatus) }
            ForEach(model.certificates) { certificate in
                VStack(alignment: .leading) {
                    Text(certificate.subject)
                    Text(certificate.role).font(.caption).foregroundColor(.secondary)
                }
            }
            if let warning = model.trustWarning {
                Text(warning).foregroundColor(.orange).fixedSize(horizontal: false, vertical: true)
            }
            HStack {
                Spacer()
                Button("Refresh") { model.refresh() }
            }
        }
        .padding(20)
        .frame(width: 480)
        .onAppear { model.refresh() }
    }
}
