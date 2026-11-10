import SerbianEIDSetup
import SwiftUI

struct SetupView: View {
    @StateObject private var model = SetupModel()
    @State private var showTroubleshooting = false

    private static let order: [CheckKind] = [.location, .reader, .card, .chain, .extensionRegistered]

    var body: some View {
        VStack(alignment: .leading, spacing: 14) {
            Text("Serbian eID setup").font(.title2.bold())
            Text("This app lets Safari and Chrome use the Serbian ID card to log in to eUprava.")
                .fixedSize(horizontal: false, vertical: true)
            Divider()

            if let report = model.report {
                ForEach(Self.order, id: \.self) { kind in
                    CheckRow(kind: kind, state: report.checks[kind] ?? .pending,
                             isWorking: model.isWorking, install: model.installChain)
                }
                if report.isReady {
                    Label("Ready: open eUprava in Safari or Chrome", systemImage: "checkmark.seal.fill")
                        .font(.headline)
                        .foregroundColor(.green)
                }
            } else {
                HStack(spacing: 8) {
                    ProgressView().controlSize(.small)
                    Text("Checking…")
                }
            }

            if let error = model.errorMessage {
                Text(error).foregroundColor(.red).fixedSize(horizontal: false, vertical: true)
            }

            DisclosureGroup("Troubleshooting", isExpanded: $showTroubleshooting) {
                VStack(alignment: .leading, spacing: 8) {
                    Text("• After installing or updating, remove the card and insert it again.")
                    Text("• Quit Chrome completely with Cmd+Q, then open it again.")
                    Text("• Plug the card reader directly into the Mac, not through a hub.")
                    Button("Remove MUP certificates") { model.removeChain() }
                        .disabled(model.isWorking)
                }
                .fixedSize(horizontal: false, vertical: true)
                .padding(.top, 6)
            }

            Divider()
            HStack {
                Text("Independent project, not affiliated with the Serbian State.")
                    .font(.caption)
                    .foregroundColor(.secondary)
                Spacer()
                Button("Check again") { model.refresh() }
            }
        }
        .padding(20)
        .frame(width: 520)
        .onAppear { model.refresh() }
    }
}

private struct CheckRow: View {
    let kind: CheckKind
    let state: CheckState
    let isWorking: Bool
    let install: () -> Void

    var body: some View {
        HStack(alignment: .top, spacing: 10) {
            icon.frame(width: 20)
            VStack(alignment: .leading, spacing: 4) {
                Text(title).font(.headline)
                if let detail {
                    Text(detail).foregroundColor(.secondary).fixedSize(horizontal: false, vertical: true)
                }
                if state == .problem(.chainMissing) {
                    Button("Install MUP certificates", action: install).disabled(isWorking)
                }
            }
        }
    }

    @ViewBuilder private var icon: some View {
        switch state {
        case .ok: Image(systemName: "checkmark.circle.fill").foregroundColor(.green)
        case .pending: Image(systemName: "circle.dotted").foregroundColor(.secondary)
        case .problem: Image(systemName: "exclamationmark.triangle.fill").foregroundColor(.orange)
        }
    }

    private var title: String {
        switch kind {
        case .location: return String(localized: "App location")
        case .reader: return String(localized: "Card reader")
        case .card: return String(localized: "ID card")
        case .chain: return String(localized: "MUP certificates")
        case .extensionRegistered: return String(localized: "Browser access")
        }
    }

    private var detail: String? {
        switch state {
        case .ok: return nil
        case .pending: return String(localized: "Waiting for the previous steps.")
        case .problem(let problem): return Self.message(for: problem)
        }
    }

    private static func message(for problem: Problem) -> String {
        switch problem {
        case .moveToApplications:
            return String(localized: "Move this app to the Applications folder, then open it from there.")
        case .noReader:
            return String(localized: "Connect a smart card reader.")
        case .noCard:
            return String(localized: "Insert your ID card into the reader.")
        case .unreadableCard:
            return String(localized: "The card could not be read. Remove it and insert it again.")
        case .notSerbianEID:
            return String(localized: "The inserted card is not a Serbian ID card.")
        case .unsupportedCardGeneration:
            return String(localized: "This ID card was issued before the current MUP certificates and is not supported.")
        case .chainMissing:
            return String(localized: "The MUP certificates are not installed. macOS will ask for your password.")
        case .tokenNotRegistered:
            return String(localized: "macOS has not activated the extension yet. Remove the card and insert it again.")
        }
    }
}
