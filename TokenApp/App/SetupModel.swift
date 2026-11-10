@preconcurrency import CryptoTokenKit
import Foundation
import SerbianEIDSetup

/// Drives the setup assistant: probes the system off the main thread and
/// re-probes whenever a reader, a card or one of our tokens comes or goes.
///
/// Probes run one at a time on a serial queue (two overlapping card sessions
/// could make the card look unreadable). A refresh requested while a probe is
/// running queues at most one follow-up probe; the generation guard discards
/// the result of a probe that was superseded by a newer request.
@MainActor
final class SetupModel: ObservableObject {
    @Published var report: SetupReport?
    /// Filled by the daily update check.
    @Published var update: ReleaseInfo?
    @Published var isWorking = false
    @Published var errorMessage: String?

    private var slotNamesObservation: NSKeyValueObservation?
    private var slotObservations: [String: NSKeyValueObservation] = [:]
    private var pendingRefresh: Task<Void, Never>?
    private var generation = 0
    private var probeRunning = false
    private var probeQueued = false
    private let probeQueue = DispatchQueue(label: "rs.serbiandocuments.SerbianEIDTokenApp.probe", qos: .userInitiated)
    private let tokenWatcher = TKTokenWatcher()

    init() {
        startObservingSlots()
        startObservingTokens()
        Task { [weak self] in
            let release = await UpdateChecker.checkIfDue()
            self?.update = release
        }
    }

    func refresh() {
        generation += 1
        if probeRunning {
            probeQueued = true
        } else {
            startProbe()
        }
    }

    private func startProbe() {
        probeRunning = true
        let current = generation
        probeQueue.async {
            let report = SetupEvaluator.evaluate(SystemProbe.inputs())
            Task { @MainActor in self.finishProbe(report, generation: current) }
        }
    }

    private func finishProbe(_ report: SetupReport, generation current: Int) {
        probeRunning = false
        if current == generation { self.report = report }
        if probeQueued {
            probeQueued = false
            startProbe()
        }
    }

    func installChain() {
        runTrustChange { try TrustInstaller.install() }
    }

    func removeChain() {
        runTrustChange { try TrustInstaller.remove() }
    }

    private func runTrustChange(_ change: @escaping @Sendable () throws -> Void) {
        guard !isWorking else { return }
        isWorking = true
        errorMessage = nil
        Task.detached(priority: .userInitiated) {
            let message: String?
            do { try change(); message = nil } catch { message = error.localizedDescription }
            await MainActor.run {
                self.isWorking = false
                self.errorMessage = message
                self.refresh()
            }
        }
    }

    // MARK: - Token observation

    /// The extension's token appears some time after the card is read; without this the
    /// checklist would keep "re-insert the card" until something else triggered a refresh.
    /// The insertion handler is also called for tokens already present when it is set.
    private func startObservingTokens() {
        tokenWatcher.setInsertionHandler { [weak self] tokenID in
            guard tokenID.hasPrefix(SystemProbe.tokenIDPrefix) else { return }
            Task { @MainActor [weak self] in
                self?.watchRemoval(of: tokenID)
                self?.scheduleRefresh()
            }
        }
    }

    /// Removal handlers are one-shot and per token; re-added on each insertion.
    private func watchRemoval(of tokenID: String) {
        tokenWatcher.addRemovalHandler({ [weak self] _ in
            Task { @MainActor [weak self] in self?.scheduleRefresh() }
        }, forTokenID: tokenID)
    }

    // MARK: - Slot observation

    /// Coalesces bursts of KVO notifications (a card insertion fires several state changes).
    private func scheduleRefresh() {
        pendingRefresh?.cancel()
        pendingRefresh = Task { [weak self] in
            try? await Task.sleep(nanoseconds: 300_000_000)
            guard !Task.isCancelled else { return }
            self?.refresh()
        }
    }

    private func startObservingSlots() {
        guard let manager = TKSmartCardSlotManager.default else { return }
        slotNamesObservation = manager.observe(\.slotNames, options: [.initial]) { [weak self] manager, _ in
            let names = manager.slotNames
            Task { @MainActor [weak self] in
                self?.updateSlotObservations(names: names, manager: manager)
                self?.scheduleRefresh()
            }
        }
    }

    private func updateSlotObservations(names: [String], manager: TKSmartCardSlotManager) {
        for name in slotObservations.keys where !names.contains(name) {
            slotObservations[name] = nil
        }
        for name in names where slotObservations[name] == nil {
            manager.getSlot(withName: name) { [weak self] slot in
                guard let slot else { return }
                Task { @MainActor [weak self] in
                    guard let self, self.slotObservations[name] == nil,
                          TKSmartCardSlotManager.default?.slotNames.contains(name) == true else { return }
                    self.slotObservations[name] = slot.observe(\.state) { [weak self] _, _ in
                        Task { @MainActor [weak self] in self?.scheduleRefresh() }
                    }
                    self.scheduleRefresh()
                }
            }
        }
    }
}
