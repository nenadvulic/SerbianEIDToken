@preconcurrency import CryptoTokenKit
import Foundation
import SerbianEIDSetup

/// Drives the setup assistant: probes the system off the main thread and
/// re-probes whenever a reader or a card comes or goes.
@MainActor
final class SetupModel: ObservableObject {
    @Published var report: SetupReport?
    /// Filled by the update check (Task 9).
    @Published var update: ReleaseInfo?
    @Published var isWorking = false
    @Published var errorMessage: String?

    private var slotNamesObservation: NSKeyValueObservation?
    private var slotObservations: [String: NSKeyValueObservation] = [:]
    private var pendingRefresh: Task<Void, Never>?
    private var generation = 0

    init() {
        startObservingSlots()
    }

    func refresh() {
        generation += 1
        let current = generation
        Task.detached(priority: .userInitiated) {
            let report = SetupEvaluator.evaluate(SystemProbe.inputs())
            await MainActor.run {
                guard current == self.generation else { return }
                self.report = report
            }
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
