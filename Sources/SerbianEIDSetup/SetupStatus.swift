import Foundation

public enum CardState: Equatable {
    case none
    case unreadable
    case notSerbianEID
    case serbianEID(authIssuedByCA4: Bool)
}

public struct SetupInputs: Equatable {
    public var isInApplicationsFolder: Bool
    public var readerCount: Int
    public var card: CardState
    /// Both MUP certificates present and root trusted.
    public var chainInstalled: Bool
    /// nil = unknown (no card).
    public var tokenRegistered: Bool?

    public init(isInApplicationsFolder: Bool, readerCount: Int, card: CardState,
                chainInstalled: Bool, tokenRegistered: Bool?) {
        self.isInApplicationsFolder = isInApplicationsFolder
        self.readerCount = readerCount
        self.card = card
        self.chainInstalled = chainInstalled
        self.tokenRegistered = tokenRegistered
    }
}

public enum Problem: Equatable {
    case moveToApplications, noReader, noCard, unreadableCard, notSerbianEID
    case unsupportedCardGeneration, chainMissing, tokenNotRegistered
}

public enum CheckState: Equatable {
    case ok
    case pending
    case problem(Problem)
}

public enum CheckKind: CaseIterable {
    case location, reader, card, chain, extensionRegistered
}

public struct SetupReport: Equatable {
    public let checks: [CheckKind: CheckState]
    public let isReady: Bool

    public init(checks: [CheckKind: CheckState], isReady: Bool) {
        self.checks = checks
        self.isReady = isReady
    }
}

public enum SetupEvaluator {
    public static func evaluate(_ inputs: SetupInputs) -> SetupReport {
        let location: CheckState = inputs.isInApplicationsFolder ? .ok : .problem(.moveToApplications)
        let reader: CheckState = inputs.readerCount == 0 ? .problem(.noReader) : .ok

        let card: CheckState
        if inputs.readerCount == 0 {
            card = .pending
        } else {
            switch inputs.card {
            case .none: card = .problem(.noCard)
            case .unreadable: card = .problem(.unreadableCard)
            case .notSerbianEID: card = .problem(.notSerbianEID)
            case .serbianEID(let ca4): card = ca4 ? .ok : .problem(.unsupportedCardGeneration)
            }
        }

        let chain: CheckState
        if card == .problem(.unsupportedCardGeneration) {
            chain = .pending
        } else {
            chain = inputs.chainInstalled ? .ok : .problem(.chainMissing)
        }

        let ext: CheckState
        switch inputs.tokenRegistered {
        case .some(true): ext = .ok
        case .some(false): ext = .problem(.tokenNotRegistered)
        case .none: ext = .pending
        }

        let checks: [CheckKind: CheckState] = [
            .location: location, .reader: reader, .card: card,
            .chain: chain, .extensionRegistered: ext,
        ]
        return SetupReport(checks: checks, isReady: checks.values.allSatisfy { $0 == .ok })
    }
}
