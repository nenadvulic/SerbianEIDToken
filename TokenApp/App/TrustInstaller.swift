import Foundation
import Security
import SerbianEIDSetup

enum TrustInstallerError: LocalizedError {
    case keychain(OSStatus)
    case trustSettings(OSStatus)
    case invalidCertificate

    var errorDescription: String? {
        switch self {
        case .keychain(let status), .trustSettings(let status):
            let detail = SecCopyErrorMessageString(status, nil) as String? ?? "\(status)"
            return String(localized: "The MUP certificates could not be changed: \(detail)")
        case .invalidCertificate:
            return String(localized: "The embedded MUP certificates are invalid.")
        }
    }
}

/// Installs and removes the pinned MUP CA4 chain for the current user.
///
/// `install()` adds the root and the intermediate to the user's default keychain
/// (the root must be findable for chain building) and, unless the chain already
/// evaluates as trusted, marks the root as a trusted root in the user
/// trust-settings domain. For each keychain item it created, the app stores the
/// item's persistent reference in `UserDefaults`; `remove()` deletes only those
/// exact items, so copies installed by hand (in any keychain) are never touched.
///
/// `isInstalled()` = the intermediate is in a keychain AND it evaluates as
/// trusted (basic X.509 policy, system/user anchors only, no network fetch), so
/// "Never Trust" settings or a missing root report not installed.
enum TrustInstaller {
    private enum Key {
        /// Persistent reference (Data) of the keychain item the app created.
        static let rootRef = "mupRootPersistentRefAddedByApp"
        static let intermediateRef = "mupIntermediatePersistentRefAddedByApp"
        static let rootTrustAdded = "mupRootTrustAddedByApp"
    }

    static func isInstalled() -> Bool {
        guard let intermediate = try? certificate(.intermediate) else { return false }
        return isInKeychain(intermediate) && chainEvaluates(intermediate)
    }

    /// Throws before any keychain write if either embedded certificate fails its pinned fingerprint.
    static func install() throws {
        let root = try certificate(.root)
        let intermediate = try certificate(.intermediate)
        let defaults = UserDefaults.standard

        if let ref = try add(root) { defaults.set(ref, forKey: Key.rootRef) }
        if let ref = try add(intermediate) { defaults.set(ref, forKey: Key.intermediateRef) }

        if !chainEvaluates(intermediate) {
            // nil = "always trust this root", the same setting as `security add-trusted-cert -r trustRoot`
            // (an empty trust-settings array), which was validated with a real card in Safari.
            let status = SecTrustSettingsSetTrustSettings(root, .user, nil)
            guard status == errSecSuccess else { throw TrustInstallerError.trustSettings(status) }
            defaults.set(true, forKey: Key.rootTrustAdded)
        }
    }

    /// Undoes only what `install()` recorded, then clears the flags.
    static func remove() throws {
        let root = try certificate(.root)
        let defaults = UserDefaults.standard

        if defaults.bool(forKey: Key.rootTrustAdded) {
            let status = SecTrustSettingsRemoveTrustSettings(root, .user)
            guard status == errSecSuccess || status == errSecItemNotFound else {
                throw TrustInstallerError.trustSettings(status)
            }
            defaults.removeObject(forKey: Key.rootTrustAdded)
        }
        for key in [Key.intermediateRef, Key.rootRef] {
            if let ref = defaults.data(forKey: key) { try delete(persistentRef: ref) }
            defaults.removeObject(forKey: key)
        }
    }

    // MARK: - Helpers

    /// Any `MUPChainError` (missing resource, fingerprint mismatch) is surfaced as the
    /// localized `invalidCertificate`, never as an untranslated framework error.
    private static func certificate(_ which: MUPCertificate) throws -> SecCertificate {
        let der: Data
        do {
            der = try MUPChain.verifiedDER(which)
        } catch {
            throw TrustInstallerError.invalidCertificate
        }
        guard let certificate = SecCertificateCreateWithData(nil, der as CFData) else {
            throw TrustInstallerError.invalidCertificate
        }
        return certificate
    }

    /// Returns the persistent reference of the item created by this call, or nil if it was already present.
    private static func add(_ certificate: SecCertificate) throws -> Data? {
        var result: CFTypeRef?
        let status = SecItemAdd([
            kSecClass as String: kSecClassCertificate,
            kSecValueRef as String: certificate,
            kSecReturnPersistentRef as String: true,
        ] as CFDictionary, &result)
        switch status {
        case errSecSuccess:
            // File-based (login) keychains return an array of persistent refs, not a single Data.
            if let ref = result as? Data { return ref }
            if let refs = result as? [Data], let ref = refs.first { return ref }
            throw TrustInstallerError.keychain(errSecInternalError)
        case errSecDuplicateItem: return nil
        default: throw TrustInstallerError.keychain(status)
        }
    }

    /// Deletes exactly the item the app created; an item already gone counts as removed.
    private static func delete(persistentRef: Data) throws {
        let status = SecItemDelete([
            kSecClass as String: kSecClassCertificate,
            kSecValuePersistentRef as String: persistentRef,
        ] as CFDictionary)
        guard status == errSecSuccess || status == errSecItemNotFound else {
            throw TrustInstallerError.keychain(status)
        }
    }

    private static func isInKeychain(_ certificate: SecCertificate) -> Bool {
        !keychainCopies(of: certificate).isEmpty
    }

    /// Keychain items whose DER equals the given certificate. No label filter: a copy
    /// imported by hand may carry any label, so all certificates are compared by DER.
    private static func keychainCopies(of certificate: SecCertificate) -> [SecCertificate] {
        let query: [String: Any] = [
            kSecClass as String: kSecClassCertificate,
            kSecMatchLimit as String: kSecMatchLimitAll,
            kSecReturnRef as String: true,
        ]
        var result: CFTypeRef?
        guard SecItemCopyMatching(query as CFDictionary, &result) == errSecSuccess,
              let items = result as? [SecCertificate] else { return [] }
        let der = SecCertificateCopyData(certificate) as Data
        return items.filter { SecCertificateCopyData($0) as Data == der }
    }

    /// True when the pinned intermediate chains to a trusted root using only the
    /// system's anchors and trust settings. Basic X.509 policy, because the SSL
    /// policy's leaf EKU checks do not fit a CA certificate. No network fetch.
    private static func chainEvaluates(_ intermediate: SecCertificate) -> Bool {
        var trust: SecTrust?
        guard SecTrustCreateWithCertificates(intermediate, SecPolicyCreateBasicX509(), &trust) == errSecSuccess,
              let trust else { return false }
        SecTrustSetNetworkFetchAllowed(trust, false)
        return SecTrustEvaluateWithError(trust, nil)
    }
}
