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
/// (the root must be findable for chain building) and marks the root as a trusted
/// root in the user trust-settings domain. Each item is recorded in `UserDefaults`
/// only if this app created it, so `remove()` never touches anything that was
/// already there (e.g. installed by hand from ca.mup.gov.rs).
///
/// `isInstalled()` = the intermediate is in a keychain AND the root has trust
/// settings in the user or admin domain.
enum TrustInstaller {
    private enum Key {
        static let rootAdded = "mupRootAddedByApp"
        static let intermediateAdded = "mupIntermediateAddedByApp"
        static let rootTrustAdded = "mupRootTrustAddedByApp"
    }

    static func isInstalled() -> Bool {
        guard let root = try? certificate(.root),
              let intermediate = try? certificate(.intermediate) else { return false }
        return isInKeychain(intermediate) && hasTrustSettings(root)
    }

    /// Throws before any keychain write if either embedded certificate fails its pinned fingerprint.
    static func install() throws {
        let root = try certificate(.root)
        let intermediate = try certificate(.intermediate)
        let defaults = UserDefaults.standard

        if try add(root) { defaults.set(true, forKey: Key.rootAdded) }
        if try add(intermediate) { defaults.set(true, forKey: Key.intermediateAdded) }

        if !hasTrustSettings(root, domain: .user) {
            let settings: [[String: Any]] = [
                [kSecTrustSettingsResult as String: SecTrustSettingsResult.trustRoot.rawValue],
            ]
            let status = SecTrustSettingsSetTrustSettings(root, .user, settings as CFArray)
            guard status == errSecSuccess else { throw TrustInstallerError.trustSettings(status) }
            defaults.set(true, forKey: Key.rootTrustAdded)
        }
    }

    /// Undoes only what `install()` recorded, then clears the flags.
    static func remove() throws {
        let root = try certificate(.root)
        let intermediate = try certificate(.intermediate)
        let defaults = UserDefaults.standard

        if defaults.bool(forKey: Key.rootTrustAdded) {
            let status = SecTrustSettingsRemoveTrustSettings(root, .user)
            guard status == errSecSuccess || status == errSecItemNotFound else {
                throw TrustInstallerError.trustSettings(status)
            }
            defaults.removeObject(forKey: Key.rootTrustAdded)
        }
        if defaults.bool(forKey: Key.intermediateAdded) {
            try delete(intermediate)
            defaults.removeObject(forKey: Key.intermediateAdded)
        }
        if defaults.bool(forKey: Key.rootAdded) {
            try delete(root)
            defaults.removeObject(forKey: Key.rootAdded)
        }
    }

    // MARK: - Helpers

    private static func certificate(_ which: MUPCertificate) throws -> SecCertificate {
        let der = try MUPChain.verifiedDER(which)
        guard let certificate = SecCertificateCreateWithData(nil, der as CFData) else {
            throw TrustInstallerError.invalidCertificate
        }
        return certificate
    }

    /// Returns true if the certificate was added by this call, false if it was already present.
    private static func add(_ certificate: SecCertificate) throws -> Bool {
        let status = SecItemAdd([
            kSecClass as String: kSecClassCertificate,
            kSecValueRef as String: certificate,
        ] as CFDictionary, nil)
        switch status {
        case errSecSuccess: return true
        case errSecDuplicateItem: return false
        default: throw TrustInstallerError.keychain(status)
        }
    }

    private static func delete(_ certificate: SecCertificate) throws {
        for item in keychainCopies(of: certificate) {
            let status = SecItemDelete([
                kSecClass as String: kSecClassCertificate,
                kSecValueRef as String: item,
            ] as CFDictionary)
            guard status == errSecSuccess || status == errSecItemNotFound else {
                throw TrustInstallerError.keychain(status)
            }
        }
    }

    private static func isInKeychain(_ certificate: SecCertificate) -> Bool {
        !keychainCopies(of: certificate).isEmpty
    }

    /// Keychain items whose DER equals the given certificate.
    private static func keychainCopies(of certificate: SecCertificate) -> [SecCertificate] {
        var query: [String: Any] = [
            kSecClass as String: kSecClassCertificate,
            kSecMatchLimit as String: kSecMatchLimitAll,
            kSecReturnRef as String: true,
        ]
        if let label = SecCertificateCopySubjectSummary(certificate) as String? {
            query[kSecAttrLabel as String] = label
        }
        var result: CFTypeRef?
        guard SecItemCopyMatching(query as CFDictionary, &result) == errSecSuccess,
              let items = result as? [SecCertificate] else { return [] }
        let der = SecCertificateCopyData(certificate) as Data
        return items.filter { SecCertificateCopyData($0) as Data == der }
    }

    private static func hasTrustSettings(_ certificate: SecCertificate) -> Bool {
        hasTrustSettings(certificate, domain: .user) || hasTrustSettings(certificate, domain: .admin)
    }

    private static func hasTrustSettings(_ certificate: SecCertificate, domain: SecTrustSettingsDomain) -> Bool {
        var settings: CFArray?
        return SecTrustSettingsCopyTrustSettings(certificate, domain, &settings) == errSecSuccess
    }
}
