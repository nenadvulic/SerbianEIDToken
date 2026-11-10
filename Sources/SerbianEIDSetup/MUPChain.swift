import Foundation
import CryptoKit

public enum MUPCertificate: CaseIterable {
    case root, intermediate

    /// SHA-256 of the DER encoding, uppercase hex without separators.
    public var expectedSHA256: String {
        switch self {
        case .root: return "6DCA4AB9CABD18E5CB0023054316ABF78C99B531B2E3AA103109AFB9DFA836D4"
        case .intermediate: return "0E3EFEB4F77F95118D2A2D5870709C924647BBDB801CAFDBE727D3F4DC354566"
        }
    }

    public var resourceName: String {
        switch self {
        case .root: return "MUPRootCA4"
        case .intermediate: return "MUPGradjaniCA4"
        }
    }
}

public enum MUPChainError: Error, Equatable {
    case missingResource(String)
    case fingerprintMismatch(MUPCertificate)
}

public enum MUPChain {
    /// Loads the embedded certificate and checks it against the pinned fingerprint.
    public static func verifiedDER(_ c: MUPCertificate, bundle: Bundle? = nil) throws -> Data {
        let bundle = bundle ?? Bundle.module
        guard let url = bundle.url(forResource: c.resourceName, withExtension: "cer", subdirectory: "Resources")
                ?? bundle.url(forResource: c.resourceName, withExtension: "cer"),
              let der = try? Data(contentsOf: url) else {
            throw MUPChainError.missingResource(c.resourceName)
        }
        try verify(der: der, as: c)
        return der
    }

    public static func verify(der: Data, as c: MUPCertificate) throws {
        let hex = SHA256.hash(data: der).map { String(format: "%02X", $0) }.joined()
        guard hex == c.expectedSHA256 else { throw MUPChainError.fingerprintMismatch(c) }
    }
}
