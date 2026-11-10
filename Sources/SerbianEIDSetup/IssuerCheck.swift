import Foundation
import Security

public enum IssuerCheck {
    /// True when the leaf's issuer name equals the CA's subject name.
    /// Invalid DER yields false. This is a name match, not a signature check.
    public static func isIssued(_ leafDER: Data, by caDER: Data) -> Bool {
        guard let leaf = SecCertificateCreateWithData(nil, leafDER as CFData),
              let ca = SecCertificateCreateWithData(nil, caDER as CFData),
              let issuer = SecCertificateCopyNormalizedIssuerSequence(leaf) as Data?,
              let subject = SecCertificateCopyNormalizedSubjectSequence(ca) as Data? else {
            return false
        }
        return issuer == subject
    }

    public static func isIssuedByMUPGradjaniCA4(_ leafDER: Data) -> Bool {
        guard let ca = try? MUPChain.verifiedDER(.intermediate) else { return false }
        return isIssued(leafDER, by: ca)
    }
}
