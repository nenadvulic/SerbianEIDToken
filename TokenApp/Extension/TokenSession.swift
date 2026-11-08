import CryptoTokenKit

/// Session skeleton: no operation is supported yet (PIN and signing come later).
final class TokenSession: TKSmartCardTokenSession, TKTokenSessionDelegate {
    func tokenSession(_ session: TKTokenSession, supports operation: TKTokenOperation,
                      keyObjectID: TKToken.ObjectID, algorithm: TKTokenKeyAlgorithm) -> Bool {
        false
    }
}
