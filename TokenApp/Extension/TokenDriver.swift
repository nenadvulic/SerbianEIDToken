import CryptoTokenKit

/// Entry point loaded by ctkd for cards that answer the declared PKCS#15 AID.
final class TokenDriver: TKSmartCardTokenDriver, TKSmartCardTokenDriverDelegate {
    override init() {
        super.init()
        delegate = self
    }

    /// Throws for cards that are not a Serbian eID, so ctkd can offer them to other drivers.
    func tokenDriver(_ driver: TKSmartCardTokenDriver, createTokenFor smartCard: TKSmartCard,
                     aid AID: Data?) throws -> TKSmartCardToken {
        try Token(smartCard: smartCard, aid: AID, tokenDriver: self)
    }
}
