import XCTest
@testable import SerbianEIDSetup

final class SetupEvaluatorTests: XCTestCase {
    private func good() -> SetupInputs {
        SetupInputs(isInApplicationsFolder: true, readerCount: 1,
                    card: .serbianEID(authIssuedByCA4: true),
                    chainInstalled: true, tokenRegistered: true)
    }

    func testAllGoodIsReady() {
        let r = SetupEvaluator.evaluate(good())
        XCTAssertTrue(r.isReady)
        for k in CheckKind.allCases { XCTAssertEqual(r.checks[k], .ok, "\(k)") }
    }

    func testNotInApplicationsBlocksReady() {
        var i = good(); i.isInApplicationsFolder = false
        let r = SetupEvaluator.evaluate(i)
        XCTAssertFalse(r.isReady)
        XCTAssertEqual(r.checks[.location], .problem(.moveToApplications))
    }

    func testNonCA4CardIsUnsupportedNotTrustProblem() {
        var i = good(); i.card = .serbianEID(authIssuedByCA4: false); i.chainInstalled = false
        let r = SetupEvaluator.evaluate(i)
        XCTAssertEqual(r.checks[.card], .problem(.unsupportedCardGeneration))
        XCTAssertEqual(r.checks[.chain], .pending)
        XCTAssertFalse(r.isReady)
    }

    func testNoReaderAfterCardWasPresent() {
        var i = good(); i.readerCount = 0; i.card = .none
        let r = SetupEvaluator.evaluate(i)
        XCTAssertEqual(r.checks[.reader], .problem(.noReader))
        XCTAssertEqual(r.checks[.card], .pending)
    }

    func testChainMissing() {
        var i = good(); i.chainInstalled = false
        let r = SetupEvaluator.evaluate(i)
        XCTAssertEqual(r.checks[.chain], .problem(.chainMissing))
        XCTAssertFalse(r.isReady)
    }

    func testTokenUnknownWithoutCardIsPending() {
        var i = good(); i.card = .none; i.tokenRegistered = nil
        let r = SetupEvaluator.evaluate(i)
        XCTAssertEqual(r.checks[.card], .problem(.noCard))
        XCTAssertEqual(r.checks[.extensionRegistered], .pending)
        XCTAssertFalse(r.isReady)
    }

    func testTokenNotRegistered() {
        var i = good(); i.tokenRegistered = false
        let r = SetupEvaluator.evaluate(i)
        XCTAssertEqual(r.checks[.extensionRegistered], .problem(.tokenNotRegistered))
    }

    func testCardProblemMapping() {
        var i = good()
        i.card = .unreadable
        XCTAssertEqual(SetupEvaluator.evaluate(i).checks[.card], .problem(.unreadableCard))
        i.card = .notSerbianEID
        XCTAssertEqual(SetupEvaluator.evaluate(i).checks[.card], .problem(.notSerbianEID))
    }
}
