import XCTest
@testable import SerbianEIDSetup

final class VersionTests: XCTestCase {
    private func json(tag: String, draft: Bool = false, pre: Bool = false) -> Data {
        Data("""
        {"tag_name":"\(tag)","html_url":"https://github.com/nenadvulic/SerbianEIDToken/releases/tag/\(tag)","draft":\(draft),"prerelease":\(pre)}
        """.utf8)
    }

    func testParsesWithAndWithoutV() {
        XCTAssertNotNil(SemanticVersion("1.2.3"))
        XCTAssertEqual(SemanticVersion("v1.2.3"), SemanticVersion("1.2.3"))
    }
    func testPrereleaseTagIsNotAVersion() {
        XCTAssertNil(SemanticVersion("v1.0.0-rc.1"))
    }
    func testIncompleteVersionRejected() {
        XCTAssertNil(SemanticVersion("1.0"))
        XCTAssertNil(SemanticVersion("abc"))
        XCTAssertNil(SemanticVersion("1.0.0.0"))
        XCTAssertNil(SemanticVersion("1.-1.0"))
    }
    func testOrdering() {
        XCTAssertTrue(SemanticVersion("1.0.10")! > SemanticVersion("1.0.9")!)
    }
    func testNewerReleaseDetected() {
        XCTAssertNotNil(UpdateDecision.newerRelease(current: "1.0.0", latestJSON: json(tag: "v1.1.0")))
    }
    func testSameVersionNoBanner() {
        XCTAssertNil(UpdateDecision.newerRelease(current: "1.1.0", latestJSON: json(tag: "v1.1.0")))
    }
    func testPrereleaseFlagIgnored() {
        XCTAssertNil(UpdateDecision.newerRelease(current: "1.0.0", latestJSON: json(tag: "v1.1.0", pre: true)))
        XCTAssertNil(UpdateDecision.newerRelease(current: "1.0.0", latestJSON: json(tag: "v1.1.0", draft: true)))
        XCTAssertNil(UpdateDecision.newerRelease(current: "1.0.0", latestJSON: json(tag: "v1.1.0-rc.1")))
    }
    func testEmptyOrGarbageJSONIgnored() {
        XCTAssertNil(UpdateDecision.newerRelease(current: "1.0.0", latestJSON: Data()))
        XCTAssertNil(UpdateDecision.newerRelease(current: "1.0.0", latestJSON: Data("{}".utf8)))
    }
}
