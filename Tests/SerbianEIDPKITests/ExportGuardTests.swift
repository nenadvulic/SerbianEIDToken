import XCTest
@testable import SerbianEIDPKI

final class ExportGuardTests: XCTestCase {
    private var base: URL!

    override func setUpWithError() throws {
        base = URL(fileURLWithPath: NSTemporaryDirectory())
            .appendingPathComponent("exportguard-\(UUID().uuidString)").resolvingSymlinksInPath()
        try FileManager.default.createDirectory(at: base, withIntermediateDirectories: true)
    }

    override func tearDownWithError() throws {
        try? FileManager.default.removeItem(at: base)
    }

    private func makeRepo(_ name: String) throws -> URL {
        let repo = base.appendingPathComponent(name)
        try FileManager.default.createDirectory(at: repo.appendingPathComponent(".git"), withIntermediateDirectories: true)
        return repo
    }

    func testOutsideAnyRepoIsAllowed() {
        XCTAssertTrue(ExportGuard.isAllowed(base.appendingPathComponent("out/certs")))
    }

    func testInsideRepoIsRefused() throws {
        let repo = try makeRepo("repo")
        XCTAssertFalse(ExportGuard.isAllowed(repo.appendingPathComponent("certs")))
        XCTAssertFalse(ExportGuard.isAllowed(repo))
        XCTAssertFalse(ExportGuard.isAllowed(repo.appendingPathComponent("capturesX")))
    }

    func testCapturesInsideRepoIsAllowed() throws {
        let repo = try makeRepo("repo")
        XCTAssertTrue(ExportGuard.isAllowed(repo.appendingPathComponent("captures")))
        XCTAssertTrue(ExportGuard.isAllowed(repo.appendingPathComponent("captures/run1")))
    }

    func testSymlinkIntoRepoIsRefused() throws {
        let repo = try makeRepo("repo")
        let link = base.appendingPathComponent("link")
        try FileManager.default.createSymbolicLink(at: link, withDestinationURL: repo)
        XCTAssertFalse(ExportGuard.isAllowed(link.appendingPathComponent("new")))
    }
}
