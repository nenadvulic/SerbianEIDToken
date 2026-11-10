import Foundation

public struct ReleaseInfo: Decodable, Equatable {
    public let tagName: String
    public let htmlURL: URL
    public let draft: Bool
    public let prerelease: Bool

    enum CodingKeys: String, CodingKey {
        case tagName = "tag_name"
        case htmlURL = "html_url"
        case draft
        case prerelease
    }
}

public enum UpdateDecision {
    /// Returns the release only if it is a published, non-pre-release whose
    /// version is strictly newer than `current`. Anything unparseable -> nil.
    public static func newerRelease(current: String, latestJSON: Data) -> ReleaseInfo? {
        guard let release = try? JSONDecoder().decode(ReleaseInfo.self, from: latestJSON),
              !release.draft, !release.prerelease,
              let latest = SemanticVersion(release.tagName),
              let installed = SemanticVersion(current),
              latest > installed
        else { return nil }
        return release
    }
}

public enum UpdateConfig {
    public static let latestReleaseURL = URL(string: "https://api.github.com/repos/nenadvulic/SerbianEIDToken/releases/latest")!
    public static let minimumInterval: TimeInterval = 86_400
}
