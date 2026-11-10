import Foundation
import SerbianEIDSetup

/// Daily check for a newer GitHub release. The only network call the app makes.
/// No cookies, no identifying headers, failures are silent.
enum UpdateChecker {
    static let lastCheckKey = "lastUpdateCheck"

    static var bundleVersion: String {
        Bundle.main.object(forInfoDictionaryKey: "CFBundleShortVersionString") as? String ?? "0.0.0"
    }

    static func checkIfDue(
        now: Date = .now,
        defaults: UserDefaults = .standard,
        currentVersion: String = UpdateChecker.bundleVersion,
        fetch: (URL) async throws -> Data = UpdateChecker.fetchFromNetwork
    ) async -> ReleaseInfo? {
        if let last = defaults.object(forKey: lastCheckKey) as? Date,
           now.timeIntervalSince(last) < UpdateConfig.minimumInterval {
            return nil
        }
        // A request is attempted from here on, so the throttle applies even if it fails.
        defaults.set(now, forKey: lastCheckKey)
        guard let data = try? await fetch(UpdateConfig.latestReleaseURL) else { return nil }
        return UpdateDecision.newerRelease(current: currentVersion, latestJSON: data)
    }

    static func fetchFromNetwork(_ url: URL) async throws -> Data {
        let config = URLSessionConfiguration.ephemeral
        config.httpCookieStorage = nil
        config.httpShouldSetCookies = false
        config.urlCache = nil
        config.timeoutIntervalForRequest = 10
        config.timeoutIntervalForResource = 10
        config.httpAdditionalHeaders = ["Accept": "application/vnd.github+json"]
        var request = URLRequest(url: url, timeoutInterval: 10)
        request.httpShouldHandleCookies = false
        let (data, response) = try await URLSession(configuration: config).data(for: request)
        guard (response as? HTTPURLResponse)?.statusCode == 200 else { throw URLError(.badServerResponse) }
        return data
    }
}
