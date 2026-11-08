import Foundation

/// Decides whether exported certificates may be written to a directory: refused inside a git
/// work tree unless under that tree's `captures/` folder.
public enum ExportGuard {
    public static func isAllowed(_ target: URL) -> Bool {
        let fm = FileManager.default
        // Resolve symlinks on the nearest existing ancestor, then re-append the missing part.
        var existing = target.standardizedFileURL
        var missing: [String] = []
        while !fm.fileExists(atPath: existing.path), existing.path != "/" {
            missing.insert(existing.lastPathComponent, at: 0)
            existing.deleteLastPathComponent()
        }
        var resolved = existing.resolvingSymlinksInPath()
        for part in missing { resolved.appendPathComponent(part) }

        var root = resolved
        while true {
            if fm.fileExists(atPath: root.appendingPathComponent(".git").path) {
                let captures = root.appendingPathComponent("captures").path + "/"
                return (resolved.path + "/").hasPrefix(captures)
            }
            if root.path == "/" { return true }
            root.deleteLastPathComponent()
        }
    }
}
