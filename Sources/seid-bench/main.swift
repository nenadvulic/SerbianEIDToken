import Foundation
import CryptoKit
import CryptoTokenKit
import Security
import SerbianEIDPKI

let usage = """
usage (run via scripts/bench.sh: plain `swift run` lacks the smartcard entitlement):
  seid-bench list [--trace]
  seid-bench export <dir>
  seid-bench sign --key auth|sign --mode pkcs1|raw|pss [--trace]
  seid-bench keychain-sign [--pss]   (signs through the installed CTK token; macOS asks the PIN)
"""

func fail(_ message: String, code: Int32 = 1) -> Never {
    FileHandle.standardError.write(Data((message + "\n").utf8))
    exit(code)
}

func openCard() -> TKSmartCard {
    guard let manager = TKSmartCardSlotManager.default else { fail("no smart card service: run via scripts/bench.sh (plain `swift run` lacks the smartcard entitlement)") }
    for name in manager.slotNames {
        var slot: TKSmartCardSlot?
        let done = DispatchSemaphore(value: 0)
        manager.getSlot(withName: name) { slot = $0; done.signal() }
        done.wait()
        print("reader: \(name)")
        guard let slot = slot else { continue }
        if slot.state == .validCard, let card = slot.makeSmartCard() {
            let atr = slot.atr?.bytes.map { String(format: "%02X", $0) }.joined(separator: " ") ?? "?"
            print("ATR: \(atr)")
            return card
        }
    }
    fail("no card found in any reader")
}

func describe(_ identity: CardIdentity) {
    let cert = SecCertificateCreateWithData(nil, identity.certificate as CFData)
    let subject = cert.flatMap { SecCertificateCopySubjectSummary($0) as String? } ?? "?"
    print("- role: \(identity.role), label: \(identity.label ?? "-"), subject: \(subject), key: RSA \(identity.keySizeInBits)")
    if let cert = cert {
        var error: Unmanaged<CFError>?
        if let values = SecCertificateCopyValues(cert, [kSecOIDX509V1IssuerName, kSecOIDX509V1ValidityNotBefore, kSecOIDX509V1ValidityNotAfter] as CFArray, &error) as? [String: Any] {
            func value(_ oid: CFString) -> Any? { (values[oid as String] as? [String: Any])?["value"] }
            if let issuer = value(kSecOIDX509V1IssuerName) as? [[String: Any]] {
                let names = issuer.compactMap { $0["value"] as? String }.joined(separator: ", ")
                print("  issuer: \(names)")
            }
            print("  valid: \(value(kSecOIDX509V1ValidityNotBefore) ?? "?") .. \(value(kSecOIDX509V1ValidityNotAfter) ?? "?")")
        }
    }
}

func discoverAll(trace: Bool) throws -> (TKSmartCard, CardObjects) {
    let card = openCard()
    let transport = SmartCardTransport(card: card, trace: trace ? { print($0) } : nil)
    let objects = try card.withSession { try PKICard(transport: transport).discover() }
    return (card, objects)
}

func runList(trace: Bool) throws {
    let (_, objects) = try discoverAll(trace: trace)
    print("identities: \(objects.identities.count)")
    objects.identities.forEach(describe)
    print("extra certificates: \(objects.extraCertificates.count)")
}

func runExport(dir: String) throws {
    let target = URL(fileURLWithPath: dir)
    guard ExportGuard.isAllowed(target) else {
        fail("refusing to export inside a git repository (only its captures/ folder is allowed)")
    }
    let (_, objects) = try discoverAll(trace: false)
    try FileManager.default.createDirectory(at: target, withIntermediateDirectories: true)
    var index = 0
    for identity in objects.identities {
        let name = "identity-\(index)-\(identity.role).cer"
        try identity.certificate.write(to: target.appendingPathComponent(name)); index += 1
        print("wrote \(name)")
    }
    for (i, der) in objects.extraCertificates.enumerated() {
        let name = "extra-\(i).cer"
        try der.write(to: target.appendingPathComponent(name))
        print("wrote \(name)")
    }
}

func runSign(key: String, mode: String, trace: Bool) throws {
    let wanted: CertificateRole = key == "auth" ? .authentication : .qualifiedSignature
    let card = openCard()
    let transport = SmartCardTransport(card: card, trace: trace ? { print($0) } : nil)
    let pki = PKICard(transport: transport)
    let message = Array("seid-bench test".utf8)
    let digest = Array(SHA256.hash(data: message))

    let outcome: (signature: [UInt8], identity: CardIdentity)? = try card.withSession {
        let objects = try pki.discover()
        guard let identity = objects.identities.first(where: { $0.role == wanted }) else {
            fail("no identity with the requested role")
        }
        guard let raw = getpass("PIN: ") else { fail("no PIN entered") }
        let pin = String(cString: raw)
        switch try pki.verifyPIN(pin) {
        case .ok: break
        case .wrong(let left):
            print("wrong PIN, retries left: \(left.map(String.init) ?? "unknown")")
            exit(2)
        case .blocked:
            print("PIN blocked")
            exit(3)
        }
        let bits = identity.keySizeInBits
        let request: SignRequest
        switch mode {
        case "pkcs1": request = try CardSignatureAlgorithm.pkcs1(.sha256).request(for: digest, modulusBits: bits)
        case "pss": request = try CardSignatureAlgorithm.pss(.sha256).request(for: digest, modulusBits: bits)
        case "raw":
            let info = try SignatureEncoding.digestInfo(digest, .sha256)
            let k = bits / 8
            let block = [0x00, 0x01] + [UInt8](repeating: 0xFF, count: k - info.count - 3) + [0x00] + info
            request = try CardSignatureAlgorithm.raw.request(for: block, modulusBits: bits)
        default: fail(usage)
        }
        return (try pki.sign(request, keyFID: identity.privateKeyFID), identity)
    }
    guard let (signature, identity) = outcome else { return }
    guard let cert = SecCertificateCreateWithData(nil, identity.certificate as CFData),
          let publicKey = SecCertificateCopyKey(cert) else { fail("cannot extract public key") }
    let algorithm: SecKeyAlgorithm = mode == "pss" ? .rsaSignatureDigestPSSSHA256 : .rsaSignatureDigestPKCS1v15SHA256
    let ok = SecKeyVerifySignature(publicKey, algorithm, Data(digest) as CFData, Data(signature) as CFData, nil)
    print(ok ? "SIGNATURE OK" : "SIGNATURE INVALIDE", "(SW=9000)")
    if !ok { exit(4) }
}

/// Signs with the Auth identity exposed by the CTK token, as any keychain client would. No PIN here.
func runKeychainSign(pss: Bool) {
    let prefix = "rs.serbiandocuments.SerbianEIDToken"
    guard let tokenID = TKTokenWatcher().tokenIDs.first(where: { $0.hasPrefix(prefix) }) else {
        fail("no \(prefix) token: is the card inserted and the app installed?")
    }
    print("token: \(tokenID)")
    let query: [String: Any] = [
        kSecClass as String: kSecClassIdentity,
        kSecAttrTokenID as String: tokenID,
        kSecReturnRef as String: true,
        kSecMatchLimit as String: kSecMatchLimitAll,
    ]
    var result: CFTypeRef?
    let status = SecItemCopyMatching(query as CFDictionary, &result)
    guard status == errSecSuccess, let items = result as? [SecIdentity] else {
        fail("no identity in the token (OSStatus \(status))")
    }
    var found: (SecIdentity, SecCertificate)?
    for identity in items {
        var cert: SecCertificate?
        guard SecIdentityCopyCertificate(identity, &cert) == errSecSuccess, let cert = cert else { continue }
        if CardIdentity.role(of: SecCertificateCopyData(cert) as Data) == .authentication {
            found = (identity, cert)
            break
        }
    }
    guard let (identity, cert) = found else { fail("no authentication identity among \(items.count)") }
    print("identity: \(SecCertificateCopySubjectSummary(cert) as String? ?? "?")")
    var key: SecKey?
    guard SecIdentityCopyPrivateKey(identity, &key) == errSecSuccess, let privateKey = key,
          let publicKey = SecCertificateCopyKey(cert) else { fail("cannot get the key pair") }
    let algorithm: SecKeyAlgorithm = pss ? .rsaSignatureDigestPSSSHA256 : .rsaSignatureDigestPKCS1v15SHA256
    let digest = Data(SHA256.hash(data: Data("seid-bench keychain test".utf8)))
    var error: Unmanaged<CFError>?
    guard let signature = SecKeyCreateSignature(privateKey, algorithm, digest as CFData, &error) else {
        fail("signature failed: \(error.map { String(describing: $0.takeRetainedValue()) } ?? "unknown")")
    }
    let ok = SecKeyVerifySignature(publicKey, algorithm, digest as CFData, signature, nil)
    print(ok ? "SIGNATURE OK" : "SIGNATURE INVALIDE", pss ? "(PSS)" : "(PKCS#1 v1.5)")
    if !ok { exit(4) }
}

var args = Array(CommandLine.arguments.dropFirst())
let trace = args.contains("--trace")
args.removeAll { $0 == "--trace" }

func option(_ name: String) -> String? {
    guard let i = args.firstIndex(of: name), i + 1 < args.count else { return nil }
    return args[i + 1]
}

do {
    switch args.first {
    case "list":
        try runList(trace: trace)
    case "export":
        guard args.count == 2 else { fail(usage) }
        try runExport(dir: args[1])
    case "sign":
        guard let key = option("--key"), ["auth", "sign"].contains(key),
              let mode = option("--mode"), ["pkcs1", "raw", "pss"].contains(mode) else { fail(usage) }
        try runSign(key: key, mode: mode, trace: trace)
    case "keychain-sign":
        guard args.count == 1 || (args.count == 2 && args[1] == "--pss") else { fail(usage) }
        runKeychainSign(pss: args.count == 2)
    default:
        print(usage)
    }
} catch let APDUError.status(sw) {
    print("card error SW=\(String(format: "%04X", sw))")
    exit(5)
} catch {
    fail("error: \(error)")
}
