# Serbian eID Token

A macOS CryptoTokenKit (CTK) extension that exposes the certificates of the Serbian
electronic ID card (Authentication and qualified Signature) to the macOS keychain, so that
Safari and Chrome can use the card to log in to eUprava.

Independent project, not affiliated with the Serbian State.

## Status

Local build only (not yet notarized or distributed). Verified on a real card:

- eUprava login works in Safari and in Chrome.
- TLS 1.3 works: the RSA-PSS signature is computed by the card in raw mode.
- The PIN is entered by the user in the standard macOS dialog, sent to the card once, and
  never stored.

## Requirements

- macOS 13 or later.
- A CCID contact smart card reader plugged DIRECTLY into the Mac. A reader on a keyboard's
  USB hub was underpowered and was not detected.
- Xcode and [xcodegen](https://github.com/yonaskolb/XcodeGen).

Tested card: SmartCafe Expert 7, ATR `3BF99600008031FE45534345372047434E335E`, with
MUP Gradjani CA 4 certificates. SELECT FILE with Le=FF was accepted at the first try
(fallbacks exist for other chips).

## Build and install

```sh
cd TokenApp
xcodegen generate
xcodebuild -project SerbianEIDTokenApp.xcodeproj -scheme SerbianEIDTokenApp \
  -configuration Debug -derivedDataPath build -allowProvisioningUpdates build

# quit the host app and kill the extension process
pkill -x SerbianEIDTokenApp; pkill -f SerbianEIDToken.appex

rm -rf /Applications/SerbianEIDTokenApp.app
cp -R build/Build/Products/Debug/SerbianEIDTokenApp.app /Applications/
open /Applications/SerbianEIDTokenApp.app      # open once so macOS registers the extension

pluginkit -m -p com.apple.ctk-tokens           # should list ...SerbianEIDTokenApp.SerbianEIDToken
```

`DEVELOPMENT_TEAM` is set in `TokenApp/project.yml`; change it to your own team.

IMPORTANT: remove and reinsert the card after every install or update. Otherwise the live
token is lost and keychain lookups fail (ctkd logs "token driver does not implement any way
to create new token instances").

## Trust chain (MUP CA4)

Install the MUP Gradjani CA 4 intermediate and the MUP Root CA 4 trusted root:

```sh
curl -fsSL -o ca4.crt  http://ca.mup.gov.rs/MUPGradjaniCA4.crt   # -L: redirects to crl.mup.gov.rs
curl -fsSL -o root4.crt http://ca.mup.gov.rs/MUPRootCA4.crt
security add-certificates -k ~/Library/Keychains/login.keychain-db ca4.crt
security add-trusted-cert -r trustRoot -k ~/Library/Keychains/login.keychain-db root4.crt
```

SHA-256 fingerprints to compare:

- MUP Root CA 4: `6D:CA:4A:B9:CA:BD:18:E5:CB:00:23:05:43:16:AB:F7:8C:99:B5:31:B2:E3:AA:10:31:09:AF:B9:DF:A8:36:D4`
- MUP Gradjani CA 4: `0E:3E:FE:B4:F7:7F:95:11:8D:2A:2D:58:70:70:9C:92:46:47:BB:DB:80:1C:AF:DB:E7:27:D3:F4:DC:35:45:66`

Why: without the chain, the card identity is untrusted and Safari did not offer it when
eUprava asked for a client certificate.

## Checks

```sh
security list-smartcards
sc_auth identities
security export-smartcard -i <tokenid>
```

Note: `security find-identity -v` hides untrusted identities, so it shows nothing until the
trust chain above is installed.

## Troubleshooting

- Chrome remembers a previous "no certificate" choice until it is fully quit (Cmd+Q).
- Safari may silently reuse a previously chosen identity for a host. Test with another host
  name, such as `https://127.0.0.1:4433`.
- Estonian EstEID token: it uses the same PKCS#15 AID, but it declines Serbian cards. No
  conflict was observed.
- Coexistence with a YubiKey/PIV token is not yet verified.

## Developer tools

- `scripts/bench.sh <command>`: builds and runs `seid-bench` (commands: `list`, `export`,
  `sign`, `keychain-sign`). Use it instead of `swift run`: it adds the
  `com.apple.security.smartcard` entitlement that card access requires.
- `scripts/tls-test-server.sh [1.2|1.3]`: local TLS server on port 4433 that requests a
  client certificate issued by the MUP CA4 chain, like eUprava. Needs OpenSSL 3 or later
  (set `OPENSSL=/path/to/openssl` if the system one is LibreSSL).

Card captures go to `captures/`, which is gitignored. It can contain personal data: never
commit it.


## License

MIT, see `LICENSE`.
