# Serbian eID Token

Log in to eUprava with the Serbian ID card in **Safari and Chrome** on your Mac. Until now
the official solution only worked in Firefox on Mac.

Independent project, not affiliated with the Serbian State or the Ministry of Interior (MUP).

---

# For users

## What it does

Serbian eID Token is a small macOS app that makes your Serbian ID card available to Safari and
Chrome. It contains a macOS smart card extension (CryptoTokenKit) that shows the card's
certificates to the system, and a setup assistant that checks everything and installs what is
missing. After setup, open eUprava in Safari or Chrome and choose your card certificate when
asked.

The app is available in English, Serbian (Cyrillic) and Serbian (Latin), following your Mac's
language.

## What you need

- A Mac with macOS 13 or later. The app is a universal binary.
- A CCID contact smart card reader, plugged directly into the Mac. A reader on a keyboard or
  an unpowered USB hub may not be detected.
- A Serbian ID card with **MUP Građani CA 4** certificates. In this version only these cards
  are supported. An older card issued before these certificates is reported by the app as
  not supported.

Signing documents is not supported in this version. It is about logging in.

## Install

1. Download the latest `.dmg` from the
   [Releases page](https://github.com/nenadvulic/SerbianEIDToken/releases).
2. Open it and drag the app to the **Applications** folder. It must run from there.
3. Open the app from Applications and follow the checklist:
   - **App location**: the app is in Applications.
   - **Card reader**: a reader is connected.
   - **ID card**: your card is in the reader.
   - **MUP certificates**: if missing, click **Install MUP certificates**. The app installs the
     MUP CA 4 certificates (after verifying their fingerprints) and macOS asks for your
     password.
   - **Browser access**: the extension is active.
4. When you see "Ready: open eUprava in Safari or Chrome", you are done.

Remove the card and insert it again after every install or update. The app checks for new
versions once a day and shows a Download link when one is available.

## Troubleshooting

- After installing or updating, remove the card and insert it again.
- Quit Chrome completely with Cmd+Q, then open it again. Chrome remembers an earlier
  "no certificate" choice until then.
- Plug the card reader directly into the Mac, not through a hub.
- Click **Check again** in the app after changing anything.

## Uninstall

1. Open the app, expand **Troubleshooting**, and click **Remove MUP certificates**.
2. Quit the app and move it from Applications to the Trash.

## Privacy

- No telemetry, no analytics, no accounts.
- Your PIN is entered only in the standard macOS system dialog. It is sent to the card once
  and is never stored or logged.
- The only network call is a daily check of
  `https://api.github.com/repos/nenadvulic/SerbianEIDToken/releases/latest` to see whether a
  new version exists.

---

# For developers

## Requirements

- macOS 13 or later, Xcode, and [xcodegen](https://github.com/yonaskolb/XcodeGen).
- A CCID reader and a card for real tests.

Tested card: SmartCafe Expert 7, ATR `3BF99600008031FE45534345372047434E335E`, with
MUP Građani CA 4 certificates. SELECT FILE with Le=FF was accepted at the first try
(fallbacks exist for other chips).

## Build locally

```sh
cd TokenApp
cp Local.xcconfig.example Local.xcconfig   # gitignored; set SEID_TEAM_ID to your Apple Team ID
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

The team ID comes from `SEID_TEAM_ID` in `TokenApp/Local.xcconfig` (copy it from
`Local.xcconfig.example`). Leaving it empty is fine for unsigned builds
(`CODE_SIGNING_ALLOWED=NO`), which is what CI does.

Remove and reinsert the card after every install or update. Otherwise the live token is
lost and keychain lookups fail (ctkd logs "token driver does not implement any way to
create new token instances").

Run the tests with `swift test`, and the localization check with
`python3 scripts/check-l10n.py` (the `sr` and `sr-Latn` strings must stay in sync).

## Trust chain (MUP CA4), manual

The app installs this for users. To do it by hand:

```sh
curl -fsSL -o ca4.crt  http://ca.mup.gov.rs/MUPGradjaniCA4.crt   # -L: redirects to crl.mup.gov.rs
curl -fsSL -o root4.crt http://ca.mup.gov.rs/MUPRootCA4.crt
security add-certificates -k ~/Library/Keychains/login.keychain-db ca4.crt
security add-trusted-cert -r trustRoot -k ~/Library/Keychains/login.keychain-db root4.crt
```

SHA-256 fingerprints to compare:

- MUP Root CA 4: `6D:CA:4A:B9:CA:BD:18:E5:CB:00:23:05:43:16:AB:F7:8C:99:B5:31:B2:E3:AA:10:31:09:AF:B9:DF:A8:36:D4`
- MUP Građani CA 4: `0E:3E:FE:B4:F7:7F:95:11:8D:2A:2D:58:70:70:9C:92:46:47:BB:DB:80:1C:AF:DB:E7:27:D3:F4:DC:35:45:66`

Without the chain, the card identity is untrusted and Safari does not offer it when eUprava
asks for a client certificate.

## Checks

```sh
security list-smartcards
sc_auth identities
security export-smartcard -i <tokenid>
```

`security find-identity -v` hides untrusted identities, so it shows nothing until the trust
chain is installed.

## Developer notes

- Safari may silently reuse a previously chosen identity for a host. Test with another host
  name, such as `https://127.0.0.1:4433`.
- Estonian EstEID token: it uses the same PKCS#15 AID, but it declines Serbian cards. No
  conflict was observed.
- Coexistence with a YubiKey/PIV token is not yet verified.
- TLS 1.3 works: the RSA-PSS signature is computed by the card in raw mode.

## Developer tools

- `scripts/bench.sh <command>`: builds and runs `seid-bench` (commands: `list`, `export`,
  `sign`, `keychain-sign`). Use it instead of `swift run`: it adds the
  `com.apple.security.smartcard` entitlement that card access requires.
- `scripts/tls-test-server.sh [1.2|1.3]`: local TLS server on port 4433 that requests a
  client certificate issued by the MUP CA4 chain, like eUprava. Needs OpenSSL 3 or later
  (set `OPENSSL=/path/to/openssl` if the system one is LibreSSL).
- `scripts/make-dmg.sh <App.app> <version> <out.dmg>`: builds the drag-to-install DMG.

Card captures go to `captures/`, which is gitignored. It can contain personal data: never
commit it.

## License

MIT, see `LICENSE`.
