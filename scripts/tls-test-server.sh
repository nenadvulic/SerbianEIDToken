#!/bin/bash
# Local TLS server that asks for a client certificate, to test the token in a browser.
# Usage: scripts/tls-test-server.sh [1.2|1.3]   (default 1.3)
# Mirrors eUprava: only certificates issued by the MUP CA4 chain are requested
# (-verify 2 with the MUP chain as CA list). Without the CA list a browser may silently
# send another keychain identity, which the server rejects, causing a retry loop.
set -euo pipefail
cd "$(dirname "$0")/.."

VERSION="${1:-1.3}"
case "$VERSION" in
  1.2) PROTO=-tls1_2 ;;
  1.3) PROTO=-tls1_3 ;;
  *) echo "usage: $0 [1.2|1.3]" >&2; exit 1 ;;
esac

OPENSSL="${OPENSSL:-openssl}"
if ! "$OPENSSL" version | grep -Eq '^OpenSSL ([3-9]|[1-9][0-9])\.'; then
  echo "OpenSSL 3 or later required (found: $("$OPENSSL" version)). Set OPENSSL=/path/to/openssl3." >&2
  exit 1
fi

DIR=captures
KEY="$DIR/tls-server.key"
CERT="$DIR/tls-server.crt"
mkdir -p "$DIR"
if [ ! -f "$KEY" ] || [ ! -f "$CERT" ]; then
  "$OPENSSL" req -x509 -newkey rsa:2048 -nodes -days 365 \
    -keyout "$KEY" -out "$CERT" -subj "/CN=localhost" \
    -addext "subjectAltName=DNS:localhost,IP:127.0.0.1"
fi

CA_DIR="$DIR/mupca"
CHAIN="$CA_DIR/chain.pem"
if [ ! -f "$CHAIN" ]; then
  mkdir -p "$CA_DIR"
  curl -fsSL -o "$CA_DIR/ca4.crt" http://ca.mup.gov.rs/MUPGradjaniCA4.crt
  curl -fsSL -o "$CA_DIR/root4.crt" http://ca.mup.gov.rs/MUPRootCA4.crt
  : > "$CHAIN"
  for f in ca4 root4; do
    if grep -q 'BEGIN CERTIFICATE' "$CA_DIR/$f.crt"; then
      cat "$CA_DIR/$f.crt" >> "$CHAIN"
      echo >> "$CHAIN"   # downloaded PEM may lack a trailing newline
    else
      "$OPENSSL" x509 -inform DER -in "$CA_DIR/$f.crt" -outform PEM >> "$CHAIN"
    fi
  done
fi

echo "TLS $VERSION server on https://localhost:4433 (Ctrl-C to stop)"
exec "$OPENSSL" s_server -accept 4433 -www -verify 2 -CAfile "$CHAIN" -cert "$CERT" -key "$KEY" "$PROTO"
