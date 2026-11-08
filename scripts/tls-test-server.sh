#!/bin/bash
# Local TLS server that asks for a client certificate, to test the token in a browser.
# Usage: scripts/tls-test-server.sh [1.2|1.3]   (default 1.3)
# -verify 1 requests a client certificate without requiring it to validate and sends no CA
# list, so the browser offers every identity it knows.
set -euo pipefail
cd "$(dirname "$0")/.."

VERSION="${1:-1.3}"
case "$VERSION" in
  1.2) PROTO=-tls1_2 ;;
  1.3) PROTO=-tls1_3 ;;
  *) echo "usage: $0 [1.2|1.3]" >&2; exit 1 ;;
esac

OPENSSL="${OPENSSL:-openssl}"
if ! "$OPENSSL" version | grep -q '^OpenSSL 3'; then
  echo "OpenSSL 3 required (found: $("$OPENSSL" version)). Set OPENSSL=/path/to/openssl3." >&2
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

echo "TLS $VERSION server on https://localhost:4433 (Ctrl-C to stop)"
exec "$OPENSSL" s_server -accept 4433 -www -verify 1 -cert "$CERT" -key "$KEY" "$PROTO"
