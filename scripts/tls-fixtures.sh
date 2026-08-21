#!/usr/bin/env bash
# Generate throwaway TLS material for the D1 TLS matrix: a test CA and a
# server certificate for the synthetic name db.internal.test. Everything
# lands in a mktemp directory (never the repo) whose path is exported to
# tests via SEQUEL_MCP_TEST_TLS_DIR.
set -euo pipefail

DIR="$(mktemp -d /tmp/sqm-tls.XXXXXX)"
chmod 700 "$DIR"
cd "$DIR"

# Tiny CA
openssl req -x509 -newkey rsa:2048 -nodes \
  -keyout ca-key.pem -out ca-cert.pem \
  -days 1 -subj "/CN=sqm-test-ca" \
  -addext "basicConstraints=critical,CA:TRUE" >/dev/null 2>&1

# Server cert for the synthetic name (SAN + CN both).
openssl req -newkey rsa:2048 -nodes \
  -keyout server-key.pem -out server.csr \
  -subj "/CN=db.internal.test" >/dev/null 2>&1
cat >server.ext <<'EOF'
subjectAltName=DNS:db.internal.test
extendedKeyUsage=serverAuth
EOF
openssl x509 -req -in server.csr \
  -CA ca-cert.pem -CAkey ca-key.pem -CAcreateserial \
  -out server-cert.pem -days 1 -extfile server.ext >/dev/null 2>&1

echo "$DIR"
