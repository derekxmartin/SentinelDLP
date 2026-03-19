#!/usr/bin/env bash
# gen-certs.sh — Generate mTLS certificates for AkesoDLP gRPC communication.
#
# Creates:
#   certs/ca.pem        — Certificate Authority
#   certs/server.pem    — Server certificate (signed by CA)
#   certs/server-key.pem — Server private key
#   certs/client.pem    — Client certificate (signed by CA)
#   certs/client-key.pem — Client private key
#
# Usage: ./scripts/gen-certs.sh [output_dir]

set -euo pipefail

OUTDIR="${1:-certs}"
DAYS=365
CN_CA="AkesoDLP CA"
CN_SERVER="akeso-dlp-server"
CN_CLIENT="akeso-dlp-agent"

echo "=== AkesoDLP mTLS Certificate Generator ==="
echo "Output directory: ${OUTDIR}"
echo ""

mkdir -p "${OUTDIR}"

# --- Certificate Authority ---
echo "[1/5] Generating CA key and certificate..."
openssl genrsa -out "${OUTDIR}/ca-key.pem" 4096 2>/dev/null
openssl req -new -x509 \
    -key "${OUTDIR}/ca-key.pem" \
    -out "${OUTDIR}/ca.pem" \
    -days "${DAYS}" \
    -subj "/CN=${CN_CA}/O=AkesoDLP/OU=Security" \
    2>/dev/null

# --- Server Certificate ---
echo "[2/5] Generating server key..."
openssl genrsa -out "${OUTDIR}/server-key.pem" 2048 2>/dev/null

echo "[3/5] Generating server certificate..."
openssl req -new \
    -key "${OUTDIR}/server-key.pem" \
    -out "${OUTDIR}/server.csr" \
    -subj "/CN=${CN_SERVER}/O=AkesoDLP/OU=Server" \
    2>/dev/null

# Create extensions file for SAN
cat > "${OUTDIR}/server-ext.cnf" <<EOF
[v3_req]
subjectAltName = @alt_names
[alt_names]
DNS.1 = localhost
DNS.2 = ${CN_SERVER}
IP.1 = 127.0.0.1
IP.2 = ::1
EOF

openssl x509 -req \
    -in "${OUTDIR}/server.csr" \
    -CA "${OUTDIR}/ca.pem" \
    -CAkey "${OUTDIR}/ca-key.pem" \
    -CAcreateserial \
    -out "${OUTDIR}/server.pem" \
    -days "${DAYS}" \
    -extfile "${OUTDIR}/server-ext.cnf" \
    -extensions v3_req \
    2>/dev/null

# --- Client Certificate ---
echo "[4/5] Generating client key..."
openssl genrsa -out "${OUTDIR}/client-key.pem" 2048 2>/dev/null

echo "[5/5] Generating client certificate..."
openssl req -new \
    -key "${OUTDIR}/client-key.pem" \
    -out "${OUTDIR}/client.csr" \
    -subj "/CN=${CN_CLIENT}/O=AkesoDLP/OU=Agent" \
    2>/dev/null

openssl x509 -req \
    -in "${OUTDIR}/client.csr" \
    -CA "${OUTDIR}/ca.pem" \
    -CAkey "${OUTDIR}/ca-key.pem" \
    -CAcreateserial \
    -out "${OUTDIR}/client.pem" \
    -days "${DAYS}" \
    2>/dev/null

# --- Cleanup ---
rm -f "${OUTDIR}"/*.csr "${OUTDIR}"/*.cnf "${OUTDIR}"/*.srl

echo ""
echo "=== Certificates generated ==="
echo "  CA:          ${OUTDIR}/ca.pem"
echo "  Server cert: ${OUTDIR}/server.pem"
echo "  Server key:  ${OUTDIR}/server-key.pem"
echo "  Client cert: ${OUTDIR}/client.pem"
echo "  Client key:  ${OUTDIR}/client-key.pem"
echo ""
echo "Server usage:"
echo "  python -m server.grpc_server --cert ${OUTDIR}/server.pem --key ${OUTDIR}/server-key.pem --ca ${OUTDIR}/ca.pem"
echo ""
echo "Client usage (agent):"
echo "  Use ${OUTDIR}/client.pem and ${OUTDIR}/client-key.pem with ${OUTDIR}/ca.pem"
