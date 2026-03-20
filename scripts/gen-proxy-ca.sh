#!/usr/bin/env bash
# gen-proxy-ca.sh — Generate mitmproxy CA certificate for DLP HTTP proxy.
#
# Creates a CA cert that clients must trust for HTTPS inspection.
# The cert is stored in a Docker volume (proxy-certs) and persists
# across container restarts.
#
# Usage:
#   ./scripts/gen-proxy-ca.sh              # generate + export to certs/
#   ./scripts/gen-proxy-ca.sh --export     # export existing CA to certs/
#
# After running, install certs/mitmproxy-ca-cert.pem in your browser
# or system trust store for HTTPS inspection to work.

set -euo pipefail

CERT_DIR="$(cd "$(dirname "$0")/.." && pwd)/certs"
CONTAINER_NAME="akeso-dlp-proxy-ca-gen"

mkdir -p "$CERT_DIR"

echo "=== AkesoDLP Proxy CA Certificate Generator ==="

# Check if proxy-certs volume already has a CA
if docker volume inspect claude-dlp_proxy-certs >/dev/null 2>&1; then
    echo "Existing proxy-certs volume found."
    EXISTING=true
else
    echo "No proxy-certs volume found. Will be created on first 'docker compose up'."
    EXISTING=false
fi

if [ "${1:-}" = "--export" ] && [ "$EXISTING" = true ]; then
    echo "Exporting existing CA certificate..."
    docker run --rm \
        -v claude-dlp_proxy-certs:/root/.mitmproxy \
        -v "$CERT_DIR":/export \
        alpine:latest \
        sh -c "cp /root/.mitmproxy/mitmproxy-ca-cert.pem /export/ 2>/dev/null && echo 'Exported.' || echo 'No CA cert found yet. Run docker compose up first.'"
else
    echo "Generating new mitmproxy CA certificate..."
    # Run mitmproxy briefly to generate the CA
    docker run --rm \
        --name "$CONTAINER_NAME" \
        -v claude-dlp_proxy-certs:/root/.mitmproxy \
        mitmproxy/mitmproxy:latest \
        mitmdump --set connection_strategy=lazy -p 0 &

    MITM_PID=$!
    sleep 3
    kill $MITM_PID 2>/dev/null || true
    wait $MITM_PID 2>/dev/null || true

    # Export the CA cert
    docker run --rm \
        -v claude-dlp_proxy-certs:/root/.mitmproxy \
        -v "$CERT_DIR":/export \
        alpine:latest \
        cp /root/.mitmproxy/mitmproxy-ca-cert.pem /export/

    echo ""
    echo "CA certificate exported to: $CERT_DIR/mitmproxy-ca-cert.pem"
fi

echo ""
echo "To trust this CA for HTTPS inspection:"
echo "  - Windows: certutil -addstore Root \"$CERT_DIR/mitmproxy-ca-cert.pem\""
echo "  - macOS:   sudo security add-trusted-cert -d -r trustRoot -k /Library/Keychains/System.keychain \"$CERT_DIR/mitmproxy-ca-cert.pem\""
echo "  - Linux:   sudo cp \"$CERT_DIR/mitmproxy-ca-cert.pem\" /usr/local/share/ca-certificates/mitmproxy-ca.crt && sudo update-ca-certificates"
echo "  - Firefox: Settings → Privacy & Security → Certificates → Import"
echo ""
echo "NOTE: This CA is for TEST ENVIRONMENTS ONLY."
