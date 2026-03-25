#!/usr/bin/env bash
set -euo pipefail

# AkesoDLP Production Deploy Script (P11-T7)
#
# Usage:
#   ./scripts/deploy.sh
#   # or via Makefile:
#   make deploy

COMPOSE_FILE="docker-compose.prod.yml"
ENV_FILE=".env"
ENV_TEMPLATE=".env.example"
VERSION="${DLP_VERSION:-0.1.0}"

echo ""
echo "=== AkesoDLP Production Deploy ==="
echo "    Version: ${VERSION}"
echo ""

# --- Generate .env if missing ---
if [ ! -f "$ENV_FILE" ]; then
    if [ -f "$ENV_TEMPLATE" ]; then
        echo "Generating .env from template..."
        cp "$ENV_TEMPLATE" "$ENV_FILE"
        # Generate random JWT secret
        JWT_SECRET=$(python3 -c "import secrets; print(secrets.token_urlsafe(64))" 2>/dev/null || openssl rand -base64 48)
        sed -i "s|DLP_JWT_SECRET=.*|DLP_JWT_SECRET=${JWT_SECRET}|" "$ENV_FILE"
        echo "  Generated .env with random JWT secret."
        echo "  IMPORTANT: Set DLP_DB_PASS to a strong password in .env"
    else
        echo "ERROR: No .env or .env.example found."
        echo "  Create .env with at minimum:"
        echo "    DLP_JWT_SECRET=<random-secret>"
        echo "    DLP_DB_PASS=<strong-password>"
        exit 1
    fi
fi

# --- Build images with version tags ---
echo "Building Docker images (v${VERSION})..."
docker compose -f "$COMPOSE_FILE" build \
    --build-arg VERSION="${VERSION}"

# Tag images
docker tag "$(docker compose -f "$COMPOSE_FILE" images server -q 2>/dev/null || echo 'akeso-dlp-server')" \
    "akeso-dlp-server:${VERSION}" 2>/dev/null || true
docker tag "$(docker compose -f "$COMPOSE_FILE" images console -q 2>/dev/null || echo 'akeso-dlp-console')" \
    "akeso-dlp-console:${VERSION}" 2>/dev/null || true

# --- Start services ---
echo "Starting services..."
docker compose -f "$COMPOSE_FILE" --env-file "$ENV_FILE" up -d

# --- Wait for health ---
echo "Waiting for server health..."
for i in $(seq 1 30); do
    if curl -sf http://localhost:8000/api/health > /dev/null 2>&1; then
        break
    fi
    sleep 2
done

if ! curl -sf http://localhost:8000/api/health > /dev/null 2>&1; then
    echo "ERROR: Server failed to start. Check logs:"
    echo "  docker compose -f $COMPOSE_FILE logs server"
    exit 1
fi

echo ""
echo "=== AkesoDLP Deployed Successfully ==="
echo ""
echo "  Console:  http://localhost:${DLP_CONSOLE_PORT:-3000}"
echo "  API:      http://localhost:${DLP_API_PORT:-8000}"
echo "  gRPC:     localhost:${DLP_GRPC_PORT:-50051}"
echo "  Metrics:  http://localhost:${DLP_API_PORT:-8000}/metrics"
echo ""
echo "  Admin credentials:"
echo "    Username: admin"
echo "    Password: AkesoDLP2026!"
echo ""
echo "  IMPORTANT: Change the default admin password after first login."
echo ""
