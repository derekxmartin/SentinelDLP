#!/usr/bin/env bash
# Wait for PostgreSQL to be ready before starting the application.
# Usage: ./scripts/wait-for-db.sh [host] [port] [max_attempts]

set -e

HOST="${1:-postgres}"
PORT="${2:-5432}"
MAX_ATTEMPTS="${3:-30}"

echo "Waiting for PostgreSQL at ${HOST}:${PORT}..."

attempt=0
while [ $attempt -lt $MAX_ATTEMPTS ]; do
    if pg_isready -h "$HOST" -p "$PORT" -U sentinel > /dev/null 2>&1; then
        echo "PostgreSQL is ready."
        exit 0
    fi
    attempt=$((attempt + 1))
    echo "Attempt ${attempt}/${MAX_ATTEMPTS} - PostgreSQL not ready, retrying in 2s..."
    sleep 2
done

echo "ERROR: PostgreSQL did not become ready after ${MAX_ATTEMPTS} attempts."
exit 1
