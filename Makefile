.PHONY: server console agent agent-build up down clean test lint \
       install dev demo demo-seed reset test-e2e help

PYTHON ?= python3
COMPOSE = docker compose

# ================================================================
#  Help
# ================================================================
help:
	@echo ""
	@echo "  AkesoDLP - Data Loss Prevention Platform"
	@echo "  ========================================="
	@echo ""
	@echo "  Quickstart:"
	@echo "    make install   - Build & start all services, seed admin user"
	@echo "    make dev       - Hot-reload development (FastAPI + Vite HMR)"
	@echo "    make demo      - Portfolio demo (install + 500+ incidents)"
	@echo "    make clean     - Stop everything, drop database, remove volumes"
	@echo ""
	@echo "  Services:"
	@echo "    make up        - Start all Docker services (detached)"
	@echo "    make down      - Stop all Docker services"
	@echo "    make logs      - Tail all service logs"
	@echo "    make server    - Run server locally (no Docker)"
	@echo "    make console   - Run console locally (no Docker)"
	@echo ""
	@echo "  Database:"
	@echo "    make db-migrate  - Run Alembic migrations"
	@echo "    make demo-seed   - Load demo data (500+ incidents, 10 users)"
	@echo "    make reset       - Drop DB, recreate, re-seed admin"
	@echo ""
	@echo "  Agent (C/C++):"
	@echo "    make agent     - Configure + build agent"
	@echo ""
	@echo "  Quality:"
	@echo "    make test      - Run server unit tests"
	@echo "    make test-e2e  - Run Playwright E2E tests"
	@echo "    make lint      - Lint server code"
	@echo "    make format    - Auto-format server code"
	@echo ""

# ================================================================
#  Install - full setup from scratch
# ================================================================
install:
	@echo ""
	@echo "=== AkesoDLP Install ==="
	@echo ""
	$(COMPOSE) build server console
	$(COMPOSE) up -d postgres redis
	@echo "Waiting for database..."
	@sleep 5
	$(COMPOSE) up -d server
	@echo "Waiting for server..."
	@sleep 8
	$(COMPOSE) up -d console
	@echo ""
	@echo "=== AkesoDLP is running ==="
	@echo ""
	@echo "  Console:  http://localhost:3000"
	@echo "  API:      http://localhost:8000"
	@echo "  API Docs: http://localhost:8000/docs"
	@echo ""
	@echo "  Admin credentials:"
	@echo "    Username: admin"
	@echo "    Password: AkesoDLP2026!"
	@echo ""

# ================================================================
#  Dev - hot-reload development
# ================================================================
dev:
	@echo ""
	@echo "=== AkesoDLP Development Mode ==="
	@echo ""
	@echo "Starting infrastructure (Postgres + Redis)..."
	$(COMPOSE) up -d postgres redis
	@echo "Waiting for database..."
	@sleep 5
	@echo ""
	@echo "Starting server (hot-reload)..."
	$(COMPOSE) up -d server
	@echo ""
	@echo "Starting console (Vite HMR)..."
	@echo "  -> cd console && npm run dev"
	@echo ""
	@echo "  Server:  http://localhost:8000 (FastAPI reload via Docker)"
	@echo "  Console: http://localhost:3000 (run 'cd console && npm run dev')"
	@echo ""
	@echo "  Admin: admin / AkesoDLP2026!"
	@echo ""

# ================================================================
#  Demo - portfolio demo with seed data
# ================================================================
demo: install demo-seed
	@echo ""
	@echo "=== AkesoDLP Demo Ready ==="
	@echo ""
	@echo "  Console:  http://localhost:3000"
	@echo "  500+ incidents, 10 users, 5 agents, 10 policies loaded."
	@echo "  Admin: admin / AkesoDLP2026!"
	@echo ""

demo-seed:
	@echo "Seeding demo data..."
	$(COMPOSE) exec server python -m server.scripts.demo_seed
	@echo "Demo data loaded."

# ================================================================
#  Reset - drop DB, recreate, fresh state
# ================================================================
reset:
	@echo "Stopping services..."
	$(COMPOSE) down
	@echo "Removing database volume..."
	docker volume rm claude-dlp_pgdata 2>/dev/null || true
	@echo "Restarting with clean database..."
	$(COMPOSE) up -d postgres redis
	@sleep 5
	$(COMPOSE) up -d server
	@sleep 8
	@echo "Database reset complete. Admin user auto-created on first start."
	@echo ""

# ================================================================
#  Clean - full teardown
# ================================================================
clean:
	@echo "Stopping all services and removing volumes..."
	$(COMPOSE) down -v --remove-orphans
	rm -rf agent/build
	rm -rf console/node_modules
	find . -type d -name __pycache__ -exec rm -rf {} + 2>/dev/null || true
	@echo "Clean complete."

# ================================================================
#  Server (Python/FastAPI)
# ================================================================
server:
	$(PYTHON) -m uvicorn server.main:app --host 0.0.0.0 --port 8000 --reload

server-install:
	$(PYTHON) -m pip install -r requirements.txt

# ================================================================
#  Console (React/Vite)
# ================================================================
console:
	cd console && npm run dev

console-install:
	cd console && npm install

console-build:
	cd console && npm run build

# ================================================================
#  Agent (C/C++)
# ================================================================
agent-configure:
	cmake -S agent -B agent/build -DCMAKE_BUILD_TYPE=Debug

agent-build:
	cmake --build agent/build --config Debug

agent: agent-configure agent-build

# ================================================================
#  Docker
# ================================================================
up:
	$(COMPOSE) up -d

down:
	$(COMPOSE) down

logs:
	$(COMPOSE) logs -f

# ================================================================
#  Database
# ================================================================
db-migrate:
	$(PYTHON) -m alembic upgrade head

db-revision:
	$(PYTHON) -m alembic revision --autogenerate -m "$(msg)"

# ================================================================
#  Proto
# ================================================================
proto:
	$(PYTHON) -m grpc_tools.protoc \
		-I proto \
		--python_out=server/proto \
		--grpc_python_out=server/proto \
		--pyi_out=server/proto \
		proto/akesodlp.proto
	sed -i 's/^import akesodlp_pb2/from server.proto import akesodlp_pb2/' server/proto/akesodlp_pb2_grpc.py

# ================================================================
#  Quality
# ================================================================
lint:
	$(PYTHON) -m ruff check server/
	$(PYTHON) -m ruff format --check server/

format:
	$(PYTHON) -m ruff check --fix server/
	$(PYTHON) -m ruff format server/

test:
	$(PYTHON) -m pytest server/ -v

test-e2e:
	cd console && npx playwright test
