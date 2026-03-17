.PHONY: server console agent agent-build up down clean test lint

PYTHON ?= python3

# --- Server (Python/FastAPI) ---
server:
	$(PYTHON) -m uvicorn server.main:app --host 0.0.0.0 --port 8000 --reload

server-install:
	$(PYTHON) -m pip install -r requirements.txt

# --- Console (React/Vite) ---
console:
	cd console && npm run dev

console-install:
	cd console && npm install

console-build:
	cd console && npm run build

# --- Agent (C/C++) ---
agent-configure:
	cmake -S agent -B agent/build -DCMAKE_BUILD_TYPE=Debug

agent-build:
	cmake --build agent/build --config Debug

agent: agent-configure agent-build

# --- Docker ---
up:
	docker compose up -d

down:
	docker compose down

logs:
	docker compose logs -f

# --- Database ---
db-migrate:
	$(PYTHON) -m alembic upgrade head

db-revision:
	$(PYTHON) -m alembic revision --autogenerate -m "$(msg)"

# --- Proto ---
proto:
	$(PYTHON) -m grpc_tools.protoc \
		-I proto \
		--python_out=server/proto \
		--grpc_python_out=server/proto \
		--pyi_out=server/proto \
		proto/sentineldlp.proto

# --- Quality ---
lint:
	$(PYTHON) -m ruff check server/
	$(PYTHON) -m ruff format --check server/

format:
	$(PYTHON) -m ruff check --fix server/
	$(PYTHON) -m ruff format server/

test:
	$(PYTHON) -m pytest server/ -v

# --- Shortcuts ---
install: server-install console-install
	@echo "All dependencies installed."

clean:
	docker compose down -v
	rm -rf agent/build
	rm -rf console/node_modules
	find . -type d -name __pycache__ -exec rm -rf {} + 2>/dev/null || true
