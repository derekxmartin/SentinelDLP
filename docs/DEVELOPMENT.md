# AkesoDLP Development Guide

## Prerequisites

- **Docker Desktop** (with Docker Compose v2)
- **Node.js 20+** (for console dev)
- **Python 3.12+** (for server dev outside Docker)
- **Visual Studio 2022 Build Tools** (for agent, with C++ and WDK)
- **CMake 3.25+** with Ninja

## Quick Start (Docker)

```bash
# Start infrastructure + server
make dev

# In a separate terminal, start console with HMR
cd console && npm install && npm run dev
```

Server: http://localhost:8000 (auto-reload on file changes)
Console: http://localhost:3000 (Vite HMR)
Admin: `admin` / `AkesoDLP2026!`

## Project Structure

```
claude-dlp/
├── agent/                  # C++ Windows agent
│   ├── driver/             # Kernel minifilter driver
│   ├── include/akeso/      # Headers
│   ├── src/                # Agent source
│   └── CMakeLists.txt
├── console/                # React frontend
│   ├── src/pages/          # Route pages
│   ├── src/components/     # Shared components
│   ├── src/api/            # API client
│   └── tests/e2e/          # Playwright tests
├── server/                 # Python backend
│   ├── api/                # FastAPI route handlers
│   ├── detection/          # Detection engine
│   ├── models/             # SQLAlchemy models
│   ├── services/           # Business logic
│   ├── proto/              # Generated gRPC stubs
│   └── scripts/            # Admin scripts
├── network/                # HTTP proxy + SMTP relay
├── proto/                  # Protobuf definitions
├── tests/                  # Integration tests
└── docker-compose.yml
```

## Agent Development

### Build (Debug)
```powershell
# From x64 Native Tools Command Prompt for VS 2022 (Admin)
cd agent
cmake --preset debug
cmake --build build/debug --target akeso-dlp-agent
```

### Build (Driver)
```powershell
cmake --preset release-driver
cmake --build build/release-driver --target akeso_dlp_filter
signtool sign /v /a /s My /n AkesoDLPTestCert /fd SHA256 build\release-driver\driver\akeso_dlp_filter.sys
```

### Run
```powershell
# Load driver (Admin)
fltmc load AkesoDLPFilter

# Run agent
.\build\debug\akeso-dlp-agent.exe --console --config config.yaml --test-policy
```

### Config (config.yaml)
```yaml
server:
  host: "172.29.48.1"  # Host IP from VM perspective
  port: 50051

discover:
  enabled: true
  target_directories:
    - "C:\\test\\docs"
  scan_interval_seconds: 60
  cpu_threshold_percent: 15

quarantine:
  enabled: true
  path: "C:\\AkesoDLP\\Quarantine"
```

## Server Development

### Run locally (without Docker)
```bash
pip install -r requirements.txt
uvicorn server.main:app --host 0.0.0.0 --port 8000 --reload
```

### Proto generation
```bash
make proto
```

### Linting
```bash
make lint    # Check
make format  # Auto-fix
```

## Console Development

### Setup
```bash
cd console
npm install
npm run dev
```

### E2E Tests
```bash
npx playwright install chromium
npm run test:e2e          # Headless
npm run test:e2e:headed   # With browser visible
npm run test:e2e:ui       # Interactive UI
```

## Testing

```bash
# Server unit tests
make test

# Integration tests (requires running server)
python -m pytest tests/integration/ -v

# E2E browser tests
cd console && npm run test:e2e

# All tests
make test && python -m pytest tests/integration/ -v && cd console && npm run test:e2e
```

## Database

```bash
# Reset database
make reset

# Load demo data
make demo-seed
```

## Common Issues

**Agent: `DriverComm: failed to connect (0x80070005)`**
→ Run as Administrator.

**Agent: `cstdint not found`**
→ Use "x64 Native Tools Command Prompt for VS 2022", not regular PowerShell.

**Agent: `x86 conflicts with x64`**
→ Wrong prompt. Use the **x64** variant, then `Remove-Item -Recurse build/debug` and rebuild.

**Server: `relation does not exist`**
→ Table missing. Run `make reset` to recreate the database.

**Console: Quick Edit Mode pauses output**
→ Right-click title bar → Properties → uncheck Quick Edit Mode.
