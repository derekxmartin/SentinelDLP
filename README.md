<p align="center">
  <img src="docs/assets/logo.png" alt="AkesoDLP" width="200">
</p>

<h1 align="center">AkesoDLP</h1>

A proof-of-concept Data Loss Prevention (DLP) platform that detects, monitors, and prevents sensitive data from leaving an organization through endpoints, network channels, and data at rest.

Shares kernel driver infrastructure with AkesoEDR.

---

## What Is DLP?

**Data Loss Prevention** (DLP) is a category of security tools that identify, monitor, and protect sensitive data — credit card numbers, social security numbers, intellectual property, medical records, source code — and enforce policies that control how that data moves across endpoints, networks, and storage.

### Why DLP Matters

Organizations generate and handle sensitive data constantly. Without DLP, that data flows freely — copied to USB drives, emailed to personal accounts, uploaded to cloud storage, pasted into chat applications. A single uncontrolled transfer can mean regulatory fines, intellectual property theft, or breach notification obligations.

- **Content inspection.** DLP looks inside files and messages, not just at metadata. It uses regex patterns, keyword dictionaries, data identifiers with validation algorithms (Luhn for credit cards, MOD-97 for IBANs), file type detection by binary signature, and document fingerprinting to classify content.

- **Policy enforcement.** Detection alone isn't enough. DLP enforces response actions — block the transfer, notify the user, require justification, quarantine the file — based on configurable policies with severity tiers and exception logic.

- **Prevention, not just detection.** A minifilter driver intercepts file system operations *before* they complete. When a user copies a file containing 50 credit card numbers to a USB drive, the write is blocked before bytes reach the device. This is the same approach enterprise DLP vendors use in production.

- **Visibility across channels.** Sensitive data leaves through many paths — USB drives, network shares, clipboard, browser uploads, email, printing. DLP monitors all of them with channel-specific interception mechanisms.

### Who Uses DLP

| Role | How They Use DLP |
|------|------------------|
| **Security Analyst** | Triages policy violations, investigates incidents, determines intent vs. accidental exposure |
| **Compliance Officer** | Ensures regulatory requirements (PCI-DSS, HIPAA, GDPR, SOX) are enforced across data handling |
| **IT Administrator** | Manages agent deployment, policy distribution, endpoint health monitoring |
| **Incident Responder** | Reviews matched content, traces data movement, coordinates remediation |
| **CISO / Risk Manager** | Uses reporting and risk scoring to understand organizational data exposure |

### Why Build One?

Understanding how DLP works at the implementation level — minifilter drivers, content inspection pipelines, policy evaluation engines, two-tier detection — reveals how enterprise data protection actually operates. AkesoDLP exists for exactly this purpose: a fully transparent, source-available DLP platform that security practitioners can study, modify, and experiment with.

---

## What It Does

AkesoDLP inspects content across endpoints, network channels, and data at rest using a multi-technology detection engine and an enterprise-grade policy evaluation model.

**Highlights:**

- **Kernel-mode minifilter driver** intercepting file writes to USB/removable storage and network shares with true pre-operation blocking
- **User-mode hooks** for clipboard monitoring (NtUserSetClipboardData) and browser upload interception (WinHttpSendRequest)
- **Dual detection engines** — C++ agent (Hyperscan SIMD regex, Aho-Corasick keywords, native validators) and Python server (google-re2, pyahocorasick, full content extraction)
- **10 validated data identifiers** with checksum/format validators: Credit Card (Luhn), SSN, IBAN (MOD-97), ABA Routing (3-7-1), Phone, Email, Passport, Driver's License, IPv4, Date of Birth
- **Policy engine** with compound rules (AND), multiple rules (OR), exception conditions (entire-message and matched-component-only), severity tiers, and match count thresholds
- **Two-Tier Detection (TTD)** — agent forwards to server for fingerprint matching and complex content extraction when local detection cannot evaluate
- **Network monitor** — HTTP proxy (mitmproxy) and SMTP relay (aiosmtpd) with inline block/modify/redirect capability
- **Document fingerprinting** via simhash for detecting full or partial content matches from indexed confidential documents
- **Endpoint Discover** — scan endpoints for sensitive data at rest with incremental scanning and CPU throttling
- **Message decomposition model** — content split into envelope, subject, body, and attachment components for targeted detection
- **File content extraction** — PDF, Office (docx/xlsx/pptx), ZIP/TAR/7z archives with recursive extraction (max depth 3)
- **6 built-in policy templates** — PCI-DSS, HIPAA, GDPR, SOX, Source Code Leakage, Confidential Documents
- **React management console** with dark mode, policy editor, incident triage, agent management, and reporting
- **AkesoSIEM integration** — emits structured DLP events for cross-product correlation with EDR, AV, and NDR telemetry
- **Shared kernel driver infrastructure** with AkesoEDR — same minifilter framework, communication ports, service model, and build system

---

## Architecture

```
┌─────────────────────────────────────────────────────────────────┐
│                         KERNEL MODE                             │
│                                                                 │
│  akeso-dlp-driver.sys (minifilter)                           │
│  ├── IRP_MJ_WRITE pre-op callback                               │
│  │   → check volume type (removable? network share?)            │
│  │   → send file path + first 4KB to user-mode via filter port  │
│  │   → wait for verdict (ALLOW / BLOCK / SCAN_FULL)             │
│  │   → BLOCK: FLT_PREOP_COMPLETE + STATUS_ACCESS_DENIED         │
│  │   → ALLOW: FLT_PREOP_SUCCESS_WITH_CALLBACK                   │
│  ├── IRP_MJ_CREATE post-op (Endpoint Discover file tracking)    │
│  └── FltCommunicationPort ("\\AkesoDLPPort")                 │
├──────────────────────────── boundary ───────────────────────────┤
│                          USER MODE                              │
│                                                                 │
│  akeso-dlp-agent.exe (Windows service)                       │
│  ├── DriverComm       → FilterConnectCommunicationPort          │
│  ├── ContentInspector  → text extraction (PDF, Office, archives)│
│  ├── DetectionEngine   → Hyperscan regex, Aho-Corasick keywords │
│  │                       data identifier validators (Luhn, etc) │
│  ├── TTDClient         → forward to server for fingerprinting   │
│  ├── PolicyEvaluator   → compound rules, exceptions, severity   │
│  ├── ResponseExecutor  → block, notify, user-cancel, quarantine │
│  ├── ClipboardMonitor  → NtUserSetClipboardData hook            │
│  ├── BrowserMonitor    → WinHttpSendRequest hook                │
│  ├── PolicyCache       → SQLite local cache with version sync   │
│  ├── IncidentQueue     → memory-mapped file (1000 entries FIFO) │
│  ├── GrpcClient        → mTLS to server (report, sync, TTD)    │
│  └── Watchdog          → health monitor + tamper protection     │
└─────────────────────────────────────────────────────────────────┘

                            │ gRPC (mTLS)
                            ▼

┌─────────────────────────────────────────────────────────────────┐
│                     SERVER STACK (Docker)                        │
│                                                                 │
│  akeso-dlp-server (Python/FastAPI)                           │
│  ├── REST API          → policies, incidents, agents, detect    │
│  ├── Auth              → JWT + TOTP MFA + role-based access     │
│  ├── gRPC Service      → agent registration, heartbeat, TTD    │
│  └── SIEM Emitter      → HTTP POST to AkesoSIEM             │
│                                                                 │
│  akeso-dlp-detect (Python)                                   │
│  ├── RegexAnalyzer     → google-re2 (safe, no backtracking)    │
│  ├── KeywordAnalyzer   → pyahocorasick                         │
│  ├── DataIdentifier    → validators (Luhn, MOD-97, ABA, etc)   │
│  ├── FileTypeAnalyzer  → python-magic (binary signatures)      │
│  ├── FingerprintAnalyzer → simhash rolling hash                │
│  └── PolicyEvaluator   → compound rule evaluation logic        │
│                                                                 │
│  akeso-dlp-network (Python)                                  │
│  ├── HTTP Proxy        → mitmproxy (inspect uploads, block)    │
│  └── SMTP Relay        → aiosmtpd (inspect email, block/modify)│
│                                                                 │
│  akeso-dlp-console (React)                                   │
│  ├── Dashboard, Incidents, Policies, Agents, Discover, Reports │
│  └── Dark mode, shadcn/ui, Recharts, shared SIEM design system │
│                                                                 │
│  PostgreSQL 16 │ Redis 7 │ MailHog (test MTA)                   │
└─────────────────────────────────────────────────────────────────┘
```

---

## Components

| Component | Language | Description |
|-----------|----------|-------------|
| **akeso-dlp-driver** | C (WDK) | Windows minifilter driver. IRP_MJ_WRITE pre/post callbacks on monitored volumes. Filter communication port to user-mode agent. Shares architectural patterns with AkesoEDR's driver. |
| **akeso-dlp-agent** | C++17 (MSVC) | Endpoint agent Windows service. Hyperscan SIMD regex, Aho-Corasick keywords, data identifier validators. Policy cache, incident queue, clipboard/browser monitors, gRPC client. |
| **akeso-dlp-server** | Python/FastAPI | Management server. REST API, policy CRUD, incident management, user/role administration, gRPC service for agent communication, SIEM event emission. |
| **akeso-dlp-detect** | Python | Server-side detection engine. Pluggable analyzers (regex, keyword, data identifier, file type, fingerprint). Policy evaluation with compound AND/OR/exception logic. |
| **akeso-dlp-network** | Python | Network monitor. HTTP proxy (mitmproxy) and SMTP relay (aiosmtpd) with inline prevent capability (block, modify, redirect). |
| **akeso-dlp-console** | React/TypeScript | Web dashboard. Policy editor, incident triage, agent management, Endpoint Discover, reporting, user risk scoring. Dark mode with AkesoSIEM shared design system. |

---

## Detection Technologies

| Technology | Agent (C/C++) | Server (Python) | Description |
|-----------|---------------|-----------------|-------------|
| Regex matching | Hyperscan (SIMD, multi-pattern) | google-re2 (safe) | PCRE patterns against message components. Hyperscan evaluates thousands of patterns simultaneously. |
| Keyword matching | Aho-Corasick | pyahocorasick | Keyword lists, phrases, dictionaries. Case modes. Proximity matching. |
| Data identifiers | Native validators (Luhn, ABA, SSN) | Python validators | Pattern + validator model. 10 built-in identifiers with checksum validation. |
| File type detection | Magic bytes (libmagic) | python-magic | Binary signature detection for 50+ types. Does not rely on extension. |
| Document fingerprinting | Deferred to server (TTD) | Simhash rolling hash | Detect full or partial content matches from indexed confidential documents. |
| Content extraction | pdfium, libxml2, minizip | pdfplumber, python-docx, openpyxl | Extract text from PDF, Office, archives (recursive, max depth 3). |

---

## Monitoring Channels

| Channel | Mechanism | Pre-operation Block? |
|---------|-----------|---------------------|
| USB / Removable Storage | Minifilter IRP_MJ_WRITE pre-op on removable volumes | Yes |
| Network Shares | Minifilter IRP_MJ_WRITE pre-op on network volumes | Yes |
| Clipboard | NtUserSetClipboardData hook | Yes (pre-set) |
| Browser Upload | WinHttpSendRequest / HttpSendRequestW hook via DLL injection | Yes (pre-send) |
| HTTP Uploads | mitmproxy transparent proxy (POST/PUT body + multipart) | Yes (403 block) |
| SMTP Email | aiosmtpd relay (headers, body, attachments) | Yes (550 reject / modify / redirect) |
| Data at Rest | Endpoint Discover scan (incremental, CPU-throttled) | Quarantine |

---

## Response Actions

| Action | Description |
|--------|-------------|
| **Block** | Minifilter returns STATUS_ACCESS_DENIED. File moved to recovery folder. Notification displayed. |
| **Notify** | System tray toast notification with policy name and violation summary. |
| **User Cancel** | Modal dialog with justification field. Submit → allow with logged justification. Timeout → block. |
| **Log** | Always executes. Incident queued for server reporting. Persists to memory-mapped file if server unreachable. |
| **Quarantine** | Move file to quarantine folder. Marker stub left at original path with recovery instructions. |

---

## Policy Templates

| Template | Detects |
|----------|---------|
| PCI-DSS | Credit card numbers (Luhn-validated), cardholder data patterns |
| HIPAA | Medical record numbers, diagnosis codes, patient identifiers |
| GDPR | EU personal data — names + national IDs, IBAN, dates of birth |
| SOX | Financial statements, audit data, insider trading indicators |
| Source Code Leakage | Language-specific patterns, API keys, connection strings, certificates |
| Confidential Documents | Fingerprinted confidential documents, classification markers |

---

## Akeso Portfolio Integration

AkesoDLP fills the data protection role in the Akeso portfolio. Events emitted to AkesoSIEM enable cross-product correlation:

```
┌──────────────────────────────────────────────────────────────┐
│                    AkesoSIEM (Go + ES)                    │
│          Central correlator — Sigma rules — alerting         │
│                                                              │
│   Ingests: akeso_edr | akeso_av | akeso_dlp |       │
│            akeso_ndr | windows | syslog                   │
└──────┬───────────┬───────────┬───────────┬───────────────────┘
       │           │           │           │
┌──────┴──┐ ┌─────┴──┐ ┌────┴───┐ ┌────┴────┐
│Akeso    │ │Akeso   │ │Akeso   │ │Akeso    │
│EDR      │ │AV      │ │DLP     │ │NDR      │
│Endpoint │ │Malware │ │Content │ │Network  │
│behavior │ │detect  │ │inspect │ │metadata │
└─────────┘ └────────┘ └────────┘ └─────────┘
```

**Cross-product correlation examples:**

- **EDR + DLP:** User whose workstation triggered EDR credential theft alert accesses confidential file within 30 minutes
- **NDR + DLP:** NDR detects anomalous outbound volume to external IP → DLP confirms accessed files were classified as confidential
- **EDR + NDR + DLP:** Credential dump on Host A → lateral movement to Host B → sensitive file access on Host B → outbound data transfer

---

## Building

### Prerequisites

- **Python 3.12+** — server, detection engine, network monitor
- **Node.js 22+** — React console
- **Docker & Docker Compose** — infrastructure services
- **Visual Studio 2022** with C++ desktop workload — agent (Windows only)
- **Windows Driver Kit (WDK)** — minifilter driver (Windows only)
- **CMake 3.20+** — agent build system

### Server Stack (Docker)

```powershell
# Start all services (PostgreSQL, Redis, FastAPI, React, MailHog)
docker compose up -d

# Verify all healthy
docker compose ps
```

### Server (Local Development)

```powershell
# Install dependencies
make server-install

# Start FastAPI dev server on :8000
make server
```

### Console (Local Development)

```powershell
# Install dependencies
make console-install

# Start Vite dev server on :3000
make console
```

### Agent (Windows, requires MSVC + CMake)

```powershell
# Configure and build
make agent

# Or step by step:
cmake -S agent -B agent/build -DCMAKE_BUILD_TYPE=Debug
cmake --build agent/build --config Debug
```

### Verify

```powershell
# API health check
(Invoke-WebRequest http://localhost:8000/api/health).Content

# Console
(Invoke-WebRequest http://localhost:3000).StatusCode

# MailHog
(Invoke-WebRequest http://localhost:8025).StatusCode
```

---

## Project Structure

```
claude-dlp/
├── Makefile                    Build targets (server, console, agent, docker, test)
├── docker-compose.yml          PostgreSQL, Redis, FastAPI, React, MailHog
├── requirements.txt            Python dependencies
├── server/                     Python server package
│   ├── main.py                FastAPI application entry point
│   ├── config.py              Settings (database, redis, auth, SIEM)
│   ├── database.py            SQLAlchemy async engine + session
│   ├── models/                SQLAlchemy ORM models
│   ├── schemas/               Pydantic request/response schemas
│   ├── routes/                FastAPI route handlers
│   ├── services/              Business logic layer
│   ├── proto/                 Generated gRPC stubs
│   ├── scripts/               Seed data, MFA reset, utilities
│   └── Dockerfile             Server container image
├── agent/                     C/C++ endpoint agent
│   ├── CMakeLists.txt         CMake build configuration
│   ├── src/                   Agent source (main, detection, policy, response)
│   ├── include/               Agent headers
│   ├── driver/                Minifilter driver source
│   └── config/                Agent YAML configuration
├── console/                   React management console
│   ├── src/                   App source (pages, components, hooks)
│   ├── public/                Static assets
│   ├── vite.config.ts         Vite + Tailwind + API proxy
│   └── Dockerfile             Console container image
├── proto/                     Shared protobuf definitions
├── scripts/                   Utility scripts (wait-for-db, cert gen)
└── migrations/                Alembic database migrations
```

---

## Implementation Phases

| Phase | Description | Status |
|-------|-------------|--------|
| P0 | Project scaffolding, Docker, database schema, protobuf | In Progress |
| P1 | Server-side detection engine (regex, keywords, data IDs, file type, fingerprint) | Pending |
| P2 | REST API & React console (auth, policies, incidents, agents) | Pending |
| P3 | Endpoint agent core — minifilter driver, service, gRPC, policy cache | Pending |
| P4 | Endpoint agent detection & response — Hyperscan, hooks, blocking, notifications | Pending |
| P5 | Network monitor — HTTP proxy, SMTP relay, inline prevent | Pending |
| P6 | Document fingerprinting (simhash) | Pending |
| P7 | Endpoint Discover — data at rest scanning | Pending |
| P8 | Reporting, user risk scoring, SIEM event export | Pending |
| P9 | Console polish, dark mode, global search, demo environment | Pending |
| P10 | Integration testing & documentation | Pending |
| P11 | Hardening & production readiness (metrics, load testing, packaging) | Pending |

**Total: 86 tasks, 12 phases.**

See `REQUIREMENTS.md` for the full implementation roadmap.

---

## License

MIT License. See [LICENSE](LICENSE).

## Disclaimer

This is an educational proof-of-concept built for learning and portfolio purposes. It is **not** production security software. Deploy only in authorized, isolated test environments.

## Acknowledgments

- *Evading EDR* by Matt Hand (No Starch Press, 2023) — shared kernel driver infrastructure patterns with AkesoEDR
