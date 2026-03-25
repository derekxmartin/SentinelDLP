# AkesoDLP Architecture

## Overview

AkesoDLP is a full-stack Data Loss Prevention platform with three tiers:

```
┌─────────────────────────────────────────────────────────┐
│                    Console (React)                       │
│  Dashboard │ Incidents │ Policies │ Agents │ Settings    │
└──────────────────────┬──────────────────────────────────┘
                       │ REST API (JWT auth)
┌──────────────────────┴──────────────────────────────────┐
│                 Server (Python/FastAPI)                   │
│  Detection Engine │ Policy Evaluator │ Incident Store     │
│  gRPC Server │ SIEM Emitter │ Risk Calculator             │
└────────┬─────────────────────────────┬──────────────────┘
         │ gRPC (heartbeat, policies,  │ HTTP POST
         │ incidents, discover)        │ (SIEM ingest)
┌────────┴─────────────────┐   ┌──────┴──────────────────┐
│   Agent (C++ / Windows)   │   │   AkesoSIEM             │
│  Minifilter Driver (WDM)  │   │   (cross-product)       │
│  ETW Browser Monitor      │   └─────────────────────────┘
│  Clipboard Monitor        │
│  Discover Scanner         │
│  Tamper Protection        │
└───────────────────────────┘
```

## Agent (C/C++)

### Kernel Driver (`agent/driver/`)
- Windows minifilter driver (WDM) — intercepts file I/O at kernel level
- Pre-operation callbacks on `IRP_MJ_WRITE` for real-time blocking
- Communication port (`\AkesoDLPPort`) for user-mode agent
- Kernel-level skip list for noise suppression (browser caches, WER, etc.)

### User-Mode Agent (`agent/src/`)
- **DriverComm**: Connects to minifilter port, receives file events, sends verdicts
- **DetectionPipeline**: Routes events through regex (Hyperscan) and keyword (Aho-Corasick) analyzers
- **BrowserUploadMonitor**: ETW tracing for browser file reads (upload detection)
- **ClipboardMonitor**: Win32 clipboard listener for copy/paste DLP
- **DiscoverScanner**: Scheduled filesystem scan with incremental caching and CPU throttling
- **GrpcClient**: Heartbeat, policy sync, incident reporting, discover integration
- **TamperProtection**: DACL hardening, uninstall password, SCM failure recovery

### Component Lifecycle
All components implement `IAgentComponent` (`Name()`, `Start()`, `Stop()`, `IsHealthy()`).
The `AgentService` manages startup ordering, watchdog health checks (5s interval), and graceful shutdown.

## Server (Python/FastAPI)

### Detection Engine (`server/detection/`)
- **DataIdentifierAnalyzer**: Regex + Luhn/checksum validation for PII patterns
- **KeywordDictionaryAnalyzer**: Aho-Corasick multi-pattern keyword matching
- **FileInspector**: Content extraction from 15+ file types (Office, PDF, archives)
- **DetectionEngine**: Orchestrates analyzers against parsed message components

### Policy Evaluation (`server/detection/`)
- Policies define rules with component targeting (body, subject, attachment, etc.)
- Severity tiers: CRITICAL, HIGH, MEDIUM, LOW, INFO
- Exception lists for allowlisted patterns/users
- Response actions: block, log, notify, quarantine, escalate, user_cancel

### Data Layer (`server/models/`, `server/services/`)
- PostgreSQL with async SQLAlchemy (asyncpg driver)
- Models: Incident, Policy, Agent, User, Role, DiscoverScan, Notification
- RBAC: Admin, Analyst, Remediator roles with granular permissions

### gRPC Server (`server/grpc_server.py`)
- Register, Heartbeat, GetPolicies, ReportIncident, DetectContent
- PolicyUpdates server-stream via Redis pub/sub
- Per-agent token bucket rate limiting
- Discover scan command dispatch via heartbeat responses

### Integrations
- **SIEM Emitter**: HTTP POST to AkesoSIEM with ECS-formatted events
- **Syslog Exporter**: CEF format over UDP/TCP/TLS
- **Risk Calculator**: Weighted scoring with recency decay (0.95^days)

## Network Monitor

### HTTP Proxy (`network/http_monitor.py`)
- mitmproxy-based HTTPS interception
- Monitor mode (log) and prevent mode (block with 403)
- Domain allowlist bypass

### SMTP Relay (`network/smtp_monitor.py`)
- aiosmtpd-based email relay
- Scans body + attachments
- Prevent mode: block (550), modify (subject prefix), redirect (quarantine)

## Console (React/TypeScript)

- Vite + React 19 + TypeScript
- Inline styles (dark theme, CSS variables)
- JWT auth with silent token refresh
- Command palette (Cmd+Shift+P) via cmdk
- Pages: Dashboard, Incidents, Policies, Agents, Discovers, Reports, Settings

## Infrastructure

```yaml
# Docker Compose services
postgres:   PostgreSQL 16 (incident store, policy cache)
redis:      Redis 7 (pub/sub for policy updates, rate limiting)
server:     FastAPI + gRPC (port 8000 + 50051)
console:    Vite dev server (port 3000)
http-proxy: mitmproxy (port 8080)
smtp-relay: aiosmtpd (port 2525)
mailhog:    SMTP test server (port 8025)
```
