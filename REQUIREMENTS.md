# AkesoDLP — Requirements Document v1.1

## A Proof-of-Concept Data Loss Prevention Platform

**Version 1.1 — Claude Code Implementation Phases | March 2026**

Built on C/C++ (agent + minifilter driver) and Python (server + detection engine) with Symantec DLP 16.0-derived policy engine and gRPC agent communication. Shares kernel driver infrastructure with AkesoEDR. Designed to emit telemetry to AkesoSIEM for cross-product correlation alongside AkesoEDR, AkesoAV, and AkesoNDR.

> **v1.1 Changelog (from v1.0):** Fixed stale TheHive reference (AkesoSIEM now has built-in case management). Added agent offline mode behavior spec (Section 3.14). Added Two-Tier Detection (TTD) request flow spec (Section 3.15). Added agent update/upgrade mechanism (Section 3.16). Added browser monitor coexistence note for AkesoEDR allowlisting (Section 3.17). Added console MFA authentication spec (Section 4.1). Added console global search spec (Section 4.2). Added console dark mode and shared design system spec (Section 4.3). Fixed SIEM event type naming alignment (Section 3.11). Expanded network monitor Docker networking spec (Section 3.10). Added Community ID tagging as v1 limitation with v2 resolution. Added Playwright E2E console test suite (P9-T5). Added deployment automation with `make install`/`make dev`/`make demo`/`make clean` (P9-T6). Added comprehensive network monitor test suite (P10-T5). Added static test fixtures and test data generation (P10-T7). Split Phase 10 into Integration Testing (P10, 7 tasks) and Hardening & Production Readiness (P11, 7 tasks). P11 adds: graceful shutdown, Prometheus metrics with Grafana template, load testing with defined pass thresholds, dead letter queue, database partitioning and archival, gRPC rate limiting, installer packaging. Total: +11 tasks (75 → 86), +1 phase (11 → 12).

-----

# PART I: REQUIREMENTS & ARCHITECTURE

## 1. Executive Summary

AkesoDLP is a proof-of-concept Data Loss Prevention platform that detects, monitors, and prevents sensitive data from leaving an organization through endpoints, network channels, and data at rest. The system is derived from a comprehensive analysis of the Symantec Data Loss Prevention 16.0 Help Center (2,111 pages), distilled to the features that demonstrate core DLP competency as a portfolio piece.

The project fills the data protection role in the Akeso portfolio. Where AkesoEDR detects threats based on process, memory, and registry behavior, AkesoDLP focuses on content — detecting sensitive data (PII, financial records, intellectual property, classified documents) and enforcing policies that control how that data moves across endpoints, networks, and storage. AkesoAV detects malware; AkesoNDR provides passive network visibility through protocol metadata extraction and behavioral detection on the wire; AkesoDLP detects data. Together with AkesoSIEM as the central correlator, the portfolio covers: endpoint behavior (EDR) + malware detection (AV) + data protection (DLP) + network detection (NDR) + log aggregation & correlation (SIEM).

The DLP–NDR relationship is particularly valuable. AkesoDLP sees what data is being exfiltrated (content classification, policy violation details), while AkesoNDR sees how it’s leaving (outbound transfer volumes, destination IPs, protocol anomalies, covert channel indicators). When correlated in AkesoSIEM, this produces detections neither tool can generate alone: NDR detects anomalous outbound volume to a new external IP → DLP confirms the accessed files were classified as confidential → combined alert with both content and network context.

The agent is built in C/C++ and shares kernel driver infrastructure with AkesoEDR. This is a deliberate architectural decision — Symantec DLP’s core value proposition is prevention, not just detection. A minifilter driver intercepts file system operations before they complete, enabling true blocking of sensitive data transfers to USB drives, network shares, and other destinations. User-mode hooks intercept clipboard operations and browser uploads before data leaves the machine. This is the same approach Symantec, Digital Guardian, and Forcepoint use in production. The entire Akeso endpoint stack (EDR + AV + DLP) shares a language, build system, and kernel driver communication model — exactly as a real security vendor would architect it.

The server and detection engine are built in Python/FastAPI, where development speed matters and there is no kernel interaction. The management console is React. Agent-server communication is gRPC with mTLS.

AkesoDLP natively integrates with AkesoSIEM by emitting structured DLP events (`dlp:policy_violation`, `dlp:block`, `dlp:audit`, `dlp:removable_media`, `dlp:classification`) via HTTP POST to the SIEM’s ingestion endpoint, enabling cross-product Sigma correlation rules alongside AkesoEDR, AkesoAV, and AkesoNDR telemetry.

### 1.1 Akeso Portfolio Architecture

```
┌──────────────────────────────────────────────────────────────────────┐
│                    AkesoSIEM (Go + Elasticsearch)                 │
│          Central correlator — Sigma rules — unified alerting         │
│              Built-in case management for alert escalation           │
│                                                                      │
│   Ingests: akeso_edr | akeso_av | akeso_dlp |               │
│            akeso_ndr | windows | syslog                           │
│                                                                      │
│   Correlation: EDR+DLP, EDR+NDR, NDR+DLP, AV+DLP, full chain       │
└──────┬───────────┬───────────┬───────────┬───────────────────────────┘
       │           │           │           │
┌──────┴──┐ ┌─────┴──┐ ┌────┴───┐ ┌────┴────┐
│Akeso    │ │Akeso   │ │Akeso   │ │Akeso    │
│EDR      │ │AV      │ │DLP     │ │NDR      │
│(C/C++)  │ │(C/C++) │ │(C/C++ +│ │(Go)     │
│         │ │        │ │Python) │ │         │
│Endpoint │ │Malware │ │Content │ │Network  │
│behavior │ │detect  │ │inspect │ │metadata │
│Process  │ │Sig scan│ │Policy  │ │Protocol │
│Memory   │ │Quarant.│ │enforce │ │dissect  │
│Registry │ │On-acc. │ │Prevent │ │Behavior │
│Network  │ │        │ │        │ │Host     │
│         │ │DLL in  │ │Shares  │ │scoring  │
│         │ │EDR proc│ │driver  │ │         │
│         │ │        │ │patterns│ │Passive  │
│         │ │        │ │w/ EDR  │ │SPAN/TAP │
└─────────┘ └────────┘ └────────┘ └─────────┘
  Endpoint    Endpoint    Endpoint    Network
  agent       module      agent       sensor
```

Each product emits ECS-normalized events to AkesoSIEM via HTTP POST to `/api/v1/ingest`. AkesoSIEM evaluates Sigma rules across all sources — including cross-product correlation rules that span EDR, AV, DLP, and NDR telemetry. AkesoSIEM’s built-in case management handles alert escalation, observable tracking, and incident resolution.

## 2. Project Goals & Non-Goals

### 2.1 Goals

- Build a working DLP system that detects sensitive content via regex patterns, keyword dictionaries, data identifiers with validation (Luhn, checksum), file type detection by binary signature, and document fingerprinting.
- Implement a policy engine derived from Symantec DLP 16.0 with compound rules (AND logic), multiple rules (OR logic), exception conditions (entire-message and matched-component-only), severity tiers, and match count thresholds.
- Deploy a C/C++ endpoint agent with a Windows minifilter driver that intercepts file operations to USB/removable storage, clipboard operations, and browser uploads — with true pre-operation blocking, not post-hoc detection.
- Share kernel driver infrastructure with AkesoEDR — the minifilter extends or coexists with AkesoEDR’s file system monitoring, using the same named pipe / shared memory communication patterns.
- Inspect network traffic via HTTP proxy and SMTP relay to detect sensitive content in web uploads and outbound email, with inline prevent capability (block, modify, redirect).
- Provide a web-based management console with MFA authentication, policy authoring, incident triage, agent management, and reporting.
- Expose a REST API for programmatic policy management, content detection, and incident CRUD.
- Emit DLP events to AkesoSIEM for cross-product correlation and unified alerting.
- Scan endpoints for sensitive data at rest (Endpoint Discover) with incremental scanning and CPU throttling.
- Ship with built-in policy templates for PCI-DSS, HIPAA, GDPR, SOX, source code leakage, and confidential document detection.

### 2.2 Non-Goals (v1)

- Replacing Symantec DLP, Microsoft Purview, or any production DLP. This is a learning and portfolio tool.
- Exact Data Matching (EDM) with indexed database profiles — requires significant index management infrastructure.
- Vector Machine Learning (VML) content classification — requires ML training pipeline.
- Form Recognition (image-based form detection) — requires specialized image processing.
- Active Directory integration for Directory Group Matching (DGM) — requires AD infrastructure.
- Cloud Detection Service / CASB integration.
- Network Discover for SharePoint, Exchange, SQL databases, IBM Lotus Notes.
- High Availability, Disaster Recovery, or Oracle RAC database clustering.
- ServiceNow End User Remediation (EUR) integration.
- Multi-language detection and language packs (Unicode support only).
- Combined single-binary with AkesoEDR (v1 ships as a separate agent that shares driver patterns but runs independently).
- Community ID tagging on DLP network monitor events. v1 correlates DLP and NDR events by IP+timestamp proximity in AkesoSIEM. v2 adds Community ID hashes to HTTP proxy and SMTP relay events for exact flow-level correlation with NDR session metadata.

## 3. System Architecture

### 3.1 Component Overview

|Component           |Language      |Responsibility                                                                                                                                                                                                                                                                                                        |
|--------------------|--------------|----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
|akeso-dlp-server |Python/FastAPI|Management server. REST API, policy CRUD, incident management, user/role administration, server-side detection engine orchestration. The “Enforce Server” equivalent.                                                                                                                                                 |
|akeso-dlp-detect |Python        |Server-side content detection engine. Pluggable analyzers (regex, keyword, data identifier, file type, fingerprint). File content extraction (PDF, Office, archives). Policy evaluation with Symantec-derived AND/OR/exception logic. Handles two-tier detection (TTD) requests from agents.                          |
|akeso-dlp-agent  |C/C++         |Endpoint agent. Windows service with minifilter driver for file system interception, user-mode hooks for clipboard and browser upload monitoring. Local first-pass detection with Hyperscan regex, Aho-Corasick keywords, and data identifier validators. Pre-operation blocking. Policy cache. gRPC client to server.|
|akeso-dlp-driver |C (WDM/WDF)   |Windows minifilter driver. Registers for IRP_MJ_WRITE and IRP_MJ_CREATE pre/post callbacks on monitored volumes. Communicates with user-mode agent via filter communication port. Shares architectural patterns with AkesoEDR’s driver.                                                                            |
|akeso-dlp-network|Python        |Network monitor. HTTP proxy (mitmproxy) and SMTP relay (aiosmtpd) for inspecting web uploads and outbound email. Inline prevent capability (block, modify, redirect).                                                                                                                                                 |
|akeso-dlp-console|React/JS      |Web dashboard. Policy editor, incident list/snapshot, agent management, dashboard with charts, reporting. MFA authentication. Dark mode. Global search.                                                                                                                                                               |
|akeso-dlp-db     |PostgreSQL    |Persistent storage. Policies, incidents, users, roles, agents, audit log. JSONB for flexible schema.                                                                                                                                                                                                                  |
|akeso-dlp-queue  |Redis         |Event streaming. Incident buffering between agent reports and server processing. TTD request queuing.                                                                                                                                                                                                                 |

### 3.2 Data Flow

```
ENDPOINT MONITORING (C/C++ agent + minifilter):

[File Write → USB] ──minifilter IRP_MJ_WRITE pre-op──→ [akeso-dlp-driver]
                                                              │
                                                │ FltSendMessage (filter port)
                                                              ↓
[Clipboard Paste] ──NtUserSetClipboardData hook──→ [akeso-dlp-agent]
[Browser Upload]  ──WinHTTP/WinInet hook─────────→   (user-mode service)
                                                              │
                                ├→ local detection (Hyperscan regex,
                                │    Aho-Corasick keywords, Luhn/checksum)
                                │
                                ├→ BLOCK (return STATUS_ACCESS_DENIED
                                │    via minifilter, or cancel hook)
                                │    + move file to recovery folder
                                │    + display notification
                                │
                                ├→ ALLOW (return FLT_PREOP_SUCCESS_WITH_CALLBACK)
                                │
                                ├→ TTD (send to server for full detection
                                │    when local engine cannot evaluate —
                                │    e.g., fingerprint matching, complex
                                │    content extraction)
                                │
                                └→ gRPC (mTLS) ──→ [akeso-dlp-server]
                                                              │
                                              ┌────────────────┤
                                             │                 │
                                             ↓                 ↓
                                     [PostgreSQL]       [AkesoSIEM]
                                     (incidents,        /api/v1/ingest
                                      policies)


SERVER-SIDE DETECTION (Python):

        [akeso-dlp-server] ←→ [akeso-dlp-detect]
               │                        │
               │  TTD requests           ├→ RegexAnalyzer (google-re2)
               │  from agents            ├→ KeywordAnalyzer (pyahocorasick)
               │                         ├→ DataIdentifierAnalyzer (validators)
               │  /api/detect            ├→ FileTypeAnalyzer (python-magic)
               │  submissions            ├→ FingerprintAnalyzer (simhash)
               │                         └→ PolicyEvaluator (Symantec logic)
               │
               ↓
        [akeso-dlp-console (React)]


NETWORK MONITORING (Python):

[HTTP POST/PUT] ──proxy──→ [akeso-dlp-network] →(detect)→ [block/pass]
[SMTP outbound] ──relay──→        │                     │
                                  ↓                     ↓
                          [akeso-dlp-server] → [incident in DB + SIEM]
```

### 3.3 Agent Architecture — Kernel + User-Mode Split

The agent follows a split architecture mirroring AkesoEDR: a kernel-mode minifilter driver handles file system interception, and a user-mode Windows service handles detection, policy evaluation, response actions, and server communication. The two components communicate via the FltCreateCommunicationPort / FilterConnectCommunicationPort API.

```
┌─────────────────────────────────────────────────────────────────┐
│                         KERNEL MODE                              │
│                                                                  │
│  akeso-dlp-driver.sys (minifilter)                           │
│  ├── IRP_MJ_WRITE pre-op callback                               │
│  │   → check volume type (removable? network share?)            │
│  │   → send file path + first 4KB to user-mode via filter port  │
│  │   → wait for verdict (ALLOW / BLOCK / SCAN_FULL)             │
│  │   → if BLOCK: return FLT_PREOP_COMPLETE + STATUS_ACCESS_DENIED│
│  │   → if ALLOW: return FLT_PREOP_SUCCESS_WITH_CALLBACK         │
│  │   → if SCAN_FULL: pend IRP, signal user-mode for full scan   │
│  │                                                               │
│  ├── IRP_MJ_CREATE post-op callback                              │
│  │   → track file handles for Endpoint Discover                  │
│  │                                                               │
│  └── FltCommunicationPort (named "\\AkesoDLPPort")           │
│                                                                  │
├──────────────────────────── boundary ────────────────────────────┤
│                                                                  │
│                          USER MODE                               │
│                                                                  │
│  akeso-dlp-agent.exe (Windows service)                        │
│  ├── DriverComm       → FilterConnectCommunicationPort           │
│  │                      receives file events from driver         │
│  │                      sends ALLOW/BLOCK verdicts back          │
│  │                                                               │
│  ├── ContentInspector  → read file content                       │
│  │                      extract text (PDF, Office, archives)     │
│  │                      decompose into message components        │
│  │                                                               │
│  ├── DetectionEngine   → Hyperscan regex (SIMD-accelerated)      │
│  │                      Aho-Corasick keywords                    │
│  │                      Data identifier validators (Luhn, etc)   │
│  │                      File type by magic bytes                 │
│  │                                                               │
│  ├── TTDClient         → Forward to server when local detection  │
│  │                      cannot evaluate (fingerprinting, complex │
│  │                      content). Async with configurable timeout│
│  │                      and fallback behavior.                   │
│  │                                                               │
│  ├── PolicyEvaluator   → compound rules (AND), multi-rule (OR)   │
│  │                      exceptions, severity tiers               │
│  │                      match count thresholds                   │
│  │                                                               │
│  ├── ResponseExecutor  → block (STATUS_ACCESS_DENIED via driver) │
│  │                      notify (Win32 toast / balloon)           │
│  │                      user-cancel (dialog + justification)     │
│  │                      quarantine (move + marker stub)          │
│  │                      log (always, queue for server)           │
│  │                                                               │
│  ├── ClipboardMonitor  → hook NtUserSetClipboardData             │
│  │                      scan content pre-paste                   │
│  │                      block or notify on violation             │
│  │                                                               │
│  ├── BrowserMonitor    → hook WinHttpSendRequest                 │
│  │                      inspect upload content pre-send          │
│  │                      cancel request on violation              │
│  │                      (see Section 3.17 for EDR coexistence)   │
│  │                                                               │
│  ├── PolicyCache       → SQLite local cache                      │
│  │                      atomic version swap                      │
│  │                      offline operation with cached policies   │
│  │                      (see Section 3.14 for offline behavior)  │
│  │                                                               │
│  ├── IncidentQueue     → memory-mapped file queue                │
│  │                      persist across service restarts          │
│  │                      drain FIFO on server reconnect           │
│  │                                                               │
│  ├── GrpcClient        → mTLS to akeso-dlp-server:50051      │
│  │                      register, heartbeat, report incidents    │
│  │                      policy sync, TTD requests                │
│  │                                                               │
│  └── Watchdog          → monitor agent service health            │
│                          restart on crash                        │
│                          tamper protection (deny stop/kill)      │
│                                                                  │
└─────────────────────────────────────────────────────────────────┘
```

### 3.4 Content Detection — Message Decomposition Model

All content inspected by AkesoDLP is first decomposed into components, following the Symantec DLP model. This decomposition is critical for accurate detection — a policy targeting “attachments only” must not trigger on matching body content.

|Component  |Description                                                                     |Available For       |
|-----------|--------------------------------------------------------------------------------|--------------------|
|envelope   |Sender, recipient, protocol metadata (email addresses, IPs, URLs, user identity)|SMTP, HTTP, endpoint|
|subject    |Email subject line or document title                                            |SMTP                |
|body       |Message body text, HTTP POST body, document main content                        |SMTP, HTTP, endpoint|
|attachments|File attachments, uploaded files, copied files                                  |SMTP, HTTP, endpoint|

For endpoint channels that lack full message structure (e.g., USB file copy), the Symantec DLP 16.0 mapping applies: Envelope → user identity, device info, destination path. Subject → mapped to envelope (no separate subject on endpoints). Body → mapped to “generic” (matches subject, body, and attachment). Attachments → mapped to “generic.” “Generic” is a virtual endpoint component that matches across subject, body, and attachment — enforcing component matching on the endpoint gives consistent behavior with server-side detection per the DLP 16.0 spec.

### 3.5 Policy Evaluation Engine

The policy evaluation engine implements the Symantec DLP 16.0 evaluation model. This logic runs both server-side (Python, for API submissions and TTD requests) and agent-side (C++, for local detection).

Evaluation order:

1. Detection rules and group (identity) rules evaluated against message components
1. “Entire message” exceptions applied — if met, message ejected entirely
1. “Matched component only” exceptions applied — if met, individual components ejected
1. Remaining matched components used to determine severity and generate incident

Logic model:

|Configuration                                    |Logic|Description                           |
|-------------------------------------------------|-----|--------------------------------------|
|Compound rules (multiple conditions in one rule) |AND  |All conditions must match             |
|Rules of the same type (multiple detection rules)|OR   |Any detection rule match suffices     |
|Rules of different types (detection + group)     |AND  |At least one from each type must match|
|Exceptions of different types (detection + group)|OR   |Any exception match ejects            |

Severity calculation: Default severity from policy (High/Medium/Low/Info). Override by match count thresholds (e.g., High at 100+ matches, Medium at 50+). Multiple severity tiers evaluated highest-first.

### 3.6 Detection Technologies

|Technology             |Agent (C/C++)                                                             |Server (Python)                   |Description                                                                                                     |
|-----------------------|--------------------------------------------------------------------------|----------------------------------|----------------------------------------------------------------------------------------------------------------|
|Regex matching         |Hyperscan (Intel, SIMD-accelerated, multi-pattern simultaneous evaluation)|google-re2 (safe, no backtracking)|PCRE patterns against message components. Hyperscan on the agent evaluates thousands of patterns simultaneously.|
|Keyword matching       |Aho-Corasick (custom or hs_compile with literal mode)                     |pyahocorasick                     |Keyword lists, phrases, dictionaries. Case modes. Proximity matching.                                           |
|Data identifiers       |Native validators (Luhn in C, ABA checksum, SSN format)                   |Python validators                 |Pattern + validator model. Built-in identifiers for CC, SSN, IBAN, phone, email, etc.                           |
|File type detection    |Magic bytes (libmagic or custom signature table)                          |python-magic                      |Binary signature detection for 50+ types. Does not rely on extension.                                           |
|Document fingerprinting|Deferred to server (TTD request — see Section 3.15)                       |Simhash rolling hash              |Detect full or partial content matches from indexed confidential documents.                                     |
|Identity matching      |Envelope metadata comparison                                              |Envelope metadata comparison      |Match on sender/recipient email, IP, username.                                                                  |
|Archive inspection     |minizip, libarchive                                                       |zipfile, tarfile, py7zr           |Recursive extraction (max depth 3) of ZIP, TAR, 7z, RAR.                                                        |
|Content extraction     |Tika client, custom PDF/Office parsers, or pdfium                         |pdfplumber, python-docx, openpyxl |Extract text from PDF, Office, plain text.                                                                      |

Why Hyperscan on the agent matters: A DLP agent sits in the critical path of every file write to a monitored destination. Hyperscan evaluates all active regex patterns against the content in a single pass using SIMD instructions. On a modern CPU, this means scanning a 10MB file against 500 patterns takes ~50ms instead of the ~2 seconds that sequential re2 evaluation would require. This is the difference between a user noticing a delay when copying files to USB and not.

### 3.7 Built-in Data Identifiers

Ship with 10 validated data identifiers, implemented in both C++ (agent) and Python (server):

|Identifier                         |Pattern                                           |Validator                               |Example Match              |
|-----------------------------------|--------------------------------------------------|----------------------------------------|---------------------------|
|Credit Card (Visa/MC/Amex/Discover)|`4[0-9]{12}(?:[0-9]{3})?`, etc.                   |Luhn checksum                           |4532015112830366           |
|US Social Security Number          |`\d{3}-\d{2}-\d{4}`                               |Area number validation (no 000/666/900+)|123-45-6789                |
|US Phone Number                    |`(\+1)?[\s.-]?\(?\d{3}\)?[\s.-]?\d{3}[\s.-]?\d{4}`|Format validation                       |(555) 123-4567             |
|Email Address                      |RFC 5322 pattern                                  |Domain validation                       |user@example.com           |
|IBAN                               |`[A-Z]{2}\d{2}[A-Z0-9]{4,}`                       |MOD-97 checksum (ISO 7064)              |GB29 NWBK 6016 1331 9268 19|
|US Passport Number                 |`[A-Z]?\d{8,9}`                                   |Format + length                         |123456789                  |
|US Driver’s License                |Multi-state patterns                              |State-specific format                   |(varies)                   |
|IPv4 Address                       |`\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}`              |Octet range (0-255)                     |192.168.1.1                |
|Date of Birth                      |Multiple date formats                             |Calendar validation                     |01/15/1990                 |
|US Bank Routing Number (ABA)       |`\d{9}`                                           |ABA checksum (3-7-1 weighted)           |021000021                  |

### 3.8 Endpoint Agent — Monitoring Channels

|Channel              |Mechanism                                                                                |Preop Block?    |Description                                                                                                                                   |
|---------------------|-----------------------------------------------------------------------------------------|----------------|----------------------------------------------------------------------------------------------------------------------------------------------|
|USB/Removable Storage|Minifilter IRP_MJ_WRITE pre-op on removable volumes                                      |Yes             |File content inspected before bytes reach device. STATUS_ACCESS_DENIED blocks write. File moved to recovery folder.                           |
|Network Shares       |Minifilter IRP_MJ_WRITE pre-op on network volumes                                        |Yes             |Same mechanism as USB. Filter identifies network redirector destinations (CIFS/SMB).                                                          |
|Clipboard            |NtUserSetClipboardData hook via IAT/inline patching or SetWindowsHookEx with WH_CLIPBOARD|Yes (pre-set)   |Content scanned before entering clipboard. Block prevents data from being available to paste targets.                                         |
|Browser Upload       |WinHttpSendRequest / HttpSendRequestW hook via DLL injection into browser processes      |Yes (pre-send)  |Upload content inspected before HTTP request is sent. Cancel prevents data from leaving machine. See Section 3.17 for AkesoEDR coexistence.|
|Print/Fax            |GDI StartDocW hook                                                                       |No (notify only)|Detect sensitive content in print jobs. Notify user. (v1 stretch goal.)                                                                       |

Device class identification for USB: SetupDiGetClassDevs + SetupDiGetDeviceRegistryProperty to enumerate USB mass storage devices. Device class GUID, vendor ID, product ID available for allowlisting. Policy can allow only encrypted USB devices (by device class) while blocking generic mass storage.

### 3.9 Endpoint Agent — Response Actions

|Action     |Mechanism                                                                               |Description                                                                                                                                                                 |
|-----------|----------------------------------------------------------------------------------------|----------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
|Block      |Minifilter returns FLT_PREOP_COMPLETE + STATUS_ACCESS_DENIED. Hook returns failure code.|File operation fails before completion. User sees “Access Denied.” File moved to recovery folder (`C:\AkesoDLP\Recovery\<timestamp>_<filename>`). Notification displayed.|
|Notify     |Win32 Shell_NotifyIcon (system tray balloon) or Toast notification via COM.             |Display policy name, violation summary, recommended action. Log user acknowledgment timestamp.                                                                              |
|User Cancel|Modal dialog (MessageBoxEx or custom HWND). Timer for auto-block.                       |User sees violation details + justification text field. Submit justification → operation allowed, justification logged with incident. Cancel or timeout (120s) → block.     |
|Log        |Always executes. Incident serialized to incident queue.                                 |Queue incident for server reporting via gRPC. Persist to memory-mapped file if server unreachable. Drain FIFO on reconnect. Max 1000 entries.                               |
|Quarantine |Move file to quarantine folder. Write .txt marker at original path.                     |For Endpoint Discover (data at rest). Original file replaced with `<filename>.quarantined.txt` containing policy name and recovery instructions.                            |

### 3.10 Network Monitor Architecture

**Relationship to AkesoNDR:** AkesoDLP’s network monitor and AkesoNDR serve complementary roles. AkesoNDR is a passive network sensor on a SPAN port — it extracts protocol metadata, detects behavioral anomalies (beaconing, lateral movement, exfiltration volume), and scores hosts, but it never modifies traffic. AkesoDLP’s network monitor is an inline proxy/relay — it inspects content, evaluates DLP policies, and can block or modify traffic that violates policy. AkesoNDR sees the network at the flow and metadata level; AkesoDLP’s network monitor sees the content at the payload level. Both emit events to AkesoSIEM where they correlate: NDR’s exfiltration volume alert + DLP’s content classification = confirmed sensitive data exfiltration with both network and content evidence.

**HTTP Monitor/Prevent (Python):** Transparent proxy via mitmproxy. Inspects POST/PUT request bodies and multipart file uploads. Monitor mode: log violations, pass traffic. Prevent mode: block with custom HTML error page (HTTP 403). Domain allowlisting for internal/trusted destinations.

**SMTP Monitor/Prevent (Python):** Relay via aiosmtpd. Inspects email headers, body, and attachments. Monitor mode: log violations, forward to upstream MTA. Prevent mode: block (550 rejection), modify (subject prefix, X-DLP-Violation header), redirect (quarantine mailbox).

**Docker Networking:** The HTTP proxy (mitmproxy) runs on port 8080 and is configured as a forward proxy. Test clients configure their HTTP proxy setting to point at `http://dlp-proxy:8080`. The SMTP relay (aiosmtpd) runs on port 2525 and relays to an upstream MTA. For development and demo, MailHog runs on port 1025 (SMTP) and 8025 (web UI) as the upstream MTA, providing a visual inbox for inspecting DLP-processed email. All three services (mitmproxy, aiosmtpd, MailHog) are defined in Docker Compose with a shared `dlp-network` bridge network. The mitmproxy CA certificate is generated at first startup via `scripts/gen-proxy-ca.sh` and must be trusted by test clients for HTTPS inspection.

**v1 limitation — Community ID:** DLP network monitor events do not include Community ID hashes in v1. Correlation between DLP network events and AkesoNDR flow metadata happens by IP+timestamp proximity in AkesoSIEM. v2 adds Community ID tagging to the HTTP proxy and SMTP relay for exact flow-level matching.

### 3.11 AkesoSIEM Integration

AkesoDLP emits events to AkesoSIEM via HTTP POST to `/api/v1/ingest`. Each event includes a top-level `source_type: "akeso_dlp"` field that routes it to the DLP parser in the SIEM. The `event_type` field differentiates between DLP event types. Events use the ECS mapping defined in the AkesoSIEM requirements document (Section 4.5):

|Event Type      |`event_type` Value    |ECS Mapping                                                           |Trigger                                                 |
|----------------|----------------------|----------------------------------------------------------------------|--------------------------------------------------------|
|Policy violation|`dlp:policy_violation`|`event.category: file`, `event.action: violation`                     |Sensitive data detected by any channel.                 |
|Block           |`dlp:block`           |`event.category: file`, `event.type: denied`, `event.outcome: failure`|Data transfer blocked by policy.                        |
|Audit           |`dlp:audit`           |`event.category: file`, `event.type: access`, `event.outcome: success`|Sensitive data access logged but allowed (monitor-only).|
|Removable media |`dlp:removable_media` |`event.category: file`, `event.type: creation`                        |Data written to USB/external drive (even if allowed).   |
|Classification  |`dlp:classification`  |`event.category: file`, `event.type: info`                            |File classified with sensitivity label.                 |

Custom ECS extensions: `dlp.policy.name`, `dlp.policy.action`, `dlp.classification`, `dlp.channel` (email/upload/usb/clipboard/share/discover), `dlp.match_count`, `dlp.data_identifiers`.

This enables AkesoSIEM cross-product Sigma correlation rules:

- **EDR + DLP:** “User whose workstation triggered EDR credential theft alert accesses confidential file within 30 minutes”
- **AV + DLP:** “File quarantined by AV was previously flagged by DLP as containing sensitive data”
- **DLP + Windows Events:** “DLP detects USB copy on machine where user authenticated with different account than usual”
- **NDR + DLP — Exfiltration Confirmation:** “NDR detects anomalous outbound transfer volume (3+ stddev above baseline) to external IP → DLP confirms the files accessed on that host were classified as confidential” (NDR sees the how, DLP sees the what)
- **EDR + NDR + DLP — Data Theft Kill Chain:** “EDR detects credential dumping on Host A → NDR detects SMB lateral movement from Host A to Host B → DLP detects sensitive file access on Host B → NDR detects outbound data transfer from Host B” (complete data theft lifecycle correlated across endpoint behavior, network traffic, and content classification)
- **NDR + DLP — Covert Channel + Sensitive Data:** “NDR detects DNS tunneling from a host → DLP previously classified files accessed by that host’s user as restricted” (data exfiltration via covert channel with content context)

### 3.12 AkesoNDR Correlation

AkesoDLP and AkesoNDR provide complementary views of data movement that, when correlated in AkesoSIEM, produce detections neither tool can generate independently.

|Scenario                        |AkesoNDR Sees                                                                                    |AkesoDLP Sees                                                                          |Correlated Detection                                                              |
|--------------------------------|----------------------------------------------------------------------------------------------------|------------------------------------------------------------------------------------------|----------------------------------------------------------------------------------|
|Data exfiltration to external IP|Outbound volume anomaly (3+ stddev), new destination IP, sustained high-throughput session          |Files accessed were classified as “confidential”, policy violation on file access         |Confirmed sensitive data exfiltration — content + network evidence                |
|Covert channel exfiltration     |DNS tunneling detection (high entropy queries, TXT record abuse, volume to single parent domain)    |User on that host accessed restricted files in preceding window                           |Sensitive data over covert channel — content classification + tunnel detection    |
|Insider threat via USB + network|No network exfiltration detected (absence of evidence)                                              |USB file copy blocked for confidential data                                               |Contained insider threat — DLP prevented, NDR confirms no network exfil occurred  |
|Lateral movement + data staging |SMB file transfer from Host A → Host B (lateral movement detection), subsequent outbound from Host B|Sensitive file access on Host A, file classification matches content transferred to Host B|Data staging across hosts — NDR traces the network hop, DLP identifies the content|

AkesoNDR’s Community ID (deterministic flow hash) enables AkesoSIEM to join NDR network sessions with DLP file transfer events when the DLP network monitor’s HTTP/SMTP inspection and NDR’s passive traffic capture observe the same flow. In v1, this correlation uses IP+timestamp proximity. In v2, the DLP network monitor tags events with Community ID for exact flow-level matching.

Cross-product Sigma correlation rules for NDR+DLP ship in AkesoSIEM’s `rules/akeso_portfolio/` directory alongside the EDR+DLP and AV+DLP rules described in the AkesoSIEM requirements document (Section 5.3).

### 3.13 Shared Infrastructure with AkesoEDR

|Component          |AkesoEDR Pattern                                                                                     |AkesoDLP Adaptation                                                                                                     |
|-------------------|--------------------------------------------------------------------------------------------------------|---------------------------------------------------------------------------------------------------------------------------|
|Kernel driver      |Kernel callbacks via PsSetCreateProcessNotifyRoutineEx, CmRegisterCallbackEx, minifilter for file system|Same minifilter framework. DLP registers for IRP_MJ_WRITE pre-op on removable/network volumes. Different altitude from EDR.|
|Driver ↔ user-mode |FltCreateCommunicationPort / FilterConnectCommunicationPort                                             |Same mechanism. DLP uses `\\AkesoDLPPort` (EDR uses `\\AkesoEDRPort`). Same message format pattern.                  |
|Service lifecycle  |Windows service via SCM. Watchdog process for restart. Anti-tamper (deny stop/kill to non-SYSTEM).      |Same service model. Same watchdog pattern. Same tamper protection approach.                                                |
|Event serialization|Binary event serialization for driver→user-mode messages.                                               |Same serialization pattern. DLP message contains: file path, volume type, first N bytes of content, file size.             |
|Logging            |Structured logging (JSON or ETW).                                                                       |Same logging infrastructure.                                                                                               |
|Build system       |MSVC / CMake. WDK for driver. x64 Windows target.                                                       |Same toolchain. Driver built with WDK. Agent built with MSVC.                                                              |

v2: Unified agent. In v2, the DLP module could load as a DLL within the AkesoEDR process, sharing a single kernel driver that handles both behavioral monitoring (EDR) and content inspection (DLP) via different minifilter altitudes.

### 3.14 Agent Offline Mode

The agent must operate correctly when the server is unreachable. Behavior depends on whether the agent has cached policies:

**With cached policies (normal offline):** The agent enforces all cached policies with full response actions including blocking. Detection runs locally using Hyperscan, Aho-Corasick, data identifiers, and file type detection. Incidents are queued to the memory-mapped file queue (max 1000 entries, FIFO drain on reconnect). TTD requests (fingerprinting, complex content extraction) cannot be serviced — the agent applies the policy’s configured TTD fallback action (default: log-only, configurable per policy to block or allow). The agent continues heartbeat attempts with exponential backoff (5s → 10s → 30s → 60s → 5min max).

**Without cached policies (first-run, empty cache):** The agent starts in log-only mode. All file operations are allowed. The agent logs all events that would have been inspected (file path, volume type, size, user) to the incident queue with `action: log_only_no_policy`. No blocking, no notifications. This ensures the agent never silently blocks operations without a policy basis. Once the server is reached and policies are synced, the agent transitions to full enforcement and logs the transition event.

**Policy version tracking:** Each policy sync records a version number in the SQLite cache. The agent reports its policy version in every heartbeat. The server can detect stale agents and flag them in the console.

### 3.15 Two-Tier Detection (TTD)

When the agent encounters content it cannot fully evaluate locally — primarily document fingerprinting and complex content extraction (encrypted PDFs, password-protected Office documents, formats without a local parser) — it sends a TTD request to the server via the `DetectContent` gRPC RPC.

**TTD flow:**

1. Agent detects a file operation that requires inspection.
1. Local detection runs first (Hyperscan, Aho-Corasick, data identifiers, file type). If local detection produces a definitive match (policy violation), the agent acts immediately without TTD.
1. If the policy includes fingerprint conditions or the file type is one the agent cannot extract locally, the agent sends a TTD request containing the file content (or a hash + content excerpt for large files >50MB).
1. The server runs the full detection engine (including FingerprintAnalyzer and full content extraction) and returns a verdict: ALLOW, BLOCK, or LOG with match details.
1. The agent applies the verdict as the response action.

**Timeout handling:** TTD requests have a configurable timeout (default: 30 seconds). If the server doesn’t respond within the timeout, the agent applies the policy’s TTD fallback action (configurable per policy: `allow`, `block`, or `log`). Default fallback: `log` (allow the operation, queue an incident noting that TTD timed out for manual review).

**IRP management during TTD:** When a TTD request is in flight for a minifilter-intercepted operation, the IRP is pended (FltCbdqEnqueue). The driver sets a watchdog timer matching the TTD timeout. If the user-mode agent fails to respond (crash, hang), the driver’s watchdog fires and completes the IRP with ALLOW to prevent system hangs.

### 3.16 Agent Update/Upgrade

Agent updates require stopping the service, potentially unloading the minifilter driver, replacing binaries, and restarting. This is handled via the installer (see Phase 11, P11-T7 for MSI packaging).

**MSI upgrade path:** The WiX MSI supports major upgrades. Installing a new version over an existing one automatically stops the service, unloads the driver (if the driver binary changed), replaces all files, reloads the driver, restarts the service, and verifies the agent re-registers with the server. Policy cache and incident queue are preserved across upgrades. The recovery folder is never touched.

**Manual upgrade procedure (for development):**

1. `sc stop AkesoDLPAgent`
1. `fltmc unload AkesoDLPFilter`
1. Replace binaries in `C:\Program Files\AkesoDLP\`
1. `fltmc load AkesoDLPFilter`
1. `sc start AkesoDLPAgent`

**Server-initiated upgrade (v2):** The server pushes an upgrade package URL via the PolicyUpdates gRPC stream. The agent downloads, verifies the signature, and applies the upgrade during a maintenance window or on next reboot. v1 does not implement server-initiated upgrades — all upgrades are manual or MSI-based.

### 3.17 Browser Monitor — AkesoEDR Coexistence

The browser upload monitor (P4-T11) uses DLL injection into browser processes to hook WinHttpSendRequest and HttpSendRequestW. This technique will trigger AkesoEDR’s behavioral detections (process injection, API hooking, suspicious DLL loading) on any machine running both agents.

**Coexistence approach:** AkesoEDR must allowlist the AkesoDLP injector DLL by its file hash and signing certificate. The DLP agent’s injector DLL is signed with the same test certificate used for the AkesoDLP driver. AkesoEDR’s allowlist configuration (in its YAML config under `exclusions.dlls`) includes the DLP injector’s SHA-256 hash. This means:

- AkesoEDR will not generate alerts for the DLP injector loading into browser processes.
- AkesoEDR will still detect all other DLL injection attempts normally.
- The allowlist is hash-based, so a modified/malicious DLL would not be excluded.

**Testing requirement:** The P4-T13 end-to-end agent test must include a coexistence scenario: AkesoEDR running alongside AkesoDLP on the same machine, verifying that the DLP browser monitor works without triggering EDR alerts, while a separate non-allowlisted DLL injection attempt still triggers EDR detection.

## 4. Management Console Requirements

### 4.1 Console Authentication

The management console uses JWT authentication with TOTP-based MFA, matching the pattern established in AkesoSIEM.

**User accounts:** Stored in PostgreSQL (not Elasticsearch, since the DLP server already uses PG). Passwords bcrypt-hashed (cost 12). Three built-in roles: Admin (full access), Analyst (read incidents, update status/notes, view policies, run detections), Remediator (Analyst permissions + modify policy status, execute Smart Response).

**JWT sessions:** Short-lived access token (15 minutes) in browser memory. Long-lived refresh token (7 days) as httpOnly/Secure/SameSite=Strict cookie. Refresh endpoint issues new access tokens silently. Logout revokes refresh token in database.

**TOTP MFA:** Optional per-user, compatible with Google Authenticator / Authy / 1Password. Enrollment via QR code in Settings. Verification required after password authentication when enabled. Admin CLI can reset MFA for locked-out users: `python -m scripts.reset_mfa <username>`.

**Rate limiting:** 5 failed login attempts per 30 seconds per IP → 429 response.

**First-run setup:** If no users exist when the console loads, redirect to a one-time admin account creation page.

### 4.2 Console Global Search

The console header includes a universal search bar that searches across incidents, policies, agents, users, and data identifiers simultaneously.

**Type detection:** The search auto-detects input type: filenames search `incident.file_path`, IP addresses search `incident.source_ip` and agent IPs, usernames search `incident.user` and `user.username`, policy names search `policy.name`. Free text searches across all searchable fields.

**Grouped results:** Results appear in a dropdown grouped by category (Incidents → Policies → Agents → Users) with counts. Click-through navigates to the relevant page with the item selected or filtered.

**Command palette:** `Cmd+Shift+P` / `Ctrl+Shift+P` opens command mode for navigation (`/incidents`, `/policies`, `/agents`, `/discover`, `/reports`, `/settings`) and quick actions (`/dark`, `/light`, `/logout`).

**Recent searches:** Last 10 searches stored in localStorage.

### 4.3 Console Design System — Dark Mode & Portfolio Consistency

The DLP console shares a design system with AkesoSIEM for visual portfolio consistency. Both dashboards are React + TailwindCSS + shadcn/ui, and should feel like products from the same vendor.

**Dark mode:** Default to dark mode with three-way toggle (Dark / Light / System) persisted to localStorage. Use Tailwind’s class strategy (`darkMode: 'class'`).

**Shared color palette:** Use the same surface palette as AkesoSIEM (Section 10.8 of the SIEM requirements): `slate-950` page background (dark), `slate-900` sidebar, `slate-800` card surfaces, `indigo-500` accent, `slate-50` light mode background. Severity colors match SIEM: Critical=red-500, High=orange-500, Medium=yellow-500, Low=blue-500, Info=slate-500.

**Typography:** Inter font at 500 weight default, matching AkesoSIEM.

**Component library:** shadcn/ui components with consistent theming. Recharts for charts (same palette as SIEM).

### 4.4 Console Pages

|Page             |Description                                                                                                                                                                                      |
|-----------------|-------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
|Dashboard        |Incident counts by severity (cards). Trend chart (30 days). Top policies bar chart. Channel breakdown pie (endpoint/network/discover). Top 5 risky users. Agent health. Recent activity timeline.|
|Incidents        |Filterable table (severity, status, policy, date, source type, channel, user). Sortable. Paginated. Click → snapshot.                                                                            |
|Incident Snapshot|Matched content with highlighting. Policy details. Response actions taken. Status/severity dropdowns. Notes section. History timeline. Custom attributes. Smart Response execution.              |
|Policies         |List with status badges. Create from template or blank. Click → editor.                                                                                                                          |
|Policy Editor    |Metadata (name, description, group, severity). Rules section (add/edit/remove conditions with component targeting). Exceptions section. Response rule attachment. Activate/Suspend.              |
|Agents           |Table (hostname, OS, agent version, driver version, policy version, status, last check-in). Status badges. Groups. Click → detail with recent incidents.                                         |
|Discover         |Scan definitions. Create/edit scans (agent groups, targets, schedule, filters). Scan status. Results summary.                                                                                    |
|Reports          |Generate on demand (summary/detail). Download CSV/PDF. Schedule recurring with email distribution.                                                                                               |
|User Risk        |Users ranked by risk score (1-100). Incident breakdown per user. Trend indicator.                                                                                                                |
|Settings         |Data identifiers, keyword dictionaries, response rules, fingerprints, network monitor config, SIEM integration, syslog export, users & roles, MFA management.                                    |

## 5. REST API

**Auth:**

- `POST /api/auth/login` → JWT token (or MFA challenge)
- `POST /api/auth/mfa` → complete MFA with TOTP code
- `POST /api/auth/refresh` → refresh token
- `GET /api/auth/me` → current user
- `PUT /api/auth/me/password` → change password
- `POST /api/auth/me/mfa/enroll` → begin MFA enrollment (returns QR URI)
- `POST /api/auth/me/mfa/verify` → confirm MFA enrollment
- `DELETE /api/auth/me/mfa` → disable MFA (requires password)

**Policies:**

- `GET /api/policies` → list (filterable by group, status)
- `POST /api/policies` → create
- `GET /api/policies/{id}` → full detail
- `PUT /api/policies/{id}` → update
- `DELETE /api/policies/{id}` → delete
- `POST /api/policies/{id}/activate` → activate
- `POST /api/policies/{id}/suspend` → suspend
- `POST /api/policies/{id}/rules` → add rule
- `POST /api/policies/{id}/exceptions` → add exception

**Detection:**

- `POST /api/detect` → submit text for evaluation
- `POST /api/detect/file` → submit file for evaluation

**Search:**

- `GET /api/search?q=<query>` → universal search across incidents, policies, agents, users

**Data Identifiers:**

- `GET /api/data-identifiers` → list
- `POST /api/data-identifiers` → create custom

**Keyword Dictionaries:**

- `GET /api/keyword-dictionaries` → list
- `POST /api/keyword-dictionaries` → create

**Fingerprints:**

- `POST /api/fingerprints` → upload document to fingerprint
- `GET /api/fingerprints` → list
- `DELETE /api/fingerprints/{id}` → remove

**Incidents:**

- `GET /api/incidents` → list (filterable, paginated)
- `GET /api/incidents/{id}` → snapshot
- `PATCH /api/incidents/{id}` → update status/severity
- `POST /api/incidents/{id}/notes` → add note
- `GET /api/incidents/{id}/history` → audit trail
- `POST /api/incidents/{id}/respond` → execute Smart Response

**Response Rules:**

- `GET /api/response-rules` → list
- `POST /api/response-rules` → create

**Templates:**

- `GET /api/templates` → list
- `POST /api/templates/{id}/apply` → create policy from template

**Agents:**

- `GET /api/agents` → list
- `GET /api/agents/{id}` → detail

**Discover:**

- `POST /api/discover/scans` → create scan
- `GET /api/discover/scans` → list
- `POST /api/discover/scans/{id}/run` → trigger

**Reports:**

- `POST /api/reports/generate` → generate
- `GET /api/reports/{id}/csv` → download

**Users & Roles:**

- `GET /api/users` → list
- `POST /api/users` → create
- `GET /api/roles` → list

**System:**

- `GET /api/health` → health check (no auth required)
- `GET /api/audit-log` → audit log

## 6. Build & Development Environment

|Aspect                   |Choice                                                                        |
|-------------------------|------------------------------------------------------------------------------|
|Agent language           |C/C++ (MSVC, C++17)                                                           |
|Driver language          |C (WDK, WDM/WDF)                                                              |
|Agent build              |CMake + MSVC + WDK                                                            |
|Agent regex              |Intel Hyperscan 5.x (SIMD multi-pattern)                                      |
|Agent keywords           |Aho-Corasick (custom or Hyperscan literal mode)                               |
|Agent content extraction |libpdfium (PDF), libxml2 (Office XML), minizip (archives), or Tika REST client|
|Agent gRPC               |gRPC C++ (grpc/grpc) + Protobuf                                               |
|Agent policy cache       |SQLite 3 (embedded, zero-config)                                              |
|Agent IPC                |FltCreateCommunicationPort (driver ↔ user-mode)                               |
|Server language          |Python 3.12+                                                                  |
|Server framework         |FastAPI (async)                                                               |
|Server ORM               |SQLAlchemy 2.0 (async)                                                        |
|Server migrations        |Alembic                                                                       |
|Server detection regex   |google-re2                                                                    |
|Server detection keywords|pyahocorasick                                                                 |
|Server file types        |python-magic (libmagic)                                                       |
|Server content extraction|pdfplumber, python-docx, openpyxl, python-pptx                                |
|Database                 |PostgreSQL 16 + JSONB                                                         |
|Event queue              |Redis 7 (Streams)                                                             |
|Agent-server comms       |gRPC with mTLS                                                                |
|Network HTTP             |mitmproxy (Python)                                                            |
|Network SMTP             |aiosmtpd (Python)                                                             |
|Network test MTA         |MailHog (Docker, ports 1025/8025)                                             |
|Console                  |React 18 + Vite + TailwindCSS + shadcn/ui                                     |
|Console E2E testing      |Playwright (headless browser)                                                 |
|Containers               |Docker + Docker Compose (server stack; agent is native Windows)               |
|Testing — server         |pytest + pytest-asyncio + httpx                                               |
|Testing — agent          |Google Test + Google Mock                                                     |

## 7. Risks & Mitigations

|Risk                                                       |Severity|Mitigation                                                                                                                                                                                              |
|-----------------------------------------------------------|--------|--------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
|Minifilter driver stability (BSOD risk)                    |High    |Extensive testing in VM. Minimal kernel logic — driver sends file metadata to user-mode, does not parse content in kernel. Pend IRP → user-mode verdict → complete IRP pattern limits kernel complexity.|
|Minifilter altitude conflicts with other security products |Medium  |Register at standard DLP altitude range (320000-329999 per Microsoft allocation). Test alongside Defender. POC targets clean VMs.                                                                       |
|Hyperscan build complexity (requires CMake + Boost + Ragel)|Medium  |Use vcpkg for dependency management. Pin Hyperscan version. Precompiled patterns cached to avoid recompilation overhead.                                                                                |
|gRPC C++ build integration                                 |Medium  |Use vcpkg or CMake FetchContent for grpc. Pin versions. CI builds validated.                                                                                                                            |
|Content extraction in C++ is limited                       |Medium  |Hybrid approach: agent handles plain text, magic bytes, and simple formats locally. Complex extraction (PDF, Office) delegated to Tika REST endpoint or server-side via TTD (see Section 3.15).         |
|HTTPS inspection requires trust                            |Medium  |mitmproxy CA cert generated at setup. Documented for test environments only.                                                                                                                            |
|Policy evaluation parity (C++ agent vs Python server)      |Medium  |Shared test suite. Same test inputs → same outputs. Property-based testing for edge cases.                                                                                                              |
|Browser monitor DLL injection triggers EDR                 |Medium  |AkesoEDR allowlists DLP injector DLL by hash. Coexistence tested as part of agent E2E test plan (see Section 3.17).                                                                                  |
|TTD timeout during file operation                          |Medium  |Configurable timeout (default 30s) with per-policy fallback action (allow/block/log). Driver watchdog prevents IRP hang on agent failure (see Section 3.15).                                            |

## 8. References

- Symantec Data Loss Prevention 16.0 Help Center (2,111 pages) — primary requirements source
- Symantec DLP Policy Evaluation Engine (DLP 16.0 specification)
- Evading EDR (Matt Hand) — AkesoEDR driver architecture reference
- AkesoEDR Requirements Document v1.0 — shared C/C++ driver infrastructure
- AkesoSIEM Requirements Document v2.4 — SIEM integration, DLP event ECS mappings (Section 4.5), cross-portfolio Sigma rules (Section 5.3), built-in case management
- AkesoNDR Requirements Document v1.0 — NDR network visibility, cross-portfolio correlation (Section 5.10), Community ID for flow correlation
- Microsoft Minifilter Driver Development: docs.microsoft.com/en-us/windows-hardware/drivers/ifs/
- Microsoft Filter Manager Concepts: altitude allocation, IRP handling, communication ports
- Intel Hyperscan: intel.github.io/hyperscan/
- Elastic Common Schema: elastic.co/docs/reference/ecs
- SigmaHQ: github.com/SigmaHQ/sigma
- gRPC C++: grpc.io/docs/languages/cpp/
- WDK documentation: docs.microsoft.com/en-us/windows-hardware/drivers/

-----

# PART II: IMPLEMENTATION PHASES

## 9. How To Use Part II With Claude Code

Same workflow as AkesoEDR, AkesoAV, AkesoSIEM, and AkesoNDR: each task has an ID, files, acceptance criteria, and complexity estimate (S/M/L/XL). Work through phases in order. Each task is scoped for a single Claude Code session.

Note on agent development: Agent and driver tasks require a Windows development environment with MSVC, WDK, and CMake. These tasks cannot be built inside Docker or Linux-based Claude Code sessions — they produce Windows binaries and .sys driver files. Server, console, and network tasks run in Docker on any platform.

-----

### Phase 0: Project Scaffolding

**Goal:** Monorepo structure, Docker setup (server stack), CMake setup (agent), database schema, shared protobuf definitions.

|ID   |Task                                                                                                                                                                                                                                                                                                                                                                                                                            |Files                                                                                      |Acceptance Criteria                                                                                                                                                                                 |Est.|
|-----|--------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|-------------------------------------------------------------------------------------------|----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|----|
|P0-T1|Init repo. Python package (`server/`), CMake project (`agent/`), React app (`console/`), Docker Compose, Makefile.                                                                                                                                                                                                                                                                                                              |`Makefile`, `server/`, `agent/CMakeLists.txt`, `console/package.json`, `docker-compose.yml`|`make server` starts FastAPI. `cmake --build` compiles agent (on Windows). `make console` starts React dev.                                                                                         |M   |
|P0-T2|Docker Compose: PostgreSQL 16, Redis 7, FastAPI server, React dev server, MailHog (test MTA, ports 1025/8025). Health checks. Shared `dlp-network` bridge network.                                                                                                                                                                                                                                                              |`docker-compose.yml`, `scripts/wait-for-db.sh`                                             |`docker compose up` → all services healthy. PG :5432, Redis :6379, API :8000, Console :3000, MailHog :1025/:8025.                                                                                   |S   |
|P0-T3|Database schema. All tables: users (with password_hash, mfa_secret, mfa_enabled), roles, policy_groups, policies, detection_rules, rule_conditions, policy_exceptions, exception_conditions, response_rules, response_actions, data_identifiers, keyword_dictionaries, incidents, incident_notes, incident_history, agents, agent_groups, sessions (refresh tokens), audit_log. SQLAlchemy 2.0 async models. Alembic migrations.|`server/models/*.py`, `migrations/`, `alembic.ini`                                         |`alembic upgrade head` creates all tables. Models compile. Round-trip CRUD on each table. Sessions table supports token revocation.                                                                 |L   |
|P0-T4|Pydantic schemas for all API request/response bodies.                                                                                                                                                                                                                                                                                                                                                                           |`server/schemas/*.py`                                                                      |All schemas validate. Example JSON round-trips correctly for policies, incidents, users, agents. Auth schemas include MFA challenge/response.                                                       |M   |
|P0-T5|Protobuf definitions. All RPCs: Register, Heartbeat, GetPolicies, PolicyUpdates (server-stream), ReportIncident, DetectContent (TTD). Compile to Python stubs.                                                                                                                                                                                                                                                                  |`proto/akesodlp.proto`, `server/proto/`                                                 |Proto compiles. Python stubs generated. Types cover all fields: IncidentReport (matches, channel, severity, file metadata), DetectionRequest (with TTD timeout and fallback config), PolicyResponse.|M   |
|P0-T6|Config loading. Server config (YAML/env). Agent config (YAML). Sections: database, redis, grpc, siem, network monitor, logging.                                                                                                                                                                                                                                                                                                 |`server/config.py`, `config.yaml.example`, `agent/config/config.yaml.example`              |Server loads and validates. Missing required fields → clear errors. Env var overrides work. Agent config parseable by C++ YAML loader. SIEM endpoint + API key configurable.                        |S   |
|P0-T7|Seed script: admin user (with bcrypt password), roles (Admin/Analyst/Remediator), 10 built-in data identifiers, 6 policy templates (PCI/HIPAA/GDPR/SOX/Source Code/Confidential).                                                                                                                                                                                                                                               |`server/scripts/seed.py`                                                                   |`python -m scripts.seed` populates DB. Admin login works (including MFA enrollment flow). Templates visible via API. Data identifiers include Luhn CC, SSN, IBAN, ABA.                              |M   |

-----

### Phase 1: Server-Side Detection Engine (Python)

**Goal:** Pluggable content analysis engine. Policy evaluator implementing full Symantec AND/OR/exception model. File content extraction. This engine handles API submissions, TTD requests from agents, and network monitor detections.

|ID   |Task                                                                                                                                                                                                                           |Files                                                                    |Acceptance Criteria                                                                                                                                                                                                                         |Est.|
|-----|-------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|-------------------------------------------------------------------------|--------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|----|
|P1-T1|Detection engine framework. ParsedMessage model with components (envelope, subject, body, attachments). BaseAnalyzer interface. Engine orchestrator runs analyzers, collects matches.                                          |`server/detection/engine.py`, `models.py`, `analyzers/__init__.py`       |Engine accepts ParsedMessage, returns list[Match]. Analyzer plugin interface defined. Component targeting works (body-only vs any).                                                                                                         |M   |
|P1-T2|RegexAnalyzer. google-re2 for safe execution. Compile patterns from policy config. Match against targeted components. Return matches with location offsets.                                                                    |`server/detection/analyzers/regex_analyzer.py`                           |SSN pattern matches “123-45-6789” in body component. Does not match when targeting attachments only. 5 patterns tested including edge cases.                                                                                                |M   |
|P1-T3|KeywordAnalyzer. pyahocorasick for multi-keyword Aho-Corasick matching. Case modes. Whole-word. Proximity (two keywords within N words).                                                                                       |`server/detection/analyzers/keyword_analyzer.py`                         |50-keyword dictionary matches in test document. Proximity: “credit” within 3 words of “card” matches, within 3 words of “union” does not. Case-insensitive mode.                                                                            |L   |
|P1-T4|DataIdentifierAnalyzer. Pattern + validator for all 10 built-in identifiers. Luhn (CC), area number (SSN), MOD-97 (IBAN), ABA checksum (routing). Custom identifier support.                                                   |`server/detection/analyzers/data_identifier_analyzer.py`, `validators.py`|Valid CC matches, invalid Luhn rejected. SSN with area 000 rejected. IBAN with bad checksum rejected. All 10 identifiers pass validation tests. >99% precision on test corpus.                                                              |L   |
|P1-T5|FileTypeAnalyzer. python-magic for binary signature. 50+ file types. File size and name pattern conditions.                                                                                                                    |`server/detection/analyzers/file_type_analyzer.py`                       |.docx renamed to .txt identified as Office. .exe renamed to .jpg identified as executable. Size > 10MB triggers. Name *.xlsx matches.                                                                                                       |M   |
|P1-T6|FileInspector. Content extraction: PDF (pdfplumber), DOCX (python-docx), XLSX (openpyxl), PPTX (python-pptx), plain text with chardet encoding detection, EML (email stdlib). Returns ParsedMessage with decomposed components.|`server/detection/file_inspector.py`                                     |Extract text from 3-page PDF. DOCX with tables. XLSX with multiple sheets. EML with attachment. Shift-JIS text detected.                                                                                                                    |L   |
|P1-T7|ArchiveInspector. Recursive extraction: ZIP, TAR, GZIP, 7z, RAR. Safety: max depth 3, max size 100MB, max files 500, zip bomb ratio check. Integrate with FileInspector.                                                       |`server/detection/archive_inspector.py`                                  |Keyword in DOCX inside ZIP → detected. Nested ZIP in TAR.GZ (depth 2) → extracted and scanned. Zip bomb (1000:1 ratio) rejected.                                                                                                            |L   |
|P1-T8|PolicyEvaluator. Full Symantec 16.0 logic: compound rules (AND), multi-rule OR, detection+group AND, exception evaluation (entire message then MCO), severity calculation with match count thresholds.                         |`server/detection/policy_evaluator.py`                                   |Compound rule (keyword AND file type): both match → incident, one misses → no incident. Exception for sender → no incident. Severity tiers: 3 matches → Medium, 10 → High. MCO exception removes only matched component, not entire message.|XL  |
|P1-T9|End-to-end detection pipeline test. Create PCI policy → submit text with 5 CC numbers → incident. Create compound policy → test AND/OR logic. Test exceptions. Test severity tiers.                                            |`tests/detection/test_pipeline.py`                                       |5 valid CCs → High incident. 5 invalid checksums → no incident. Body keywords + attachment CC → both components in match. CEO exception → no incident. 8+ test scenarios pass.                                                              |M   |

-----

### Phase 2: REST API & Console

**Goal:** Full CRUD API with JWT auth + MFA. React console with dark mode, global search, dashboard, incident management, policy editor.

|ID    |Task                                                                                                                                                                                                                                                                                                                                                                                              |Files                                                                                                                                                                                                        |Acceptance Criteria                                                                                                                                                                                                                                     |Est.|
|------|--------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|-------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|--------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|----|
|P2-T1 |Auth endpoints. JWT login/refresh with MFA support. bcrypt password hashing. TOTP enrollment/verification/disable. Role-based permission middleware. Rate limiting (5 attempts/30s/IP).                                                                                                                                                                                                           |`server/api/auth.py`, `server/services/auth_service.py`, `server/services/mfa_service.py`                                                                                                                    |Login → JWT. MFA enabled → MFA challenge after password. Correct TOTP → token issued. No token → 401. Analyst reads incidents but can’t create policies → 403. Token refresh works. 6th failed attempt → 429.                                           |L   |
|P2-T2 |Policy CRUD endpoints. Full lifecycle. Rules, conditions, exceptions management. Activate/suspend. Create from template. Audit logging on all mutations.                                                                                                                                                                                                                                          |`server/api/policies.py`, `server/services/policy_service.py`                                                                                                                                                |Create from PCI template → policy with pre-configured rules. Add custom rule. Activate toggles status. Audit log entry per mutation.                                                                                                                    |L   |
|P2-T3 |Detection endpoints. `POST /api/detect` (text). `POST /api/detect/file` (file upload → extract → scan). Returns violations with match details and component locations.                                                                                                                                                                                                                            |`server/api/detection.py`                                                                                                                                                                                    |Text with 3 SSNs → violations with locations. PDF upload → extracted, scanned, violations returned. Response includes matched_text, component, start/end offsets.                                                                                       |M   |
|P2-T4 |Incident endpoints. List (filter, sort, paginate). Snapshot (full detail). Update status/severity. Notes. History.                                                                                                                                                                                                                                                                                |`server/api/incidents.py`, `server/services/incident_service.py`                                                                                                                                             |`GET /api/incidents?severity=high&status=new` → paginated results <500ms. Patch status → audit entry. Notes append. History tracks all changes.                                                                                                         |M   |
|P2-T5 |Supporting endpoints. Data identifiers, keyword dictionaries, response rules, fingerprints, users/roles, health, audit log. Global search endpoint (`GET /api/search`).                                                                                                                                                                                                                           |`server/api/identifiers.py`, `dictionaries.py`, `response_rules.py`, `users.py`, `system.py`, `search.py`                                                                                                    |All CRUD works. Custom data identifier → usable in detection. Keyword dictionary → loaded by analyzer. Search returns grouped results across incidents/policies/agents/users.                                                                           |M   |
|P2-T6 |gRPC server. Implement all RPCs alongside FastAPI (port 50051). mTLS with cert generation script. Agent registration → DB entry. Heartbeat → status update. GetPolicies → serialized policy set. ReportIncident → incident created in DB. DetectContent (TTD) → run detection engine, return verdict with match details and configured fallback action.                                           |`server/grpc_server.py`, `server/services/agent_service.py`, `scripts/gen-certs.sh`                                                                                                                          |Registration creates agent record. Heartbeat updates last_checkin. Policies returned in proto format. Incident reported → appears in API. TTD request → detection result returned with timeout respected. mTLS rejects unsigned client.                 |L   |
|P2-T7 |Console shell. React + Vite + TailwindCSS + shadcn/ui. Layout with sidebar nav. JWT API client with MFA flow. Login page + MFA verification page. Auth guard with silent refresh. Dark mode toggle (Dark/Light/System). Global search bar with type detection + command palette (`Cmd+Shift+P`). First-run admin setup redirect. Shared design system matching AkesoSIEM palette (Section 4.3).|`console/src/App.jsx`, `Layout.jsx`, `api/client.js`, `pages/Login.jsx`, `pages/MFAVerify.jsx`, `components/GlobalSearch.jsx`, `components/CommandPalette.jsx`, `stores/authStore.js`, `stores/themeStore.js`|Console at :3000. Login authenticates with MFA when enabled. JWT stored. Nav between pages. Protected routes redirect to login. Dark mode persists. `Cmd+Shift+P` opens command palette. Global search returns grouped results. First run → admin setup.|L   |
|P2-T8 |Dashboard page. Severity cards. Trend chart (Recharts). Recent incidents. Active policies count. Agent count (placeholder until Phase 3).                                                                                                                                                                                                                                                         |`console/src/pages/Dashboard.jsx`                                                                                                                                                                            |Loads <3s. Cards correct. Chart renders. Click incident → navigate.                                                                                                                                                                                     |M   |
|P2-T9 |Incidents pages. Filterable table (severity, status, policy, date, source, channel). Sortable. Paginated. Snapshot page: matched content with highlights, status/severity dropdowns, notes, history timeline.                                                                                                                                                                                     |`console/src/pages/Incidents.jsx`, `IncidentSnapshot.jsx`                                                                                                                                                    |Filter + sort → correct results. Snapshot highlights matched text. Status update saves. Notes append. History timeline renders.                                                                                                                         |L   |
|P2-T10|Policy editor pages. Policy list with status badges. Policy detail: metadata, rules with conditions and component targeting, exceptions, response rules. Create from template. Activate/suspend.                                                                                                                                                                                                  |`console/src/pages/Policies.jsx`, `PolicyEditor.jsx`                                                                                                                                                         |Create PCI from template. Add keyword rule targeting body only. Add exception for sender. Attach response rule. Activate. Policy enforced on `/api/detect`.                                                                                             |L   |

-----

### Phase 3: Endpoint Agent — Driver & Core (C/C++)

**Goal:** Minifilter driver that intercepts file writes to removable/network volumes. User-mode agent service that receives events from driver, communicates with server via gRPC.

|ID   |Task                                                                                                                                                                                                                                                                                                                                                                                          |Files                                                                                                     |Acceptance Criteria                                                                                                                                                                                                                                                     |Est.|
|-----|----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|----------------------------------------------------------------------------------------------------------|------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|----|
|P3-T1|CMake build system for agent. MSVC + WDK integration. vcpkg for dependencies (gRPC, Hyperscan, SQLite3, libcurl). Debug + Release configs.                                                                                                                                                                                                                                                    |`agent/CMakeLists.txt`, `agent/vcpkg.json`, `agent/cmake/FindWDK.cmake`                                   |`cmake --build . --config Release` produces `akeso-dlp-agent.exe`. Dependencies resolved via vcpkg. WDK found for driver build.                                                                                                                                      |M   |
|P3-T2|Minifilter driver skeleton. Register minifilter with FltRegisterFilter. IRP_MJ_WRITE pre-op callback on all volumes. IRP_MJ_CREATE post-op callback. Filter communication port (`\\AkesoDLPPort`). Altitude registration in 320000 range. INF file for installation.                                                                                                                       |`agent/driver/akeso_dlp_filter.c`, `agent/driver/filter_comm.c`, `agent/driver/akeso_dlp_filter.inf`|Driver loads (`fltmc load AkesoDLPFilter`). Communication port created. User-mode can connect. Driver listed in `fltmc instances`. Unloads cleanly.                                                                                                                  |XL  |
|P3-T3|Volume classification in driver. Identify removable volumes (FILE_REMOVABLE_MEDIA), network volumes (FILE_REMOTE_DEVICE), fixed volumes. Only intercept writes to removable + network volumes. Configurable via user-mode message.                                                                                                                                                            |`agent/driver/volume_filter.c`                                                                            |USB drive insertion → volume classified as removable. Network share → classified as network. Write to C:\ → not intercepted. Write to USB → intercepted and sent to user-mode.                                                                                          |L   |
|P3-T4|Driver ↔ user-mode communication. Driver sends: file path, volume type, originating PID, file size, first 4KB of content via FltSendMessage. User-mode responds: ALLOW, BLOCK, or SCAN_FULL. On BLOCK: driver returns STATUS_ACCESS_DENIED. On SCAN_FULL: driver pends IRP, signals user-mode, waits for final verdict. Watchdog timer on pended IRPs (matches TTD timeout from Section 3.15).|`agent/driver/filter_comm.c` (extend), `agent/src/driver_comm.cpp`                                        |User-mode receives file write event from driver. Sends ALLOW → write completes. Sends BLOCK → write fails with ACCESS_DENIED. SCAN_FULL → IRP pended, full content read by user-mode, verdict sent, IRP completed. Watchdog fires after timeout → ALLOW (prevents hang).|XL  |
|P3-T5|Agent service core. Windows service (SCM registration). Config loading (YAML via yaml-cpp). Startup sequence: load config → load policy cache → connect to driver → initialize detection → connect to server → start heartbeat. Graceful shutdown. Watchdog thread for service health. Offline mode behavior per Section 3.14 (cached policies → enforce, no cache → log-only).               |`agent/src/main.cpp`, `agent/src/agent_service.cpp`, `agent/src/config.cpp`                               |Service installs and starts via `sc create`. Config loads. Connects to driver port. Graceful stop on SERVICE_CONTROL_STOP. Watchdog restarts on unexpected thread exit. Starts in log-only mode with empty cache. Transitions to enforcement on policy sync.            |L   |
|P3-T6|gRPC client (C++). Connect to server with mTLS. Register, heartbeat (60s), pull policies, report incidents. TTD requests with configurable timeout and fallback behavior. Exponential backoff on connection failure. Async with completion queue.                                                                                                                                             |`agent/src/grpc_client.cpp`, `agent/src/tls_config.cpp`, `agent/src/ttd_client.cpp`                       |Agent registers → appears in `/api/agents`. Heartbeat updates last_checkin. Connection failure → backoff → reconnect. Policy pull returns current set. TTD request → server evaluates → verdict returned. TTD timeout → fallback action applied.                        |L   |
|P3-T7|Policy cache. SQLite embedded database. Store serialized policy set with version number. Atomic version swap (write to temp table → swap on commit). Load on startup before server connect. Sync on GetPolicies/PolicyUpdates. Report policy version in heartbeat.                                                                                                                            |`agent/src/policy_cache.cpp`                                                                              |Agent starts with cached policies (no server needed). Server update → cache updated atomically. Policy version tracks correctly. Empty cache → agent starts in log-only mode. Version reported in heartbeat.                                                            |M   |
|P3-T8|Incident queue. Memory-mapped file for persistence across restarts. FIFO drain on server reconnect. Max 1000 entries, oldest dropped when full. Serialization via protobuf.                                                                                                                                                                                                                   |`agent/src/incident_queue.cpp`                                                                            |Disconnect server → create violation → incident queued to file. Restart agent → queue survives. Reconnect → queue drains → incidents in server. Queue at 1000 → oldest dropped.                                                                                         |M   |

-----

### Phase 4: Endpoint Agent — Detection & Response (C/C++)

**Goal:** Local detection engine with Hyperscan, response actions with true pre-operation blocking, clipboard and browser monitoring.

|ID    |Task                                                                                                                                                                                                                                                                                                                              |Files                                                                                 |Acceptance Criteria                                                                                                                                                                                                                                                             |Est.|
|------|----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|--------------------------------------------------------------------------------------|--------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|----|
|P4-T1 |Hyperscan regex analyzer. Compile all regex patterns from policy into a single Hyperscan database. Multi-pattern simultaneous matching. Scratch allocation per thread. Precompile + serialize patterns for fast reload.                                                                                                           |`agent/src/detection/hs_regex_analyzer.cpp`                                           |100 patterns compiled into single database. 10MB file scanned in <100ms. All 10 data identifier patterns match correctly. Precompiled database loads in <10ms.                                                                                                                  |L   |
|P4-T2 |Aho-Corasick keyword analyzer. Build automaton from keyword dictionaries. Case-sensitive/insensitive. Whole-word boundary detection.                                                                                                                                                                                              |`agent/src/detection/keyword_analyzer.cpp`                                            |500-keyword dictionary matches in test file. Case-insensitive mode works. Whole-word: “card” matches but “discard” does not. Automaton builds in <100ms for 10K keywords.                                                                                                       |M   |
|P4-T3 |Data identifier validators. Luhn (CC), SSN area number, IBAN MOD-97, ABA checksum, format validators for phone/email/passport/DL.                                                                                                                                                                                                 |`agent/src/detection/validators.cpp`                                                  |Valid CC passes Luhn. Invalid CC rejected. SSN with 000/666/900+ area rejected. All 10 validators tested independently. Validator outputs match Python server outputs for same inputs.                                                                                          |M   |
|P4-T4 |File type detection. Magic byte signature table (custom, no libmagic dependency). 50+ types: Office, PDF, images, archives, executables, scripts. File size and name pattern matching.                                                                                                                                            |`agent/src/detection/file_type_detector.cpp`, `agent/src/detection/magic_signatures.h`|.docx renamed to .txt → identified as Office. .exe renamed to .jpg → identified as PE executable. Custom signature table covers all 50 types.                                                                                                                                   |M   |
|P4-T5 |Content extraction (agent-side). Plain text with encoding detection (BOM + heuristic). ZIP archive extraction (minizip or libarchive). For complex formats (PDF, Office): option A — embedded pdfium/libxml2, or option B — send to Tika REST endpoint, or option C — forward to server via TTD (Section 3.15).                   |`agent/src/detection/content_extractor.cpp`                                           |Plain text UTF-8/UTF-16 read correctly. ZIP extracted to memory (max depth 2 on agent, full depth on server). PDF extraction via chosen method returns text.                                                                                                                    |L   |
|P4-T6 |Policy evaluator (C++). Mirrors Python server logic: compound rules AND, multi-rule OR, detection+group AND, exceptions (entire message then MCO), severity tiers with match count thresholds.                                                                                                                                    |`agent/src/detection/policy_evaluator.cpp`                                            |Same test inputs as Python evaluator produce identical results. Compound rule, exception, severity tier, MCO exception all tested. Property-based test: 100 random policy configs → C++ output == Python output.                                                                |L   |
|P4-T7 |Detection pipeline integration. Driver sends file event → agent reads content → extracts text → runs detection → evaluates policy → determines if TTD needed → returns verdict to driver (ALLOW/BLOCK). Full pipeline from minifilter callback to verdict, including TTD path.                                                    |`agent/src/detection/pipeline.cpp`                                                    |File write to USB with sensitive content → BLOCK verdict → write fails. File write with clean content → ALLOW → write succeeds. File requiring fingerprint check → TTD request sent → server verdict applied. End-to-end latency <500ms for 5MB file against 50 active patterns.|L   |
|P4-T8 |Block response. On BLOCK verdict: move original file to recovery folder (`C:\AkesoDLP\Recovery\{timestamp}_{filename}`). Display Win32 toast notification with policy name and violation summary. Queue incident for server.                                                                                                   |`agent/src/response/block_action.cpp`, `agent/src/response/notification.cpp`          |Blocked file appears in recovery folder. Toast notification displays. Incident queued with correct policy ID, severity, matched content. User sees “Access Denied” on the file operation.                                                                                       |M   |
|P4-T9 |Notify and User Cancel responses. Notify: toast with policy details + acknowledgment logging. User Cancel: modal dialog with justification text field, 120s timeout, auto-block on timeout.                                                                                                                                       |`agent/src/response/notify_action.cpp`, `agent/src/response/user_cancel_action.cpp`   |Notify: toast displays, acknowledgment timestamp logged. User Cancel: justification submitted → operation allowed, justification in incident. Timeout → block.                                                                                                                  |M   |
|P4-T10|Clipboard monitor. Hook NtUserSetClipboardData via IAT patch or SetClipboardViewer/AddClipboardFormatListener. Read CF_UNICODETEXT and CF_HDROP content. Run detection. Block (prevent clipboard set) or notify on violation. Attribution: foreground window process name logged.                                                 |`agent/src/monitor/clipboard_monitor.cpp`                                             |Copy 10 credit card numbers → detection triggers. Block mode: data does not enter clipboard. Notify mode: data enters clipboard, notification shown. Source app name in incident. Non-sensitive copy → no trigger.                                                              |L   |
|P4-T11|Browser upload monitor. Hook WinHttpSendRequest and/or HttpSendRequestW via DLL injection into browser processes. Inspect POST body and multipart uploads. Block (cancel HTTP request) or notify on violation. AkesoEDR coexistence: injector DLL signed with test certificate, hash added to EDR allowlist (see Section 3.17).|`agent/src/monitor/browser_monitor.cpp`, `agent/src/monitor/injector.cpp`             |Upload sensitive file via Chrome → detection triggers. Block: upload cancelled, user sees error. Notify: upload proceeds, incident logged with URL. DLL injected into browser process cleanly, unloads on agent stop. AkesoEDR (if present) does not alert on DLP injector.  |XL  |
|P4-T12|Tamper protection. Deny SERVICE_STOP and process termination for non-SYSTEM accounts. Require uninstall password (stored as salted hash). Watchdog restarts agent on crash.                                                                                                                                                       |`agent/src/tamper_protect.cpp`                                                        |Standard user cannot stop service (`sc stop` fails). Standard user cannot kill process (`taskkill` fails). Uninstall without password fails. Crash → watchdog restarts within 5s.                                                                                               |M   |
|P4-T13|End-to-end agent test. Install driver + agent → copy sensitive file to USB → block → incident in server → visible in console. Copy clean file → allowed. Policy exception → allowed. EDR coexistence test: DLP browser monitor + AkesoEDR running simultaneously → no false EDR alerts for DLP injector.                       |`tests/agent/test_e2e.md` (manual test plan)                                          |Sensitive USB copy blocked. Clean copy allowed. Exception works. Incident in console with correct channel (usb), matched content, response action. Recovery folder has blocked file. EDR coexistence verified (if EDR available).                                               |M   |

-----

### Phase 5: Network Monitor (Python)

**Goal:** HTTP and SMTP inspection with inline prevent. Docker-integrated.

|ID   |Task                                                                                                                                                                                                                                       |Files                                                                                                     |Acceptance Criteria                                                                                                              |Est.|
|-----|-------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|----------------------------------------------------------------------------------------------------------|---------------------------------------------------------------------------------------------------------------------------------|----|
|P5-T1|HTTP monitor. mitmproxy addon. Intercept POST/PUT. Extract body + multipart uploads. Run detection engine. Monitor mode: log + pass.                                                                                                       |`network/http_monitor.py`, `network/dlp_addon.py`                                                         |POST with 5 SSNs → incident with URL + source IP. Multipart file upload → scanned. Normal traffic passes.                        |L   |
|P5-T2|HTTP prevent. Block with configurable HTML block page (403). Severity-based (block High, log Medium). Domain allowlisting.                                                                                                                 |`network/http_prevent.py`, `network/templates/block_page.html`                                            |Sensitive upload → 403 + block page. Allowlisted domain → passed. Medium → logged not blocked.                                   |M   |
|P5-T3|SMTP monitor. aiosmtpd relay. Parse headers, body, attachments. Detect. Forward to upstream MTA (MailHog at :1025 in Docker). Monitor mode.                                                                                                |`network/smtp_monitor.py`                                                                                 |Sensitive attachment → incident with sender/recipients/subject. Forwarded to MailHog (visible at :8025).                         |L   |
|P5-T4|SMTP prevent. Block (550 + NDR). Modify (subject prefix + header). Redirect (quarantine mailbox).                                                                                                                                          |`network/smtp_prevent.py`                                                                                 |Block → 550. Modify → [DLP VIOLATION] prefix. Redirect → quarantine receives, original doesn’t.                                  |M   |
|P5-T5|Docker integration + console settings. Add HTTP proxy (port 8080) + SMTP relay (port 2525) + mitmproxy CA generation script to Docker Compose. Console page for network monitor config (mode toggle, domain allowlist, severity threshold).|`docker-compose.yml` (extend), `scripts/gen-proxy-ca.sh`, `console/src/pages/settings/NetworkSettings.jsx`|`docker compose up` starts all network services. Console shows status. Mode toggle effective. CA cert generated on first startup.|M   |

-----

### Phase 6: Document Fingerprinting

**Goal:** Index confidential documents and detect partial content matches.

|ID   |Task                                                                                                                                      |Files                                                                      |Acceptance Criteria                                                                                                            |Est.|
|-----|------------------------------------------------------------------------------------------------------------------------------------------|---------------------------------------------------------------------------|-------------------------------------------------------------------------------------------------------------------------------|----|
|P6-T1|Fingerprint analyzer. Simhash rolling hash. Chunk text → hash → store. Compare incoming content → similarity score. Threshold default 40%.|`server/detection/analyzers/fingerprint_analyzer.py`                       |Index 10-page document. Submit 50% copied content → match detected. Unrelated content → no match. Similarity score in metadata.|L   |
|P6-T2|Fingerprint management API + console. Upload documents. List indexed. Delete. Console settings page.                                      |`server/api/fingerprints.py`, `console/src/pages/settings/Fingerprints.jsx`|Upload PDF → fingerprinted → in list. Detection runs against DB. Delete removes from detection.                                |M   |

-----

### Phase 7: Endpoint Discover

**Goal:** Agent-side data-at-rest scanning with incremental mode, CPU throttling, quarantine.

|ID   |Task                                                                                                                                                       |Files                                                            |Acceptance Criteria                                                                                   |Est.|
|-----|-----------------------------------------------------------------------------------------------------------------------------------------------------------|-----------------------------------------------------------------|------------------------------------------------------------------------------------------------------|----|
|P7-T1|Discover scanner (C++ agent). Walk target directories. Filter by type/size/path. Extract content. Run detection. Report incidents as source_type: discover.|`agent/src/discover/scanner.cpp`, `agent/src/discover/config.cpp`|Scan /test/docs/ → finds 3 files with PII. Incidents with file path, owner, mod date. Exclusions work.|L   |
|P7-T2|Incremental scanning. Track file hashes + mod times in SQLite. Full scan first, then incremental.                                                          |`agent/src/discover/incremental.cpp`                             |Full: 100 files. Add 2 → incremental: 2 scanned. Modify 1 → incremental: 1 scanned.                   |M   |
|P7-T3|CPU throttling. Monitor CPU via GetSystemTimes. Sleep between files to stay under threshold (15%).                                                         |`agent/src/discover/throttle.cpp`                                |CPU stays below 15% over 1-minute window. Other high-CPU process → scan slows.                        |M   |
|P7-T4|Quarantine action. Move file to quarantine folder. Write .quarantined.txt marker at original path.                                                         |`agent/src/response/quarantine_action.cpp`                       |Sensitive file → quarantine folder. Original replaced with marker stub.                               |S   |
|P7-T5|Discover management (server + console). Scan definitions, schedule, status. Trigger via API.                                                               |`server/api/discover.py`, `console/src/pages/Discover.jsx`       |Create scan → assign to agent → trigger → status in console. Results show files scanned, violations.  |M   |

-----

### Phase 8: Reporting, User Risk & SIEM Export

**Goal:** Incident reports, user risk scoring, syslog/SIEM integration, Smart Response rules.

|ID   |Task                                                                                                                                                                                                 |Files                                                                               |Acceptance Criteria                                                                                                                                                                  |Est.|
|-----|-----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|------------------------------------------------------------------------------------|-------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|----|
|P8-T1|Report generator. Summary (counts by severity/policy/source/status). Detail (full list). Date range. Trend comparison.                                                                               |`server/services/report_generator.py`                                               |Summary for 30 days → correct aggregations. Period comparison shows delta.                                                                                                           |M   |
|P8-T2|Report export: CSV + PDF.                                                                                                                                                                            |`server/services/report_exporter.py`                                                |CSV opens in Excel correctly. PDF formatted with tables.                                                                                                                             |M   |
|P8-T3|User risk scoring. Weighted by severity (High=10/Med=5/Low=2/Info=1). Recency decay (0.95^days). Normalize 1-100.                                                                                    |`server/services/risk_calculator.py`                                                |5 High incidents this week → score >80. 1 Low 60 days ago → score <10. Ranking correct.                                                                                              |M   |
|P8-T4|Syslog export. CEF format. UDP/TCP/TLS. Configurable severity filter.                                                                                                                                |`server/services/syslog_exporter.py`                                                |Incident → CEF to syslog server. Fields correct. Test connection button works.                                                                                                       |M   |
|P8-T5|SIEM emitter. HTTP POST to AkesoSIEM `/api/v1/ingest`. All 5 DLP event types with correct ECS fields per Section 3.11. `source_type: akeso_dlp` and `event_type` field per event. API key auth.|`server/services/siem_emitter.py`                                                   |Incident → SIEM receives `dlp:policy_violation` with `dlp.policy.name`, `dlp.classification`, `dlp.channel`. API key auth. `source_type` and `event_type` fields present and correct.|M   |
|P8-T6|Smart Response rules. Manual execution from incident snapshot. Actions: Add Note, Set Status, Send Email, Escalate.                                                                                  |`server/services/smart_response.py`, update `console/src/pages/IncidentSnapshot.jsx`|Execute “Escalate” → High severity + Escalated status + email sent + audit logged. Dropdown in snapshot.                                                                             |M   |
|P8-T7|Reports + User Risk console pages.                                                                                                                                                                   |`console/src/pages/Reports.jsx`, `UserRisk.jsx`                                     |Generate report → download. Risk table sorts by score. Click user → incidents.                                                                                                       |M   |

-----

### Phase 9: Console Polish & Demo Environment

**Goal:** Dashboard polish, settings pages, demo seed data, E2E testing, deployment automation. Portfolio-ready.

|ID   |Task                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                         |Files                                                                                                                                                                                                                                                                                            |Acceptance Criteria                                                                                                                                                                                                          |Est.|
|-----|-----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|-------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|-----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|----|
|P9-T1|Agent management pages. Agent list (hostname, OS, agent version, driver version, status, last check-in). Detail (info, recent incidents, policy version). Groups.                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                            |`console/src/pages/Agents.jsx`, `AgentDetail.jsx`, `AgentGroups.jsx`                                                                                                                                                                                                                             |Agents listed with status badges. Click → detail. Group assignment works.                                                                                                                                                    |M   |
|P9-T2|Dashboard rewrite. Trend chart. Top policies. Channel pie (endpoint/network/discover). Top 5 risky users. Agent health. Activity timeline.                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                   |`console/src/pages/Dashboard.jsx`                                                                                                                                                                                                                                                                |All 6 widgets render with real data. Responsive. Time range selector.                                                                                                                                                        |L   |
|P9-T3|Settings pages. All CRUD: data identifiers, keyword dictionaries, response rules, fingerprints, network config, SIEM config, syslog, users/roles, MFA management.                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                            |`console/src/pages/settings/*.jsx`                                                                                                                                                                                                                                                               |All operations work via UI. Custom identifier → available in policy editor. Syslog test connection. MFA enable/disable works for user accounts.                                                                              |L   |
|P9-T4|Demo seed. 500+ incidents across 30 days. Endpoint/network/discover mix. 10 users. 5 agents. 10 policies.                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                    |`server/scripts/demo_seed.py`                                                                                                                                                                                                                                                                    |Dashboard shows realistic data. Risk table shows varied scores. Agent list shows 5 agents.                                                                                                                                   |M   |
|P9-T5|Playwright headless browser E2E test suite. Test suites: **Auth flows** (login, MFA challenge, token refresh, logout, first-run setup). **Incidents** (page loads, filter, sort, snapshot opens with highlighted content, status update saves, notes append). **Policy editor** (create from template, add rule with component targeting, add exception, activate). **Dashboard** (all widgets render, charts display). **Settings** (CRUD for identifiers, dictionaries, SIEM config). **Dark mode** (toggle switches theme, persists). **Global search** (type query → grouped results, `Cmd+Shift+P` → command palette). All tests run headless in CI via `make test-e2e`.|`console/tests/e2e/auth.spec.ts`, `console/tests/e2e/incidents.spec.ts`, `console/tests/e2e/policies.spec.ts`, `console/tests/e2e/dashboard.spec.ts`, `console/tests/e2e/settings.spec.ts`, `console/tests/e2e/theme.spec.ts`, `console/tests/e2e/search.spec.ts`, `console/playwright.config.ts`|All 7 test suites pass headless. Auth round-trip completes. Incident snapshot highlights matched text. Policy creation from template works end-to-end. Global search returns grouped results. ≥30 test cases across 7 suites.|L   |
|P9-T6|Deployment automation. `make install` starts Docker Compose, runs migrations, seeds admin user, prints credentials + console URL. `make dev` for hot-reload development (FastAPI reload + Vite HMR). `make demo` for portfolio demos (install + demo seed + open console). `make clean` for reset (stop containers, drop database, remove volumes).                                                                                                                                                                                                                                                                                                                          |`Makefile` (extend), `scripts/install.sh`, `scripts/demo.sh`                                                                                                                                                                                                                                     |`make install` → console accessible, admin credentials printed. `make demo` → 500+ incidents, 10 users, 5 agents, dashboard populated. `make clean` → clean state. `make dev` → hot-reload works for server and console.     |M   |

-----

### Phase 10: Integration Testing & Documentation

**Goal:** End-to-end validation across all channels and components. Portfolio-ready documentation.

|ID    |Task                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                    |Files                                                                                                                                   |Acceptance Criteria                                                                                                                                                                                                                                                                                                        |Est.|
|------|----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|----------------------------------------------------------------------------------------------------------------------------------------|---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|----|
|P10-T1|Full lifecycle. PCI policy → agent detects CC on USB → block → incident → remediator resolves → report.                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                 |`tests/integration/lifecycle_test.py`                                                                                                   |End-to-end. Correct policy, severity, matches, response action, status transitions, audit trail.                                                                                                                                                                                                                           |L   |
|P10-T2|Cross-channel. Same document: endpoint USB + network email + discover scan → 3 incidents, same policy, different sources.                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                               |`tests/integration/cross_channel_test.py`                                                                                               |3 incidents. Correct source_type each. Same policy ID. Console filters per source.                                                                                                                                                                                                                                         |M   |
|P10-T3|SIEM + NDR integration. DLP incident → SIEM ingest → ECS fields correct → Sigma rule `product: akeso_dlp` fires. Verify NDR+DLP cross-product Sigma rule evaluates when both NDR exfil alert and DLP classification event exist for same host. Verify `source_type` and `event_type` fields are present and correctly formatted.                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                     |`tests/integration/siem_test.py`                                                                                                        |Event in SIEM. `dlp.policy.name`, `dlp.classification`, `dlp.channel` populated. `source_type: akeso_dlp` and `event_type: dlp:policy_violation` present. DLP-only Sigma rule fires. NDR+DLP correlation rule fires when paired with mock ndr:detection exfiltration event for same host.                               |M   |
|P10-T4|Detection parity. 100 test inputs run through both Python server and C++ agent evaluators → identical results.                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                          |`tests/integration/parity_test.py`                                                                                                      |Zero divergence on all 100 inputs. Compound rules, exceptions, severity tiers, edge cases all match.                                                                                                                                                                                                                       |L   |
|P10-T5|Network monitor test suite. 5-level test coverage: (1) Proxy/relay plumbing — GET passes through, POST with clean content passes, multipart upload intact, HTTPS CONNECT works, domain allowlist bypasses, SMTP relay preserves headers/body/attachments/encoding. (2) Detection accuracy — POST with valid CCs triggers, DOCX with SSNs in multipart upload triggers, ZIP-compressed sensitive attachment triggers, near-miss data (invalid Luhn) does not trigger, component attribution correct (body vs attachment). (3) Response actions — HTTP block returns 403 + block page and request never reaches destination, severity-based filtering (block High, log Medium), SMTP block returns 550 and email absent from MailHog, SMTP modify adds subject prefix + header, SMTP redirect delivers to quarantine only. (4) Integration — blocked upload creates incident with correct channel/URL/policy/matched content, incident emitted to SIEM as `dlp:block` with correct ECS fields. (5) Concurrency/resilience — 10 simultaneous sensitive POSTs all blocked, 50MB upload completes without timeout, 20-email burst without drops, detection timeout → fallback action applied.|`tests/integration/network_monitor_test.py`, `tests/integration/docker-compose.test.yml` (adds echo server for destination verification)|All 5 test levels pass. Block page served on violation. Clean traffic unmodified. MailHog API confirms email delivery/absence. Echo server confirms request delivery/absence. Concurrent requests all handled correctly. Test echo server (httpbin or minimal FastAPI) in test Docker Compose for destination verification.|L   |
|P10-T6|Documentation. README, ARCHITECTURE.md, API.md, DEMO.md, DEVELOPMENT.md.                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                |`README.md`, `docs/*.md`                                                                                                                |README: zero to running. DEMO: 10 scenarios. ARCHITECTURE: kernel/user split, detection pipeline, policy evaluation.                                                                                                                                                                                                       |M   |
|P10-T7|Static test fixtures + test data generation. JSON fixture files for all 5 DLP event types (policy_violation, block, audit, removable_media, classification) conforming to AkesoSIEM Appendix A schemas. Python scenario generator producing multi-channel attack narratives (USB exfiltration, email leak, discover scan finding) with realistic field values. Fixtures replayable to AkesoSIEM via `akeso-cli ingest replay`.                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                 |`tests/fixtures/dlp_events/*.json`, `tools/generate_dlp_scenarios.py`                                                                   |All 5 event types have ≥3 fixture events. Fixtures conform to SIEM Appendix A schemas. Scenario generator produces valid NDJSON. Replay to SIEM → events indexed and `product: akeso_dlp` Sigma rules evaluate correctly.                                                                                               |M   |

-----

### Phase 11: Hardening & Production Readiness

**Goal:** Graceful shutdown, observability, performance validation, failure handling, database maintenance, installer packaging.

|ID    |Task                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                              |Files                                                                                                                                                                   |Acceptance Criteria                                                                                                                                                                                                                                                         |Est.|
|------|------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|------------------------------------------------------------------------------------------------------------------------------------------------------------------------|----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|----|
|P11-T1|Graceful shutdown. Coordinated drain-and-flush on SIGTERM for all server components: FastAPI completes in-flight API requests (30s timeout), gRPC server completes in-flight RPCs (including active TTD evaluations), Redis consumer drains current batch, network monitor proxy/relay finishes active connections, SIEM emitter flushes pending events. Docker Compose `stop_grace_period: 30s`.                                                                                                                                                                                                                 |`server/shutdown.py`, `server/grpc_server.py` (extend), `network/http_monitor.py` (extend), `network/smtp_monitor.py` (extend), `docker-compose.yml` (stop_grace_period)|`docker compose down` → all in-flight requests complete, no incidents lost, no half-written database rows. TTD request in flight → completes or returns fallback verdict before shutdown. SIEM emitter flushes → all pending events delivered. Clean exit within 30s.       |M   |
|P11-T2|Prometheus metrics. Expose `/metrics` endpoint on FastAPI server. Metrics: `dlp_detections_total` (counter, labels: channel, severity, action), `dlp_detection_duration_seconds` (histogram), `dlp_incidents_total` (counter, labels: channel, status), `dlp_agent_heartbeat_age_seconds` (gauge per agent), `dlp_grpc_requests_total` (counter, labels: rpc_method), `dlp_ttd_requests_total` (counter, labels: outcome — success/timeout/error), `dlp_ttd_duration_seconds` (histogram), `dlp_queue_depth` (gauge — Redis queue), `dlp_policy_evaluation_cache_hits` (counter). Grafana dashboard template JSON.|`server/metrics.py`, `server/api/metrics_endpoint.py`, `grafana/dlp_dashboard.json`                                                                                     |Prometheus scrapes `/metrics` successfully. All listed metrics present and updating. `dlp_detection_duration_seconds` histogram shows correct percentiles. Grafana template imports and displays data. Metrics update in real time during load test.                        |L   |
|P11-T3|Load testing. Server-side: 50 concurrent `/api/detect/file` requests with 5MB PDFs — measure p50/p95/p99 latency, error rate, memory usage. gRPC: 10 agents reporting incidents simultaneously + 5 concurrent TTD requests — measure throughput and queue depth. Network monitor: 20 concurrent HTTP POSTs through proxy + 10 concurrent SMTP emails through relay — measure detection latency and block accuracy under load. Define pass thresholds: p95 detection latency <2s for 5MB file, p95 TTD round-trip <5s, zero missed blocks under concurrency, memory stable (no leak over 10-minute sustained load).|`tests/benchmark/load_test.py`, `tests/benchmark/network_load_test.py`                                                                                                  |All pass thresholds met. p95 detection <2s. p95 TTD <5s. Zero missed blocks under concurrent load. Memory stable over 10-minute run. Results logged with percentile breakdowns.                                                                                             |L   |
|P11-T4|Dead letter queue. Failed detections (corrupted file, regex engine crash, memory exhaustion, archive extraction failure) → DLQ table in PostgreSQL with original request, error message, timestamp, retry count. Automatic retry (max 3 attempts with exponential backoff). Failed gRPC incident reports from agents → server-side retry queue. DLQ visible in console Settings page with retry/dismiss actions.                                                                                                                                                                                                  |`server/services/dead_letter_queue.py`, `server/models/dead_letter.py`, `console/src/pages/settings/DeadLetterQueue.jsx`                                                |Corrupted PDF submitted → DLQ entry created with error. Retry → re-processed. 3 failures → permanent DLQ (no more retries). Console shows DLQ entries with retry button. Dismiss removes entry. Agent incident report fails mid-processing → retried from server-side queue.|M   |
|P11-T5|Database maintenance. Partition `incidents` table by month using PostgreSQL declarative partitioning. Archival job: move incidents older than configurable retention (default 365 days) to `incidents_archive` table (compressed, read-only). Index maintenance: `REINDEX CONCURRENTLY` on high-churn indexes (incidents by status, by severity, by date). Scheduled via pg_cron or Python APScheduler. Console Settings shows partition status and archive stats.                                                                                                                                                |`server/services/db_maintenance.py`, `migrations/` (partition migration), `server/tasks/archive_job.py`                                                                 |Incidents table partitioned by month. New month → partition auto-created. Archive job moves old incidents → `incidents_archive` queryable but not in default incident list. Index reindex runs without locking. Console shows partition count and archive row count.        |M   |
|P11-T6|gRPC rate limiting. Per-agent rate limit on `ReportIncident` RPC (default: 100 incidents/minute). Per-agent rate limit on `DetectContent` TTD RPC (default: 20 requests/minute). Exceeding limit → gRPC `RESOURCE_EXHAUSTED` status with retry-after hint. Agent-side: respect retry-after, buffer excess incidents in local queue. Server-side: rate limit state in Redis (sliding window counter per agent ID). Configurable per agent group.                                                                                                                                                                   |`server/services/grpc_rate_limiter.py`, `agent/src/grpc_client.cpp` (extend)                                                                                            |Agent sending 200 incidents/minute → first 100 accepted, remainder receive RESOURCE_EXHAUSTED. Agent buffers rejected incidents and retries after backoff. Rate limit configurable per agent group via API. Redis counter resets correctly on window slide.                 |M   |
|P11-T7|Installer packaging. Agent: WiX MSI for Windows — installs driver, agent service, default config, gRPC certs. Configurable `SERVER_ADDRESS`, `SIEM_ENDPOINT`, `SIEM_API_KEY` as MSI properties. Silent install support for SCCM/GPO. Uninstaller stops service, unloads driver, removes binaries (preserves policy cache and recovery folder). Server: `make deploy` target that builds Docker images with versioned tags, generates `.env` from template, runs `docker compose up -d`, runs migrations, seeds admin user.                                                                                        |`agent/installer/AkesoDLP-Agent.wxs`, `agent/installer/build.bat`, `Makefile` (deploy target), `docker-compose.prod.yml`, `scripts/deploy.sh`                        |Agent MSI: `msiexec /i AkesoDLP-Agent.msi /qn SERVER_ADDRESS="server:50051"` → driver loaded, service running, config populated. `msiexec /x ... /qn` → clean uninstall. Server: `make deploy` → all containers running, console accessible, admin login works.          |L   |

-----

## Phase Summary

|Phase|Name                              |Tasks|Depends On|Focus                       |
|-----|----------------------------------|-----|----------|----------------------------|
|P0   |Scaffolding                       |7    |—         |Foundation                  |
|P1   |Detection Engine (Python)         |9    |P0        |Server-side detection       |
|P2   |REST API & Console                |10   |P0, P1    |Interface                   |
|P3   |Agent Core (C/C++)                |8    |P0, P2    |Driver + agent + comms      |
|P4   |Agent Detection & Response (C/C++)|13   |P3        |Endpoint prevention         |
|P5   |Network Monitor (Python)          |5    |P1, P2    |Network detection           |
|P6   |Fingerprinting                    |2    |P1        |Advanced detection          |
|P7   |Endpoint Discover                 |5    |P4        |Data at rest                |
|P8   |Reporting & SIEM                  |7    |P2        |Analytics + integration     |
|P9   |Console Polish & Demo             |6    |P2–P8     |UI/UX + testing + deployment|
|P10  |Integration Testing & Docs        |7    |All       |Validation                  |
|P11  |Hardening & Production Readiness  |7    |All       |Reliability + packaging     |

**Total: 86 tasks, 12 phases. Estimated 58–81 Claude Code sessions.**

-----

## Code Conventions

### C/C++ (Agent + Driver)

C++17 (MSVC). C11 for driver code (WDK requirement). CMake build system. vcpkg for dependencies. Errors as HRESULT or NTSTATUS (driver). Structured logging via ETW or JSON to file. Google Test + Google Mock for unit tests. Driver tested in VM with kernel debugger attached.

### Python (Server + Detection + Network)

Python 3.12+. Type hints everywhere. `async`/`await` for I/O. Pydantic for validation. SQLAlchemy 2.0 async. pytest + pytest-asyncio. ruff for linting/formatting.

### React (Console)

React 18 + Vite. TailwindCSS with `darkMode: 'class'`. shadcn/ui components. Inter font at 500 weight. Recharts for charts. fetch with JWT interceptor. Playwright for headless browser E2E tests. Shared design system with AkesoSIEM (same color palette, typography, severity colors).

### Protobuf / gRPC

Proto files in shared `proto/` directory. C++ stubs generated via CMake. Python stubs generated via grpcio-tools. mTLS required on all connections.

### Database

PostgreSQL 16. JSONB for flexible configs. Alembic migrations. Foreign keys enforced. Indexes on filter/sort patterns.

-----

## v2 Roadmap

- Unified agent: DLP module loads as DLL within AkesoEDR process, sharing single kernel driver with different minifilter altitudes for behavioral monitoring (EDR) and content inspection (DLP).
- Exact Data Matching (EDM): Index structured data (CSV/DB), detect exact record matches with multi-column key matching.
- Vector Machine Learning (VML): Train statistical models for similarity-based content classification.
- OCR detection: Tesseract integration for text extraction from images and scanned PDFs.
- Active Directory integration: Synchronized Directory Group Matching (DGM).
- Cloud channels: Box, Dropbox, Google Drive, OneDrive API connectors.
- SOAR integration: Automated playbooks (trigger AkesoEDR ISOLATE on critical DLP + EDR correlation alert in AkesoSIEM, trigger AkesoFW block on NDR + DLP exfiltration correlation).
- NDR deep correlation: Bidirectional API between DLP server and AkesoNDR for real-time enrichment — NDR queries DLP for content classification of hosts involved in exfiltration alerts; DLP queries NDR for network context on flagged file transfers.
- Community ID tagging: Tag DLP network monitor events (HTTP proxy, SMTP relay) with Community ID hashes so AkesoSIEM can join DLP content inspection events with NDR flow metadata for the same network session.
- macOS agent: Port to macOS with Endpoint Security framework for file system interception.
- Enrichment pipeline: GeoIP, LDAP/CSV lookup plugins for user attribute enrichment.
- FlexResponse framework: Custom response actions via C++ plugin DLLs.
- Hyperscan on server: Replace re2 with Hyperscan on the Python server via hyperscan Python bindings for pattern parity with agent.