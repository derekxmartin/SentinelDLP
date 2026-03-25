# AkesoDLP Demo Guide

## Quick Start

```bash
make demo
```

This starts all services, seeds 500+ incidents, 10 users, 5 agents, and 10 policies.
Open http://localhost:3000 — login with `admin` / `AkesoDLP2026!`.

## Demo Scenarios

### 1. Dashboard Overview
- Open the Dashboard — all 6 widgets populated with real data
- Switch time range (7d / 30d / 90d) — charts update
- Note the severity distribution, top policies, channel breakdown

### 2. Incident Investigation
- Navigate to Incidents — 500+ incidents across endpoint/network/discover
- Filter by severity (CRITICAL) — see the most urgent violations
- Click an incident — view the snapshot with matched content highlighted
- Add a note: "Confirmed data exfiltration attempt"
- Change status: Open → Investigating → Resolved
- Check History tab — complete audit trail

### 3. Real-Time Endpoint Detection
- On the VM, create a file with sensitive content:
  ```powershell
  Set-Content -Path "C:\test\secret.txt" -Value "SSN: 123-45-6789"
  ```
- The agent detects, scans, and blocks in real-time (~15ms)
- Toast notification appears on the endpoint
- Incident appears in the console within 60 seconds (next heartbeat)

### 4. USB Exfiltration Block
- Insert a USB drive (or use a mapped drive in the VM)
- Copy a file containing credit card numbers to the USB
- Minifilter driver intercepts the write and blocks it
- Agent logs the violation and reports to server

### 5. Browser Upload Detection
- Open Edge/Chrome on the endpoint
- Navigate to any file upload site
- Upload a file containing SSNs
- ETW tracing detects the browser file read
- Pipeline scans content and triggers policy violation

### 6. Clipboard DLP
- Copy sensitive text (SSN, CC number) to clipboard
- ClipboardMonitor detects and scans the content
- If policy matches, clipboard is cleared and user is notified

### 7. Discover Scan
- Navigate to Discovers in the console
- Create a new scan targeting `C:\test\docs`
- Click the play button to trigger a remote scan
- Agent executes the scan and reports results back
- Violations (SSN in files) appear with file owner and modification date

### 8. Policy Management
- Navigate to Policies — view all active policies
- Click a policy to open the editor
- Modify severity or add a new rule pattern
- Activate/deactivate policies — changes propagate to agents via gRPC

### 9. User Risk Scoring
- Navigate to User Risk — see risk scores (1-100)
- Users with many recent HIGH incidents score highest
- Click a user — view their incident history
- Recency decay: older incidents contribute less to score

### 10. Report Export
- Navigate to Reports
- Select date range and click Generate
- Download as CSV (opens in Excel) or PDF (formatted tables)
- Report includes: severity breakdown, top policies, trend analysis
