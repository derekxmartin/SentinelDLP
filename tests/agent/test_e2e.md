# P4-T13: End-to-End Agent Test Plan

Manual test plan for validating the AkesoDLP agent across all Phase 4 features.

## Prerequisites

- Windows 10/11 VM with test signing enabled (`bcdedit /set testsigning on`)
- Minifilter driver installed, signed, and loaded (`fltmc load AkesoDLPFilter`)
- Agent built: `cmake --preset debug && cmake --build build/debug`
- USB flash drive available
- Edge browser installed
- Two user accounts: **Administrator** and **Standard User**

## Test Data

Create the following files on the Desktop before testing:

```powershell
# Sensitive file (credit card + SSN)
Set-Content "$env:USERPROFILE\Desktop\sensitive.txt" -Value @"
CONFIDENTIAL Report
Customer: John Doe
SSN: 123-45-6789
Credit Card: 4111-1111-1111-1111
INTERNAL ONLY
"@

# Clean file (no sensitive data)
Set-Content "$env:USERPROFILE\Desktop\clean.txt" -Value "This is a normal document with no sensitive content."
```

---

## Test 1: USB Block — Sensitive File

**Validates:** Driver interception, content scanning, block verdict, recovery, toast notification

| Step | Action | Expected Result |
|------|--------|-----------------|
| 1 | Start agent: `.\build\debug\akeso-dlp-agent.exe --console --test-policy` | Agent starts, all components healthy |
| 2 | Insert USB flash drive | Drive mounts (e.g., `E:\`) |
| 3 | Copy `sensitive.txt` to USB: drag-and-drop or `copy` | **Copy fails** — Windows shows error |
| 4 | Check agent console | `[SCAN]` with `VolumeType=Removable`, `[VIOLATION]` for PCI-DSS or PII, `[BLOCK]` verdict |
| 5 | Check toast notification | Balloon shows "AkesoDLP: File Blocked" with policy name and severity |
| 6 | Check recovery folder: `dir C:\AkesoDLP\Recovery\` | `sensitive.txt` (or timestamped copy) present |
| 7 | Check incident queue | `[info] IncidentQueue: Enqueued incident` in log |

**Pass criteria:** File does NOT reach the USB drive. Recovery copy exists. Incident logged.

---

## Test 2: USB Allow — Clean File

**Validates:** Clean files pass through without false positives

| Step | Action | Expected Result |
|------|--------|-----------------|
| 1 | Agent still running from Test 1 | — |
| 2 | Copy `clean.txt` to USB drive | **Copy succeeds** |
| 3 | Check agent console | `[SCAN]` → `[ALLOW]` — no violation |
| 4 | Verify file on USB | `clean.txt` present with correct content |

**Pass criteria:** File reaches USB. No block, no notification.

---

## Test 3: Browser Upload Block — Sensitive File

**Validates:** ETW browser upload monitor, content scanning, block notification

| Step | Action | Expected Result |
|------|--------|-----------------|
| 1 | Agent running with `--test-policy` | BrowserUploadMonitor: ETW trace session started |
| 2 | Open Edge, navigate to Gmail (or any file upload form) | — |
| 3 | Compose new email, click Attach, select `sensitive.txt` | — |
| 4 | Check agent console | `[UPLOAD]` with `C:\` path, `[UPLOAD_SCAN]`, `[UPLOAD_VIOLATION]` PCI-DSS, `[UPLOAD_BLOCK]` |
| 5 | Check toast notification | "AkesoDLP: File Blocked" with policy name |

**Pass criteria:** Upload detected, violation identified, block notification shown. Note: ETW detection is post-hoc — the file may still upload. The browser extension (issue #66) is needed for true pre-upload blocking.

---

## Test 4: Browser Upload Allow — Clean File

**Validates:** Clean uploads are not flagged

| Step | Action | Expected Result |
|------|--------|-----------------|
| 1 | Agent running | — |
| 2 | In Edge, attach `clean.txt` to an email | — |
| 3 | Check agent console | `[UPLOAD]` → `[UPLOAD_SCAN]` → no violation logged |

**Pass criteria:** No block notification. No violation in log.

---

## Test 5: Clipboard Monitor — Sensitive Content

**Validates:** Clipboard DLP scanning, block/notify responses

| Step | Action | Expected Result |
|------|--------|-----------------|
| 1 | Agent running with `--test-policy` | ClipboardMonitor: started |
| 2 | Open `sensitive.txt` in Notepad, select all, Ctrl+C | — |
| 3 | Check agent console | `[CLIPBOARD]` detection, `[CLIP_VIOLATION]` for PCI-DSS/PII policy |
| 4 | Check toast notification | Block or notify notification displayed |

**Pass criteria:** Clipboard content scanned and violation detected.

---

## Test 6: UserCancel Response — Justification

**Validates:** UserCancel dialog, justification capture, timeout behavior

| Step | Action | Expected Result |
|------|--------|-----------------|
| 1 | Agent running with `--test-policy` | — |
| 2 | Copy `sensitive.txt` to USB (the file contains "CONFIDENTIAL" which triggers UserCancel policy) | UserCancel dialog appears |
| 3 | Enter justification text, click Allow | Copy proceeds. Log shows justification text |
| 4 | Repeat copy | UserCancel dialog appears again |
| 5 | Wait 120 seconds without responding | Dialog times out, copy is **blocked** |

**Pass criteria:** Dialog appears, justification captured on allow, auto-block on timeout.

---

## Test 7: Notify Response — Acknowledge

**Validates:** Notify toast for low-severity matches

| Step | Action | Expected Result |
|------|--------|-----------------|
| 1 | Create file: `Set-Content "$env:USERPROFILE\Desktop\internal.txt" -Value "INTERNAL ONLY document"` | — |
| 2 | Copy `internal.txt` to USB | **Copy succeeds** |
| 3 | Check agent console | `[VIOLATION]` for "Internal Document Tracking", `[NOTIFY]` action |
| 4 | Check toast | Notification shown (not a block) |

**Pass criteria:** File copies successfully. Notification shown. Incident logged.

---

## Test 8: Tamper Protection — Process Kill

**Validates:** Process DACL hardening

| Step | Action | Expected Result |
|------|--------|-----------------|
| 1 | Start agent as Administrator | TamperProtection: process DACL hardened |
| 2 | Open a **non-elevated** PowerShell as Standard User | — |
| 3 | `Get-Process akeso-dlp-agent \| Select-Object Id` | Note the PID |
| 4 | `taskkill /PID <pid> /F` | **"Access is denied"** |
| 5 | Verify agent is still running | Agent console still active, logs still flowing |

**Pass criteria:** Standard user cannot terminate the agent process.

---

## Test 9: Tamper Protection — Uninstall Password

**Validates:** Uninstall password gate

| Step | Action | Expected Result |
|------|--------|-----------------|
| 1 | Set password: `.\akeso-dlp-agent.exe --set-uninstall-password TestPW123` | "Uninstall password set successfully" |
| 2 | `.\akeso-dlp-agent.exe --uninstall` | "Uninstall password required" |
| 3 | `.\akeso-dlp-agent.exe --uninstall --uninstall-password wrong` | "Incorrect uninstall password" |
| 4 | `.\akeso-dlp-agent.exe --uninstall --uninstall-password TestPW123` | "Service uninstalled successfully" (or not installed message) |
| 5 | Clean up: delete `C:\AkesoDLP\config\uninstall.key` | — |

**Pass criteria:** Uninstall blocked without correct password.

---

## Test 10: Tamper Protection — Service DACL (Service Mode Only)

**Validates:** Service stop denied to non-SYSTEM

| Step | Action | Expected Result |
|------|--------|-----------------|
| 1 | Install service: `.\akeso-dlp-agent.exe --install` | "Service installed successfully" |
| 2 | Start service: `Start-Service AkesoDLPAgent` | Service starts |
| 3 | As Standard User: `sc stop AkesoDLPAgent` | **"Access is denied"** |
| 4 | As Administrator: `Stop-Service AkesoDLPAgent` | Service stops (Admins retain access) |
| 5 | Clean up: `.\akeso-dlp-agent.exe --uninstall` | — |

**Pass criteria:** Standard user cannot stop the service.

---

## Test 11: Watchdog Recovery

**Validates:** SCM failure actions restart agent within 5s

| Step | Action | Expected Result |
|------|--------|-----------------|
| 1 | Install and start service (as in Test 10) | — |
| 2 | Kill the process as SYSTEM: `taskkill /F /PID <pid>` from an elevated SYSTEM shell | Process terminates |
| 3 | Wait 5 seconds | — |
| 4 | `Get-Service AkesoDLPAgent` | Status: **Running** (SCM restarted it) |

**Pass criteria:** Service auto-restarts within 5 seconds of crash.

---

## Test 12: Clean Shutdown Stats

**Validates:** All components shut down cleanly with accurate stats

| Step | Action | Expected Result |
|------|--------|-----------------|
| 1 | Run agent in console mode, perform several test operations | — |
| 2 | Press Ctrl+C | — |
| 3 | Check shutdown log | All components report "stopped" with stats |

**Expected shutdown log:**
```
DetectionPipeline: stopped - scanned=N, allowed=N, blocked=N, violations=N
BrowserUploadMonitor: stopped (detected=N, scanned=N)
ClipboardMonitor: stopped (changes=N, extractions=N, clears=N)
DriverComm: stopped (rx=N, tx=N)
```

**Pass criteria:** All components stop in reverse order. No crashes or hangs.

---

## Summary Matrix

| # | Test | Channel | Expected | Priority |
|---|------|---------|----------|----------|
| 1 | USB block — sensitive | USB | Block | Critical |
| 2 | USB allow — clean | USB | Allow | Critical |
| 3 | Browser upload block | Browser | Block | High |
| 4 | Browser upload allow | Browser | Allow | High |
| 5 | Clipboard block | Clipboard | Block | High |
| 6 | UserCancel dialog | USB | Dialog | Medium |
| 7 | Notify response | USB | Notify | Medium |
| 8 | Tamper — process kill | Agent | Denied | High |
| 9 | Tamper — uninstall pw | Agent | Denied | High |
| 10 | Tamper — service DACL | Service | Denied | Medium |
| 11 | Watchdog recovery | Service | Restart | Medium |
| 12 | Clean shutdown | Agent | Clean | Medium |
