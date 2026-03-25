# AkesoDLP API Reference

Base URL: `http://localhost:8000/api`

Interactive docs: http://localhost:8000/docs (Swagger UI)

## Authentication

All endpoints except `/api/auth/login` and `/api/health` require a Bearer token.

### POST /api/auth/login
```json
{ "username": "admin", "password": "AkesoDLP2026!" }
→ { "access_token": "...", "token_type": "bearer" }
```

### POST /api/auth/refresh
Refresh token sent via HTTP-only cookie. Returns new access token.

### GET /api/auth/me
Returns current user profile.

## Incidents

### GET /api/incidents
Query params: `page`, `page_size`, `severity`, `status`, `channel`, `source_type`, `sort_by`, `sort_order`

### GET /api/incidents/{id}
Full incident snapshot with matched content.

### PATCH /api/incidents/{id}
Update status or severity. Body: `{ "status": "investigating" }`

### POST /api/incidents/{id}/notes
Add investigation note. Body: `{ "content": "..." }`

### GET /api/incidents/{id}/history
Audit trail of all status changes and actions.

### POST /api/incidents
Create incident (used by gRPC agent reports and tests).

## Detection

### POST /api/detect
Scan text content. Body: `{ "text": "..." }`
Returns matches with analyzer name, rule, offsets, matched text.

### POST /api/detect/file
Upload file for content extraction and scanning. Multipart form data.

## Policies

### GET /api/policies
List all policies. Query: `status=active`

### POST /api/policies
Create policy with rules, severity, response actions.

### GET /api/policies/{id}
### PUT /api/policies/{id}
### DELETE /api/policies/{id}

## Agents

### GET /api/agents
List registered agents with status, version, last heartbeat.

### GET /api/agents/{id}
Agent detail with system info, recent incidents.

### GET /api/agents/stats
`{ "total": 5, "online": 3, "offline": 1, "stale": 1, "error": 0 }`

### POST /api/agents/groups
Create agent group. Body: `{ "name": "...", "description": "..." }`

## Discovers

### GET /api/discovers
### POST /api/discovers
### POST /api/discovers/{id}/trigger
### GET /api/discovers/{id}

## Reports

### POST /api/reports/summary
Body: `{ "start_date": "...", "end_date": "..." }`
Returns: by_severity, by_policy, by_channel, by_status, top_users, total_incidents.

### POST /api/reports/incidents/csv
Export incidents as CSV.

### POST /api/reports/incidents/pdf
Export incidents as PDF.

### GET /api/reports/risk
User risk scores. Query: `days=30`

## Settings

### GET/POST/PUT/DELETE /api/identifiers
Data identifier CRUD.

### GET/POST/PUT/DELETE /api/dictionaries
Keyword dictionary CRUD.

### GET/POST/PUT/DELETE /api/response-rules
Response rule CRUD.

### GET/POST/PUT/DELETE /api/users
User management (admin only).

### GET /api/auth/roles
List available roles.

## gRPC (Agent Communication)

Port 50051. Proto: `proto/akesodlp.proto`

- **Register**: Agent registration with hostname, OS, version, IP
- **Heartbeat**: Periodic health check, receives commands (run_discover)
- **GetPolicies**: Pull policy updates by version
- **ReportIncident**: Submit detection violations
- **DetectContent**: Two-tier detection (agent → server)
- **PolicyUpdates**: Server-stream for real-time policy changes
- **GetDiscoverScans**: Pull assigned scan definitions
- **ReportDiscoverResults**: Push scan results back to server

## Health

### GET /api/health
`{ "status": "ok" }` — no auth required.
