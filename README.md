# Sentinel API

Backend for the Sentinel security hub. Ingests logs from a WAF/CDN, an API
gateway or nginx, application servers, and host/auth logs, normalizes and
enriches them, runs MITRE ATT&CK-mapped detection rules, and serves the alert
triage queue and live request stream to the dashboard.

Standalone Go service with no monorepo coupling, built so the ingestion and
detection core can be reused by other products.

## Architecture

```
shipper (HTTP) ─┐
file tailer     ─┼─> RawLog ─> Normalizer ─> Enricher (geo/ASN) ─> Detection Engine ─> Alert Service
simulator       ─┘                                                │                    └─> Postgres / memory store
                                                                  └─> Live request ring + SSE hub ─> dashboard
```

- **ingest** (`internal/ingest`): HTTP shipper endpoint, nginx + sshd file
  tailer, and a traffic simulator for zero-infra demo mode.
- **enrich** (`internal/enrich`): pluggable `Resolver`; default ships an
  offline ASN/geo table. Swap in MaxMind/ipinfo behind the same interface for
  production.
- **detect** (`internal/detect`): sliding-window rules, MITRE-mapped:
  - `dir-enum` — Directory Enumeration, T1595.001 / T1083
  - `port-scan` — Sequential Port Scan, T1046
  - `sqli` — SQLi Pattern, T1190
  - `auth-brute` — Credential Brute Force, T1110
  - `waf-block-spike` — WAF Block Spike, T1190
  - `db-anomaly` — Anomalous DB Query Volume, T1190
  - `webshell` — Webshell Delivery, T1505.003
- **alerts** (`internal/alerts`): lifecycle OPEN → ASSIGNED → IN_PROGRESS →
  RESOLVED with an auditable action trail and MTTR tracking. Repeated hits
  merge into the open alert rather than spamming the queue.
- **analysis** (`internal/analysis`): kill-chain phases, extracted indicators
  and incident grouping with SLA tracking.
- **containment** / **edge** (`internal/containment`, `internal/edge`):
  deployable, revocable controls (IP block, rate limit, WAF rule) enforced on
  the live pipeline before detection.
- **store** (`internal/store`): `alerts.Store` interface with in-memory
  (demo/sim) and Postgres (`pgx`) implementations. Raw events stay in an
  in-memory ring; alerts are the durable contract.

## Run it

Zero-infra demo (simulator + memory store):

```
cp .env.example .env
task dev          # or: go run ./cmd/sentinel-api
curl localhost:3000/health
```

The simulator seeds a backdated alert history, then runs continuous realistic
traffic with attack bursts. Point the dashboard at `http://localhost:3000`.

Production store (Postgres):

```
docker run -d --name sentinel-pg -e POSTGRES_PASSWORD=change-me -e POSTGRES_DB=sentinel -p 5432:5432 postgres:16
SENTINEL_STORE_KIND=postgres \
SENTINEL_STORE_DATABASE_URL=postgres://postgres:change-me@localhost:5432/sentinel \
task migrate:up && task dev
```

Ingest real logs:

```
# HTTP shipper (single, array, or NDJSON)
curl -X POST localhost:3000/api/v1/ingest -d '{"source":"gateway","asset":"api-gw-01","fields":{...}}'
# File tailing (nginx combined + sshd syslog lines)
SENTINEL_TAIL_PATHS=/var/log/nginx/access.log SENTINEL_TAIL_ASSET=api-gw-01 task dev
```

## API

| Method | Path | Purpose |
|---|---|---|
| GET | `/health` | liveness, event totals, store kind |
| GET | `/api/v1/summary` | hub header: counts, MTTR, assets, alert timeline |
| GET | `/api/v1/assets` | monitored assets |
| GET | `/api/v1/alerts?status=&severity=&asset=&q=` | triage queue (active first, severity desc) |
| GET | `/api/v1/alerts/:id` | alert detail |
| GET | `/api/v1/alerts/:id/events` | related raw events |
| GET | `/api/v1/alerts/:id/chain` | kill chain for the alert's source |
| GET | `/api/v1/alerts/:id/iocs` | extracted indicators |
| PATCH | `/api/v1/alerts/:id/assign` | `{assignee}` |
| PATCH | `/api/v1/alerts/:id/status` | `{status}` |
| POST | `/api/v1/alerts/:id/actions` | `{action,note}` — respond/investigate/ack/block_ip/mitigate/false_positive/comment |
| GET | `/api/v1/incidents` | grouped cases with SLA status |
| GET | `/api/v1/incidents/:id` | incident detail |
| POST | `/api/v1/incidents/:id/assign` | `{assignee}` |
| POST | `/api/v1/incidents/:id/contain` | `{type,duration,note}` deploy a control across the case |
| GET | `/api/v1/containment?target_ip=` | active and historical controls |
| POST | `/api/v1/containment` | `{type,target_ip,duration,note,alert_ids}` |
| POST | `/api/v1/containment/:id/revoke` | revoke a control |
| GET | `/api/v1/requests?asset=&limit=` | recent request log |
| GET | `/api/v1/requests/stream` | SSE live stream (`event: request`) |
| GET | `/api/v1/metrics?asset=&window=` | time-series for charts |
| POST | `/api/v1/ingest` | raw log shipper (optional `Authorization: Bearer <token>`) |

## Config

Everything is overridable via `SENTINEL_*` env vars; see `configs/config.yaml`
and `.env.example`.

## Tests

```
task test        # go test ./...
task lint        # gofmt + go vet + build
```

## Roadmap

- Real WAF / nginx / journald connectors behind the RawLog seam
- MaxMind/ipinfo enrichment in production, caching in Redis
- Persist raw events for retention and replay
- Alert routing/notifications, RBAC, action approvals
