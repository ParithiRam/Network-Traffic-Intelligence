# NTI · Network Traffic Intelligence

A cloud-native traffic intelligence platform inspired by Gigamon-style
deep observability: capture, parse, filter, analyze, and visualize network
traffic in real time, with anomaly detection and SIEM-friendly export.

## What's inside

```
backend/   FastAPI service: ingest -> queue -> worker -> metrics + alerts
frontend/  React + Vite dashboard (real-time charts, alerts feed, rule editor)
sample-rules.yaml   Example filter ruleset
docker-compose.yml  Backend + dashboard + two demo microservices
```

The platform supports three ingestion modes:

| Mode      | How                                                | When to use            |
|-----------|----------------------------------------------------|------------------------|
| Simulator | `NTI_SIMULATE=1` (default)                         | Demos, CI, no Npcap   |
| PCAP      | `NTI_PCAP_PATH=/path/to/file.pcap`                 | Replay captures        |
| Live      | `tcpdump -w - | python -m app.cli pipe-pcap` *     | Real interface (admin) |

\* Live mode requires admin / Npcap on Windows; the simulator is the default
because it works everywhere.

## Quick start (Docker)

```bash
docker compose up --build
```

- Dashboard: http://localhost:8080
- API:       http://localhost:8000/docs
- WebSocket: ws://localhost:8000/ws/stream

The compose file also brings up two dummy microservices that talk to each
other so you can see something resembling east-west traffic.

## Local development

### Backend
```bash
cd backend
pip install -r requirements.txt
uvicorn app.main:app --reload
pytest -q
```

Environment overrides (all optional):

| Variable             | Default                              | Notes |
|----------------------|--------------------------------------|-------|
| `NTI_SIMULATE`       | `1`                                  | `0` to disable the simulator |
| `NTI_SIM_PPS`        | `40`                                 | Synthetic packets/second |
| `NTI_PCAP_PATH`      | unset                                | Read packets from a PCAP file instead |
| `NTI_RULES_PATH`     | `./rules.yaml`                       | Where rules persist |
| `NTI_DB_URL`         | `sqlite+aiosqlite:///./nti.db`       | Alerts store |
| `NTI_PORTSCAN_PORTS` | `20`                                 | Port-scan detection threshold |
| `NTI_SPIKE_Z`        | `3.0`                                | Bandwidth-spike z-score |

### Frontend
```bash
cd frontend
npm install
npm run dev   # http://localhost:5173 (proxies /api and /ws to :8000)
```

## CLI

The backend installs a `nti` console script that talks to a running server.

```bash
nti rules list
nti rules add alert-tls-google --proto TLS --sni-regex 'google\.com$'
nti rules import sample-rules.yaml
nti alerts list -n 20
nti alerts tail              # follow alerts via WebSocket
nti export cef -o alerts.cef # SIEM-friendly export
```

`NTI_BASE_URL` overrides the target (default `http://localhost:8000`).

## What the platform detects

Out of the box, even with no rules configured:

- **Port scans** — same source touching many distinct destination ports
  inside a sliding window.
- **Bandwidth spikes** — per-second byte rate exceeding a z-score threshold
  over a rolling baseline.
- **TLS SNI extraction** — even without decryption, we extract the server
  name from ClientHello and surface it for filtering and alerting.
- **HTTP host extraction** — pulled from clear-text HTTP request headers.

User-defined YAML rules layer on top: CIDR, port, protocol, SNI/host regex,
direction (internal / external / inbound / outbound).

## SIEM integration

```bash
curl http://localhost:8000/api/export/cef?limit=1000   # ArcSight CEF
curl http://localhost:8000/api/export/jsonl?limit=1000 # Splunk / ELK
```

Both endpoints stream — they are safe to point at as a recurring SIEM job.

## API surface

| Method | Path                       | Purpose                          |
|--------|----------------------------|----------------------------------|
| GET    | `/api/health`              | Liveness + queue depth          |
| GET    | `/api/metrics`             | Snapshot: top talkers, protos, bw |
| GET    | `/api/alerts?limit=N`      | Recent alerts (newest first)    |
| GET    | `/api/rules`               | List filter rules               |
| POST   | `/api/rules`               | Upsert by name                  |
| DELETE | `/api/rules/{name}`        | Remove a rule                   |
| GET    | `/api/export/cef`          | Streaming CEF                   |
| GET    | `/api/export/jsonl`        | Streaming JSON Lines            |
| WS     | `/ws/stream`               | metrics (1Hz) + alerts + sampled packets |
