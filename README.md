
# NTI — Network Traffic Intelligence

**A cloud-native network traffic intelligence platform for real-time observability, anomaly detection, and security monitoring.**

NTI captures, parses, filters, analyzes, and visualizes network traffic in real time. It provides deep traffic visibility, configurable detection rules, live alerting, and SIEM-friendly exports through a modern web dashboard and REST API.

## Overview

NTI is designed to make network traffic analysis accessible through a lightweight, containerized architecture.

It supports three ingestion modes:

- **Simulator:** Generate synthetic network traffic for demos, development, and CI.
- **PCAP Replay:** Analyze previously captured network traffic.
- **Live Capture:** Monitor traffic from a real network interface.

## Features

### Network Traffic Intelligence
- Real-time packet ingestion and processing.
- Protocol identification and traffic classification.
- Source and destination IP tracking.
- Top talkers and bandwidth analysis.
- TLS Server Name Indication (SNI) extraction.
- HTTP Host header extraction.
- Direction-aware traffic filtering.

### Anomaly Detection

| Detection | Description |
|---|---|
| Port Scanning | Detects sources accessing multiple destination ports within a sliding time window. |
| Bandwidth Spikes | Identifies unusual traffic volume using rolling-baseline z-score analysis. |
| TLS SNI | Extracts server names from TLS ClientHello messages. |
| HTTP Host | Identifies hostnames from clear-text HTTP requests. |

### Custom Detection Rules

Create YAML-based traffic filtering rules using:

- Source and destination CIDR ranges.
- Source and destination ports.
- Network protocols.
- TLS SNI regular expressions.
- HTTP Host regular expressions.
- Traffic direction: internal, external, inbound, and outbound.

### Real-Time Dashboard
- Live traffic metrics and charts.
- Top talkers and protocol distribution.
- Real-time alerts feed.
- Sampled packet visibility.
- Interactive rule editor.
- WebSocket-powered updates.

### SIEM Integration

Export alerts in industry-friendly formats:

- **CEF:** ArcSight-compatible event format.
- **JSONL:** Suitable for Splunk, ELK, and other log pipelines.

---

## Architecture

```text
                 Network Traffic
                        |
          +-------------+-------------+
          |             |             |
       Simulator     PCAP Replay   Live Capture
          |             |             |
          +-------------+-------------+
                        |
                  Ingestion Layer
                        |
                    Event Queue
                        |
                 Processing Worker
                        |
          +-------------+-------------+
          |             |             |
       Parsing       Detection      Filtering
          |             |             |
          +-------------+-------------+
                        |
                 Metrics + Alerts
                        |
             +----------+----------+
             |                     |
          FastAPI              WebSocket
             |                     |
        REST API             Live Dashboard
             |                     |
        SIEM Export          React + Vite
```

---

## Quick Start

### Prerequisites

- Docker
- Docker Compose

### Run with Docker Compose

Clone the repository:

```bash
git clone <repository-url>
cd NTI
```

Build and start the platform:

```bash
docker compose up --build
```

### Access the Services

| Service | URL |
|---|---|
| Dashboard | http://localhost:8080 |
| API | http://localhost:8000 |
| API Documentation | http://localhost:8000/docs |
| WebSocket | ws://localhost:8000/ws/stream |

Docker Compose also starts two demo microservices that communicate with each other, generating east-west traffic for monitoring.

---

## Traffic Ingestion Modes

### 1. Simulator Mode (Default)

```bash
NTI_SIMULATE=1
```

Generates synthetic network traffic without requiring packet capture permissions or special hardware.

Configure the packet generation rate:

```bash
NTI_SIM_PPS=40
```

Recommended for:
- Development and testing.
- CI/CD environments.
- Dashboard demonstrations.
- Environments without packet capture capabilities.

### 2. PCAP Replay Mode

Set the path to an existing packet capture:

```bash
NTI_PCAP_PATH=/path/to/file.pcap
```

Recommended for:
- Offline traffic analysis.
- Security investigations.
- Testing detection rules.
- Reproducible demonstrations.

### 3. Live Capture Mode

Live ingestion can be connected through the PCAP pipe interface.

```bash
tcpdump -w - | python -m app.cli pipe-pcap
```

**Requirements:**
- Administrative/root privileges where required.
- `tcpdump` on supported Linux systems.
- Npcap on Windows.
- Appropriate network interface access.

Live capture should only be enabled on networks and interfaces you are authorized to monitor.

---

## Local Development

### Backend Setup

Navigate to the backend directory:

```bash
cd backend
```

Install dependencies:

```bash
pip install -r requirements.txt
```

Start the FastAPI server:

```bash
uvicorn app.main:app --reload
```

Run tests:

```bash
pytest -q
```

Backend API documentation:

```text
http://localhost:8000/docs
```

### Frontend Setup

Navigate to the frontend directory:

```bash
cd frontend
```

Install dependencies:

```bash
npm install
```

Start the development server:

```bash
npm run dev
```

Access the dashboard:

```text
http://localhost:5173
```

The Vite development server proxies `/api` and `/ws` requests to the backend running on port `8000`.

---

## Configuration

NTI supports environment-based configuration.

| Variable | Default | Description |
|---|---|---|
| `NTI_SIMULATE` | `1` | Enable or disable synthetic traffic generation. |
| `NTI_SIM_PPS` | `40` | Synthetic packets generated per second. |
| `NTI_PCAP_PATH` | Unset | Path to a PCAP capture file. |
| `NTI_RULES_PATH` | `./rules.yaml` | Persistent YAML rules file. |
| `NTI_DB_URL` | `sqlite+aiosqlite:///./nti.db` | Database connection for alert storage. |
| `NTI_PORTSCAN_PORTS` | `20` | Distinct destination-port threshold for port-scan detection. |
| `NTI_SPIKE_Z` | `3.0` | Bandwidth anomaly z-score threshold. |

Example:

```bash
NTI_SIMULATE=1 \
NTI_SIM_PPS=100 \
NTI_PORTSCAN_PORTS=15 \
NTI_SPIKE_Z=2.5 \
uvicorn app.main:app --reload
```

---

## Detection Rules

NTI supports custom YAML-based filtering and alerting rules.

Example rule:

```yaml
rules:
  - name: alert-tls-google
    proto: TLS
    sni_regex: 'google\.com$'
```

### CLI Rule Management

List configured rules:

```bash
nti rules list
```

Add a TLS detection rule:

```bash
nti rules add alert-tls-google \
  --proto TLS \
  --sni-regex 'google\.com$'
```

Import rules:

```bash
nti rules import sample-rules.yaml
```

### Alert Management

List the latest alerts:

```bash
nti alerts list -n 20
```

Follow alerts in real time:

```bash
nti alerts tail
```

### SIEM Export

Export alerts to CEF:

```bash
nti export cef -o alerts.cef
```

Configure the CLI server URL:

```bash
export NTI_BASE_URL=http://localhost:8000
```

Default:

```text
http://localhost:8000
```

---

## REST API Reference

NTI exposes a REST API through FastAPI.

| Method | Endpoint | Description |
|---|---|---|
| GET | `/api/health` | Health status and queue depth. |
| GET | `/api/metrics` | Traffic metrics snapshot. |
| GET | `/api/alerts?limit=N` | Retrieve recent alerts. |
| GET | `/api/rules` | List detection rules. |
| POST | `/api/rules` | Create or update a rule. |
| DELETE | `/api/rules/{name}` | Delete a rule. |
| GET | `/api/export/cef` | Stream alerts in CEF format. |
| GET | `/api/export/jsonl` | Stream alerts in JSON Lines format. |
| WS | `/ws/stream` | Live metrics, alerts, and sampled packets. |

### Example API Requests

Check service health:

```bash
curl http://localhost:8000/api/health
```

Get current metrics:

```bash
curl http://localhost:8000/api/metrics
```

Retrieve recent alerts:

```bash
curl "http://localhost:8000/api/alerts?limit=20"
```

List detection rules:

```bash
curl http://localhost:8000/api/rules
```

Export alerts as CEF:

```bash
curl "http://localhost:8000/api/export/cef?limit=1000"
```

Export alerts as JSONL:

```bash
curl "http://localhost:8000/api/export/jsonl?limit=1000"
```

---

## WebSocket Streaming

NTI provides a WebSocket endpoint for real-time monitoring.

```text
ws://localhost:8000/ws/stream
```

The stream provides:

- Metrics updates at approximately 1 Hz.
- Newly generated alerts.
- Sampled packet information.

The React dashboard uses this stream to update traffic visualizations and alert feeds without requiring continuous REST polling.

---

## SIEM Integration

NTI supports streaming exports for external security monitoring systems.

### CEF

```bash
curl "http://localhost:8000/api/export/cef?limit=1000"
```

Suitable for ArcSight-compatible SIEM ingestion.

### JSON Lines

```bash
curl "http://localhost:8000/api/export/jsonl?limit=1000"
```

## Technology Stack

| Component | Technology |
|---|---|
| Backend | Python, FastAPI |
| Frontend | React, Vite |
| Real-Time Communication | WebSockets |
| Database | SQLite, SQLAlchemy Async |
| Rule Engine | YAML-based configuration |
| Packet Processing | PCAP ingestion and parsing |
| Deployment | Docker, Docker Compose |
| Testing | Pytest |
| Integration | CEF and JSONL exports |

---

## Security and Responsible Use

NTI is intended for authorized network observability, traffic analysis, and defensive security monitoring.

- Only capture traffic on networks you own or are authorized to monitor.
- Restrict access to the API and dashboard in production.
- Protect PCAP files because they may contain sensitive information.
- Secure SIEM export endpoints and database access.
- Avoid exposing the WebSocket or API publicly without appropriate access controls.

---

## Testing

Run backend tests:

```bash
cd backend
pytest -q
```

For a complete demonstration, start the Docker Compose environment and verify:

1. The API health endpoint responds.
2. Synthetic traffic appears in the dashboard.
3. Metrics update in real time.
4. Alerts appear when detection conditions are met.
5. Rules can be created, updated, and removed.
6. CEF and JSONL exports return events.

---


## License

Add your preferred open-source license before distributing this project.

---

**NTI — Network Traffic Intelligence**

*See your network. Understand its behavior. Detect anomalies. Respond with intelligence.*
