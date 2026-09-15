# AihaX

**Enter URL. Click Start. Get a Professional Pentest Report.**

AihaX is an AI-powered automated penetration testing platform that runs a 9-agent pipeline to perform end-to-end web application security testing — from reconnaissance to professional PDF reports — with no manual intervention after clicking START.

## Architecture

```
[Electron Shell]  →  localhost:3000 (React)
        ↓
[Docker Container]
  ├── FastAPI backend (localhost:8000)
  ├── Redis (agent memory + pub/sub)
  ├── ChromaDB (long-term learning)
  ├── SQLite (scan history)
  └── Pentest tools (Nmap, SQLMap, Nuclei, Dalfox, Playwright, ...)
```

## Prerequisites

- **Windows 10/11** (64-bit) — macOS support planned for v1.1
- **Docker Desktop 25+** — must be installed and running
- **Node.js 18+** — for Electron and React development
- **Python 3.11+** — optional, for local backend development outside Docker

## Quick Start (Development)

### 1. Start the backend (Docker)

```powershell
cd docker
$env:AIHAX_REPORTS = "$env:USERPROFILE\AihaX\Reports"
$env:AIHAX_DB = "$env:USERPROFILE\AihaX\db"
$env:AIHAX_CONFIG = "$env:USERPROFILE\AihaX\config"
docker-compose up -d --build
```

Verify health: `curl http://localhost:8000/api/health`

### 2. Start the frontend

```powershell
cd frontend
npm install
npm run dev
```

Open http://localhost:3000

### 3. Start Electron (optional — full desktop experience)

```powershell
cd electron
npm install
npm run dev
```

## Project Structure

```
aihax/
├── electron/          # Electron desktop shell
├── frontend/          # React + Tailwind UI
├── backend/           # FastAPI + 9-agent pipeline
│   ├── agents/        # Recon, Auth, Vuln, Verify, Learning, Report, Remediation, Impact, BugBounty
│   ├── core/          # Config, encryption, Redis, ChromaDB
│   ├── models/        # SQLAlchemy ORM + Pydantic schemas
│   ├── routers/       # REST API endpoints
│   └── services/      # Scan orchestrator
├── docker/            # Dockerfile + docker-compose
└── templates/         # Jinja2 report templates
```

## 9-Agent Pipeline

| Agent | Name | Purpose |
|-------|------|---------|
| 1 | Recon | Subdomain discovery, port scan, tech stack detection |
| 2 | Authentication | Playwright login + 2FA handling |
| 3 | Vulnerability Testing | 15 MVP vulns (expanding to 77) |
| 4 | Verification | False positive elimination |
| 5 | Learning | Redis + ChromaDB pattern storage |
| 6 | Report Generation | WeasyPrint PDF output |
| 7 | Remediation | Claude API framework-specific fixes |
| 8 | Business Impact | Claude API risk assessment |
| 9 | Bug Bounty Export | HackerOne/Bugcrowd format (optional) |

## API Endpoints

| Method | Endpoint | Description |
|--------|----------|-------------|
| GET | `/api/health` | Health check |
| POST | `/api/scan/start` | Start new scan |
| GET | `/api/scan/{id}` | Scan status + agent states |
| DELETE | `/api/scan/{id}` | Cancel scan |
| GET | `/api/scan/history/list` | Past scans |
| GET | `/api/findings/{id}` | Get findings |
| GET | `/api/report/{id}` | Download PDF |
| POST | `/api/settings` | Save API keys |
| WS | `/ws/{id}` | Real-time updates |

## Configuration

API keys are stored encrypted at `~/AihaX/config/vault.enc` using AES-256-GCM with a machine-specific key. Configure in the Settings screen:

- **Claude API Key** — required for Agents 7 & 8 (remediation + business impact)
- **Shodan API Key** — optional, enhances recon
- **VirusTotal API Key** — optional, threat intel
- **Twilio** — required only for SMS OTP 2FA

## Reports

PDF reports are saved to `~/AihaX/Reports/{scan_id}.pdf` via Docker volume mount.

## Development Phases

| Phase | Status | Description |
|-------|--------|-------------|
| 0 | ✅ Complete | Project scaffold + Docker |
| 1 | ✅ Complete | FastAPI + Electron shell + React UI |
| 2 | 🔲 Next | Config panel validation + Auth agent hardening |
| 3–12 | 🔲 Planned | See planning documents |

## Security Notice

AihaX is a penetration testing tool. Only scan targets you own or have explicit written authorization to test. Unauthorized scanning may violate computer fraud laws.

## License

Proprietary — AihaX v1.0
