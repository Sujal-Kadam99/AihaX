# AihaX First Scan Setup Guide

## Prerequisites (install these first)

### 1. Docker Desktop (REQUIRED)
Download: https://www.docker.com/products/docker-desktop/
- Install and **start** Docker Desktop
- Wait until the whale icon shows "Running"

### 2. Node.js 18+ (REQUIRED for UI)
Download: https://nodejs.org/ (LTS version)
- Install with default options
- Restart your terminal after install
- Verify: `node --version` and `npm --version`

---

## Quick Start (3 steps)

### Step 1 — Start Backend (Docker)

Open PowerShell:

```powershell
cd "C:\Users\sujal\OneDrive\Documents\Desktop\Aihax\docker"

$env:AIHAX_REPORTS = "$env:USERPROFILE\AihaX\Reports"
$env:AIHAX_DB      = "$env:USERPROFILE\AihaX\db"
$env:AIHAX_CONFIG  = "$env:USERPROFILE\AihaX\config"

docker-compose up -d --build
```

Wait 2-5 minutes on first build. Verify:

```powershell
Invoke-RestMethod http://127.0.0.1:8000/api/health
```

Expected: `status: ok`, `redis: ok`

### Step 2 — Start Frontend

Open a **new** PowerShell window:

```powershell
cd "C:\Users\sujal\OneDrive\Documents\Desktop\Aihax\frontend"
npm install
npm run dev
```

Open: **http://localhost:3000**

### Step 3 — Run Your First Scan

1. Go to **Settings** → add your Claude API key (optional, for AI remediation)
2. Click **New Scan**
3. Enter target URL: `https://demo.testfire.net` (IBM's public demo bank app)
4. Set Depth: **Light**
5. Leave credentials empty (works without login)
6. Click **START SCAN**
7. Watch the 9-agent pipeline run live
8. When complete → **Findings** → **Download PDF**

---

## Good Test Targets (public, legal to scan)

| URL | Notes |
|-----|-------|
| `https://demo.testfire.net` | IBM demo banking app — best first target |
| `https://juice-shop.herokuapp.com` | OWASP Juice Shop (if online) |
| Your own website | Always best choice |

**Blocked automatically:** localhost, 127.0.0.1, 10.x, 192.168.x (private IPs)

---

## Security Fixes Applied

- API bound to `127.0.0.1` only (not exposed on LAN)
- Redis internal-only (no public port)
- API token auth on all endpoints (auto-fetched by frontend)
- WebSocket requires token
- Private/internal URLs blocked
- Rate limit: 5 scans per minute
- Admin panel fields wired in UI + auth agent
- Removed `--reload` from production Docker

---

## Troubleshooting

| Problem | Solution |
|---------|----------|
| `docker not recognized` | Install Docker Desktop, restart PC |
| `npm not recognized` | Install Node.js from nodejs.org, restart terminal |
| Port 8000 in use | `docker-compose down` in docker folder |
| Redis error in health | Docker not fully started — wait 30s and retry |
| Scan blocked URL error | Use a public domain, not localhost/IP |
| 401 Unauthorized | Restart frontend — it auto-fetches API token |

---

## Reports Location

`C:\Users\sujal\AihaX\Reports\{scan-id}.pdf`

## API Token Location

`C:\Users\sujal\AihaX\config\.api_token` (auto-generated, do not share)
