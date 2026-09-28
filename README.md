# AihaX

AI-powered application security testing and verification platform for web apps, APIs, and exposed attack surfaces.

AihaX combines reconnaissance, deterministic vulnerability checks, verification strategies, and reporting into a single security workflow designed for real-world testing with strong guardrails and false-positive controls.

## Latest updates

The project has recently expanded from a basic prototype into a production-style security engine with:

- 77 deterministic vulnerability checks across 7 OWASP-aligned categories
- batch verification coverage for C/D class checks, including C078-C086 and expanded hypothesis logic
- 30 verification strategies for reducing false positives and validating real exploitation paths
- stronger recon capabilities with app/API wordlists, Katana crawling support, and live recon mode
- hardened execution pipeline with safer tool resolution, allow_loopback handling, and report fallbacks
- repository cleanup to remove large binaries and reduce noisy artifacts

## Core capabilities

### Deterministic security checks
AihaX includes a full catalog of production checks covering:

- recon and asset exposure
- authentication and session weaknesses
- injection and parser issues
- XSS and client-side abuse
- configuration and hardening gaps
- data exposure and sensitive file leakage
- business logic and access-control flaws

The implementation is documented in `docs/checks/README.md` and the check catalog under `docs/checks/`.

### Verification engine
Each candidate issue is passed through a multi-layer verification pipeline designed to reject generic HTTP errors and weak signals. This includes:

- deterministic exploit and validation probes
- differential analysis against expected safe behavior
- evidence capture for verified findings
- false-positive controls based on status codes, headers, and response signatures

### Recon and live testing
Recent updates include:

- app/API wordlist expansion for broader discovery
- Katana crawler integration for deeper surface mapping
- project-local tool resolution for internal binaries and support utilities
- live recon mode and safer pass-through execution

## Architecture

```text
Target / Asset
  -> Scope validation and request budget controls
  -> Request engine / transport layer
  -> Recon and discovery agents
  -> Deterministic vulnerability checks
  -> Verification and differential validation
  -> Evidence capture and report generation
```

## Repository structure

```text
AihaX/
├── backend/              # API and scanning orchestration
├── docker/                # container setup and runtime config
├── docs/                  # security check catalog and implementation docs
├── electron/              # desktop shell (if present in your checkout)
├── frontend/              # UI and dashboard
├── bin/                   # bundled tool dependencies and helper binaries
├── templates/             # report templates
├── wordlists/             # target discovery and recon wordlists
├── README.md              # project overview
├── .gitignore             # local/runtime exclusions
├── requirements*.txt      # Python dependencies
├── package*.json          # frontend/electron dependencies
└── ...
```

## Quick start

### Docker backend

```powershell
cd docker
$env:AIHAX_REPORTS = "$env:USERPROFILE\AihaX\Reports"
$env:AIHAX_DB = "$env:USERPROFILE\AihaX\db"
$env:AIHAX_CONFIG = "$env:USERPROFILE\AihaX\config"
docker-compose up -d --build
```

Verify health:

```bash
curl http://localhost:8000/api/health
```

### Frontend

```powershell
cd frontend
npm install
npm run dev
```

Open the app at http://localhost:3000

### Optional desktop app

```powershell
cd electron
npm install
npm run dev
```

## Security and governance

AihaX is designed for authorized security testing only. Every scan should be scoped to assets you own or explicitly have permission to assess.

## Recent feature highlights

- Batch C/D checks and broader coverage for exploit verification
- real-target validation and safeguard logic for high-risk checks
- recon pipeline hardening and safer tool execution
- removal of large tracked binaries to keep the repository lighter and cleaner
- improved detection coverage for default credentials, directory listings, verbose errors, and transport issues

## Notes

The repository has been actively evolving with a strong emphasis on deterministic verification and reducing false positives in real-world web and API assessments.

## License

Proprietary project license (see repository policy and any included licensing files for details).
