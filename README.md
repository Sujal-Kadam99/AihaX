# AihaX

AihaX is a desktop-first application security assessment platform for authorized testing of web applications. It combines a React interface, Electron shell, and FastAPI service for managing scope, assessment campaigns, findings, evidence, and reports.

> Run assessments only against systems you own or are explicitly authorized to test. Live reconnaissance requires explicit operator confirmation, a concrete in-scope target, recorded authorization, and server-side safety checks.

## Latest updates

- Vulnerability check catalog spans C001–C086, with the canonical registry currently covering C001–C077 and additional checks available in the wider check modules.
- Expanded verification strategies, evidence capture, and false-positive controls.
- Reconnaissance pipeline improvements for discovery, parameter handling, and bounded live execution.
- Campaign persistence and lifecycle handling, signed billing entitlements, and shared team workspaces.
- Windows Electron update workflow gated on signed release artifacts and a configured HTTPS feed.

Capabilities and maturity vary by check and deployment configuration. See [the check catalog](docs/checks/README.md) and [verification model](docs/finding_verification_model.md).

## Architecture

```text
Electron desktop shell (optional)
└── React + Vite interface (localhost:3000)
    └── FastAPI backend (localhost:8000)
        ├── SQLite persistence and reports
        ├── Redis worker and event support
        ├── Reconnaissance and verification services
        └── Optional security tools and external integrations
```

The development Docker Compose stack runs the backend, Redis, and frontend. SQLite, reports, and configuration are mounted from host directories. ChromaDB is an optional backend capability, not a required service in the Compose stack.

## Requirements

- Windows 10/11 and Docker Desktop for the documented desktop/container workflow.
- Python 3.11+ for running the backend directly.
- Node.js and npm for the frontend and Electron development.
- Git and OpenSSL for release and entitlement-key workflows, when needed.

## Quick start

1. Copy `.env.example` to `.env` and set unique local values for `JWT_SECRET_KEY`, `AIHAX_MASTER_KEY`, and `AIHAX_REDIS_PASSWORD`. Do not commit `.env` or production secrets.
2. Start the backend services from the repository root:

   ```powershell
   docker compose -f docker/docker-compose.yml up --build
   ```

3. In another terminal, install and run the web interface:

   ```powershell
   cd frontend
   npm install
   npm run dev
   ```

4. Open <http://localhost:3000>. The API health endpoint is <http://127.0.0.1:8000/api/health>.

For the desktop shell, install its dependencies and start Electron:

```powershell
cd electron
npm install
npm run dev
```

Use the assessment UI to select an authorized program, enter a concrete target, validate scope, record authorization, and choose the assessment mode. Live reconnaissance has a separate confirmation and preflight workflow; read [its operator requirements](docs/recon_live_execution.md) before enabling it.

## Development

Backend dependencies are listed in `backend/requirements.txt`; frontend and Electron scripts are in their respective `package.json` files.

```powershell
# Backend tests
python -m pytest backend/tests

# Frontend tests and production build
cd frontend
npm test
npm run build

# Electron updater-policy tests
cd ../electron
npm run test:update
```

The repository also includes Ruff configuration in `pyproject.toml`. Some integration and live-target tests may require local services, tools, or explicitly authorized test targets; inspect test names and fixtures before running them.

## Configuration and deployment notes

- `.env.example` documents local and cloud settings. Use fresh secrets in each environment.
- Billing integrations require Stripe credentials and configured price IDs. Local configuration alone does not provide a hosted subscription issuer.
- Signed tier entitlements use Ed25519 keys. Keep the private signing key in the trusted issuer; desktop installations should receive only the verification key. See [signed entitlements](docs/operations/signed-entitlements.md).
- Team workspaces and role behavior are described in [team workspaces](docs/operations/team-workspaces.md).
- Windows release builds require a signing certificate, HTTPS update feed, and expected publisher configuration. See [secure updates](docs/operations/secure-updates.md).
- The Compose backend is bound to loopback. Review authentication, CORS, trusted-host, secret, persistence, and network settings before deploying beyond local development.

## Documentation

- [Live reconnaissance execution and preflight](docs/recon_live_execution.md)
- [Reconnaissance architecture and scope safety](docs/recon_architecture.md), [scope safety](docs/recon_scope_safety.md)
- [Campaign lifecycle and persistence](docs/operations/campaign-lifecycle.md), [task recovery](docs/operations/task-recovery.md)
- [Signed entitlements](docs/operations/signed-entitlements.md)
- [Team workspaces](docs/operations/team-workspaces.md)
- [Secure Windows updates](docs/operations/secure-updates.md)
- [Verification model](docs/finding_verification_model.md)

## License

No license file is currently included. All rights are reserved unless the repository owner adds a license granting other rights.
