# AihaX Master Implementation Plan

## 1. Current Repository State
The repository has been initialized with a basic monolithic structure:
- **`backend/`**: A Python FastAPI backend with placeholders for core services (`core`, `models`, `routers`, `agents`, `services`).
- **`frontend/`**: A Vite + React frontend application with TailwindCSS and Lucide icons.
- **`electron/`**: An Electron wrapper configured for desktop distribution.
- **`db/`**: Local SQLite database storage (`aihax.db`).
- **`docker/`**: Containerization setup (`Dockerfile`, `docker-compose.yml`).
- **`templates/`**: HTML templates for reports and bugbounty exports.

## 2. Existing Code and Technologies
- **Backend**: Python, FastAPI, SQLite (local), Redis (for caching/queues), ChromaDB (for vector search). 
- **Frontend**: React, Vite, Tailwind CSS, React Router, Zod (for validation).
- **Desktop**: Electron.
- **Packaging**: PyInstaller (implied via dist folder) and Electron Builder.

## 3. Missing Infrastructure
- Complete cloud-backed Google Login integration.
- Secure, cryptographically signed offline entitlement cache system.
- Explicit, versioned Check Registry supporting 77 checks.
- AI/LLM security testing orchestration engine with strict cost/rate controls.
- Secure Update System mechanism.
- Team workspace & RBAC implementation.

## 4. Product Architecture
A desktop-first security assessment platform catering to freelancers and small security consultancies. 
Features three primary tiers:
- **Community**: Basic onboarding and assessments with usage limits.
- **Pro**: Premium capabilities, unmetered usage, custom branding.
- **Team**: Shared workspaces, role-based access, and collaborative assessments.
The differentiator is the evidence-backed verification pipeline engineered to achieve a 99% false-positive reduction, defined as a measurable precision target against a documented benchmark dataset under defined test conditions (not an absolute universal guarantee).

## 5. Technical Architecture
The architecture strictly enforces separation of concerns between local and cloud planes:
- **Local Desktop Execution**: The Electron app and bundled FastAPI backend execute scans, manage temporary evidence, and hold the local SQLite state. All scan payloads run locally.
- **Cloud Identity**: Fully cloud-backed centralized identity utilizing Google Login.
- **Cloud Billing**: Stripe integration hosted on cloud infrastructure.
- **Cloud Entitlements**: The authoritative source of truth for all plans and usage limits.
- **Secure Update Service**: Cloud-hosted distribution of verified client updates.
- **Founder Control Plane**: Cloud-hosted administrative dashboard for tenant management and system observability.

## 6. Database Architecture
- **Local Storage**: SQLite for all scan data, execution state, findings, and temporary evidence.
- **Cloud Storage (Conceptual)**: Authoritative tables for Users, Organizations, Plans, Entitlements, Stripe usage ledger, and Audit Logs.
- **Security**: Strict tenant isolation across all layers and explicit authorization rules for both local and cloud interfaces.

## 7. Authentication Architecture
- **Primary Identity**: Designed around full cloud-backed identity using Google Login via OAuth2/OIDC.
- **Exclusion**: Local authentication or basic API-key authentication is strictly prohibited as the final primary identity model.
- **Security**: IDOR protection, CSRF mitigation, and strict dependency-injected authorization checks at all API boundaries.

## 8. Entitlement Architecture
- **Cloud-Side Source of Truth**: Entitlements, plan state, and usage metrics are evaluated and managed exclusively by the cloud service.
- **Offline Grace Period**: The desktop app uses a securely signed, cached entitlement JWT/token to function during limited offline periods.
- **Enforcement**: The local client must never independently grant itself Pro, Team, or Founder privileges.

### Phase 11: Reporting (✅ Complete)
**Goal:** Generate downloadable PDF reports from Findings.

**Tasks:**
- [x] Integrate a PDF generation library (e.g., `pdfkit` or `reportlab`). (Used `WeasyPrint` & `Jinja2`)
- [x] Create `report_generator.py` in `backend/services`.
- [x] Implement PDF layout (Executive Summary, Vulnerability List, Evidence, Remediation).
- [x] Ensure frontend `Download PDF` button fetches and downloads the generated blob.

### Phase 12: Pro Entitlements (🚧 Next Up)

## 9. AI/LLM Security Testing Architecture
Dedicated architecture for executing advanced LLM-based security workflows:
- **Target Adapters**: Standardized interfaces to safely connect AI models with application targets.
- **Controlled Test Execution**: Sandboxed, deterministic execution pipelines for AI agents.
- **Evidence Collection & Verification**: Automated extraction of reproducible proof (HTTP logs, payloads) for all AI claims.
- **Rate & Cost Controls**: Hard limits on token usage, execution timeouts, and API spend per scan/tenant.
- **Credential Protection**: Secure storage and authorization boundaries to prevent exfiltration of underlying LLM provider API keys.

## 10. Scan Orchestration Architecture
- **State Machine**: Scans progress through predefined states: QUEUED, VALIDATING, RUNNING, VERIFYING, COMPLETED, FAILED, CANCELLED.
- **Queueing**: Asynchronous job queue handling retries and idempotency.
- **Audit**: Comprehensive audit events for state transitions.

## 11. Check Registry Architecture
- **Explicit Registry**: A standardized, versioned registry capable of supporting the planned 77 checks across multiple security categories.
- **Standardized Contracts**: Each check requires a Unique ID, Name, Category, Description, Execution contract, Evidence contract, and Severity mapping.
- **Rollout**: Do not implement all 77 checks in Phase 0; establish the robust registry structure first.

## 12. Verification Architecture
- **Pipeline**: Potential Finding -> Reproduction Attempt -> Independent Verification -> Counter-Hypothesis -> Evidence Evaluation -> Confidence Calculation -> Final Verdict.
- **Verdict Categories**: Verified, Potential, Likely False Positive, Inconclusive.
- **Benchmark Driven**: Relies on data-driven precision targets tested against a benchmark dataset.

### Phase 10: Findings & Evidence (✅ Complete)
**Goal:** Expose verification results (verdict, confidence, proof response) to the frontend.

**Tasks:**
- [x] Update `FindingResponse` schema in `schemas.py` to include `verdict`, `false_positive`, `proof_response`.
- [x] Expose `get_finding_detail` endpoint for full evidence retrieval.
- [x] Update frontend `Findings.jsx` table to display a Verdict column.
- [x] Update frontend `FindingDrawer.jsx` to display `proof_response` in Proof tab.

## 13. Update System Architecture
- **Update Classes**: Optional, Recommended, Required, Security-Critical.
- **Distribution**: Cryptographically verified update packages delivered by the Secure Update Service.
- **Migrations**: Safe database migrations that do not silently destroy data.
- **Policy**: Never execute unverified packages or silently downgrade.

## 14. Security & Dependency Risks
- IDOR across tenant boundaries in the Cloud Identity/Billing planes.
- SSRF via the scan engine and AI Target Adapters.
- Secrets exposure for LLM credentials and Cloud APIs.
- Usage, rate-limit, and payment webhook abuse.
- Vulnerable Node.js / Python dependencies requiring continuous monitoring.

## 15. Recommended Implementation Order
- [x] 0. Foundation
- [x] 1. Design System
- [x] 2. Authentication
- [x] 3. Database
- [x] 4. App Shell
- [x] 5. Community Experience
- [x] 6. Assessment Creation
- [x] 7. Scan Orchestration
- [x] 8. Check Registry
- [x] 9. Verification
- [x] Phase 10: Findings & Evidence UI (React + Tailwind)
- [x] Phase 11: Reporting (PDF Generation)
- [ ] Phase 12: Pro Entitlements (Freemium logic)
- [ ] 13. Stripe
- [ ] 14. Secure Update System
- [ ] 15. Cloud Integrations
- [ ] 16. Team Workspaces
- [ ] 17. Founder Control Plane
- [ ] 18. Security Testing
- [ ] 19. Beta
- [ ] 20. Release

## 16. What must NOT be built yet
- Do not invent new features outside of the documented phases.
- Do not implement the Stripe integration or Pro Entitlements until foundational phases are stable.
- Do not bypass security controls or authorization checks for convenience.
- Do not implement all 77 checks in Phase 0 (focus on the registry architecture first).
- Do not write production code until this implementation plan is approved.
