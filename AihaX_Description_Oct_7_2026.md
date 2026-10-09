# AihaX — Project Description & Status Update

> **Date:** October 7, 2026
> **"Enter URL. Click Start. Get a Professional Pentest Report."**

## 🧠 What Is AihaX?

AihaX is a **fully autonomous, AI-powered penetration testing platform** for web applications. It replaces the manual effort of a security researcher by running a coordinated pipeline of specialized AI agents — from the moment a URL is entered to the moment a polished PDF report lands on your desk — with **zero manual intervention in between**.

It is built for **Windows-first deployment** as a **desktop Electron application**, backed by a containerized FastAPI brain.

---

## 🏗️ Architecture Overview

```text
┌─────────────────────────────────────────────────────────┐
│                   User's Desktop                        │
│  ┌──────────────────────┐   ┌──────────────────────┐   │
│  │  Electron Shell      │──▶│  React UI (Vite)     │   │
│  │  (native app frame)  │   │  localhost:3000      │   │
│  └──────────────────────┘   └──────────────────────┘   │
│                    │                                     │
│  ┌─────────────────▼────────────────────────────────┐  │
│  │              Docker Container                    │  │
│  │  ┌──────────────┐  ┌────────┐  ┌─────────────┐  │  │
│  │  │  FastAPI     │  │ Redis  │  │  ChromaDB   │  │  │
│  │  │  (port 8000) │  │ pub/sub│  │  (vectors)  │  │  │
│  │  └──────────────┘  └────────┘  └─────────────┘  │  │
│  │  ┌──────────────┐  ┌──────────────────────────┐  │  │
│  │  │  SQLite DB   │  │ Pentest Tools: Nmap,     │  │  │
│  │  │  (history)   │  │ SQLMap, Nuclei, Dalfox,  │  │  │
│  │  └──────────────┘  │ Playwright, Gobuster...  │  │  │
│  │                    └──────────────────────────┘  │  │
│  └──────────────────────────────────────────────────┘  │
└─────────────────────────────────────────────────────────┘
```

### Technology Stack

| Layer | Technology |
|---|---|
| **Desktop shell** | Electron |
| **Frontend** | React + Vite + Tailwind CSS |
| **Backend** | Python 3.11 + FastAPI |
| **Real-time comms** | WebSockets + Redis pub/sub |
| **Long-term memory** | ChromaDB (vector embeddings) |
| **Scan history** | SQLite (via SQLAlchemy ORM) |
| **Containerization** | Docker + docker-compose |
| **Report output** | WeasyPrint PDF (Jinja2 templates) |
| **AI/LLM** | Claude API (remediation + risk) |
| **Secrets** | AES-256-GCM encrypted vault |

---

## 🤖 The Complete AI Agent Pipeline

AihaX utilizes a sequential and parallel pipeline of 11 distinct autonomous agents (9 primary workflow agents + 2 specialized guards), each excelling in one phase of a real pentest:

1. **Recon Agent:** Nmap port scan, subdomain discovery, Shodan/VirusTotal enrichment.
2. **Auth Agent:** Playwright-driven login automation, 2FA handling (TOTP + SMS via Twilio), cookie management.
3. **Vulnerability Testing Agent:** Executes vulnerability checks, parameter discovery, and attack surface mapping.
4. **Exploit Chain Agent:** Analyzes isolated weaknesses and chains them together into high-impact attacks.
5. **Verify Agent:** Multi-strategy false-positive elimination, adversarial judge, reproducibility scoring.
6. **Learning Agent:** Stores patterns in Redis and ChromaDB, improving future scan accuracy.
7. **Report Agent:** WeasyPrint PDF report generation, structuring findings with severity and proofs-of-concept.
8. **Remediation Agent:** Claude API generates framework-specific code fixes (Express, Django, Spring, etc.).
9. **Impact Agent:** Claude API performs business risk assessments, CVSS scoring, and financial impact estimations.
10. **Bug Bounty Agent:** Exports findings in HackerOne / Bugcrowd-ready formats.
11. **Scope Agent:** Enforces scan boundaries and blocks out-of-scope targets (crucial safety guardrail).

---

## 🔍 86 Vulnerability Checks (c001–c086)

AihaX features exactly **86 individual, independently-testable vulnerability check modules** covering the full OWASP Top 10 and beyond. These have all been fully implemented in `backend/agents/checks/`.

*   **Injection:** SQLi, NoSQL, OS Command, SSTI, CRLF, LDAP, EL injection.
*   **XSS (8 variants):** Reflected, Stored, DOM, Context-specific, Mutation XSS, Filter bypass.
*   **Authentication & Access Control:** Auth bypass, JWT weaknesses, IDOR, BOLA/API, Mass Assignment, Privilege Escalation.
*   **Advanced:** HTTP request smuggling, Web cache poisoning, Race conditions, SSRF, XXE, Cross-site WebSocket hijacking.
*   **Cloud & Infra:** Open ports, TLS config, Cloud bucket exposure, Exposed API keys, Git metadata exposure.

---

## 🚀 STATUS UPDATE (As of October 7, 2026)

**Overall Status:** Advanced Production Execution / Live Readiness
**Implementation:** The physical codebase is completely synchronized with architectural ambitions. 

### Recent Milestones Reached
1. **100% Agent Implementation:** All 9 core agents + 2 specialized agents are fully fleshed out and communicating within the backend.
2. **Full OWASP Surface Coverage:** Exactly 86 vulnerability checks (`c001` through `c086`) have been successfully implemented.
3. **Services & Execution Engine:** The complex backend services directory sits at 48 core modules, successfully bringing online the `verification_engine.py`, `campaign_operations.py`, and `false_positive_gate.py`.

### Current Focus: Phase 27 - Certification & Tool Provisioning
We are actively working on **Phase 27**, ensuring live-fire readiness and hardening the system's external toolsets.
*   **Test Coverage Expansion:** We have expanded testing to **95 test files** (up from the original 92), indicating heavy validation is underway.
*   **Live Tool Provisioning:** Actively integrating external OS-level tooling into the Docker architecture (e.g., configuring `install-tools.sh` for things like Nmap, Nuclei, Sqlmap).
*   **Certification Hardening:** Current efforts on `test_phase27_certification_hardening.py` confirm the system is undergoing rigorous security and execution boundary checks before final deployment.

AihaX has evolved from MVP to a fully realized, weaponized, and autonomous pentesting platform equipped with industry-leading false positive mitigation.
