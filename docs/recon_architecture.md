# AihaX Reconnaissance Architecture

## Overview

The AihaX reconnaissance architecture enforces a strict unidirectional pipeline:

```text
Campaign
   ↓
Authorization Record
   ↓
Concrete Authorized Target
   ↓
Execution Mode Selection (AUDIT | DRY_RUN | AUTHORIZED_LIVE_RECON)
   ↓
ReconPreflightGate
   ↓
UnifiedReconOrchestrator
   ↓
┌─────────────────────────────────────────────┐
│ Authorized Recon Providers                  │
│                                             │
│ • Subdomain enumeration (Subfinder, Amass)  │
│ • Certificate Transparency (crt.sh)         │
│ • DNS resolution/enrichment (dnspython)     │
│ • HTTP/HTTPS probing (HttpProbeEngine)      │
│ • Technology fingerprinting (TechDetector)  │
│ • Endpoint/route discovery                  │
└─────────────────────────────────────────────┘
   ↓
Normalize + Deduplicate
   ↓
ScopeValidator (Discovered vs Executable)
   ↓
Attack Surface Graph
   ↓
CanonicalReconSnapshot (SHA-256 Hash)
   ↓
Vulnerability Test Selector (Applicability Gating)
   ↓
Hypothesis Generation
```

## Architectural Separation

Reconnaissance is strictly separated from vulnerability execution:

**Recon → Intelligence → Vulnerability Test Selector**

Reconnaissance never automatically attacks discovered assets. Discovered subdomains and endpoints are tagged `NOT_EXECUTABLE` by default. Any subsequent test execution requires its own authorization record, scope validation, and execution gate.
