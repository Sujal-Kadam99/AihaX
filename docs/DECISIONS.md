# Architecture Decisions Log

## 1. Architectural Separation of Planes
- **Decision**: Strictly separate the system into distinct operational planes: Local Desktop Execution, Cloud Identity, Cloud Billing, Cloud Entitlements, Secure Update Service, and Founder Control Plane.
- **Rationale**: Prevents conflation of sensitive local scan data with cloud-based business logic, ensuring robust privacy while maintaining centralized business controls.
- **Impact**: Requires explicit API boundaries and well-defined contracts between the local Electron client and cloud services.

## 2. Authentication: Google Login
- **Decision**: Authentication must be designed around full cloud-backed identity with Google Login (OAuth2/OIDC). Local authentication or API-key authentication will not be used as the final primary identity model.
- **Rationale**: Provides robust, centralized security, reduces credential management overhead, and ensures identity consistency across cloud billing and entitlement planes.
- **Impact**: All local execution flows requiring user context must validate against a secure cloud session or token.

## 3. Server-Side Entitlements with Cached Grace Period
- **Decision**: Entitlements must have a single authoritative cloud-side source of truth. The local client must never independently grant itself Pro, Team, or Founder privileges. The desktop app will utilize a securely signed cached entitlement for offline grace periods.
- **Rationale**: Prevents bypass of community usage limits or premium features via local tampering.
- **Impact**: Requires atomic usage decrements, strict synchronization logic, and robust JWT/signature validation in the local application.

## 4. Evidence-Backed Verification & Precision Targets
- **Decision**: The 99% false-positive objective is defined as a measurable precision target on a documented benchmark dataset under defined test conditions, rather than an absolute universal guarantee.
- **Rationale**: Sets realistic, mathematically verifiable engineering goals without making unsupported marketing claims.
- **Impact**: The scan orchestrator and verification pipeline must output metrics that can be scored against benchmark datasets.

## 5. Versioned Check Registry
- **Decision**: Implement an explicit, versioned Check Registry architecture capable of supporting the planned 77 checks across security categories.
- **Rationale**: Ensures standard contracts (execution, evidence, severity) and backward compatibility for scan results over time.
- **Impact**: Must establish the registry structure in early phases without actually implementing all 77 checks in Phase 0.

## 6. AI/LLM Security Testing Architecture
- **Decision**: Add a dedicated architecture for LLM testing featuring target adapters, controlled test execution, evidence collection, verification, rate/cost controls, authorization boundaries, and provider credential protection.
- **Rationale**: Safely orchestrates non-deterministic AI security agents without risking infinite loops, extreme API costs, or credential exfiltration.
- **Impact**: Significant architectural investment in sandboxing, timeout enforcement, and cost-metering before enabling AI features.

## 7. Security Architecture
- **Decision**: Implementation of explicit authorization logic and tenant boundaries over assumed trust, avoiding any reliance on frontend routing for protection.
- **Rationale**: Eliminates classes of IDOR, Privilege Escalation, and SSRF.
- **Impact**: Core agents and routing layers must authenticate every single state-modifying action and query.
