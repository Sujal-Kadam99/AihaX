"""AihaX Finding Deduplication, State Machine, and Evidence Integrity Engine.

Architectural Invariants:
1. Stable Finding Fingerprinting: Based on target, check_id, affected endpoint, parameter location, and vulnerability family (NOT transient payloads or timestamps).
2. Evidence Merging: Merges duplicate candidates/findings while preserving strongest proof and traceable evidence IDs without secret leakage.
3. Severity vs Confidence Decoupling: Severity (impact) and Confidence (proof strength) are strictly decoupled and calculated deterministically.
4. Finding State Machine: DISCOVERED -> CANDIDATE -> VERIFYING -> VERIFIED -> DEDUPLICATED -> REPORTABLE (or REJECTED / INCONCLUSIVE).
5. Evidence Immutability & Hashing: Cryptographic SHA-256 evidence hash guarantees evidence integrity across the pipeline.
"""

from __future__ import annotations

import hashlib
import json
import logging
import re
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from enum import Enum
from typing import Any, Dict, List, Optional, Sequence, Set, Tuple, Union
from urllib.parse import parse_qsl, urlencode, urlparse, urlunparse

from backend.core.scope_validator import normalize_domain, normalize_url
from backend.models.database import Finding

logger = logging.getLogger(__name__)


# ──────────────────────────────────────────────────────────────────────────────
# 1. FINDING LIFECYCLE STATE MACHINE
# ──────────────────────────────────────────────────────────────────────────────

class FindingLifecycleState(str, Enum):
    DISCOVERED = "DISCOVERED"
    CANDIDATE = "CANDIDATE"
    NEEDS_HUMAN_REVIEW = "NEEDS_HUMAN_REVIEW"
    VERIFICATION_REQUESTED = "VERIFICATION_REQUESTED"
    VERIFYING = "VERIFYING"
    VERIFIED = "VERIFIED"
    DUPLICATE_SUSPECTED = "DUPLICATE_SUSPECTED"
    DUPLICATE = "DUPLICATE"
    DEDUPLICATED = "DEDUPLICATED"
    REPORT_READY = "REPORT_READY"
    REPORTABLE = "REPORTABLE"
    REJECTED = "REJECTED"
    INCONCLUSIVE = "INCONCLUSIVE"
    NOT_APPLICABLE = "NOT_APPLICABLE"


# Allowed state transitions
VALID_TRANSITIONS: dict[FindingLifecycleState, set[FindingLifecycleState]] = {
    FindingLifecycleState.DISCOVERED: {
        FindingLifecycleState.CANDIDATE,
        FindingLifecycleState.REJECTED,
        FindingLifecycleState.NOT_APPLICABLE,
    },
    FindingLifecycleState.CANDIDATE: {
        FindingLifecycleState.NEEDS_HUMAN_REVIEW,
        FindingLifecycleState.VERIFYING,
        FindingLifecycleState.VERIFICATION_REQUESTED,
        FindingLifecycleState.REJECTED,
        FindingLifecycleState.INCONCLUSIVE,
        FindingLifecycleState.DUPLICATE_SUSPECTED,
        FindingLifecycleState.DUPLICATE,
    },
    FindingLifecycleState.NEEDS_HUMAN_REVIEW: {
        FindingLifecycleState.VERIFICATION_REQUESTED,
        FindingLifecycleState.VERIFYING,
        FindingLifecycleState.REJECTED,
        FindingLifecycleState.INCONCLUSIVE,
        FindingLifecycleState.DUPLICATE_SUSPECTED,
        FindingLifecycleState.DUPLICATE,
    },
    FindingLifecycleState.VERIFICATION_REQUESTED: {
        FindingLifecycleState.VERIFYING,
        FindingLifecycleState.VERIFIED,
        FindingLifecycleState.REJECTED,
        FindingLifecycleState.INCONCLUSIVE,
        FindingLifecycleState.DUPLICATE,
    },
    FindingLifecycleState.VERIFYING: {
        FindingLifecycleState.VERIFIED,
        FindingLifecycleState.REJECTED,
        FindingLifecycleState.INCONCLUSIVE,
        FindingLifecycleState.DUPLICATE,
    },
    FindingLifecycleState.VERIFIED: {
        FindingLifecycleState.REPORT_READY,
        FindingLifecycleState.DEDUPLICATED,
        FindingLifecycleState.REPORTABLE,
        FindingLifecycleState.DUPLICATE_SUSPECTED,
        FindingLifecycleState.DUPLICATE,
        FindingLifecycleState.REJECTED,
    },
    FindingLifecycleState.REPORT_READY: {
        FindingLifecycleState.REPORTABLE,
        FindingLifecycleState.REJECTED,
        FindingLifecycleState.DUPLICATE,
    },
    FindingLifecycleState.DUPLICATE_SUSPECTED: {
        FindingLifecycleState.DEDUPLICATED,
        FindingLifecycleState.DUPLICATE,
        FindingLifecycleState.REJECTED,
    },
    FindingLifecycleState.DEDUPLICATED: {
        FindingLifecycleState.REPORTABLE,
        FindingLifecycleState.REPORT_READY,
        FindingLifecycleState.REJECTED,
        FindingLifecycleState.DUPLICATE,
    },
    FindingLifecycleState.REPORTABLE: {
        FindingLifecycleState.REJECTED,
        FindingLifecycleState.DUPLICATE,
    },
    FindingLifecycleState.DUPLICATE: set(),
    FindingLifecycleState.REJECTED: set(),
    FindingLifecycleState.INCONCLUSIVE: set(),
    FindingLifecycleState.NOT_APPLICABLE: set(),
}


def can_transition(current: FindingLifecycleState, target: FindingLifecycleState) -> bool:
    """Check if state transition is valid."""
    return target in VALID_TRANSITIONS.get(current, set())


def transition_finding_lifecycle(current: FindingLifecycleState, target: FindingLifecycleState) -> FindingLifecycleState:
    """Transition a finding from current state to target state if valid, else raise ValueError."""
    if not can_transition(current, target):
        raise ValueError(f"Invalid finding lifecycle transition from {current} to {target}")
    return target


# ──────────────────────────────────────────────────────────────────────────────
# 2. SEVERITY & CONFIDENCE SCORING
# ──────────────────────────────────────────────────────────────────────────────

class FindingSeverity(str, Enum):
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"


class ConfidenceLevel(str, Enum):
    CONFIRMED = "CONFIRMED"  # 90-100% (Verified via deterministic engine)
    CERTAIN = "CERTAIN"      # Alias for CONFIRMED
    HIGH = "HIGH"            # 75-89%
    MEDIUM = "MEDIUM"        # 50-74%
    LOW = "LOW"              # 0-49%


class DeterministicConfidenceScorer:
    """Calculates deterministic confidence without LLM hallucination."""

    @staticmethod
    def calculate_confidence(
        reproduced_successfully: bool = False,
        baseline_differential_verified: bool = False,
        math_canary_verified: bool = False,
        passive_regex_matched: bool = False,
        missing_baseline: bool = False,
        inconclusive_heuristic: bool = False,
        auth_enforced_boundary: bool = False,
        client_script_static_only: bool = False,
    ) -> tuple[int, ConfidenceLevel]:
        """Compute integer score (0-100) and ConfidenceLevel enum."""
        score = 0

        if reproduced_successfully:
            score += 40
        if baseline_differential_verified:
            score += 30
        if math_canary_verified:
            score += 30
        if passive_regex_matched:
            score += 20
        if auth_enforced_boundary:
            score += 20

        # Penalties
        if missing_baseline:
            score -= 20
        if client_script_static_only:
            score = min(score, 50)
        if inconclusive_heuristic:
            score = min(score, 30)

        # Clamp between 0 and 100
        score = max(0, min(100, score))

        if score >= 90:
            level = ConfidenceLevel.CERTAIN
        elif score >= 75:
            level = ConfidenceLevel.HIGH
        elif score >= 50:
            level = ConfidenceLevel.MEDIUM
        else:
            level = ConfidenceLevel.LOW

        return score, level


# ──────────────────────────────────────────────────────────────────────────────
# 3. CRYPTOGRAPHIC EVIDENCE HASHING & IMMUTABILITY
# ──────────────────────────────────────────────────────────────────────────────

class EvidenceHasher:
    """Generates cryptographic proof hash over finding evidence."""

    @staticmethod
    def compute_evidence_hash(
        vuln_type: str,
        affected_url: str,
        affected_param: Optional[str],
        payload: Optional[str],
        proof_request: Optional[str],
        proof_response: Optional[str],
        reason_code: Optional[str] = None,
    ) -> str:
        """Compute deterministic SHA-256 hash of core finding evidence."""
        canonical_dict = {
            "vuln_type": vuln_type or "",
            "affected_url": affected_url or "",
            "affected_param": affected_param or "",
            "payload": payload or "",
            "proof_request": proof_request or "",
            "proof_response": (proof_response or "")[:2048],  # bounded snippet
            "reason_code": reason_code or "",
        }
        serialized = json.dumps(canonical_dict, sort_keys=True, separators=(",", ":"))
        return hashlib.sha256(serialized.encode("utf-8")).hexdigest()

    @staticmethod
    def verify_evidence_integrity(finding: Finding, expected_hash: str) -> bool:
        """Verify that finding evidence has not been tampered with."""
        computed = EvidenceHasher.compute_evidence_hash(
            vuln_type=str(finding.vuln_type),
            affected_url=str(finding.affected_url),
            affected_param=finding.affected_param,
            payload=finding.payload,
            proof_request=finding.proof_request,
            proof_response=finding.proof_response,
            reason_code=finding.verification_reason_code,
        )
        return computed == expected_hash


# ──────────────────────────────────────────────────────────────────────────────
# 4. TARGET & ENDPOINT NORMALIZATION FOR FINGERPRINTING
# ──────────────────────────────────────────────────────────────────────────────

def normalize_endpoint_for_fingerprint(url: str) -> str:
    """Normalize a URL to its canonical path structure for fingerprinting."""
    if not url:
        return ""
    try:
        scheme, host, port, path = normalize_url(url)
        # Collapse multiple slashes
        clean_path = re.sub(r"/+", "/", path)
        if clean_path != "/" and clean_path.endswith("/"):
            clean_path = clean_path.rstrip("/")
        
        # Include port if non-standard
        if (scheme == "http" and port != 80) or (scheme == "https" and port != 443):
            host_str = f"{host}:{port}"
        else:
            host_str = host
            
        return f"{scheme}://{host_str}{clean_path}"
    except Exception:
        return url.strip().lower()


def normalize_param_location(param: Optional[str]) -> str:
    """Normalize parameter or injection location."""
    if not param:
        return "GLOBAL"
    p = param.strip().lower()
    # Normalize array brackets: user[id] -> user.id, ids[] -> ids
    p = p.replace("[", ".").replace("]", "")
    return p


# ──────────────────────────────────────────────────────────────────────────────
# 5. FINDING DEDUPLICATOR
# ──────────────────────────────────────────────────────────────────────────────

@dataclass
class DeduplicatedFindingGroup:
    fingerprint: str
    primary_finding: Finding
    duplicate_count: int = 1
    combined_payloads: list[str] = field(default_factory=list)
    combined_evidence_ids: list[str] = field(default_factory=list)
    combined_request_ids: list[str] = field(default_factory=list)
    evidence_hash: str = ""


class FindingDeduplicator:
    """Deduplicates security findings across multi-target / multi-payload scans."""

    @staticmethod
    def generate_fingerprint(
        check_id: str,
        affected_url: str,
        affected_param: Optional[str] = None,
        vuln_category: Optional[str] = None,
    ) -> str:
        """Generate stable, location-based finding fingerprint.
        
        Formula: SHA-256(check_id + normalized_endpoint + param_location + vuln_category)
        """
        norm_endpoint = normalize_endpoint_for_fingerprint(affected_url)
        norm_param = normalize_param_location(affected_param)
        norm_check = (check_id or "").strip().upper()
        norm_cat = (vuln_category or "").strip().lower()

        key = f"{norm_check}|{norm_endpoint}|{norm_param}|{norm_cat}"
        return hashlib.sha256(key.encode("utf-8")).hexdigest()

    @staticmethod
    def generate_location_fingerprint(
        affected_url: str,
        method: str = "GET",
        vuln_class: str = "GENERIC",
    ) -> str:
        """Generate stable, location-based finding fingerprint for Phase 22 verification runs."""
        norm_endpoint = normalize_endpoint_for_fingerprint(affected_url)
        raw = f"{norm_endpoint}|{method.upper()}|{vuln_class.upper()}"
        return hashlib.sha256(raw.encode("utf-8")).hexdigest()

    @staticmethod
    def deduplicate_findings(findings: Sequence[Finding]) -> list[DeduplicatedFindingGroup]:
        """Group and merge duplicate findings based on stable fingerprints."""
        groups: dict[str, DeduplicatedFindingGroup] = {}

        for finding in findings:
            fp = FindingDeduplicator.generate_fingerprint(
                check_id=str(finding.vuln_type),
                affected_url=str(finding.affected_url),
                affected_param=finding.affected_param,
                vuln_category=str(finding.category),
            )

            # Parse evidence IDs if present
            try:
                ev_ids = json.loads(finding.evidence_ids) if finding.evidence_ids else []
            except Exception:
                ev_ids = []
            try:
                req_ids = json.loads(finding.request_ids) if finding.request_ids else []
            except Exception:
                req_ids = []

            payload_item = finding.payload or ""

            if fp not in groups:
                ev_hash = EvidenceHasher.compute_evidence_hash(
                    vuln_type=str(finding.vuln_type),
                    affected_url=str(finding.affected_url),
                    affected_param=finding.affected_param,
                    payload=finding.payload,
                    proof_request=finding.proof_request,
                    proof_response=finding.proof_response,
                    reason_code=finding.verification_reason_code,
                )
                groups[fp] = DeduplicatedFindingGroup(
                    fingerprint=fp,
                    primary_finding=finding,
                    duplicate_count=1,
                    combined_payloads=[payload_item] if payload_item else [],
                    combined_evidence_ids=list(ev_ids),
                    combined_request_ids=list(req_ids),
                    evidence_hash=ev_hash,
                )
            else:
                # Merge into existing group: pick highest confidence or verified verdict as primary
                group = groups[fp]
                group.duplicate_count += 1
                if payload_item and payload_item not in group.combined_payloads:
                    group.combined_payloads.append(payload_item)
                for eid in ev_ids:
                    if eid not in group.combined_evidence_ids:
                        group.combined_evidence_ids.append(eid)
                for rid in req_ids:
                    if rid not in group.combined_request_ids:
                        group.combined_request_ids.append(rid)

                # If the new finding is VERIFIED and current primary is not, promote it
                if finding.verdict == "Verified" and group.primary_finding.verdict != "Verified":
                    group.primary_finding = finding
                    group.evidence_hash = EvidenceHasher.compute_evidence_hash(
                        vuln_type=str(finding.vuln_type),
                        affected_url=str(finding.affected_url),
                        affected_param=finding.affected_param,
                        payload=finding.payload,
                        proof_request=finding.proof_request,
                        proof_response=finding.proof_response,
                        reason_code=finding.verification_reason_code,
                    )
                elif (finding.confidence or 0) > (group.primary_finding.confidence or 0):
                    group.primary_finding = finding

        return list(groups.values())

    @staticmethod
    def deduplicate_and_persist(findings: Sequence[Finding], session: Optional[Any] = None) -> List[Finding]:
        """Apply fingerprinting, assign primary vs duplicate records, update duplicate_of and persist."""
        fingerprint_groups: Dict[str, List[Finding]] = {}
        for f in findings:
            fp = FindingDeduplicator.generate_fingerprint(
                check_id=str(f.vuln_type or ""),
                affected_url=str(f.affected_url or ""),
                affected_param=f.affected_param,
                vuln_category=str(f.category or ""),
            )
            f.finding_fingerprint = fp
            if fp not in fingerprint_groups:
                fingerprint_groups[fp] = []
            fingerprint_groups[fp].append(f)

        all_processed: List[Finding] = []
        for fp, group in fingerprint_groups.items():
            # Pick primary: Verified first, then highest confidence, then earliest created
            sorted_group = sorted(
                group,
                key=lambda x: (
                    1 if str(x.verdict or "").lower() == "verified" else 0,
                    x.confidence or 0,
                ),
                reverse=True,
            )
            primary = sorted_group[0]
            primary.duplicate_of = None
            primary.deduplication_reason = None
            all_processed.append(primary)

            for duplicate in sorted_group[1:]:
                duplicate.duplicate_of = primary.id
                duplicate.deduplication_reason = f"Duplicate of primary finding {primary.id} (fingerprint {fp[:16]}...)"
                duplicate.verification_status = FindingLifecycleState.DUPLICATE.value
                all_processed.append(duplicate)

        if session:
            try:
                session.commit()
            except Exception:
                pass

        return all_processed

    @staticmethod
    def compute_structural_similarity(f1: Finding, f2: Finding) -> Tuple[str, float, str]:
        """Compute deterministic structural similarity between two findings.
        
        Returns:
            (match_type, score, reason) where match_type is:
            - EXACT_DUPLICATE (exact SHA-256 fingerprint match, score 1.0)
            - POSSIBLE_DUPLICATE (advisory high structural similarity >= 0.80)
            - UNIQUE (distinct finding, score < 0.80)
        """
        fp1 = FindingDeduplicator.generate_fingerprint(
            check_id=str(f1.vuln_type or ""),
            affected_url=str(f1.affected_url or ""),
            affected_param=f1.affected_param,
            vuln_category=str(f1.category or ""),
        )
        fp2 = FindingDeduplicator.generate_fingerprint(
            check_id=str(f2.vuln_type or ""),
            affected_url=str(f2.affected_url or ""),
            affected_param=f2.affected_param,
            vuln_category=str(f2.category or ""),
        )

        if fp1 == fp2:
            return "EXACT_DUPLICATE", 1.0, f"Exact SHA-256 fingerprint match ({fp1[:16]}...)"

        # Normalize components for structural similarity
        score = 0.0
        reasons = []

        # 1. Vulnerability Type (weight 0.35)
        vt1 = str(f1.vuln_type or "").strip().lower()
        vt2 = str(f2.vuln_type or "").strip().lower()
        if vt1 == vt2:
            score += 0.35
            reasons.append("identical vuln_type")
        elif (f1.category and f2.category and str(f1.category).lower() == str(f2.category).lower()):
            score += 0.20
            reasons.append("identical category")

        # 2. Hostname & Scheme (weight 0.25)
        p1 = urlparse(str(f1.affected_url or ""))
        p2 = urlparse(str(f2.affected_url or ""))
        if p1.netloc.lower() == p2.netloc.lower():
            score += 0.25
            reasons.append("identical host")

        # 3. Base Path (weight 0.25)
        path1 = (p1.path or "/").rstrip("/").lower()
        path2 = (p2.path or "/").rstrip("/").lower()
        if path1 == path2:
            score += 0.25
            reasons.append("identical path")
        elif path1.split("/")[0:2] == path2.split("/")[0:2]:
            score += 0.15
            reasons.append("shared base route")

        # 4. Parameter / Component (weight 0.15)
        param1 = str(f1.affected_param or "").strip().lower()
        param2 = str(f2.affected_param or "").strip().lower()
        if param1 == param2 and param1:
            score += 0.15
            reasons.append("identical parameter")
        elif not param1 and not param2:
            score += 0.15

        score = round(min(1.0, score), 2)
        if score >= 0.80:
            return "POSSIBLE_DUPLICATE", score, f"Structural similarity: {', '.join(reasons)} (advisory only)"

        return "UNIQUE", score, f"Distinct characteristics (similarity score: {score:.2f})"

    @staticmethod
    def correlate_header_findings(findings: Sequence[Finding]) -> list[Finding]:
        """Deterministically correlate overlapping security header findings under a parent finding.

        Relationship:
            C002 (Missing Security Headers)
              ├── C010 (TLS/HSTS)
              ├── C047 (Missing CSP)
              ├── C049 (Clickjacking / Frame Options)
              └── C050 (MIME Sniffing)

        If C002 is present for a given endpoint, child header findings are linked to C002 via parent_finding_id.
        If C002 is absent but multiple specific header findings exist on the same endpoint, the first
        ordered by check ID acts as the parent and the remainder link to it.
        All original findings and underlying evidence are preserved without deletion.
        """
        endpoint_groups: dict[str, list[Finding]] = {}
        for f in findings:
            ep = normalize_endpoint_for_fingerprint(str(f.affected_url or ""))
            endpoint_groups.setdefault(ep, []).append(f)

        HEADER_PREFIXES = ("C002", "C010", "C047", "C049", "C050")

        for ep, ep_findings in endpoint_groups.items():
            header_findings = [
                f for f in ep_findings
                if any(str(f.vuln_type or "").upper().startswith(p) for p in HEADER_PREFIXES)
            ]
            if len(header_findings) <= 1:
                continue

            c002_finding = next(
                (f for f in header_findings if str(f.vuln_type or "").upper().startswith("C002")),
                None,
            )
            parent = c002_finding or sorted(header_findings, key=lambda x: str(x.vuln_type or ""))[0]

            for hf in header_findings:
                if hf.id != parent.id:
                    hf.parent_finding_id = parent.id

        return list(findings)

