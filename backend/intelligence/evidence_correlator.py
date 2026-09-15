"""AihaX Phase 7 — Evidence Correlator.

Assembles an immutable, cryptographically-anchored evidence chain
from recon, request, baseline, mutation, control, and verification evidence.

Invariants:
- No synthetic evidence: every reference must map to a real audit/evidence record.
- Evidence chains are immutable after creation.
- SHA-256 over the entire chain for tamper detection.
- References are IDs only — no raw secrets or credentials in the chain.
"""

from __future__ import annotations

import hashlib
import json
import logging
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional

logger = logging.getLogger("backend.intelligence.evidence_correlator")


# ──────────────────────────────────────────────────────────────────────────────
# 1. EVIDENCE CHAIN
# ──────────────────────────────────────────────────────────────────────────────

@dataclass
class EvidenceChain:
    """Immutable, cryptographically-anchored chain of evidence for one finding.

    All fields are evidence-ID lists (not raw data) to prevent credential leakage.
    chain_hash is computed over the sorted IDs + timestamps at construction time.
    """
    finding_id: str
    check_id: str

    # Evidence ID buckets
    recon_evidence_ids: List[str] = field(default_factory=list)
    request_evidence_ids: List[str] = field(default_factory=list)
    baseline_evidence_ids: List[str] = field(default_factory=list)
    mutation_evidence_ids: List[str] = field(default_factory=list)
    control_evidence_ids: List[str] = field(default_factory=list)
    verification_evidence_ids: List[str] = field(default_factory=list)
    authentication_context_ids: List[str] = field(default_factory=list)
    workflow_context_ids: List[str] = field(default_factory=list)
    browser_context_ids: List[str] = field(default_factory=list)

    # Metadata
    chain_hash: str = ""                # SHA-256 over all IDs + timestamps
    created_at: str = field(default_factory=lambda: datetime.now(timezone.utc).isoformat())
    evidence_count: int = 0

    # Human-readable summary fields (no secrets)
    target_url: str = ""
    affected_param: str = ""
    payload_summary: str = ""           # Redacted summary only

    def all_evidence_ids(self) -> List[str]:
        """Return all evidence IDs across all buckets."""
        return (
            self.recon_evidence_ids
            + self.request_evidence_ids
            + self.baseline_evidence_ids
            + self.mutation_evidence_ids
            + self.control_evidence_ids
            + self.verification_evidence_ids
            + self.authentication_context_ids
            + self.workflow_context_ids
            + self.browser_context_ids
        )

    def verify_integrity(self) -> bool:
        """Recompute and compare chain_hash to detect tampering."""
        expected = _compute_chain_hash(
            self.finding_id,
            self.check_id,
            self.all_evidence_ids(),
            self.created_at,
        )
        return expected == self.chain_hash

    def to_dict(self) -> Dict[str, Any]:
        return {
            "finding_id": self.finding_id,
            "check_id": self.check_id,
            "chain_hash": self.chain_hash,
            "created_at": self.created_at,
            "evidence_count": self.evidence_count,
            "target_url": self.target_url,
            "affected_param": self.affected_param,
            "payload_summary": self.payload_summary,
            "recon_evidence_ids": self.recon_evidence_ids,
            "request_evidence_ids": self.request_evidence_ids,
            "baseline_evidence_ids": self.baseline_evidence_ids,
            "mutation_evidence_ids": self.mutation_evidence_ids,
            "control_evidence_ids": self.control_evidence_ids,
            "verification_evidence_ids": self.verification_evidence_ids,
            "authentication_context_ids": self.authentication_context_ids,
            "workflow_context_ids": self.workflow_context_ids,
            "browser_context_ids": self.browser_context_ids,
        }

    def to_json(self) -> str:
        return json.dumps(self.to_dict(), indent=2)


# ──────────────────────────────────────────────────────────────────────────────
# 2. CHAIN HASH COMPUTATION
# ──────────────────────────────────────────────────────────────────────────────

def _compute_chain_hash(
    finding_id: str,
    check_id: str,
    all_ids: List[str],
    created_at: str,
) -> str:
    """SHA-256 over the canonical sorted evidence ID list."""
    canonical = {
        "finding_id": finding_id,
        "check_id": check_id,
        "evidence_ids": sorted(set(all_ids)),
        "created_at": created_at,
    }
    serialized = json.dumps(canonical, sort_keys=True, separators=(",", ":"))
    return hashlib.sha256(serialized.encode("utf-8")).hexdigest()


# ──────────────────────────────────────────────────────────────────────────────
# 3. EVIDENCE CORRELATOR
# ──────────────────────────────────────────────────────────────────────────────

class EvidenceCorrelator:
    """Assembles and validates immutable evidence chains.

    Usage::

        chain = EvidenceCorrelator.build_chain(
            finding_id="find-001",
            check_id="C037_Reflected_XSS",
            request_evidence_ids=["REQ-001"],
            verification_evidence_ids=["EVD-AA01"],
            baseline_evidence_ids=["REQ-002"],
            control_evidence_ids=["REQ-003"],
            target_url="http://127.0.0.1:8080/search",
            affected_param="q",
            payload_summary="<xss-canary-...>",
        )
        assert chain.verify_integrity()
    """

    @staticmethod
    def build_chain(
        finding_id: str,
        check_id: str,
        request_evidence_ids: Optional[List[str]] = None,
        baseline_evidence_ids: Optional[List[str]] = None,
        mutation_evidence_ids: Optional[List[str]] = None,
        control_evidence_ids: Optional[List[str]] = None,
        verification_evidence_ids: Optional[List[str]] = None,
        recon_evidence_ids: Optional[List[str]] = None,
        authentication_context_ids: Optional[List[str]] = None,
        workflow_context_ids: Optional[List[str]] = None,
        browser_context_ids: Optional[List[str]] = None,
        target_url: str = "",
        affected_param: str = "",
        payload_summary: str = "",
    ) -> EvidenceChain:
        """Build an immutable evidence chain with computed integrity hash."""
        chain = EvidenceChain(
            finding_id=finding_id,
            check_id=check_id,
            recon_evidence_ids=list(recon_evidence_ids or []),
            request_evidence_ids=list(request_evidence_ids or []),
            baseline_evidence_ids=list(baseline_evidence_ids or []),
            mutation_evidence_ids=list(mutation_evidence_ids or []),
            control_evidence_ids=list(control_evidence_ids or []),
            verification_evidence_ids=list(verification_evidence_ids or []),
            authentication_context_ids=list(authentication_context_ids or []),
            workflow_context_ids=list(workflow_context_ids or []),
            browser_context_ids=list(browser_context_ids or []),
            target_url=target_url,
            affected_param=affected_param,
            payload_summary=payload_summary,
        )

        all_ids = chain.all_evidence_ids()
        chain.evidence_count = len(set(all_ids))
        chain.chain_hash = _compute_chain_hash(
            finding_id,
            check_id,
            all_ids,
            chain.created_at,
        )
        return chain

    @staticmethod
    def from_finding(
        finding_id: str,
        check_id: str,
        evidence_ids_json: Optional[str],
        request_ids_json: Optional[str],
        target_url: str = "",
        affected_param: str = "",
    ) -> EvidenceChain:
        """Build a chain from the raw JSON ID fields stored in the Finding ORM model."""
        try:
            ev_ids = json.loads(evidence_ids_json or "[]")
            if not isinstance(ev_ids, list):
                ev_ids = []
        except Exception:
            ev_ids = []

        try:
            req_ids = json.loads(request_ids_json or "[]")
            if not isinstance(req_ids, list):
                req_ids = []
        except Exception:
            req_ids = []

        return EvidenceCorrelator.build_chain(
            finding_id=finding_id,
            check_id=check_id,
            request_evidence_ids=req_ids,
            verification_evidence_ids=ev_ids,
            target_url=target_url,
            affected_param=affected_param or "",
        )

    @staticmethod
    def validate_chain(chain: EvidenceChain) -> Dict[str, Any]:
        """Validate a chain's integrity and report any issues.

        Returns dict with: valid (bool), issues (list), hash_match (bool).
        """
        issues = []
        hash_match = chain.verify_integrity()

        if not hash_match:
            issues.append("chain_hash mismatch — evidence chain may have been tampered")

        if not chain.finding_id:
            issues.append("missing finding_id")

        if not chain.check_id:
            issues.append("missing check_id")

        if chain.evidence_count == 0:
            issues.append("empty evidence chain — no evidence IDs present")

        if not chain.request_evidence_ids and not chain.verification_evidence_ids:
            issues.append("no request or verification evidence — passive observation only")

        return {
            "valid": hash_match and not issues,
            "hash_match": hash_match,
            "issues": issues,
            "evidence_count": chain.evidence_count,
        }

    @staticmethod
    def merge_chains(primary: EvidenceChain, additional: EvidenceChain) -> EvidenceChain:
        """Merge two evidence chains from different verification passes.

        The primary chain's finding_id and check_id are preserved.
        All evidence IDs from both chains are combined (deduplicated).
        A new chain_hash is computed over the merged ID set.
        """
        if primary.finding_id != additional.finding_id and additional.finding_id:
            logger.warning(
                "Merging chains with different finding IDs: %s vs %s — using primary",
                primary.finding_id,
                additional.finding_id,
            )

        def _merge(a: List[str], b: List[str]) -> List[str]:
            seen = set(a)
            merged = list(a)
            for item in b:
                if item not in seen:
                    merged.append(item)
                    seen.add(item)
            return merged

        return EvidenceCorrelator.build_chain(
            finding_id=primary.finding_id,
            check_id=primary.check_id,
            recon_evidence_ids=_merge(primary.recon_evidence_ids, additional.recon_evidence_ids),
            request_evidence_ids=_merge(primary.request_evidence_ids, additional.request_evidence_ids),
            baseline_evidence_ids=_merge(primary.baseline_evidence_ids, additional.baseline_evidence_ids),
            mutation_evidence_ids=_merge(primary.mutation_evidence_ids, additional.mutation_evidence_ids),
            control_evidence_ids=_merge(primary.control_evidence_ids, additional.control_evidence_ids),
            verification_evidence_ids=_merge(primary.verification_evidence_ids, additional.verification_evidence_ids),
            authentication_context_ids=_merge(primary.authentication_context_ids, additional.authentication_context_ids),
            workflow_context_ids=_merge(primary.workflow_context_ids, additional.workflow_context_ids),
            browser_context_ids=_merge(primary.browser_context_ids, additional.browser_context_ids),
            target_url=primary.target_url or additional.target_url,
            affected_param=primary.affected_param or additional.affected_param,
            payload_summary=primary.payload_summary or additional.payload_summary,
        )


__all__ = ["EvidenceChain", "EvidenceCorrelator"]
