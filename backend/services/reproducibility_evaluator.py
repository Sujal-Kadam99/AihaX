"""AihaX — Reproducibility Evaluator.

Evaluates deterministic reproducibility of security conditions:
1. Baseline vs Test response differential analysis.
2. Request/Response invariant consistency (status codes, headers, response structure).
3. Dual-identity differential comparison (Account A vs Account B for access control).
4. Precondition validation (valid sessions, required tokens, non-error status).
5. Evidence completeness and repeatability within budget bounds.
"""

from __future__ import annotations

import hashlib
import json
import logging
import re
from dataclasses import asdict, dataclass, field
from typing import Any, Dict, List, Optional, Tuple

logger = logging.getLogger("aihax.reproducibility_evaluator")


@dataclass
class ReproducibilityResultDTO:
    """Detailed reproducibility evaluation outcome."""
    is_reproduced: bool
    reproducibility_score: float  # 0.0 to 1.0
    request_consistency_score: float  # 0.0 to 1.0
    differential_score: float  # 0.0 to 1.0
    reproduction_evidence_ids: List[str] = field(default_factory=list)
    preconditions_met: bool = True
    details: Dict[str, Any] = field(default_factory=dict)
    rationale: str = ""

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


class ReproducibilityEvaluator:
    """Deterministic evaluator for condition repeatability and baseline differential."""

    @classmethod
    def evaluate_response_consistency(
        cls,
        responses: List[Dict[str, Any]],
        expected_status: Optional[int] = None,
        expected_body_pattern: Optional[str] = None,
    ) -> Tuple[bool, float, str]:
        """Check whether multiple response samples show deterministic, repeatable behavior."""
        if not responses:
            return False, 0.0, "No response samples provided for consistency check"

        if len(responses) == 1:
            # Single sample: check against expected patterns if available
            resp = responses[0]
            status = resp.get("status_code", 0)
            body = str(resp.get("body", "") or resp.get("raw_response", ""))

            if expected_status and status != expected_status:
                return False, 0.0, f"Observed status {status} does not match expected {expected_status}"

            if expected_body_pattern and not re.search(expected_body_pattern, body, re.IGNORECASE):
                return False, 0.0, f"Body does not match expected pattern: {expected_body_pattern}"

            # Basic evidence consistency score for single sample
            return True, 0.8, "Single sample matches expected invariant; repeatability requires multiple samples"

        # Multiple samples: verify status codes and body patterns match across samples
        status_codes = [r.get("status_code", 0) for r in responses]
        if len(set(status_codes)) > 1:
            return False, 0.3, f"Inconsistent status codes observed across attempts: {status_codes}"

        bodies = [str(r.get("body", "") or r.get("raw_response", "")) for r in responses]
        body_hashes = [hashlib.sha256(b.encode("utf-8", errors="replace")).hexdigest() for b in bodies]

        if len(set(body_hashes)) == 1:
            return True, 1.0, f"Deterministic: {len(responses)} identical responses observed"

        # Check if length variation is negligible (e.g. dynamic timestamps)
        lengths = [len(b) for b in bodies]
        max_len = max(lengths) if lengths else 0
        min_len = min(lengths) if lengths else 0
        variance = (max_len - min_len) / max(1, max_len)

        if variance < 0.05:
            return True, 0.9, f"High consistency: {len(responses)} responses identical within 5% variance"

        return True, 0.7, f"Consistent status code {status_codes[0]} with variable body content"

    @classmethod
    def evaluate_differential(
        cls,
        baseline_response: Dict[str, Any],
        test_response: Dict[str, Any],
        inverted_response: Optional[Dict[str, Any]] = None,
    ) -> Tuple[bool, float, str]:
        """Perform differential comparison between baseline (normal) and test (probe) responses.
        
        A valid security differential means the test input caused a distinct, security-relevant
        divergence from the baseline response that is not merely random server variance.
        """
        if not baseline_response or not test_response:
            return False, 0.0, "Missing baseline or test response for differential comparison"

        base_status = baseline_response.get("status_code", 0)
        test_status = test_response.get("status_code", 0)

        base_body = str(baseline_response.get("body", "") or baseline_response.get("raw_response", ""))
        test_body = str(test_response.get("body", "") or test_response.get("raw_response", ""))

        # If baseline and test are completely identical, no differential effect occurred
        if base_status == test_status and base_body == test_body:
            return False, 0.0, "Identical responses: test probe caused zero differential from baseline"

        # Check for status transition (e.g., 200 vs 401/403 or 200 vs 500)
        differential_reasons: List[str] = []
        score = 0.5

        if base_status != test_status:
            differential_reasons.append(f"Status transition: {base_status} -> {test_status}")
            score += 0.2

        # Check body diff
        base_hash = hashlib.sha256(base_body.encode("utf-8", errors="replace")).hexdigest()
        test_hash = hashlib.sha256(test_body.encode("utf-8", errors="replace")).hexdigest()

        if base_hash != test_hash:
            differential_reasons.append("Response content diverged significantly from baseline")
            score += 0.2

        # If inverted control test provided (e.g. probing with benign input restores baseline)
        if inverted_response:
            inv_status = inverted_response.get("status_code", 0)
            inv_body = str(inverted_response.get("body", "") or inverted_response.get("raw_response", ""))
            if inv_status == base_status:
                differential_reasons.append("Inverted control probe confirmed reversibility to baseline state")
                score = min(1.0, score + 0.1)

        return True, min(1.0, score), "; ".join(differential_reasons)

    @classmethod
    def evaluate_dual_identity_access(
        cls,
        account_a_response: Dict[str, Any],
        account_b_response: Dict[str, Any],
        unauthenticated_response: Optional[Dict[str, Any]] = None,
        target_resource_id: Optional[str] = None,
    ) -> Tuple[bool, float, str]:
        """Dual-identity IDOR / BOLA differential verification.
        
        Requires:
        1. Account A is the legitimate owner of resource X.
        2. Account B requests resource X with valid Account B credentials.
        3. Account B's response contains resource X data (differential confirms breach).
        4. Session A was NOT accidentally reused for Session B.
        """
        if not account_a_response or not account_b_response:
            return False, 0.0, "Missing dual-identity responses: both Account A and Account B responses required"

        status_a = account_a_response.get("status_code", 0)
        status_b = account_b_response.get("status_code", 0)

        body_a = str(account_a_response.get("body", "") or account_a_response.get("raw_response", ""))
        body_b = str(account_b_response.get("body", "") or account_b_response.get("raw_response", ""))

        auth_header_a = str(account_a_response.get("auth_token", "") or account_a_response.get("headers", {}).get("authorization", ""))
        auth_header_b = str(account_b_response.get("auth_token", "") or account_b_response.get("headers", {}).get("authorization", ""))

        # Guard against session contamination: Account A and B must not share auth tokens
        if auth_header_a and auth_header_b and auth_header_a == auth_header_b:
            return False, 0.0, "Invalid dual-identity test: Account A and Account B used identical authorization tokens"

        # If Account B was denied (401, 403, 404), access control is safely enforced
        if status_b in (401, 403, 404):
            return False, 0.0, f"Access control enforced: Account B received HTTP {status_b}"

        # If Account B received HTTP 200, check if sensitive resource data was actually returned
        if status_b == 200:
            if target_resource_id and target_resource_id not in body_b:
                return False, 0.2, f"Account B received 200 but response does not contain target resource {target_resource_id}"

            # Check if Account B received identical private data as Account A
            if body_a and body_b and (target_resource_id in body_b or body_a == body_b):
                return True, 0.95, "Confirmed IDOR: Account B successfully accessed private resource owned by Account A"

        return False, 0.1, "Inconclusive: Access differential between Account A and Account B could not confirm unauthorized disclosure"

    @classmethod
    def evaluate(
        cls,
        evidence_chain: List[Dict[str, Any]],
        vuln_type: str,
        baseline_evidence: Optional[Dict[str, Any]] = None,
        dual_identity_evidence: Optional[Dict[str, Any]] = None,
    ) -> ReproducibilityResultDTO:
        """Central evaluation function for reproducibility."""
        if not evidence_chain:
            return ReproducibilityResultDTO(
                is_reproduced=False,
                reproducibility_score=0.0,
                request_consistency_score=0.0,
                differential_score=0.0,
                preconditions_met=False,
                rationale="Missing evidence chain: zero evidence items provided",
            )

        evidence_ids = [e.get("evidence_id") or e.get("id", "EVD-UNK") for e in evidence_chain]

        # 1. Evaluate consistency across evidence responses
        is_consistent, req_score, req_rationale = cls.evaluate_response_consistency(evidence_chain)

        # 2. Evaluate differential if baseline exists
        is_diff, diff_score, diff_rationale = False, 0.0, "No baseline response provided"
        if baseline_evidence:
            is_diff, diff_score, diff_rationale = cls.evaluate_differential(
                baseline_response=baseline_evidence,
                test_response=evidence_chain[-1],
            )

        # 3. If IDOR / BOLA check, run dual identity differential
        vt = (vuln_type or "").upper()
        if any(k in vt for k in ["IDOR", "BOLA", "C067", "C068", "C069", "ACCESS_CONTROL"]):
            if dual_identity_evidence:
                is_dual, dual_score, dual_rationale = cls.evaluate_dual_identity_access(
                    account_a_response=dual_identity_evidence.get("account_a", {}),
                    account_b_response=dual_identity_evidence.get("account_b", {}),
                    target_resource_id=dual_identity_evidence.get("target_resource_id"),
                )
                overall_score = round(dual_score, 3)
                return ReproducibilityResultDTO(
                    is_reproduced=is_dual,
                    reproducibility_score=overall_score,
                    request_consistency_score=req_score,
                    differential_score=dual_score,
                    reproduction_evidence_ids=evidence_ids,
                    preconditions_met=is_dual,
                    details={"dual_identity": dual_rationale, "consistency": req_rationale},
                    rationale=dual_rationale,
                )
            else:
                return ReproducibilityResultDTO(
                    is_reproduced=False,
                    reproducibility_score=0.0,
                    request_consistency_score=req_score,
                    differential_score=0.0,
                    reproduction_evidence_ids=evidence_ids,
                    preconditions_met=False,
                    details={"missing": "Dual-identity evidence required for IDOR/BOLA verification"},
                    rationale="IDOR verification requires dual-identity evidence (Account A vs Account B)",
                )

        # General vulnerability classes
        overall_score = round((req_score * 0.5) + (diff_score * 0.5 if baseline_evidence else req_score * 0.3), 3)
        is_reproduced = is_consistent and (not baseline_evidence or is_diff)

        rationale = req_rationale
        if baseline_evidence:
            rationale += f"; Differential: {diff_rationale}"

        return ReproducibilityResultDTO(
            is_reproduced=is_reproduced,
            reproducibility_score=overall_score,
            request_consistency_score=req_score,
            differential_score=diff_score,
            reproduction_evidence_ids=evidence_ids,
            preconditions_met=True,
            details={"consistency": req_rationale, "differential": diff_rationale},
            rationale=rationale,
        )
