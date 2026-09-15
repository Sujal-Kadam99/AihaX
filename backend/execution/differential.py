"""AihaX Deterministic Response Differential & False-Positive Defense Engine."""

from __future__ import annotations

import html
import logging
import re
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from difflib import SequenceMatcher
from enum import Enum
from typing import Any, Dict, List, Optional

from backend.execution.baseline import BaselineSnapshot
from backend.execution.canary import CanaryCategory, CanaryRecord
from backend.execution.mutation_engine import ParameterMutation
from backend.services.request_engine import RequestEvidence

logger = logging.getLogger("backend.execution.differential")


class ReflectionContext(str, Enum):
    RAW_HTML = "RAW_HTML"
    HTML_ENCODED = "HTML_ENCODED"
    ATTRIBUTE = "ATTRIBUTE"
    JAVASCRIPT = "JAVASCRIPT"
    JSON = "JSON"
    HEADER = "HEADER"
    NONE = "NONE"


@dataclass(frozen=True)
class ResponseDifferential:
    """Deterministic comparison between baseline, mutated response, and negative control."""

    differential_id: str
    canary_id: str
    check_id: str
    parameter_id: str
    status_changed: bool
    baseline_status: int
    mutated_status: Optional[int]
    content_type_changed: bool
    length_delta: int
    body_similarity: float
    reflection_detected: bool
    reflection_context: ReflectionContext
    canary_signal_matched: bool
    control_signal_matched: bool
    syntax_error_detected: bool
    generic_500_detected: bool
    timing_delta_ms: float
    is_candidate: bool
    candidate_reason: str
    confidence: int
    analyzed_at: str = field(
        default_factory=lambda: datetime.now(timezone.utc).isoformat()
    )

    def to_dict(self) -> dict[str, Any]:
        d = asdict(self)
        d["reflection_context"] = self.reflection_context.value
        return d


class ResponseDifferentialEngine:
    """Evaluates causality and security signals between baseline and mutated responses."""

    SQL_ERROR_PATTERNS = [
        r"you have an error in your sql syntax",
        r"warning: mysql_",
        r"unclosed quotation mark after the character string",
        r"quoted string not properly terminated",
        r"pg_query\(\): query failed:",
        r"sqlite3::sqlexception",
        r"syntax error at or near",
        r"microsoft ole db provider for odbc drivers",
    ]

    @classmethod
    def analyze_differential(
        cls,
        baseline: BaselineSnapshot,
        mutated_evidence: RequestEvidence,
        canary: CanaryRecord,
        mutation: ParameterMutation,
        control_evidence: Optional[RequestEvidence] = None,
    ) -> ResponseDifferential:
        """Deterministically compare mutated response against baseline and negative control."""
        mut_status = mutated_evidence.response_status
        mut_body = mutated_evidence.response_body or ""
        mut_headers = {k.lower(): v for k, v in mutated_evidence.response_headers.items()}
        base_body = baseline.request_evidence.response_body or ""

        # Status & Length Deltas
        status_changed = (mut_status != baseline.status_code)
        length_delta = (mut_evidence_len := len(mut_body.encode("utf-8", "replace"))) - baseline.body_length
        content_type_changed = (mut_headers.get("content-type") != baseline.content_type)

        # Body Similarity
        similarity = SequenceMatcher(None, base_body[:4000], mut_body[:4000]).ratio() if (base_body or mut_body) else 1.0

        # Generic 500 detection
        generic_500 = (mut_status == 500 and baseline.status_code != 500)

        # Timing Delta
        timing_delta_ms = mutated_evidence.duration_ms - baseline.response_time_ms

        # Signal Matching & Reflection Context
        canary_matched = False
        reflection_detected = False
        reflection_context = ReflectionContext.NONE
        syntax_error = False

        # 1. Reflection analysis
        if canary.category in (CanaryCategory.REFLECTION, CanaryCategory.HEADER_INJECTION):
            if canary.payload in mut_body:
                canary_matched = True
                reflection_detected = True
                reflection_context = cls._classify_reflection_context(mut_body, canary.payload)
            elif html.escape(canary.payload) in mut_body:
                reflection_detected = True
                reflection_context = ReflectionContext.HTML_ENCODED
                canary_matched = False  # Encoded reflection is not raw exploitable XSS

            # Header injection check
            if canary.category == CanaryCategory.HEADER_INJECTION:
                for hk, hv in mut_headers.items():
                    if "aihax" in hk or "aihax" in hv:
                        canary_matched = True
                        reflection_context = ReflectionContext.HEADER

        # 2. Arithmetic / SSTI calculation match
        elif canary.category in (CanaryCategory.ARITHMETIC, CanaryCategory.SSTI):
            if canary.expected_signal in mut_body and canary.payload not in mut_body:
                # Result was computed by remote engine (e.g. 31337 appeared without literal mathematical string)
                canary_matched = True
            elif canary.expected_signal in mut_body and canary.expected_signal not in base_body:
                canary_matched = True

        # 3. SQL syntax probe
        elif canary.category == CanaryCategory.SQL_SYNTAX:
            for pattern in cls.SQL_ERROR_PATTERNS:
                if re.search(pattern, mut_body, re.IGNORECASE):
                    syntax_error = True
                    canary_matched = True
                    break

        # 4. Path traversal indicator
        elif canary.category == CanaryCategory.PATH_TRAVERSAL:
            if canary.expected_signal in mut_body:
                canary_matched = True

        # 5. File upload artifact
        elif canary.category == CanaryCategory.SAFE_UPLOAD:
            if canary.expected_signal in mut_body or (mut_status in (200, 201) and not status_changed):
                canary_matched = True

        # Negative Control Signal Evaluation
        control_matched = False
        if control_evidence and control_evidence.response_body:
            ctrl_body = control_evidence.response_body
            if canary.category == CanaryCategory.SQL_SYNTAX:
                for pattern in cls.SQL_ERROR_PATTERNS:
                    if re.search(pattern, ctrl_body, re.IGNORECASE):
                        control_matched = True
                        break
            elif canary.negative_control_expected and canary.negative_control_expected in ctrl_body:
                # If negative control payload ALSO produced the anomalous signal, it's NOT a vulnerability
                if canary.category in (CanaryCategory.ARITHMETIC, CanaryCategory.SSTI):
                    control_matched = True

        # Candidate Decision & Confidence
        is_cand = False
        reason = "No anomalous security signal detected."
        conf = 0

        if canary_matched and not control_matched:
            is_cand = True
            conf = 90 if reflection_context == ReflectionContext.RAW_HTML or canary.category == CanaryCategory.ARITHMETIC else 75
            reason = f"Deterministic security signal confirmed for {canary.category.value} on parameter '{mutation.parameter_name}'."
        elif generic_500 and not syntax_error:
            # Generic 500 without syntax or canary signal is NOT a vulnerability
            is_cand = False
            conf = 10
            reason = "HTTP 500 observed without specific vulnerability error signature (Rejected false positive)."
        elif reflection_context == ReflectionContext.HTML_ENCODED:
            is_cand = False
            conf = 20
            reason = "Canary reflected but safely HTML-entity encoded (Defended against false-positive XSS)."

        return ResponseDifferential(
            differential_id=f"diff-{canary.canary_id}",
            canary_id=canary.canary_id,
            check_id=canary.check_id,
            parameter_id=mutation.parameter_id,
            status_changed=status_changed,
            baseline_status=baseline.status_code,
            mutated_status=mut_status,
            content_type_changed=content_type_changed,
            length_delta=length_delta,
            body_similarity=round(similarity, 4),
            reflection_detected=reflection_detected,
            reflection_context=reflection_context,
            canary_signal_matched=canary_matched,
            control_signal_matched=control_matched,
            syntax_error_detected=syntax_error,
            generic_500_detected=generic_500,
            timing_delta_ms=round(timing_delta_ms, 2),
            is_candidate=is_cand,
            candidate_reason=reason,
            confidence=conf,
        )

    @classmethod
    def _classify_reflection_context(cls, body: str, payload: str) -> ReflectionContext:
        """Identify execution context of raw reflection in HTML."""
        idx = body.find(payload)
        if idx == -1:
            return ReflectionContext.NONE
        prefix = body[max(0, idx - 100):idx].lower()
        if "<script" in prefix and "</script" not in prefix:
            return ReflectionContext.JAVASCRIPT
        if re.search(r'<\w+[^>]*\b\w+\s*=\s*["\'][^"\']*$', prefix):
            return ReflectionContext.ATTRIBUTE
        if body.strip().startswith("{") and body.strip().endswith("}"):
            return ReflectionContext.JSON
        return ReflectionContext.RAW_HTML
