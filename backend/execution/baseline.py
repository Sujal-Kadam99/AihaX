"""AihaX Baseline Request & Response Capture Engine."""

from __future__ import annotations

import hashlib
import json
import logging
import re
import time
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional
from urllib.parse import urlencode, urlparse, urlunparse

from backend.execution.parameter_model import DiscoveredParameter, ParameterLocation
from backend.recon.models import DiscoveredEndpoint
from backend.services.request_engine import (
    AuthenticationContext,
    RequestEngine,
    RequestEvidence,
    RequestSpec,
    RequestTimeout,
)

logger = logging.getLogger("backend.execution.baseline")


@dataclass(frozen=True)
class BaselineSnapshot:
    """Immutable baseline response fingerprint captured before active security testing."""

    baseline_id: str
    endpoint_url: str
    method: str
    status_code: int
    headers: dict[str, str]
    content_type: str
    body_hash: str
    body_length: int
    response_time_ms: float
    body_preview: str
    structure_fingerprint: str
    is_redirect: bool
    redirect_target: Optional[str]
    auth_context_name: Optional[str]
    request_evidence: RequestEvidence
    captured_at: str = field(
        default_factory=lambda: datetime.now(timezone.utc).isoformat()
    )

    def to_dict(self) -> dict[str, Any]:
        d = asdict(self)
        d["request_evidence"] = self.request_evidence.to_dict()
        return d


class BaselineCaptureEngine:
    """Captures empirical response baselines before applying any parameter mutations."""

    @classmethod
    async def capture_baseline(
        cls,
        request_engine: RequestEngine,
        endpoint: DiscoveredEndpoint,
        parameters: Optional[list[DiscoveredParameter]] = None,
        auth_context: Optional[AuthenticationContext] = None,
        timeout_seconds: float = 10.0,
    ) -> Optional[BaselineSnapshot]:
        """Send benign baseline request to establish ground truth for differential comparisons."""
        method = endpoint.method.upper()
        target_url = endpoint.url
        headers: dict[str, str] = {
            "User-Agent": "AihaX-Security-Baseline/1.0 (Authorized Audit)"
        }
        body_bytes: Optional[bytes] = None
        params = parameters or []

        # Construct benign query parameters if present
        query_params = [p for p in params if p.location == ParameterLocation.QUERY]
        if query_params:
            parsed = urlparse(target_url)
            existing_qs = urlparse(target_url).query
            qs_dict = {}
            if existing_qs:
                from urllib.parse import parse_qsl
                qs_dict.update(dict(parse_qsl(existing_qs)))
            for p in query_params:
                if p.name not in qs_dict and p.baseline_value is not None:
                    qs_dict[p.name] = str(p.baseline_value)
            if qs_dict:
                target_url = urlunparse((
                    parsed.scheme,
                    parsed.netloc,
                    parsed.path,
                    parsed.params,
                    urlencode(qs_dict),
                    parsed.fragment,
                ))

        # Construct benign body for POST/PUT/PATCH
        if method in ("POST", "PUT", "PATCH"):
            json_params = [p for p in params if p.location == ParameterLocation.JSON]
            form_params = [p for p in params if p.location == ParameterLocation.FORM]

            if json_params:
                headers["Content-Type"] = "application/json"
                body_dict = {}
                for p in json_params:
                    val = p.baseline_value if p.baseline_value is not None else "baseline"
                    if p.param_type.value == "INTEGER" and str(val).isdigit():
                        val = int(val)
                    elif p.param_type.value == "BOOLEAN":
                        val = str(val).lower() == "true"
                    body_dict[p.name] = val
                body_bytes = json.dumps(body_dict).encode("utf-8")
            elif form_params:
                headers["Content-Type"] = "application/x-www-form-urlencoded"
                fdict = {p.name: str(p.baseline_value or "baseline") for p in form_params}
                body_bytes = urlencode(fdict).encode("utf-8")

        spec = RequestSpec(
            method=method,
            url=target_url,
            headers=headers,
            body=body_bytes,
            timeout=RequestTimeout(total=timeout_seconds),
            follow_redirects=False,
            auth_context=auth_context,
            authorization_confirmed=True,
        )

        evidence = await request_engine.execute(spec)
        if not evidence.success or evidence.response_status is None:
            logger.warning("Failed capturing baseline for %s %s: status=%s", method, target_url, evidence.response_status)
            return None

        body_str = evidence.response_body or ""
        body_bytes_resp = body_str.encode("utf-8", errors="replace")
        body_hash = hashlib.sha256(body_bytes_resp).hexdigest()
        body_len = evidence.response_size or len(body_bytes_resp)

        resp_headers = {k.lower(): v for k, v in evidence.response_headers.items()}
        content_type = resp_headers.get("content-type", "unknown")

        # Compute structural fingerprint (stripping dynamic tokens/timestamps)
        cleaned_body = re.sub(r"\b\d{4}-\d{2}-\d{2}[T ]\d{2}:\d{2}:\d{2}\b", "[DATE]", body_str)
        cleaned_body = re.sub(r"\b[0-9a-fA-F]{32,64}\b", "[HASH]", cleaned_body)
        structure_fp = hashlib.sha256(cleaned_body[:2048].encode("utf-8")).hexdigest()[:16]

        is_redirect = (evidence.response_status in (301, 302, 303, 307, 308))
        redirect_target = resp_headers.get("location")

        return BaselineSnapshot(
            baseline_id=f"base-{hashlib.sha256(f'{method}:{target_url}:{auth_context.name if auth_context else None}'.encode()).hexdigest()[:12]}",
            endpoint_url=target_url,
            method=method,
            status_code=evidence.response_status,
            headers=resp_headers,
            content_type=content_type,
            body_hash=body_hash,
            body_length=body_len,
            response_time_ms=evidence.duration_ms,
            body_preview=body_str[:500],
            structure_fingerprint=structure_fp,
            is_redirect=is_redirect,
            redirect_target=redirect_target,
            auth_context_name=auth_context.name if auth_context else None,
            request_evidence=evidence,
        )
