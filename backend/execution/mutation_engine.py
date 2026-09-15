"""AihaX Centralized Parameter Mutation Engine."""

from __future__ import annotations

import json
import logging
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from enum import Enum
from typing import Any, Dict, List, Optional
from urllib.parse import parse_qsl, urlencode, urlparse, urlunparse

from backend.execution.canary import CanaryRecord
from backend.execution.parameter_model import DiscoveredParameter, ParameterLocation
from backend.recon.models import DiscoveredEndpoint
from backend.services.request_engine import (
    AuthenticationContext,
    RequestSpec,
    RequestTimeout,
)

logger = logging.getLogger("backend.execution.mutation_engine")


class MutationStrategy(str, Enum):
    REPLACE = "REPLACE"
    APPEND = "APPEND"
    PREPEND = "PREPEND"
    TYPE_CHANGE = "TYPE_CHANGE"
    BOUNDARY = "BOUNDARY"
    ENCODING = "ENCODING"
    STRUCTURAL = "STRUCTURAL"
    HEADER = "HEADER"


@dataclass(frozen=True)
class ParameterMutation:
    """Represents a discrete mutation applied to a single discovered parameter."""

    mutation_id: str
    parameter_id: str
    parameter_name: str
    location: ParameterLocation
    strategy: MutationStrategy
    original_value: Any
    mutated_value: Any
    canary_id: str
    check_id: str
    created_at: str = field(
        default_factory=lambda: datetime.now(timezone.utc).isoformat()
    )

    def to_dict(self) -> dict[str, Any]:
        d = asdict(self)
        d["location"] = self.location.value
        d["strategy"] = self.strategy.value
        return d


class ParameterMutationEngine:
    """Applies controlled, deterministic parameter mutations within RequestSpec structures."""

    @classmethod
    def create_mutated_request(
        cls,
        endpoint: DiscoveredEndpoint,
        parameter: DiscoveredParameter,
        canary: CanaryRecord,
        strategy: MutationStrategy = MutationStrategy.REPLACE,
        custom_payload: Optional[str] = None,
        auth_context: Optional[AuthenticationContext] = None,
        timeout_seconds: float = 10.0,
    ) -> tuple[RequestSpec, ParameterMutation]:
        """Generate a RequestSpec with the targeted parameter mutated according to strategy and canary."""
        payload = custom_payload if custom_payload is not None else canary.payload
        orig_val = parameter.baseline_value
        mutated_val = cls._apply_strategy(orig_val, payload, strategy)

        method = endpoint.method.upper()
        target_url = endpoint.url
        headers: dict[str, str] = {
            "User-Agent": "AihaX-Security-Scanner/1.0 (Authorized Audit)"
        }
        body_bytes: Optional[bytes] = None

        # 1. Mutate Query Parameter
        if parameter.location == ParameterLocation.QUERY:
            parsed = urlparse(target_url)
            qs_dict = dict(parse_qsl(parsed.query, keep_blank_values=True))
            qs_dict[parameter.name] = str(mutated_val)
            target_url = urlunparse((
                parsed.scheme,
                parsed.netloc,
                parsed.path,
                parsed.params,
                urlencode(qs_dict),
                parsed.fragment,
            ))

        # 2. Mutate Path Parameter
        elif parameter.location == ParameterLocation.PATH:
            parsed = urlparse(target_url)
            path = parsed.path
            # Replace {param} or :param in path
            new_path = path.replace(f"{{{parameter.name}}}", str(mutated_val))
            new_path = new_path.replace(f":{parameter.name}", str(mutated_val))
            target_url = urlunparse((
                parsed.scheme,
                parsed.netloc,
                new_path,
                parsed.params,
                parsed.query,
                parsed.fragment,
            ))

        # 3. Mutate JSON Body Field
        elif parameter.location == ParameterLocation.JSON:
            headers["Content-Type"] = "application/json"
            base_dict = {}
            if parameter.json_path and parameter.json_path.startswith("$."):
                # Nested or top-level JSON key
                field_key = parameter.json_path[2:]
                base_dict[field_key] = mutated_val
            else:
                base_dict[parameter.name] = mutated_val
            body_bytes = json.dumps(base_dict).encode("utf-8")

        # 4. Mutate Form Body Field
        elif parameter.location == ParameterLocation.FORM:
            headers["Content-Type"] = "application/x-www-form-urlencoded"
            fdict = {parameter.name: str(mutated_val)}
            body_bytes = urlencode(fdict).encode("utf-8")

        # 5. Mutate Header
        elif parameter.location == ParameterLocation.HEADER:
            headers[parameter.name] = str(mutated_val)

        # 6. Mutate Cookie
        elif parameter.location == ParameterLocation.COOKIE:
            headers["Cookie"] = f"{parameter.name}={mutated_val}"

        # 7. Mutate Multipart Upload
        elif parameter.location == ParameterLocation.MULTIPART:
            boundary = "----WebKitFormBoundaryAihaXAudit"
            headers["Content-Type"] = f"multipart/form-data; boundary={boundary}"
            pname = parameter.name
            fname = "audit_probe.txt"
            body_text = (
                f"--{boundary}\r\n"
                f'Content-Disposition: form-data; name="{pname}"; filename="{fname}"\r\n'
                f"Content-Type: text/plain\r\n\r\n"
                f"{mutated_val}\r\n"
                f"--{boundary}--\r\n"
            )
            body_bytes = body_text.encode("utf-8")

        spec = RequestSpec(
            method=method,
            url=target_url,
            headers=headers,
            body=body_bytes,
            timeout=RequestTimeout(total=timeout_seconds),
            follow_redirects=False,
            auth_context=auth_context,
            authorization_confirmed=True,
            metadata={
                "check_id": canary.check_id,
                "parameter_id": parameter.parameter_id,
                "parameter_name": parameter.name,
                "canary_id": canary.canary_id,
                "strategy": strategy.value,
            },
        )

        mutation = ParameterMutation(
            mutation_id=f"mut-{canary.canary_id}",
            parameter_id=parameter.parameter_id,
            parameter_name=parameter.name,
            location=parameter.location,
            strategy=strategy,
            original_value=orig_val,
            mutated_value=mutated_val,
            canary_id=canary.canary_id,
            check_id=canary.check_id,
        )

        return spec, mutation

    @classmethod
    def _apply_strategy(cls, original: Any, payload: str, strategy: MutationStrategy) -> Any:
        if strategy == MutationStrategy.REPLACE:
            return payload
        if strategy == MutationStrategy.APPEND:
            return f"{original or ''}{payload}"
        if strategy == MutationStrategy.PREPEND:
            return f"{payload}{original or ''}"
        if strategy == MutationStrategy.TYPE_CHANGE:
            if isinstance(original, int) or str(original).isdigit():
                return [payload]
            return 9999999
        if strategy == MutationStrategy.BOUNDARY:
            return 2147483647 if (isinstance(original, int) or str(original).isdigit()) else "A" * 1024
        if strategy == MutationStrategy.ENCODING:
            from urllib.parse import quote
            return quote(payload)
        return payload
