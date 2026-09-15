"""AihaX Discovered Parameter & Input Location Data Models."""

from __future__ import annotations

from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from enum import Enum
from typing import Any, Dict, List, Optional


class ParameterLocation(str, Enum):
    QUERY = "QUERY"
    PATH = "PATH"
    FORM = "FORM"
    JSON = "JSON"
    MULTIPART = "MULTIPART"
    HEADER = "HEADER"
    COOKIE = "COOKIE"
    GRAPHQL_VARIABLE = "GRAPHQL_VARIABLE"
    GRAPHQL_ARGUMENT = "GRAPHQL_ARGUMENT"


class ParameterType(str, Enum):
    STRING = "STRING"
    INTEGER = "INTEGER"
    BOOLEAN = "BOOLEAN"
    ARRAY = "ARRAY"
    OBJECT = "OBJECT"
    FILE = "FILE"
    UNKNOWN = "UNKNOWN"


class ParameterSource(str, Enum):
    URL_QUERY = "URL_QUERY"
    HTML_FORM = "HTML_FORM"
    HTML_LINK = "HTML_LINK"
    OPENAPI_SPEC = "OPENAPI_SPEC"
    JSON_BODY = "JSON_BODY"
    MULTIPART_BODY = "MULTIPART_BODY"
    GRAPHQL_SCHEMA = "GRAPHQL_SCHEMA"
    JS_ANALYSIS = "JS_ANALYSIS"
    OBSERVED_REQUEST = "OBSERVED_REQUEST"
    USER_SUPPLIED = "USER_SUPPLIED"


@dataclass(frozen=True)
class DiscoveredParameter:
    """Represents a concrete, evidence-backed input parameter on an endpoint."""

    parameter_id: str
    endpoint_url: str
    method: str
    name: str
    location: ParameterLocation
    param_type: ParameterType
    source: ParameterSource
    provenance: str
    baseline_value: Optional[Any] = None
    sample_values: list[Any] = field(default_factory=list)
    is_required: bool = False
    json_path: Optional[str] = None
    discovered_at: str = field(
        default_factory=lambda: datetime.now(timezone.utc).isoformat()
    )

    def to_dict(self) -> dict[str, Any]:
        d = asdict(self)
        d["location"] = self.location.value
        d["param_type"] = self.param_type.value
        d["source"] = self.source.value
        return d
