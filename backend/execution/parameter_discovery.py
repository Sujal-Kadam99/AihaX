"""AihaX Real-Target Parameter Discovery Engine."""

from __future__ import annotations

import json
import logging
import re
import uuid
from typing import Any, Dict, List, Optional, Set, Tuple
from urllib.parse import parse_qs, urlparse

from backend.execution.parameter_model import (
    DiscoveredParameter,
    ParameterLocation,
    ParameterSource,
    ParameterType,
)
from backend.recon.models import DiscoveredEndpoint, EndpointType

logger = logging.getLogger("backend.execution.parameter_discovery")


class ParameterDiscoveryEngine:
    """Discovers testable input locations strictly from observed application evidence."""

    @classmethod
    def discover_parameters(
        cls,
        endpoint: DiscoveredEndpoint,
        raw_html: Optional[str] = None,
        observed_json: Optional[dict[str, Any]] = None,
        openapi_details: Optional[dict[str, Any]] = None,
    ) -> list[DiscoveredParameter]:
        """Extract all valid parameters associated with an endpoint without inventing synthetic inputs."""
        parameters: list[DiscoveredParameter] = []
        seen_keys: set[str] = set()

        def add_param(
            name: str,
            location: ParameterLocation,
            param_type: ParameterType = ParameterType.STRING,
            source: ParameterSource = ParameterSource.OBSERVED_REQUEST,
            provenance: str = "",
            baseline_val: Optional[Any] = None,
            json_path: Optional[str] = None,
            is_req: bool = False,
        ):
            if not name or not isinstance(name, str):
                return
            clean_name = name.strip()
            if not clean_name:
                return

            key = f"{location.value}:{clean_name}:{json_path or ''}"
            if key in seen_keys:
                return
            seen_keys.add(key)

            parameters.append(
                DiscoveredParameter(
                    parameter_id=f"param-{uuid.uuid4().hex[:8]}",
                    endpoint_url=endpoint.url,
                    method=endpoint.method,
                    name=clean_name,
                    location=location,
                    param_type=param_type,
                    source=source,
                    provenance=provenance,
                    baseline_value=baseline_val,
                    sample_values=[baseline_val] if baseline_val is not None else [],
                    is_required=is_req,
                    json_path=json_path,
                )
            )

        # 1. Discover Query Parameters from URL
        parsed = urlparse(endpoint.url)
        if parsed.query:
            qs = parse_qs(parsed.query, keep_blank_values=True)
            for k, vals in qs.items():
                baseline_val = vals[0] if vals else ""
                ptype = cls._infer_param_type(baseline_val)
                add_param(
                    name=k,
                    location=ParameterLocation.QUERY,
                    param_type=ptype,
                    source=ParameterSource.URL_QUERY,
                    provenance=f"Extracted from URL query string in {endpoint.url}",
                    baseline_val=baseline_val,
                )

        # 2. Discover Path Parameters from Route Templates (e.g. /accounts/{id} or /users/:userId)
        path_matches = re.findall(r"\{([a-zA-Z0-9_]+)\}|:([a-zA-Z0-9_]+)", endpoint.path)
        for m1, m2 in path_matches:
            param_name = m1 or m2
            if param_name:
                add_param(
                    name=param_name,
                    location=ParameterLocation.PATH,
                    param_type=ParameterType.STRING,
                    source=ParameterSource.OPENAPI_SPEC if "OPENAPI" in endpoint.source.value else ParameterSource.OBSERVED_REQUEST,
                    provenance=f"Extracted from path template {endpoint.path}",
                    baseline_val="1" if "id" in param_name.lower() else "default",
                    is_req=True,
                )

        # 3. Discover Parameters from Registered Endpoint Metadata (from HTML Crawling/OpenAPI)
        if endpoint.parameters:
            for p in endpoint.parameters:
                loc = ParameterLocation.MULTIPART if endpoint.is_upload else (
                    ParameterLocation.QUERY if endpoint.method == "GET" else ParameterLocation.FORM
                )
                add_param(
                    name=p,
                    location=loc,
                    param_type=ParameterType.FILE if (endpoint.is_upload and "file" in p.lower()) else ParameterType.STRING,
                    source=ParameterSource.OPENAPI_SPEC if "OPENAPI" in endpoint.source.value else ParameterSource.HTML_FORM,
                    provenance=f"Discovered via {endpoint.source.value} metadata",
                )

        # 4. Discover Form Inputs from HTML
        if raw_html:
            cls._extract_html_form_parameters(raw_html, endpoint.url, add_param)

        # 5. Discover JSON Body Fields from Observed Payload
        if observed_json:
            cls._extract_json_parameters(observed_json, add_param)

        # 6. Discover Parameters from OpenAPI Spec Details
        if openapi_details:
            cls._extract_openapi_parameters(openapi_details, add_param)

        return parameters

    @classmethod
    def _infer_param_type(cls, val: Any) -> ParameterType:
        if isinstance(val, bool) or str(val).lower() in ("true", "false"):
            return ParameterType.BOOLEAN
        if isinstance(val, int) or (isinstance(val, str) and val.isdigit()):
            return ParameterType.INTEGER
        if isinstance(val, list):
            return ParameterType.ARRAY
        if isinstance(val, dict):
            return ParameterType.OBJECT
        return ParameterType.STRING

    @classmethod
    def _extract_html_form_parameters(cls, html: str, target_url: str, add_fn):
        """Extract input parameters from HTML forms."""
        forms = re.findall(r"<form\b([^>]*)>(.*?)</form>", html, re.IGNORECASE | re.DOTALL)
        for form_attrs, form_body in forms:
            enctype_m = re.search(r'enctype=["\']([^"\']*)["\']', form_attrs, re.IGNORECASE)
            is_multipart = enctype_m and "multipart/form-data" in enctype_m.group(1).lower()

            # Inputs
            inputs = re.findall(r"<input\b([^>]*)>", form_body, re.IGNORECASE)
            for inp_attrs in inputs:
                name_m = re.search(r'name=["\']([^"\']+)["\']', inp_attrs, re.IGNORECASE)
                val_m = re.search(r'value=["\']([^"\']*)["\']', inp_attrs, re.IGNORECASE)
                type_m = re.search(r'type=["\']([^"\']+)["\']', inp_attrs, re.IGNORECASE)
                if name_m:
                    pname = name_m.group(1)
                    pval = val_m.group(1) if val_m else ""
                    ptype_str = (type_m.group(1) if type_m else "text").lower()

                    loc = ParameterLocation.MULTIPART if is_multipart or ptype_str == "file" else ParameterLocation.FORM
                    ptype = ParameterType.FILE if ptype_str == "file" else cls._infer_param_type(pval)

                    add_fn(
                        name=pname,
                        location=loc,
                        param_type=ptype,
                        source=ParameterSource.HTML_FORM,
                        provenance=f"HTML <input name='{pname}' type='{ptype_str}'> in form",
                        baseline_val=pval,
                    )

            # Select dropdowns
            selects = re.findall(r"<select\b([^>]*)name=[\"']([^\"']+)[\"'](.*?)>(.*?)</select>", form_body, re.IGNORECASE | re.DOTALL)
            for _, sname, _, sbody in selects:
                opt_m = re.search(r"<option\b[^>]*value=[\"']([^\"']+)[\"']", sbody, re.IGNORECASE)
                val = opt_m.group(1) if opt_m else ""
                add_fn(
                    name=sname,
                    location=ParameterLocation.FORM,
                    param_type=ParameterType.STRING,
                    source=ParameterSource.HTML_FORM,
                    provenance=f"HTML <select name='{sname}'>",
                    baseline_val=val,
                )

            # Textareas
            textareas = re.findall(r"<textarea\b[^>]*name=[\"']([^\"']+)[\"'][^>]*>(.*?)</textarea>", form_body, re.IGNORECASE | re.DOTALL)
            for tname, tbody in textareas:
                add_fn(
                    name=tname,
                    location=ParameterLocation.FORM,
                    param_type=ParameterType.STRING,
                    source=ParameterSource.HTML_FORM,
                    provenance=f"HTML <textarea name='{tname}'>",
                    baseline_val=tbody.strip(),
                )

    @classmethod
    def _extract_json_parameters(cls, obj: Any, add_fn, parent_path: str = "$"):
        """Recursively extract parameters from observed JSON structures."""
        if isinstance(obj, dict):
            for k, v in obj.items():
                current_path = f"{parent_path}.{k}"
                ptype = cls._infer_param_type(v)
                if isinstance(v, (str, int, float, bool)) or v is None:
                    add_fn(
                        name=k,
                        location=ParameterLocation.JSON,
                        param_type=ptype,
                        source=ParameterSource.JSON_BODY,
                        provenance=f"JSON field at {current_path}",
                        baseline_val=v,
                        json_path=current_path,
                    )
                elif isinstance(v, dict):
                    cls._extract_json_parameters(v, add_fn, current_path)
                elif isinstance(v, list) and v:
                    cls._extract_json_parameters(v[0], add_fn, f"{current_path}[0]")

    @classmethod
    def _extract_openapi_parameters(cls, details: dict[str, Any], add_fn):
        """Extract OpenAPI parameter schemas and body properties."""
        params = details.get("parameters", [])
        if isinstance(params, list):
            for p in params:
                if isinstance(p, dict) and "name" in p:
                    pname = p["name"]
                    in_loc = p.get("in", "query").lower()
                    loc = ParameterLocation.QUERY
                    if in_loc == "path":
                        loc = ParameterLocation.PATH
                    elif in_loc == "header":
                        loc = ParameterLocation.HEADER
                    elif in_loc == "cookie":
                        loc = ParameterLocation.COOKIE

                    schema = p.get("schema", {})
                    type_str = schema.get("type", "string") if isinstance(schema, dict) else "string"
                    ptype = ParameterType.INTEGER if type_str == "integer" else (
                        ParameterType.BOOLEAN if type_str == "boolean" else ParameterType.STRING
                    )
                    add_fn(
                        name=pname,
                        location=loc,
                        param_type=ptype,
                        source=ParameterSource.OPENAPI_SPEC,
                        provenance=f"OpenAPI schema parameter in '{in_loc}'",
                        baseline_val=p.get("example") or p.get("default") or "1",
                        is_req=p.get("required", False),
                    )

        req_body = details.get("requestBody", {})
        if isinstance(req_body, dict):
            content = req_body.get("content", {})
            if isinstance(content, dict):
                for mime, mdetails in content.items():
                    schema = mdetails.get("schema", {})
                    if isinstance(schema, dict):
                        props = schema.get("properties", {})
                        if isinstance(props, dict):
                            is_json = "json" in mime.lower()
                            loc = ParameterLocation.JSON if is_json else ParameterLocation.FORM
                            for prop_name, prop_schema in props.items():
                                type_str = prop_schema.get("type", "string") if isinstance(prop_schema, dict) else "string"
                                ptype = ParameterType.INTEGER if type_str == "integer" else (
                                    ParameterType.BOOLEAN if type_str == "boolean" else ParameterType.STRING
                                )
                                add_fn(
                                    name=prop_name,
                                    location=loc,
                                    param_type=ptype,
                                    source=ParameterSource.OPENAPI_SPEC,
                                    provenance=f"OpenAPI requestBody schema for {mime}",
                                    baseline_val=prop_schema.get("example") or prop_schema.get("default"),
                                    json_path=f"$.{prop_name}" if is_json else None,
                                )
