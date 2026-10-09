"""C023 — SQL Injection Check for AihaX."""

from __future__ import annotations

import re
from typing import Any, Dict, Optional
from urllib.parse import parse_qs, urlencode, urlparse, urlunparse

from backend.core.check_registry import (
    BaseCheck,
    CheckCategory,
    CheckContract,
    CheckResult,
    Severity,
    registry,
)
from backend.services.request_engine import RequestEngine, RequestSpec, RequestTimeout


SENSITIVE_PARAMETER = re.compile(r"password|passwd|secret|token|api.?key|session|cookie|csrf|credit.?card|ssn", re.I)
HIGH_VALUE_PARAMETER = re.compile(r"^(q|query|search|term|filter|id)$", re.I)


class C023SQLInjection(BaseCheck):
    contract = CheckContract(
        id="C023_SQL_Injection",
        name="SQL Injection",
        category=CheckCategory.INJECTION,
        description="Detects database syntax error disclosures and SQL exception signatures resulting from unescaped quote and delimiter injection.",
        severity=Severity.CRITICAL,
        vulnerability_type="SQL Injection",
        cwe="CWE-89",
        owasp_category="A03:2021-Injection",
        security_property="User-supplied query parameters must be parameterized and not concatenated directly into SQL execution contexts",
        remediation_guidance="Use parameterized queries (prepared statements) or Object Relational Mappers (ORMs) for all database operations.",
        references=[
            "https://cwe.mitre.org/data/definitions/89.html",
            "https://cheatsheetseries.owasp.org/cheatsheets/SQL_Injection_Prevention_Cheat_Sheet.html",
        ],
        verification_strategy="C023_SQL_Injection",
        required_evidence=["affected_url", "affected_param", "payload", "proof_request", "proof_response"],
        destructive=False,
        supported_methods={"GET"},
        requires_parameters=True,
        max_requests=10,
    )

    SQL_ERRORS = [
        ("MySQL", re.compile(r"you have an error in your sql syntax", re.I)),
        ("MySQL", re.compile(r"warning: mysql_", re.I)),
        ("PostgreSQL", re.compile(r"pg_query\(\): query failed: error:", re.I)),
        ("PostgreSQL", re.compile(r"syntax error at or near", re.I)),
        ("MSSQL", re.compile(r"unclosed quotation mark after the character string", re.I)),
        ("MSSQL", re.compile(r"microsoft ole db provider for sql server", re.I)),
        ("SQLite", re.compile(r"sqlite3::sqlexception", re.I)),
        ("SQLite", re.compile(r"sqlite_error:\s*(?:incomplete input|near\b|unrecognized token)", re.I)),
        ("SQLite", re.compile(r"unrecognized token: \"", re.I)),
        ("Oracle", re.compile(r"ora-00933: sql command not properly ended", re.I)),
        ("Oracle", re.compile(r"ora-01756: quoted string not properly terminated", re.I)),
    ]

    async def execute(
        self,
        request_engine: RequestEngine,
        target_url: str,
        config: Dict[str, Any],
    ) -> Optional[CheckResult]:
        targets: list[tuple[str, list[str]]] = []
        parsed_target = urlparse(target_url)
        target_params = list(parse_qs(parsed_target.query, keep_blank_values=True).keys())
        if target_params:
            targets.append((target_url, target_params))

        # Recon endpoint records are the source of truth for additional
        # parameters. Only GET endpoints are tested by this read-only check.
        for endpoint in config.get("discovered_endpoints", []):
            if str(endpoint.get("method", "GET")).upper() != "GET":
                continue
            endpoint_url = endpoint.get("url")
            params = endpoint.get("parameters") or []
            if not endpoint_url or not params:
                continue
            if not request_engine.scope_validator.validate_target(endpoint_url).allowed:
                continue
            targets.append((endpoint_url, [str(name) for name in params if name]))

        # Deduplicate endpoint/parameter pairs and do not invent parameter
        # names when recon has found no testable input.
        seen: set[tuple[str, str]] = set()
        payloads = ["'", "''", "1' OR '1'='1", "' OR 1=1--", "1) OR (1=1"]
        targets.sort(key=lambda item: (
            0 if any(HIGH_VALUE_PARAMETER.fullmatch(name) for name in item[1]) else 1,
            0 if re.search(r"search|query", urlparse(item[0]).path, re.I) else 1,
            0 if "/api/" in urlparse(item[0]).path or "/rest/" in urlparse(item[0]).path else 1,
            item[0],
        ))
        requests_used = 0

        for endpoint_url, param_names in targets:
            parsed = urlparse(endpoint_url)
            params = parse_qs(parsed.query, keep_blank_values=True)
            for param_name in param_names:
                if SENSITIVE_PARAMETER.search(param_name):
                    continue
                if (endpoint_url, param_name) in seen:
                    continue
                seen.add((endpoint_url, param_name))
                baseline_params = dict(params)
                baseline_params[param_name] = baseline_params.get(param_name) or ["1"]
                baseline_url = urlunparse(parsed._replace(query=urlencode(baseline_params, doseq=True)))

                # Establish that this is a reachable input before injecting.
                if requests_used >= self.contract.max_requests:
                    return None
                baseline = await request_engine.execute(RequestSpec(
                    url=baseline_url,
                    method="GET",
                    timeout=RequestTimeout(connect=5.0, read=10.0, total=15.0),
                ))
                requests_used += 1
                if not baseline.success or baseline.response_status is None:
                    continue

                for payload in payloads:
                    if requests_used >= self.contract.max_requests:
                        return None
                    test_params = dict(baseline_params)
                    test_params[param_name] = [payload]
                    test_url = urlunparse(parsed._replace(query=urlencode(test_params, doseq=True)))

                    spec = RequestSpec(
                        url=test_url,
                        method="GET",
                        timeout=RequestTimeout(connect=5.0, read=10.0, total=15.0),
                    )
                    resp = await request_engine.execute(spec)
                    requests_used += 1
                    if not resp.success:
                        continue

                    body = resp.response_body or ""
                    for db_type, err_pat in self.SQL_ERRORS:
                        match = err_pat.search(body)
                        if match:
                            snippet = body[max(0, match.start() - 30) : min(len(body), match.end() + 70)].replace("\n", " ")
                            request_path = urlparse(test_url).path or "/"
                            if urlparse(test_url).query:
                                request_path += f"?{urlparse(test_url).query}"
                            proof_request = (
                                f"GET {request_path} HTTP/1.1\r\n"
                                f"Host: {urlparse(test_url).netloc}\r\n\r\n"
                            )
                            return CheckResult(
                                check_id=self.contract.id,
                                title=f"{self.contract.name} ({db_type})",
                                target=target_url,
                                affected_url=test_url,
                                affected_param=param_name,
                                vulnerability_type=self.contract.vulnerability_type,
                                severity=Severity.CRITICAL,
                                candidate_reason=f"Target disclosed {db_type} SQL error signature when injected with payload '{payload}' on parameter '{param_name}'.",
                                request_ids=[baseline.request_id, resp.request_id],
                                evidence_ids=[baseline.evidence_id, resp.evidence_id],
                                observed_data={"db_type": db_type, "parameter": param_name, "error_snippet": snippet, "baseline_status": baseline.response_status, "injected_status": resp.response_status},
                                payload=payload,
                                proof_request=proof_request,
                                proof_response=f"SQL Error Disclosed ({db_type}): {snippet}",
                                confidence=95,
                                verification_status="CANDIDATE",
                            )

        return None


# Register check
registry.register(C023SQLInjection)
