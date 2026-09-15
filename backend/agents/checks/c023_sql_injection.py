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
        verification_strategy="generic_reproducibility",
        required_evidence=["affected_url", "proof_response", "sql_error_signature"],
        destructive=False,
    )

    SQL_ERRORS = [
        ("MySQL", re.compile(r"you have an error in your sql syntax", re.I)),
        ("MySQL", re.compile(r"warning: mysql_", re.I)),
        ("PostgreSQL", re.compile(r"pg_query\(\): query failed: error:", re.I)),
        ("PostgreSQL", re.compile(r"syntax error at or near", re.I)),
        ("MSSQL", re.compile(r"unclosed quotation mark after the character string", re.I)),
        ("MSSQL", re.compile(r"microsoft ole db provider for sql server", re.I)),
        ("SQLite", re.compile(r"sqlite3::sqlexception", re.I)),
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
        parsed = urlparse(target_url)
        params = parse_qs(parsed.query, keep_blank_values=True)
        if not params:
            # Test default test query parameter if none present
            params = {"id": ["1"]}

        for param_name in list(params.keys()):
            for payload in ["'", "''", "1' OR '1'='1", "1) OR (1=1"]:
                test_params = dict(params)
                test_params[param_name] = [payload]
                new_query = urlencode(test_params, doseq=True)
                test_url = urlunparse((parsed.scheme, parsed.netloc, parsed.path, parsed.params, new_query, parsed.fragment))

                spec = RequestSpec(
                    url=test_url,
                    method="GET",
                    timeout=RequestTimeout(connect=5.0, read=10.0, total=15.0),
                )
                resp = await request_engine.execute(spec)
                if not resp.success:
                    continue

                body = resp.response_body or ""
                for db_type, err_pat in self.SQL_ERRORS:
                    match = err_pat.search(body)
                    if match:
                        snippet = body[max(0, match.start() - 30) : min(len(body), match.end() + 70)].replace("\n", " ")
                        return CheckResult(
                            check_id=self.contract.id,
                            title=f"{self.contract.name} ({db_type})",
                            target=target_url,
                            affected_url=test_url,
                            affected_param=param_name,
                            vulnerability_type=self.contract.vulnerability_type,
                            severity=Severity.CRITICAL,
                            candidate_reason=f"Target disclosed {db_type} SQL error signature when injected with payload '{payload}' on parameter '{param_name}'.",
                            request_ids=[resp.request_id],
                            evidence_ids=[resp.evidence_id],
                            observed_data={"db_type": db_type, "parameter": param_name, "error_snippet": snippet},
                            payload=payload,
                            proof_response=f"SQL Error Disclosed ({db_type}): {snippet}",
                            confidence=95,
                            verification_status="CANDIDATE",
                        )

        return None


# Register check
registry.register(C023SQLInjection)
