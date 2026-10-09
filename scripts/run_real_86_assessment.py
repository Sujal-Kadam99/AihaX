"""Run AihaX's registered 86-check pipeline against an operator-owned loopback Juice Shop.

This runner uses the production RequestEngine and AiohttpTransport. It contains no
mock transport or synthetic response path. It refuses non-loopback targets and
requires an explicit authorization record.
"""
from __future__ import annotations

import argparse
import asyncio
import hashlib
import ipaddress
import json
import re
import sys
import uuid
from datetime import datetime, timezone
from pathlib import Path
from urllib.parse import parse_qsl, urlencode, urlparse, urlunparse

PROJECT_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(PROJECT_ROOT))

import backend.agents.checks  # noqa: F401 - register the complete check inventory
import backend.persistence.models  # noqa: F401 - register relationships used by the production app
from backend.core.check_registry import registry
from backend.core.scope_validator import ScopeValidator
from backend.services.campaign_executor import CampaignExecutor
from backend.services.coverage_validator import CoverageValidator
from backend.services.request_engine import RequestEngine, RequestSpec, redact_body


SENSITIVE_QUERY_KEYS = re.compile(r"password|passwd|pwd|secret|token|api.?key|ssn|credit.?card", re.I)


def sanitize_url(url: str) -> str:
    parsed = urlparse(url)
    query = [(key, "[REDACTED]" if SENSITIVE_QUERY_KEYS.search(key) else value)
              for key, value in parse_qsl(parsed.query, keep_blank_values=True)]
    return urlunparse(parsed._replace(query=urlencode(query, doseq=True)))


def safe_text(value: str | None, limit: int = 800) -> str | None:
    if value is None:
        return None
    return redact_body(value)[:limit]


class EvidenceCapturingRequestEngine(RequestEngine):
    """Use the real engine/transport and retain redacted evidence records."""

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.captured_evidence: list[dict] = []

    async def execute(self, spec: RequestSpec):
        evidence = await super().execute(spec)
        self.captured_evidence.append({
            "check_id": self.current_check_id,
            "finding_id": self.current_finding_id,
            "execution_phase": self.current_phase or "unattributed",
            "evidence_id": evidence.evidence_id,
            "request_id": evidence.request_id,
            "timestamp": evidence.timestamp,
            "method": evidence.method,
            "url": sanitize_url(evidence.url),
            "request_headers": evidence.request_headers,
            "request_body": safe_text(evidence.request_body),
            "response_status": evidence.response_status,
            "response_headers": evidence.response_headers,
            "response_excerpt": safe_text(evidence.response_body),
            "response_size": evidence.response_size,
            "response_sha256": evidence.response_hash,
            "request_sha256": evidence.request_hash,
            "scope_decision": evidence.scope_decision,
            "redirect_chain": [sanitize_url(url) for url in evidence.redirect_chain],
            "transport_error": evidence.transport_error,
            "success": evidence.success,
        })
        return evidence


def finding_record(finding) -> dict:
    fields = (
        "id", "title", "vuln_type", "category", "severity", "affected_url",
        "affected_param", "payload", "verdict", "verification_status", "confidence",
        "evidence_ids", "request_ids", "proof_request", "proof_response", "false_positive",
    )
    record = {field: getattr(finding, field, None) for field in fields}
    if record.get("affected_url"):
        record["affected_url"] = sanitize_url(record["affected_url"])
    for key in ("payload", "proof_request", "proof_response"):
        if isinstance(record.get(key), str):
            record[key] = safe_text(record[key], 2000)
    return record


def write_json(path: Path, value) -> None:
    path.write_text(json.dumps(value, indent=2, sort_keys=True, default=str) + "\n", encoding="utf-8")


def require_loopback_url(value: str) -> tuple[str, int, str, str]:
    parsed = urlparse(value)
    if parsed.scheme != "http" or not parsed.hostname or parsed.username or parsed.password:
        raise ValueError("Target must be a plain HTTP URL without userinfo")
    host = parsed.hostname.casefold()
    if host == "localhost":
        pass
    else:
        try:
            if not ipaddress.ip_address(host).is_loopback:
                raise ValueError("Only loopback targets are allowed by this runner")
        except ValueError as exc:
            if "Only loopback" in str(exc):
                raise
            raise ValueError("Target hostname must be localhost or a loopback IP literal") from exc
    port = parsed.port or 80
    scope_host = f"[{host}]" if ":" in host else host
    return host, port, value.rstrip("/"), scope_host


async def run(args) -> Path:
    host, port, target, scope_host = require_loopback_url(args.target)
    scope = ScopeValidator(
        in_scope_assets=[f"http://{scope_host}:{port}"],
        allowed_ports=[port],
        allowed_schemes=["http"],
        scope_notes=f"{args.authorization_record}; operator-owned loopback Juice Shop only",
    )
    engine = EvidenceCapturingRequestEngine(
        scope_validator=scope,
        rate_limit_rps=args.rps,
        max_concurrency=1,
    )

    # Verify the actual target software through a real, scope-gated HTTP request.
    engine.current_phase = "preflight"
    preflight = await engine.execute(RequestSpec(
        url=target,
        method="GET",
        authorization_confirmed=True,
    ))
    if not preflight.success or preflight.response_status != 200:
        raise RuntimeError(f"Live target preflight failed: HTTP {preflight.response_status}; {preflight.transport_error}")
    body = (preflight.response_body or "").casefold()
    if "juice shop" not in body:
        raise RuntimeError("Live target did not identify itself as Juice Shop; refusing to scan an unverified service")
    engine.current_phase = None

    campaign_id = str(uuid.uuid4())
    executor = CampaignExecutor(
        scope_validator=scope,
        safe_mode=True,
        rate_limit_rps=args.rps,
        max_concurrency=1,
        campaign_budget=args.campaign_budget,
        target_budget=args.campaign_budget,
        check_budget=args.check_budget,
        recon_budget=args.recon_budget,
    )
    # Inject only the real transport engine so all checks and verifiers use the
    # same scope, request policy, network connection path, and evidence capture.
    executor.request_engine = engine
    engine.request_budget_reserver = executor.budget.reserve_request

    started_at = datetime.now(timezone.utc).isoformat()
    result = await executor.execute_campaign(
        campaign_id=campaign_id,
        target_url=target,
        mode="SAFE_SCAN",
        selected_checks=None,
        enable_recon=True,
    )
    completed_at = datetime.now(timezone.utc).isoformat()
    coverage = CoverageValidator.build_coverage_report(result)

    output = Path(args.output_dir).resolve() / campaign_id
    output.mkdir(parents=True, exist_ok=False)
    all_check_ids = {check.id for check in registry.list_checks()}
    covered_ids = {record.check_id for record in coverage.records}
    coverage_data = coverage.to_dict()
    coverage_data["registry"] = registry.get_registry_metadata()
    coverage_data["registry_reconciles"] = (all_check_ids == covered_ids)
    evidence_by_check: dict[str, list[dict]] = {}
    for item in engine.captured_evidence:
        if item.get("check_id"):
            evidence_by_check.setdefault(item["check_id"], []).append(item)
    for record in coverage_data.get("records", []):
        related = evidence_by_check.get(record.get("check_id"), [])
        record["real_request_count"] = len(related)
        record["request_evidence_ids"] = [item["evidence_id"] for item in related]
        record["verification_evidence_ids"] = [
            item["evidence_id"] for item in related if item.get("execution_phase") == "verification"
        ]

    findings = [finding_record(finding) for finding in result.findings]
    verified_reports = [report.model_dump(mode="json") for report in result.reports]
    summary = result.to_summary_dict()
    summary.update({"started_at": started_at, "completed_at": completed_at})
    summary["observed_engine_exchanges_including_preflight"] = len(engine.captured_evidence)
    summary["preflight_exchanges_outside_campaign_budget"] = 1
    summary["coverage_ids_match_loaded_registry"] = all_check_ids == covered_ids

    write_json(output / "summary.json", summary)
    write_json(output / "coverage.json", coverage_data)
    write_json(output / "endpoints.json", result.endpoints)
    write_json(output / "recon-result.json", result.recon_result or {})
    write_json(output / "findings.json", findings)
    write_json(output / "verified-reports.json", verified_reports)
    write_json(output / "request-evidence.json", engine.captured_evidence)
    write_json(output / "audit-trail.json", result.audit_trail)
    write_json(output / "safety-events.json", result.safety_events)
    write_json(output / "budget-events.json", result.budget_events)

    md = [
        "# Live AihaX 86-Check Registry Run with Recon",
        "",
        "## Run facts",
        "",
        f"- Target: `{sanitize_url(target)}`",
        f"- Authorization record: {args.authorization_record}",
        f"- Campaign ID: `{campaign_id}`",
        f"- Time: {started_at} to {completed_at}",
        f"- Registry checks: {len(all_check_ids)}; coverage records: {len(covered_ids)}; exact ID match: {all_check_ids == covered_ids}",
        f"- Checks executed: {result.checks_executed}; requests used: {result.requests_used}/{result.requests_budget}",
        f"- Live discovered endpoints: {len(result.endpoints)}; endpoint parameters: {result.parameters_discovered}",
        f"- Candidate findings: {result.candidates_count}; independently verified: {result.verified_findings_count}; rejected: {result.rejected_candidates_count}; inconclusive: {result.inconclusive_results_count}",
        f"- Captured real RequestEngine exchanges (including verifiers): {len(engine.captured_evidence)}",
        "- Recon requests and discovered endpoint metadata are captured in the same campaign evidence; only checks that consume endpoint metadata are counted as endpoint-tested.",
        "- Endpoint URLs, methods, discovered parameters, and discovery source are preserved in `endpoints.json`.",
        "",
        "## Verified reports",
        "",
    ]
    if not verified_reports:
        md.append("No verified report was produced by this run.")
    for report in verified_reports:
        md.extend([
            f"### {report.get('title', 'Verified finding')} ({report.get('severity', 'unknown')})",
            "",
            str(report.get("summary", "")),
            "",
            f"- Affected URL: `{sanitize_url(report.get('affected_url', ''))}`",
            f"- CWE: {report.get('cwe') or 'not assigned by registry'}",
            f"- Remediation: {report.get('suggested_fix', '')}",
            "",
            "#### Reproduction request",
            "",
            "```http",
            safe_text(report.get("proof_of_concept", {}).get("request"), 2000) or "",
            "```",
            "",
            "#### Observed response (redacted)",
            "",
            "```http",
            safe_text(report.get("proof_of_concept", {}).get("response"), 3000) or "",
            "```",
            "",
        ])
    (output / "report.md").write_text("\n".join(md) + "\n", encoding="utf-8")

    manifest = {
        "campaign_id": campaign_id,
        "target": sanitize_url(target),
        "authorization_record": args.authorization_record,
        "registry": registry.get_registry_metadata(),
        "files_sha256": {},
    }
    for path in sorted(output.iterdir()):
        if path.is_file() and path.name != "manifest.json":
            manifest["files_sha256"][path.name] = hashlib.sha256(path.read_bytes()).hexdigest()
    write_json(output / "manifest.json", manifest)
    return output


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--target", default="http://127.0.0.1:3001")
    parser.add_argument("--authorization-record", required=True,
                        help="Operator authorization/provisioning note for the local Juice Shop deployment")
    parser.add_argument("--output-dir", default="reports/live-86-assessments")
    parser.add_argument("--rps", type=int, default=1)
    parser.add_argument("--campaign-budget", type=int, default=2000)
    parser.add_argument("--check-budget", type=int, default=20)
    parser.add_argument("--recon-budget", type=int, default=100,
                        help="Maximum recon exchanges within the campaign and target budgets")
    args = parser.parse_args()
    if not args.authorization_record.strip():
        parser.error("--authorization-record must not be blank")
    try:
        output = asyncio.run(run(args))
    except Exception as exc:
        print(f"Live assessment stopped: {type(exc).__name__}: {exc}", file=sys.stderr)
        return 2
    print(output)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
