"""Bounded CLI/API adapters used by VulnerabilityTestingAgent.

All executable tools are dispatched through ToolExecutionBoundary. Arguments are
constructed here from validated campaign data; callers never supply raw argv.
"""

from __future__ import annotations

import re
import tempfile
from pathlib import Path
from typing import Any, Dict, Iterable, List, Optional
from urllib.parse import urlparse, urlunparse

from backend.execution.tool_execution_boundary import (
    ExecutionProfile,
    ToolExecutionBoundary,
    ToolExecutionRequest,
)
from backend.services.vulnerability_hypothesis_engine import VulnerabilityHypothesis


_WORDLIST = (
    "api", "app", "auth", "admin", "assets", "backup", "config", "docs", "health",
    "login", "logout", "old", "private", "robots.txt", "server-status", "sitemap.xml",
    "static", "status", "swagger", "uploads", "user", "users", "v1", "v2", "www",
)
_SAFE_VERSION = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._+:/ -]{0,79}$")


class VulnerabilityToolAdapters:
    """Execute only bounded profiles that are supported by the installed tool."""

    def __init__(self, boundary: Optional[ToolExecutionBoundary] = None) -> None:
        self.boundary = boundary or ToolExecutionBoundary()

    async def run(
        self,
        *,
        name: str,
        target_url: str,
        hypotheses: List[VulnerabilityHypothesis],
        campaign_id: str,
        authorization_confirmed: bool,
        in_scope_assets: List[str],
        out_of_scope_assets: List[str],
        rate_limit_rps: int,
        max_requests: int,
        db: Any = None,
        technology_versions: Optional[List[str]] = None,
    ) -> Dict[str, Any]:
        """Run a tool profile and return honest status, output summary, and evidence hashes."""
        key = name.strip().lower()
        related = [h for h in hypotheses if self._is_relevant(key, h)]
        if key == "searchsploit" and technology_versions:
            # SearchSploit is a local reference lookup; results remain unverified leads.
            query = next((v.strip() for v in technology_versions if _SAFE_VERSION.fullmatch(v.strip())), None)
            if query:
                return await self._run_searchsploit(
                    query=query,
                    target_url=target_url,
                    campaign_id=campaign_id,
                    in_scope_assets=in_scope_assets,
                    out_of_scope_assets=out_of_scope_assets,
                    db=db,
                )
        if not related:
            return {"tool": key, "status": "NOT_APPLICABLE", "reason": "No generated hypothesis or recon version evidence applies to this tool."}
        if not authorization_confirmed:
            return {"tool": key, "status": "BLOCKED_AUTHORIZATION", "reason": "Active authorization is required."}
        if max_requests <= 0:
            return {"tool": key, "status": "BLOCKED_BUDGET", "reason": "Campaign request budget is exhausted."}

        profile, args, timeout = self._build_profile(
            key, target_url, related, rate_limit_rps=max(1, rate_limit_rps),
            max_requests=max(1, max_requests),
        )
        if profile is None:
            return {"tool": key, **args}
        request = ToolExecutionRequest(
            campaign_id=campaign_id,
            target=target_url,
            tool_name=key,
            execution_profile=profile,
            args=args,
            timeout_seconds=timeout,
            authorization_confirmed=authorization_confirmed,
            execution_mode="AUTHORIZED_LIVE_RECON",
            in_scope_assets=in_scope_assets,
            out_of_scope_assets=out_of_scope_assets,
        )
        result = await self.boundary.execute(request, db=db)
        for arg in args:
            if arg.startswith(tempfile.gettempdir()) and Path(arg).is_file():
                try:
                    Path(arg).unlink()
                except OSError:
                    pass
        status_map = {
            "SUCCESS": "COMPLETED",
            "NOT_INSTALLED": "UNAVAILABLE",
            "BLOCKED_SCOPE": "BLOCKED_SCOPE",
            "BLOCKED_SAFETY": "BLOCKED_SAFETY",
            "BLOCKED_AUTHORIZATION": "BLOCKED_AUTHORIZATION",
            "TIMEOUT": "TIMEOUT",
            "OUTPUT_LIMIT": "OUTPUT_LIMIT",
        }
        return {
            "tool": key,
            "status": status_map.get(result.execution_status, result.execution_status),
            "executed": result.execution_status in {"SUCCESS", "PROCESS_ERROR", "TIMEOUT", "OUTPUT_LIMIT"},
            "version": result.tool_version or "UNKNOWN",
            "configuration": {"profile": profile, "timeout_seconds": result.timeout_seconds, "arguments": result.sanitized_args},
            "exit_code": result.exit_code,
            "summary": result.parsed_summary,
            "stdout_hash": result.stdout_hash,
            "stderr_hash": result.stderr_hash,
            "evidence_hash": result.output_hash,
            "reason": result.error_category,
            "related_hypothesis_ids": [h.hypothesis_id for h in related],
            "request_count": None,
            "request_budget_enforcement": "TOOL_PROFILE_ONLY",
            "request_count_note": "The tool does not expose a reliable request count. Rate, concurrency, duration, and profile limits are applied where supported; this is not a hard per-request campaign budget cap.",
        }

    async def _run_searchsploit(
        self, *, query: str, target_url: str, campaign_id: str,
        in_scope_assets: List[str], out_of_scope_assets: List[str], db: Any,
    ) -> Dict[str, Any]:
        request = ToolExecutionRequest(
            campaign_id=campaign_id,
            target=target_url,
            tool_name="searchsploit",
            execution_profile=ExecutionProfile.OFFLINE_REFERENCE_LOOKUP.value,
            args=["--json", query],
            timeout_seconds=20,
            authorization_confirmed=True,
            execution_mode="AUTHORIZED_LIVE_RECON",
            in_scope_assets=in_scope_assets or [target_url],
            out_of_scope_assets=out_of_scope_assets,
        )
        result = await self.boundary.execute(request, db=db)
        status = "OFFLINE_LEADS" if result.execution_status == "SUCCESS" else result.execution_status
        return {
            "tool": "searchsploit",
            "status": status,
            "executed": result.execution_status in {"SUCCESS", "PROCESS_ERROR", "TIMEOUT", "OUTPUT_LIMIT"},
            "version": result.tool_version or "UNKNOWN",
            "configuration": {"profile": ExecutionProfile.OFFLINE_REFERENCE_LOOKUP.value, "query": query},
            "exit_code": result.exit_code,
            "summary": result.parsed_summary,
            "stdout_hash": result.stdout_hash,
            "stderr_hash": result.stderr_hash,
            "evidence_hash": result.output_hash,
            "reason": result.error_category,
            "finding_status": "LEAD_ONLY_NOT_VERIFIED",
            "request_count": 0,
        }
    def _is_relevant(self, name: str, hyp: VulnerabilityHypothesis) -> bool:
        cid = hyp.check_id.upper()
        if name == "sqlmap":
            return cid in {"C023", "C024"} and bool(hyp.parameter)
        if name == "commix":
            return cid in {"C026", "C027"} and bool(hyp.parameter)
        if name == "nikto":
            return cid in {"C002", "C010", "C011", "C047", "C048", "C049", "C050", "C052", "C065"}
        if name in {"ffuf", "dirsearch"}:
            return bool(hyp.endpoint)
        if name == "metasploit":
            return cid in {"C011", "C047", "C048", "C049", "C050", "C052", "C065"}
        if name == "routersploit":
            return any(token in (hyp.endpoint + " " + hyp.expected_signal).lower() for token in ("router", "firmware", "embedded"))
        if name == "beef":
            return cid in {"C037", "C038"}
        if name == "searchsploit":
            return False
        return False

    def _build_profile(
        self,
        name: str,
        target: str,
        hypotheses: List[VulnerabilityHypothesis],
        *,
        rate_limit_rps: int,
        max_requests: int,
    ) -> tuple[Optional[str], Any, int]:
        hyp = hypotheses[0]
        cap = min(max_requests, 25)
        if name == "nikto":
            return ExecutionProfile.BOUNDED_VULNERABILITY_CHECK.value, [
                "-h", target, "-nointeractive", "-maxtime", "3m", "-Tuning", "1235b", "-Pause", str(max(0.5, 1 / rate_limit_rps)),
            ], 180
        if name in {"ffuf", "dirsearch"}:
            wordlist_file = Path(tempfile.gettempdir()) / f"aihax-vta-{name}-paths.txt"
            wordlist_file.write_text("\n".join(_WORDLIST[:cap]) + "\n", encoding="utf-8")
            base = _directory_base(target)
            if name == "ffuf":
                return ExecutionProfile.BOUNDED_CONTENT_DISCOVERY.value, [
                    "-w", str(wordlist_file), "-u", base.rstrip("/") + "/FUZZ", "-rate", str(min(rate_limit_rps, 2)),
                    "-maxtime", "30", "-t", "1", "-mc", "all", "-fc", "404", "-s",
                ], 45
            return ExecutionProfile.BOUNDED_CONTENT_DISCOVERY.value, [
                "-u", base, "-w", str(wordlist_file), "--threads", "1", "--max-rate", str(min(rate_limit_rps, 2)),
                "--max-time", "30", "--format", "simple", "--quiet",
            ], 45
        if name == "sqlmap":
            return ExecutionProfile.BOUNDED_VULNERABILITY_CHECK.value, [
                "-u", hyp.endpoint, "-p", hyp.parameter or "", "--batch", "--smart", "--risk=1", "--level=1",
                "--threads=1", "--timeout=5", "--retries=0", "--technique=BEU", "--delay", str(max(0.5, 1 / rate_limit_rps)),
            ], 60
        if name == "commix":
            return ExecutionProfile.BOUNDED_VULNERABILITY_CHECK.value, [
                "--url", hyp.endpoint, "--batch", "--level=1", "--risk=1", "--technique=CT",
                "--timeout=5", "--retries=0", "--skip-heuristics", "--delay", str(max(0.5, 1 / rate_limit_rps)),
            ], 60
        if name == "searchsploit":
            return None, {"status": "NOT_RUN_NO_VERSION_EVIDENCE", "reason": "Recon did not provide a normalized product/version pair."}, 0
        if name in {"metasploit", "routersploit", "beef"}:
            # These frameworks need per-module reviewed profiles or a controlled browser
            # session. Do not fall back to interactive consoles or arbitrary modules.
            return None, {"status": "BLOCKED_SAFE_PROFILE", "reason": f"No audited bounded execution profile is registered for {name}; arbitrary modules and browser commands are disabled."}, 0
        return None, {"status": "UNSUPPORTED", "reason": "No adapter profile is registered."}, 0


def _directory_base(url: str) -> str:
    parsed = urlparse(url)
    return urlunparse((parsed.scheme, parsed.netloc, parsed.path.rstrip("/"), "", "", ""))
