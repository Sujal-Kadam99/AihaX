"""Bounded OWASP ZAP adapter for its internal Docker daemon API.

Target traffic originates in the ZAP container and is constrained by a context
built only from the campaign's authorized scope. The adapter itself only sends
API requests to the fixed internal Docker service, never to an assessment URL.
"""

from __future__ import annotations

import asyncio
import os
import re
import time
import uuid
from typing import Any, Dict, Iterable, Optional
from urllib.parse import urlencode, urlparse
from urllib.request import Request, urlopen

from backend.core.scope_validator import ScopeValidator, validate_destination_safety


class ZapApiClient:
    def __init__(self, base_url: Optional[str] = None, api_key: Optional[str] = None) -> None:
        self.base_url = (base_url or os.getenv("AIHAX_ZAP_API_URL", "http://zap:8080")).rstrip("/")
        self.api_key = api_key or os.getenv("AIHAX_ZAP_API_KEY", "")
        parsed = urlparse(self.base_url)
        if parsed.scheme != "http" or parsed.hostname != "zap" or parsed.port != 8080:
            raise ValueError("ZAP API must use the private Docker service at http://zap:8080.")
        if not self.api_key:
            raise ValueError("AIHAX_ZAP_API_KEY is required.")

    def _get(self, path: str, params: Dict[str, Any]) -> Dict[str, Any]:
        query = urlencode({"apikey": self.api_key, **params})
        request = Request(f"{self.base_url}{path}?{query}", headers={"Accept": "application/json"}, method="GET")
        with urlopen(request, timeout=5) as response:
            import json
            return json.loads(response.read().decode("utf-8"))

    async def _api(self, path: str, **params: Any) -> Dict[str, Any]:
        return await asyncio.to_thread(self._get, path, params)

    async def run(
        self,
        *,
        target_url: str,
        scope_assets: Iterable[str],
        out_of_scope_assets: Iterable[str],
        active_scan: bool,
        max_urls: int,
        max_scan_minutes: int,
    ) -> Dict[str, Any]:
        name = f"aihax-{uuid.uuid4().hex[:10]}"
        context = await self._api("/JSON/context/action/newContext/", contextName=name)
        context_id = str(context.get("contextId", ""))
        if not context_id:
            raise RuntimeError("ZAP did not return a context ID.")
        scope_patterns = _scope_hosts(scope_assets)
        excluded_patterns = _scope_hosts(out_of_scope_assets)
        for host_pattern in scope_patterns:
            await self._api(
                "/JSON/context/action/includeInContext/",
                contextName=name,
                regex=host_pattern,
            )
        for pattern in excluded_patterns:
            await self._api(
                "/JSON/context/action/excludeFromContext/",
                contextName=name,
                regex=pattern,
            )
        await self._api("/JSON/ascan/action/setOptionMaxScanDurationInMins/", Integer=max_scan_minutes)
        spider = await self._api(
            "/JSON/spider/action/scan/",
            url=target_url,
            contextName=name,
            maxChildren=max_urls,
            recurse="true",
            subtreeOnly="true",
        )
        spider_id = str(spider.get("scan", ""))
        await self._wait_for_scan("/JSON/spider/view/status/", spider_id, timeout_seconds=90)
        await self._wait_for_passive_scan(timeout_seconds=30)
        active_scan_id = None
        if active_scan:
            active = await self._api(
                "/JSON/ascan/action/scan/",
                url=target_url,
                recurse="true",
                inScopeOnly="true",
                contextId=context_id,
            )
            active_scan_id = str(active.get("scan", ""))
            await self._wait_for_scan(
                "/JSON/ascan/view/status/",
                active_scan_id,
                timeout_seconds=max_scan_minutes * 60,
            )
        alerts = await self._api("/JSON/alert/view/alerts/", baseurl=target_url, start=0, count=500)
        version = await self._api("/JSON/core/view/version/")
        return {
            "status": "COMPLETED",
            "executed": True,
            "tool": "OWASP ZAP",
            "version": version.get("version", "UNKNOWN"),
            "configuration": {
                "context": name,
                "scope_patterns": scope_patterns,
                "excluded_patterns": excluded_patterns,
                "max_urls": max_urls,
                "active_scan": active_scan,
                "max_scan_minutes": max_scan_minutes,
            },
            "spider_scan_id": spider_id,
            "active_scan_id": active_scan_id,
            "alerts": alerts.get("alerts", []),
        }

    async def _wait_for_scan(self, status_path: str, scan_id: str, timeout_seconds: int) -> None:
        if not scan_id:
            raise RuntimeError("ZAP did not return a scan ID.")
        deadline = time.monotonic() + timeout_seconds
        while time.monotonic() < deadline:
            result = await self._api(status_path, scanId=scan_id)
            if int(result.get("status", 0)) >= 100:
                return
            await asyncio.sleep(1)
        stop_path = "/JSON/spider/action/stop/" if "spider" in status_path else "/JSON/ascan/action/stop/"
        try:
            await self._api(stop_path, scanId=scan_id)
        finally:
            raise TimeoutError(f"ZAP scan {scan_id} exceeded its time limit and was stopped.")

    async def _wait_for_passive_scan(self, timeout_seconds: int) -> None:
        deadline = time.monotonic() + timeout_seconds
        while time.monotonic() < deadline:
            result = await self._api("/JSON/pscan/view/recordsToScan/")
            if int(result.get("recordsToScan", 0)) <= 0:
                return
            await asyncio.sleep(1)


class ZapAdapter:
    def __init__(self, client: Optional[Any] = None) -> None:
        self.client = client

    async def scan(
        self,
        *,
        target_url: str,
        in_scope_assets: Iterable[str],
        out_of_scope_assets: Iterable[str],
        authorization_confirmed: bool,
        tool_selected: bool = True,
        authorization_record_id: Optional[str] = None,
        active_scan: bool = False,
        max_urls: int = 50,
        max_scan_minutes: int = 5,
    ) -> Dict[str, Any]:
        if not tool_selected:
            return {"status": "NOT_SELECTED", "tool": "OWASP ZAP", "reason": "ZAP was not selected for this campaign."}
        if not authorization_confirmed or not authorization_record_id:
            return {"status": "BLOCKED_AUTHORIZATION", "tool": "OWASP ZAP", "reason": "A confirmed campaign authorization record is required before sending target traffic."}
        if active_scan and (not authorization_confirmed or not authorization_record_id):
            return {"status": "BLOCKED_AUTHORIZATION", "tool": "OWASP ZAP", "reason": "Active scanning requires confirmed authorization and an authorization record ID."}
        if not (1 <= max_urls <= 100) or not (1 <= max_scan_minutes <= 10):
            return {"status": "BLOCKED_SAFETY", "tool": "OWASP ZAP", "reason": "ZAP limits must be at most 100 URLs and 10 minutes."}
        validator = ScopeValidator(
            in_scope_assets=list(in_scope_assets),
            out_of_scope_assets=list(out_of_scope_assets),
        )
        decision = validator.validate_target(target_url)
        safe, safety_reason = validate_destination_safety(target_url)
        if not decision.allowed:
            return {"status": "BLOCKED_SCOPE", "tool": "OWASP ZAP", "reason": decision.reason}
        if not safe:
            return {"status": "BLOCKED_SAFETY", "tool": "OWASP ZAP", "reason": safety_reason}
        try:
            client = self.client or ZapApiClient()
        except ValueError as exc:
            return {"status": "UNAVAILABLE", "tool": "OWASP ZAP", "reason": str(exc)}
        try:
            return await client.run(
                target_url=target_url,
                scope_assets=list(in_scope_assets),
                out_of_scope_assets=list(out_of_scope_assets),
                active_scan=active_scan,
                max_urls=max_urls,
                max_scan_minutes=max_scan_minutes,
            )
        except Exception as exc:
            return {"status": "FAILED", "tool": "OWASP ZAP", "reason": f"ZAP adapter failed: {type(exc).__name__}: {exc}"}


def _scope_hosts(scope_assets: Iterable[str]) -> list[str]:
    patterns = []
    for raw in scope_assets:
        value = str(raw).strip()
        if not value:
            continue
        parsed = urlparse(value if "://" in value else f"https://{value}")
        host = parsed.hostname or ""
        if not host:
            continue
        if host.startswith("*."):
            host = host[2:]
            prefix = r"(?:[a-z0-9-]+\.)*"
        else:
            prefix = ""
        port = f":{parsed.port}" if parsed.port else r"(?::[0-9]+)?"
        path = parsed.path.rstrip("/")
        path_pattern = re.escape(path) + r"(?:/.*)?" if path else r"(?:/.*)?"
        patterns.append(r"^https?://" + prefix + re.escape(host) + port + path_pattern + r"(?:\?.*)?$")
    return sorted(set(patterns))
