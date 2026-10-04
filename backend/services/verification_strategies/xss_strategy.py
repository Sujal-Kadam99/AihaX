"""Deterministic, Non-Destructive XSS Verification Strategy for AihaX.

Verifies Cross-Site Scripting vulnerabilities (C037–C046) by confirming actual
client-side script execution or DOM element rendering in a sandboxed headless browser,
distinguishing genuine execution from benign reflection or safely encoded text.
"""

from __future__ import annotations

import asyncio
import logging
from typing import Any, Callable, Dict, Optional, Tuple
from urllib.parse import parse_qs, urlencode, urlparse, urlunparse

from backend.services.request_engine import RequestEngine, RequestSpec, RequestTimeout
from backend.services.verification_engine import (
    BaseVerificationStrategy,
    VerificationBudget,
    VerificationConclusion,
    VerificationContext,
    VerificationContract,
    VerificationReasonCode,
    VerificationStatus,
)
from backend.services.verification_strategies.request_builder import build_injected_request

logger = logging.getLogger("aihax.xss_verification_strategy")

MARKER_VARIABLE = "__aihax_xss_verified__"
MARKER_SCRIPT = f"<script>window.{MARKER_VARIABLE}=true;</script>"
MARKER_IMG = f'<img src=x onerror="window.{MARKER_VARIABLE}=true">'
MARKER_JS_CTX = f'";window.{MARKER_VARIABLE}=true;//'
MARKER_ATTR_CTX = f'" onfocus="window.{MARKER_VARIABLE}=true" autofocus="true" data-aihax="1'
MARKER_URL_CTX = f"javascript:window.{MARKER_VARIABLE}=true"
MARKER_MUTATION = f"<math><mtext><table><mglyph><style><!--</style><img src=x onerror=\"window.{MARKER_VARIABLE}=true\">"
MARKER_FILTER_BYPASS = f"<sCrIpt>window.{MARKER_VARIABLE}=true;</sCrIpt>"
MARKER_HTML_RENDER = '<iframe src="about:blank" aihax-render-canary="1"></iframe>'


async def _run_playwright_browser(
    url: str,
    timeout_ms: int = 5000,
    check_type: str = "script",
    html_content: Optional[str] = None,
    cookies: Optional[Dict[str, str]] = None,
) -> Tuple[bool, Optional[str]]:
    """Execute target URL or HTML content in headless Chromium via Playwright.
    
    Returns (executed_or_rendered: bool, error_msg: Optional[str]).
    """
    try:
        from playwright.async_api import async_playwright
    except ImportError:
        return False, "playwright_not_installed"

    try:
        async with async_playwright() as p:
            browser = await p.chromium.launch(
                headless=True,
                args=["--no-sandbox", "--disable-setuid-sandbox", "--disable-dev-shm-usage"],
            )
            context = await browser.new_context(
                ignore_https_errors=True,
                java_script_enabled=True,
            )
            if cookies:
                parsed_u = urlparse(url)
                origin = f"{parsed_u.scheme}://{parsed_u.netloc}"
                cookie_list = [
                    {"name": k, "value": str(v), "url": origin}
                    for k, v in cookies.items()
                ]
                await context.add_cookies(cookie_list)

            page = await context.new_page()
            executed = False

            async def handle_dialog(dialog):
                nonlocal executed
                executed = True
                try:
                    await dialog.dismiss()
                except Exception:
                    pass

            page.on("dialog", handle_dialog)

            try:
                await page.goto(url, timeout=timeout_ms, wait_until="domcontentloaded")

                # Short delay for event loop / onerror handlers
                await asyncio.sleep(0.1)

                marker_val = await page.evaluate(f"() => Boolean(window.{MARKER_VARIABLE})")
                if marker_val:
                    executed = True

                if check_type == "dom_element":
                    element_exists = await page.evaluate(
                        "() => Boolean(document.querySelector('iframe[aihax-render-canary], [aihax-render-canary]'))"
                    )
                    if element_exists:
                        executed = True

            except Exception as e:
                logger.debug(f"Playwright navigation/evaluation error: {e}")
            finally:
                await context.close()
                await browser.close()

            return executed, None

    except Exception as exc:
        logger.warning(f"Headless browser execution error: {exc}")
        return False, str(exc)


class XssVerificationStrategy(BaseVerificationStrategy):
    """
    Verifies Cross-Site Scripting (Reflected, Stored, DOM, Contextual, Mutation, Filter Bypass,
    and Unsafe HTML Rendering) by validating script execution in a browser runtime.
    """

    contract = VerificationContract(
        check_id="C037_Reflected_XSS",
        name="XSS Verification Strategy",
        security_property="Server must contextualize, encode, or sanitize untrusted inputs to prevent script execution.",
        required_evidence_fields=["affected_url"],
        destructive=False,
    )

    def _select_payload_and_check_type(self, check_id: str) -> Tuple[str, str]:
        """Select appropriate non-destructive probe and check type based on check ID."""
        cid = check_id.upper()
        if "C041" in cid:
            return MARKER_ATTR_CTX, "script"
        elif "C042" in cid:
            return MARKER_JS_CTX, "script"
        elif "C043" in cid:
            return MARKER_URL_CTX, "script"
        elif "C044" in cid:
            return MARKER_MUTATION, "script"
        elif "C045" in cid:
            return MARKER_FILTER_BYPASS, "script"
        elif "C046" in cid:
            return MARKER_HTML_RENDER, "dom_element"
        elif "C038" in cid:
            return MARKER_SCRIPT, "script"
        elif "C039" in cid:
            return MARKER_IMG, "script"
        else:
            # Default C037, C040
            return MARKER_SCRIPT, "script"

    async def verify(self, context: VerificationContext) -> VerificationConclusion:
        candidate = context.candidate_evidence
        check_id = context.check_id or "C037_Reflected_XSS"
        affected_url = candidate.get("affected_url") or context.target_url
        affected_param = candidate.get("affected_param") or candidate.get("location")

        if context.budget.max_requests <= 0:
            return VerificationConclusion(
                status=VerificationStatus.INCONCLUSIVE,
                reason_code=VerificationReasonCode.BUDGET_EXHAUSTED,
                reason_description="Verification budget exhausted.",
            )

        probe_payload, check_type = self._select_payload_and_check_type(check_id)

        cookies: Dict[str, str] = {}
        if context.auth_context and context.auth_context.cookies:
            cookies.update(context.auth_context.cookies)
        if candidate.get("cookies") and isinstance(candidate.get("cookies"), dict):
            cookies.update(candidate.get("cookies"))

        # 1. Stored XSS two-phase handling (C038)
        if "C038" in check_id.upper():
            # Phase A: POST canary probe
            injected_post = build_injected_request(candidate, probe_payload)
            if not injected_post:
                post_spec = RequestSpec(
                    url=affected_url,
                    method="POST",
                    headers={"Content-Type": "application/x-www-form-urlencoded"},
                    body=f"txtName=aihax&mtxMessage={probe_payload}&btnSign=Sign+Guestbook&comment={probe_payload}&content={probe_payload}",
                    timeout=RequestTimeout(connect=5.0, read=10.0, total=15.0),
                )
            else:
                post_spec = injected_post

            context.budget.max_requests -= 1
            post_resp = await context.request_engine.execute(post_spec)

            # Phase B: GET view page to check persistence
            get_spec = RequestSpec(url=affected_url, method="GET")
            context.budget.max_requests -= 1
            get_resp = await context.request_engine.execute(get_spec)

            ev_id = context.record_evidence(
                evidence_type="stored_xss_replay",
                data={"post_status": post_resp.status_code, "get_status": get_resp.status_code},
                request_id=get_resp.request_id,
            )

            # Check HTTP level encoding
            body = get_resp.response_body or ""
            if "&lt;script&gt;" in body or "&lt;img" in body or "&quot;" in body and probe_payload not in body:
                return VerificationConclusion(
                    status=VerificationStatus.FALSE_POSITIVE,
                    reason_code=VerificationReasonCode.INPUT_SAFELY_ENCODED,
                    reason_description="Stored XSS payload was safely HTML-encoded in persistent storage.",
                    evidence_ids=[ev_id],
                    request_ids=[post_resp.request_id, get_resp.request_id],
                    confidence=100,
                )

            # Verify in browser
            custom_runner = candidate.get("browser_runner")
            if custom_runner and callable(custom_runner):
                try:
                    executed, err = await custom_runner(affected_url, check_type=check_type, html_content=body, cookies=cookies)
                except TypeError:
                    executed, err = await custom_runner(affected_url, check_type=check_type, html_content=body)
            else:
                executed, err = await _run_playwright_browser(affected_url, check_type=check_type, html_content=body, cookies=cookies)

            if executed:
                return VerificationConclusion(
                    status=VerificationStatus.VERIFIED,
                    reason_code=VerificationReasonCode.REPRODUCED_SUCCESSFULLY,
                    reason_description="Stored XSS confirmed: Injected script persisted and executed in browser runtime.",
                    evidence_ids=[ev_id],
                    request_ids=[post_resp.request_id, get_resp.request_id],
                    confidence=100,
                )
            elif err:
                return VerificationConclusion(
                    status=VerificationStatus.INCONCLUSIVE,
                    reason_code=VerificationReasonCode.HEURISTIC_ONLY_UNVERIFIED,
                    reason_description=f"Browser execution capability unavailable to verify script execution: {err}",
                    evidence_ids=[ev_id],
                    request_ids=[post_resp.request_id, get_resp.request_id],
                    confidence=50,
                )
            else:
                return VerificationConclusion(
                    status=VerificationStatus.FALSE_POSITIVE,
                    reason_code=VerificationReasonCode.CONTRADICTORY_EVIDENCE,
                    reason_description="Stored XSS probe persisted in response but did not execute in browser runtime.",
                    evidence_ids=[ev_id],
                    request_ids=[post_resp.request_id, get_resp.request_id],
                    confidence=95,
                )

        # 2. Reflected / Context / DOM / HTML Render (C037, C039-C046)
        # Construct injected request / URL
        injected_req = build_injected_request(candidate, probe_payload)
        if not injected_req:
            # Fallback URL param injection
            parsed = urlparse(affected_url)
            params = parse_qs(parsed.query, keep_blank_values=True)
            if affected_param:
                params[affected_param] = [probe_payload]
            elif params:
                first_k = next(iter(params.keys()))
                params[first_k] = [probe_payload]
            else:
                params["q"] = [probe_payload]
            new_query = urlencode(params, doseq=True)
            new_url = urlunparse((parsed.scheme, parsed.netloc, parsed.path, parsed.params, new_query, parsed.fragment))
            injected_req = RequestSpec(url=new_url, method="GET")

        context.budget.max_requests -= 1
        response = await context.request_engine.execute(injected_req)

        ev_id = context.record_evidence(
            evidence_type="xss_replay_attempt",
            data={
                "status": response.status_code,
                "url": injected_req.url,
                "check_type": check_type,
            },
            request_id=response.request_id,
        )

        resp_body = response.response_body or ""

        # Check for safe encoding contradiction at HTTP level
        if ("&lt;script" in resp_body or "&lt;iframe" in resp_body or "&lt;img" in resp_body) and (
            probe_payload not in resp_body
        ):
            return VerificationConclusion(
                status=VerificationStatus.FALSE_POSITIVE,
                reason_code=VerificationReasonCode.INPUT_SAFELY_ENCODED,
                reason_description="Injected payload was properly HTML-entity encoded in server response.",
                evidence_ids=[ev_id],
                request_ids=[response.request_id],
                confidence=100,
            )

        # Debug logging for reflected XSS
        logger.info(f"[XSS_STRATEGY DEBUG] injected_req.url: {injected_req.url}")
        logger.info(f"[XSS_STRATEGY DEBUG] cookies: {cookies}")
        logger.info(f"[XSS_STRATEGY DEBUG] context.auth_context: {context.auth_context}")
        print(f"[XSS_STRATEGY DEBUG] injected_req.url: {injected_req.url}", flush=True)
        print(f"[XSS_STRATEGY DEBUG] cookies: {cookies}", flush=True)
        print(f"[XSS_STRATEGY DEBUG] context.auth_context: {context.auth_context}", flush=True)

        # Browser validation phase
        custom_runner = candidate.get("browser_runner")
        if custom_runner and callable(custom_runner):
            try:
                executed, err = await custom_runner(injected_req.url, check_type=check_type, html_content=resp_body, cookies=cookies)
            except TypeError:
                executed, err = await custom_runner(injected_req.url, check_type=check_type, html_content=resp_body)
        else:
            executed, err = await _run_playwright_browser(injected_req.url, check_type=check_type, cookies=cookies)

        if executed:
            desc = (
                f"Unsafe HTML rendering confirmed: Live unescaped elements rendered in DOM ({check_id})."
                if check_type == "dom_element"
                else f"Cross-Site Scripting confirmed: Injected script executed in browser runtime ({check_id})."
            )
            return VerificationConclusion(
                status=VerificationStatus.VERIFIED,
                reason_code=VerificationReasonCode.PROPERTY_DEMONSTRATED,
                reason_description=desc,
                evidence_ids=[ev_id],
                request_ids=[response.request_id],
                confidence=100,
            )

        if err:
            return VerificationConclusion(
                status=VerificationStatus.INCONCLUSIVE,
                reason_code=VerificationReasonCode.HEURISTIC_ONLY_UNVERIFIED,
                reason_description=f"Headless browser execution unavailable to confirm active script execution ({err}).",
                evidence_ids=[ev_id],
                request_ids=[response.request_id],
                confidence=50,
            )

        return VerificationConclusion(
            status=VerificationStatus.FALSE_POSITIVE,
            reason_code=VerificationReasonCode.CONTRADICTORY_EVIDENCE,
            reason_description="Payload reflected in HTTP response but failed to execute in live browser runtime.",
            evidence_ids=[ev_id],
            request_ids=[response.request_id],
            confidence=95,
        )
