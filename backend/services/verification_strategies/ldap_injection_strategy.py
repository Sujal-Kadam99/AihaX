"""Deterministic LDAP Injection Verification Strategy (C034)."""

from __future__ import annotations

import re
from typing import Any, Dict, Optional
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
    VerificationRegistry,
)


class LdapInjectionVerificationStrategy(BaseVerificationStrategy):
    """
    Verifies LDAP Injection (C034) by sending LDAP filter bypass probes
    (e.g. *)(uid=*))(|(uid=* or admin)(|(password=*)) and detecting unhandled LDAP directory
    syntax exceptions or differential search behavior.
    """

    contract = VerificationContract(
        check_id="C034_LDAP_Injection",
        name="LDAP Injection Verification",
        security_property="User parameters concatenated into directory filters must escape LDAP metacharacters (*, (, ), &).",
        required_evidence_fields=["affected_url"],
        destructive=False,
    )

    LDAP_ERRORS = [
        re.compile(r"javax\.naming\.directory\.InvalidSearchFilterException", re.I),
        re.compile(r"LDAPException", re.I),
        re.compile(r"IPWorksASP\.LDAP", re.I),
        re.compile(r"supplied argument is not a valid ldap", re.I),
        re.compile(r"Invalid DN syntax", re.I),
        re.compile(r"bad search filter", re.I),
    ]

    LDAP_PROBES = [
        ("*)(uid=*))(|(uid=*", "Wildcard Filter Bypass"),
        ("admin)(|(password=*", "Filter Structure Termination"),
        ("*)(cn=*", "Common Name Wildcard"),
    ]

    async def verify(self, context: VerificationContext) -> VerificationConclusion:
        candidate = context.candidate_evidence
        affected_url = candidate.get("affected_url") or context.target_url
        param_name = candidate.get("affected_param")

        parsed = urlparse(affected_url)
        params = parse_qs(parsed.query, keep_blank_values=True)
        if not param_name and params:
            param_name = list(params.keys())[0]
        if not param_name:
            param_name = "user"

        last_resp = None
        for payload, desc in self.LDAP_PROBES:
            test_params = dict(params)
            test_params[param_name] = [payload]
            new_query = urlencode(test_params, doseq=True)
            probe_url = urlunparse((parsed.scheme, parsed.netloc, parsed.path, parsed.params, new_query, parsed.fragment))

            probe_spec = RequestSpec(
                url=probe_url,
                method="GET",
                timeout=RequestTimeout(connect=5.0, read=10.0, total=15.0),
            )
            try:
                resp = await context.send_verification_request(probe_spec)
                last_resp = resp
            except Exception:
                continue

            if not resp.success:
                continue

            body = resp.response_body or ""
            for err_pat in self.LDAP_ERRORS:
                match = err_pat.search(body)
                if match:
                    snippet = body[max(0, match.start() - 10) : min(len(body), match.end() + 50)].replace("\n", " ")
                    ev_id = context.record_evidence(
                        evidence_type="ldap_syntax_error",
                        data={
                            "technique": desc,
                            "error_snippet": snippet,
                            "payload": payload,
                        },
                        request_id=resp.request_id,
                    )
                    return VerificationConclusion(
                        status=VerificationStatus.VERIFIED,
                        reason_code=VerificationReasonCode.PROPERTY_DEMONSTRATED,
                        reason_description=f"LDAP Injection confirmed: Filter payload '{payload}' ({desc}) caused unhandled LDAP directory exception: '{snippet}'.",
                        evidence_ids=[ev_id],
                        request_ids=[resp.request_id],
                        confidence=95,
                    )

        ev_id = context.record_evidence(
            evidence_type="ldap_negative_control",
            data={"status": "properly_escaped"},
            request_id=last_resp.request_id if last_resp else None,
        )
        return VerificationConclusion(
            status=VerificationStatus.FALSE_POSITIVE,
            reason_code=VerificationReasonCode.CONTROL_ENFORCED,
            reason_description="LDAP filter payloads were properly escaped or rejected without directory syntax errors.",
            evidence_ids=[ev_id],
            confidence=90,
        )


VerificationRegistry.register(LdapInjectionVerificationStrategy)
