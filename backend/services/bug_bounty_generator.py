"""Bug Bounty Report Generator Service."""

import json
import logging
from typing import Any, List, Optional

from backend.core.check_registry import registry
from backend.models.database import Finding
from backend.models.schemas import BugBountyFindingDTO, BugBountyPoCDTO

logger = logging.getLogger(__name__)

class BugBountyReportGenerator:
    def __init__(self, api_key: Optional[str] = None, settings: Any = None):
        self.api_key = api_key
        self.settings = settings

    async def generate_for_findings(self, findings: List[Finding]) -> List[BugBountyFindingDTO]:
        """Generate Bug Bounty DTOs for a list of verified findings."""
        verified_findings = [f for f in findings if f.verdict == "Verified" and not f.false_positive]
        
        dtos = []
        for finding in verified_findings:
            dto = await self._generate_single(finding)
            if dto:
                dtos.append(dto)
                
        return dtos

    async def _generate_single(self, finding: Finding) -> Optional[BugBountyFindingDTO]:
        # 1. Extract canonical metadata from Check Registry
        try:
            check_class = registry.get_check(finding.vuln_type)
            contract = check_class.contract
            vuln_type = getattr(contract, "vulnerability_type", finding.category)
            cwe = getattr(contract, "cwe", None)
            owasp_category = getattr(contract, "owasp_category", None)
            remediation_guidance = getattr(contract, "remediation_guidance", None)
            references = list(getattr(contract, "references", []))
        except KeyError:
            vuln_type = finding.category
            cwe = None
            owasp_category = None
            remediation_guidance = None
            references = []

        # Construct deterministic baseline fields with strict FACT vs [INFERENCE] separation
        param_desc = f" affecting parameter '{finding.affected_param}'" if finding.affected_param else ""
        cwe_desc = f" ({cwe})" if cwe else ""
        disposition = getattr(finding, "finding_disposition", "VULNERABILITY")
        is_hardening = disposition == "HARDENING_ONLY" or getattr(finding, "verification_status", "") == "HARDENING_ONLY"

        if is_hardening:
            default_summary = (
                f"FACT: Observed absence of recommended security control ({vuln_type}){cwe_desc} on {finding.affected_url}{param_desc}. "
                f"[INFERENCE]: Implementing this control provides defense-in-depth protection according to industry best practices."
            )
            default_steps = [
                f"1. Send an authorized HTTP request to target URL: '{finding.affected_url}'.",
                f"2. Inspect the server HTTP response headers and directives.",
                f"3. Observe that the recommended security control ({vuln_type}) is absent in the response.",
            ]
            confirmed_impact = (
                f"FACT: The server response omits the recommended defense-in-depth control on {finding.affected_url}. "
                f"No active exploitation or security boundary bypass was demonstrated."
            )
            potential_impact = (
                f"[INFERENCE] In specific threat scenarios, absence of this defense-in-depth control may weaken "
                f"client-side browser protections or transport security guarantees."
            )
        else:
            default_summary = (
                f"FACT: A verified {vuln_type} vulnerability{cwe_desc} was identified on {finding.affected_url}{param_desc}. "
                f"Deterministic verification confirmed a violation of the expected security boundary."
            )
            default_steps = [
                f"1. Send a request to target URL: '{finding.affected_url}'.",
            ]
            if finding.affected_param:
                default_steps.append(f"2. Supply input targeting parameter: '{finding.affected_param}'.")
            if finding.payload:
                default_steps.append(f"3. Transmit the verification payload: '{finding.payload}'.")
            default_steps.append("4. Observe that the server returns the verified proof response demonstrating the vulnerability condition.")

            confirmed_impact = (
                f"FACT: Observed server behavior on {finding.affected_url} conclusively demonstrates security property violation "
                f"supported by verified evidence artifacts."
            )
            potential_impact = (
                f"[INFERENCE] An attacker could leverage this {vuln_type} condition to compromise confidentiality or integrity "
                f"of data processed by the target application."
            )
        fix_guidance = remediation_guidance or "Implement proper input sanitization, strict authorization controls, and secure transport according to industry best practices."

        target_host = finding.affected_url.split('/')[2] if '//' in finding.affected_url else finding.affected_url

        # Default DTO base
        dto = BugBountyFindingDTO(
            title=finding.title,
            summary=default_summary,
            severity=finding.severity,
            confidence=finding.confidence,
            vulnerability_type=vuln_type,
            cwe=cwe,
            owasp_category=owasp_category,
            target=target_host,
            affected_url=finding.affected_url,
            steps_to_reproduce=default_steps,
            impact_confirmed=confirmed_impact,
            impact_potential=potential_impact,
            proof_of_concept=BugBountyPoCDTO(
                description="Deterministic request and response evidence captured during verification.",
                request=finding.proof_request or "",
                response=finding.proof_response or "",
                payload=finding.payload or "",
            ),
            suggested_fix=fix_guidance,
            references=references
        )

        # 2. LLM Enrichment (Optional)
        if self.api_key and self.settings:
            try:
                enriched = await self._call_llm_enrichment(finding, vuln_type)
                
                # Apply LLM enrichments safely (advisory only)
                if enriched.get("summary"):
                    dto.summary = str(enriched["summary"])
                if enriched.get("steps_to_reproduce") and isinstance(enriched["steps_to_reproduce"], list):
                    dto.steps_to_reproduce = [str(step) for step in enriched["steps_to_reproduce"]]
                if enriched.get("impact_confirmed"):
                    dto.impact_confirmed = str(enriched["impact_confirmed"])
                if enriched.get("impact_potential"):
                    dto.impact_potential = str(enriched["impact_potential"])
                if enriched.get("proof_of_concept_description"):
                    dto.proof_of_concept.description = str(enriched["proof_of_concept_description"])
                if enriched.get("suggested_fix"):
                    dto.suggested_fix = str(enriched["suggested_fix"])
                
            except Exception as e:
                logger.error(f"LLM enrichment failed for finding {finding.id}: {e}")

        # 3. Deterministic Evidence Override (Anti-Hallucination)
        # We MUST overwrite any LLM PoC values with the exact byte-for-byte evidence
        dto.proof_of_concept.request = finding.proof_request or (f"GET {finding.affected_url} HTTP/1.1" if finding.affected_url else "")
        dto.proof_of_concept.response = finding.proof_response or ""
        dto.proof_of_concept.payload = finding.payload or ""

        if not dto.steps_to_reproduce:
            dto.steps_to_reproduce = default_steps

        return dto

    async def _call_llm_enrichment(self, finding: Finding, vuln_type: str) -> dict:
        import anthropic
        
        client = anthropic.AsyncAnthropic(api_key=self.api_key, timeout=self.settings.claude_timeout)
        
        # We pass evidence as strictly untrusted text
        system_prompt = (
            "You are a strict technical report writer. "
            "You summarize vulnerability evidence into a JSON structure. "
            "NEVER invent or hallucinate URLs, payloads, parameters, requests, responses, or reproduction steps that are not explicitly present in the provided evidence. "
            "NEVER invent CVEs or references. "
            "Distinguish clearly between confirmed impact (what the evidence proves) and potential impact (what could theoretically happen)."
        )

        user_content = f"""
Vulnerability Type: {vuln_type}
Affected URL: {finding.affected_url}
Parameter: {finding.affected_param or 'None'}

Evidence Payload: 
```
{finding.payload or 'None'}
```

Evidence Request:
```
{finding.proof_request or 'None'}
```

Evidence Response Snippet:
```
{finding.proof_response or 'None'}
```

Return ONLY a JSON object with this exact schema:
{{
    "summary": "Short 2-3 sentence technical summary of what was found based strictly on evidence.",
    "steps_to_reproduce": [
        "1. ...",
        "2. ..."
    ],
    "impact_confirmed": "What the evidence actually proves happened.",
    "impact_potential": "What this vulnerability could theoretically lead to.",
    "proof_of_concept_description": "A short 1 sentence description of what the payload/request does.",
    "suggested_fix": "Generic mitigation advice."
}}
"""

        response = await client.messages.create(
            model=self.settings.claude_model,
            max_tokens=1000,
            system=system_prompt,
            messages=[{
                "role": "user",
                "content": user_content
            }],
        )
        
        content = response.content[0].text
        # Extract JSON from potential markdown blocks
        if "```json" in content:
            content = content.split("```json")[1].split("```")[0]
        elif "```" in content:
            content = content.split("```")[1].split("```")[0]
            
        return json.loads(content.strip())
