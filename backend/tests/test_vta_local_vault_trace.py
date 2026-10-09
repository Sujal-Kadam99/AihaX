import json
from urllib.parse import parse_qs, urlparse

import pytest

from backend.agents.recon_agent import ReconObservation, ReconObservationCategory, ReconSnapshot
from backend.agents.vulnerability_testing_agent import VulnerabilityTestingAgent
from backend.core.scope_validator import ScopeValidator
from backend.evidence.evidence_store import EvidenceVault
from backend.models.database import Finding, Scan
from backend.persistence.models import Campaign
from backend.persistence.repository import CampaignRepository
from backend.services.request_engine import MockTransport, RawResponse, RequestEngine
from backend.services.vulnerability_execution_engine import ExecutionMode, VulnerabilityExecutionEngine
from backend.services.vulnerability_registry import VulnerabilityRegistry


@pytest.mark.asyncio
async def test_local_vta_finding_claim_request_response_resolves_in_fresh_vault(db_session):
    target = "https://example.com"
    endpoint = f"{target}/search"

    def respond(method, url, headers, params, body):
        value = parse_qs(urlparse(url).query).get("query", [""])[0]
        if "'" in value:
            return RawResponse(
                status_code=500,
                headers={"content-type": "text/html"},
                body=b"SQLITE_ERROR: near quote: syntax error",
                observed_size=39,
            )
        return RawResponse(status_code=200, headers={"content-type": "text/plain"}, body=b"baseline", observed_size=8)

    transport = MockTransport()
    transport.register_handler(lambda method, url: url.startswith(endpoint), respond)
    scope = ScopeValidator(in_scope_assets=[target])
    request_engine = RequestEngine(scope_validator=scope, transport=transport)
    agent = VulnerabilityTestingAgent(
        scan_id="fixture-vta-trace",
        db=db_session,
        execution_engine=VulnerabilityExecutionEngine(request_engine=request_engine, scope_validator=scope),
    )
    db_session.add(Campaign(
        id="fixture-vta-trace",
        name="Local evidence trace fixture",
        target_url=target,
        mode="RECON_THEN_VTA",
        status="RUNNING",
    ))
    db_session.add(Scan(id="fixture-vta-trace", target_url=target, status="running"))
    db_session.flush()
    definition = agent.selector.registry.get_definition("C023")
    agent.selector.registry.get_all_definitions = lambda: [definition]
    recon = ReconSnapshot(
        campaign_id="fixture-vta-trace",
        target=target,
        status="COMPLETED",
        observations=[
            ReconObservation(
                category=ReconObservationCategory.ENDPOINT.value,
                value=endpoint,
                normalized_value=endpoint,
                discovered_by=["local_fixture"],
            ),
            ReconObservation(
                category=ReconObservationCategory.PARAMETER.value,
                value="query",
                normalized_value="query",
                discovered_by=["local_fixture"],
                metadata={"endpoint": endpoint, "location": "query"},
            ),
        ],
        tool_results={},
        graph_snapshot=None,
        observation_count=2,
        snapshot_hash="fixture",
    )

    result = await agent.run_vulnerability_pipeline(
        target_url=target,
        recon_snapshot=recon,
        mode=ExecutionMode.SIMULATION,
        authorization_confirmed=True,
        in_scope_assets=[target],
    )

    assert result.findings
    finding = db_session.query(Finding).filter_by(scan_id="fixture-vta-trace").first()
    assert finding and finding.verification_status == "CANDIDATE"
    evidence_id = json.loads(finding.evidence_ids)[0]
    vault_record = EvidenceVault(CampaignRepository(db_session)).get_evidence(evidence_id)
    assert vault_record is not None
    assert "query=" in vault_record.sanitized_request
    assert "SQL error signature detected" in vault_record.payload_summary
    assert "HTTP 500" in vault_record.sanitized_response
    assert vault_record.request_id
    assert all(request_id in vault_record.request_id for request_id in json.loads(finding.request_ids))
