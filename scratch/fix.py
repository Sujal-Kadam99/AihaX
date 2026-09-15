import sys

# Read the file up to line 397
with open('backend/tests/test_phase26_tool_validation.py', 'r', encoding='utf-8') as f:
    lines = f.readlines()
lines = lines[:397]

clean_code = """
class TestPhase26GAU:
    \"\"\"GAU URL discovery, canonicalization, deduplication, and scope classification.\"\"\"

    @pytest.mark.asyncio
    async def test_gau_url_parsing_and_scope_classification(self):
        \"\"\"URLs in-scope marked DISCOVERED_NOT_AUTHORIZED; out-of-scope marked DISCOVERED_OUT_OF_SCOPE.\"\"\"
        def mock_gau_runner(cmd, args, timeout):
            stdout = (
                b\"https://www.mitacsc.ac.in/about\\n\"
                b\"https://www.mitacsc.ac.in/courses?id=1\\n\"
                b\"https://external-thirdparty.com/ad\\n\"
            )
            return 0, stdout, b\"\"

        boundary = ToolExecutionBoundary(process_runner=mock_gau_runner)
        engine = LiveReconValidationEngine(tool_boundary=boundary)

        with patch.object(engine.tool_availability, \"resolve_binary_path\", return_value=\"/bin/gau\"):
            scope_val = ScopeValidator(in_scope_assets=[\"www.mitacsc.ac.in\", \"mitacsc.ac.in\"])
            rec = await engine._validate_gau(
                base_domain=\"mitacsc.ac.in\",
                target=\"https://www.mitacsc.ac.in\",
                campaign_id=\"p26-camp\",
                auth_id=\"auth-valid\",
                scope_validator=scope_val,
                scope_hash=\"scope-hash-1\",
            )
            assert rec.status == ToolValidationStatus.EXECUTED_RESULTS_NORMALIZED
            assert rec.parsed_result_count == 3
            assert rec.normalized_result_count == 3

            in_scope_assets = [a for a in rec.normalized_assets if a[\"scope_status\"] == \"IN_SCOPE\"]
            out_of_scope_assets = [a for a in rec.normalized_assets if a[\"scope_status\"] == \"OUT_OF_SCOPE\"]

            assert len(in_scope_assets) == 2
            assert len(out_of_scope_assets) == 1

            for a in in_scope_assets:
                assert a[\"authorization_status\"] == \"DISCOVERED_NOT_AUTHORIZED\"
                assert a[\"is_executable\"] is False

            for a in out_of_scope_assets:
                assert a[\"authorization_status\"] == \"DISCOVERED_OUT_OF_SCOPE\"
                assert a[\"is_executable\"] is False

    @patch(\"backend.recon.recon_tool_availability.ReconToolAvailability.resolve_binary_path\", return_value=None)
    @pytest.mark.asyncio
    async def test_gau_missing_binary_returns_binary_unavailable(self, mock_resolve):
        engine = LiveReconValidationEngine()
        rec = await engine._validate_gau(
            base_domain=\"mitacsc.ac.in\",
            target=\"https://www.mitacsc.ac.in\",
            campaign_id=\"p26-camp\",
            auth_id=\"auth-valid\",
            scope_validator=ScopeValidator(in_scope_assets=[\"mitacsc.ac.in\"]),
            scope_hash=\"scope-hash-1\",
        )
        assert rec.status == ToolValidationStatus.BINARY_UNAVAILABLE


# ==============================================================================
# 7. WhatWeb Fingerprinting (Section 5, 16)
# ==============================================================================

class TestPhase26WhatWeb:
    \"\"\"WhatWeb read-only technology fingerprinting.\"\"\"

    @pytest.mark.asyncio
    async def test_whatweb_technology_json_parsing(self):
        \"\"\"JSON output is parsed and normalized into technology assets.\"\"\"
        def mock_whatweb_runner(cmd, args, timeout):
            import json
            payload = [{
                \"target\": \"https://www.mitacsc.ac.in\",
                \"http_status\": 200,
                \"plugins\": {
                    \"Apache\": {\"version\": [\"2.4.41\"]},
                    \"PHP\": {\"version\": [\"7.4.3\"]},
                    \"HTML5\": {},
                }
            }]
            return 0, json.dumps(payload).encode(\"utf-8\"), b\"\"

        boundary = ToolExecutionBoundary(process_runner=mock_whatweb_runner)
        engine = LiveReconValidationEngine(tool_boundary=boundary)

        with patch.object(engine.tool_availability, \"resolve_binary_path\", return_value=\"/bin/whatweb\"):
            rec = await engine._validate_whatweb(
                target=\"https://www.mitacsc.ac.in\",
                campaign_id=\"p26-camp\",
                auth_id=\"auth-valid\",
                scope_validator=ScopeValidator(in_scope_assets=[\"www.mitacsc.ac.in\"]),
                scope_hash=\"scope-hash-1\",
            )
            assert rec.status == ToolValidationStatus.EXECUTED_RESULTS_NORMALIZED
            assert rec.normalized_result_count == 3
            techs = {a[\"asset\"] for a in rec.normalized_assets}
            assert \"https://www.mitacsc.ac.in:apache\" in techs
            assert \"https://www.mitacsc.ac.in:php\" in techs
            assert \"https://www.mitacsc.ac.in:html5\" in techs

    @pytest.mark.asyncio
    async def test_whatweb_aggressive_mode_rejected(self):
        \"\"\"Aggressive scanning flags are rejected under policy.\"\"\"
        engine = LiveReconValidationEngine()
        rec = await engine._validate_whatweb(
            target=\"https://www.mitacsc.ac.in\",
            campaign_id=\"p26-camp\",
            auth_id=\"auth-valid\",
            scope_validator=ScopeValidator(in_scope_assets=[\"www.mitacsc.ac.in\"]),
            scope_hash=\"scope-hash-1\",
            custom_args=[\"-a\", \"3\", \"https://www.mitacsc.ac.in\"],
        )
        assert rec.status == ToolValidationStatus.BLOCKED_POLICY
        assert \"Aggressive WhatWeb scanning modes are forbidden\" in rec.failure_reason

    @patch(\"backend.recon.recon_tool_availability.ReconToolAvailability.resolve_binary_path\", return_value=None)
    @pytest.mark.asyncio
    async def test_whatweb_missing_binary_returns_binary_unavailable(self, mock_resolve):
        engine = LiveReconValidationEngine()
        rec = await engine._validate_whatweb(
            target=\"https://www.mitacsc.ac.in\",
            campaign_id=\"p26-camp\",
            auth_id=\"auth-valid\",
            scope_validator=ScopeValidator(in_scope_assets=[\"www.mitacsc.ac.in\"]),
            scope_hash=\"scope-hash-1\",
        )
        assert rec.status == ToolValidationStatus.BINARY_UNAVAILABLE


# ==============================================================================
# 8. Policy-Gated & Stub Tools (Section 17, 18, 19, 20, 21)
# ==============================================================================

class TestPhase26PolicyGatedAndStubTools:
    \"\"\"Explicit semantic status enforcement for stubs and active scanning tools.\"\"\"

    def test_sublist3r_formally_stub_only(self):
        \"\"\"Sublist3r must report STUB_ONLY / PRODUCTION_CAPABILITY_NOT_IMPLEMENTED.\"\"\"
        engine = LiveReconValidationEngine()
        rec = engine._validate_sublist3r(
            target=\"https://www.mitacsc.ac.in\",
            campaign_id=\"p26-camp\",
            auth_id=\"auth-valid\",
            scope_hash=\"scope-hash-1\",
        )
        assert rec.status == ToolValidationStatus.STUB_ONLY
        assert \"STUB_ONLY / PRODUCTION_CAPABILITY_NOT_IMPLEMENTED\" in rec.failure_reason

    @patch(\"backend.recon.recon_tool_availability.ReconToolAvailability.resolve_binary_path\", return_value=None)
    @pytest.mark.asyncio
    async def test_nmap_blocked_policy_without_port_scan_auth(self, mock_resolve):
        \"\"\"Nmap is BLOCKED_POLICY unless explicit port scanning authorization is granted.\"\"\"
        engine = LiveReconValidationEngine()
        rec = await engine._validate_nmap(
            base_domain=\"mitacsc.ac.in\",
            target=\"https://www.mitacsc.ac.in\",
            campaign_id=\"p26-camp\",
            auth_id=\"auth-valid\",
            allow_port_scan=False,
            scope_validator=ScopeValidator(in_scope_assets=[\"mitacsc.ac.in\"]),
            scope_hash=\"scope-hash-1\",
        )
        assert rec.status == ToolValidationStatus.BLOCKED_POLICY
        assert \"Port scanning is not explicitly authorized\" in rec.failure_reason

    @patch(\"backend.recon.recon_tool_availability.ReconToolAvailability.resolve_binary_path\", return_value=None)
    @pytest.mark.asyncio
    async def test_gobuster_blocked_policy_without_dir_scan_auth(self, mock_resolve):
        \"\"\"Gobuster is BLOCKED_POLICY unless directory fuzzing is explicitly permitted.\"\"\"
        engine = LiveReconValidationEngine()
        rec = await engine._validate_gobuster(
            target=\"https://www.mitacsc.ac.in\",
            campaign_id=\"p26-camp\",
            auth_id=\"auth-valid\",
            allow_dir_scan=False,
            scope_validator=ScopeValidator(in_scope_assets=[\"mitacsc.ac.in\"]),
            scope_hash=\"scope-hash-1\",
        )
        assert rec.status == ToolValidationStatus.BLOCKED_POLICY
        assert \"Directory brute-forcing / fuzzing is not explicitly authorized\" in rec.failure_reason

    def test_nuclei_and_dalfox_not_selected_recon_only(self):
        \"\"\"Nuclei and Dalfox must report NOT_SELECTED_RECON_ONLY (no vulnerability scanning).\"\"\"
        engine = LiveReconValidationEngine()
        rec_nuclei = engine._validate_nuclei(
            target=\"https://www.mitacsc.ac.in\",
            campaign_id=\"p26-camp\",
            auth_id=\"auth-valid\",
            scope_hash=\"scope-hash-1\",
        )
        assert rec_nuclei.status == ToolValidationStatus.NOT_SELECTED_RECON_ONLY

        rec_dalfox = engine._validate_dalfox(
            target=\"https://www.mitacsc.ac.in\",
            campaign_id=\"p26-camp\",
            auth_id=\"auth-valid\",
            scope_hash=\"scope-hash-1\",
        )
        assert rec_dalfox.status == ToolValidationStatus.NOT_SELECTED_RECON_ONLY


# ==============================================================================
# 9. Controlled Validation Suite Integration Test (Section 11, 29)
# ==============================================================================

class TestPhase26FullSuiteIntegration:
    \"\"\"Execute validation suite for https://www.mitacsc.ac.in and verify all invariants.\"\"\"

    @pytest.mark.asyncio
    async def test_suite_execution_with_truthful_reporting(self, db_session):
        \"\"\"Full suite runs and produces truthful statuses: zero fake LIVE_VALIDATED.\"\"\"
        engine = LiveReconValidationEngine()
        
        # Patch all tools to return None for their binary path so they get BINARY_UNAVAILABLE
        # The suite will test the actual availability!
        with patch(\"backend.recon.recon_tool_availability.ReconToolAvailability.resolve_binary_path\", return_value=None):
            res = await engine.execute_validation_suite(
                target=\"https://www.mitacsc.ac.in\",
                campaign_id=\"camp-p26-mitacsc\",
                authorization_record_id=\"auth-p26-valid\",
                operator_confirmed=True,
                db_session=db_session,
                allow_port_scan=False,
                allow_dir_scan=False,
            )

        assert res.suite_status == \"VALIDATION_COMPLETE\"
        assert res.target == \"https://www.mitacsc.ac.in\"
        assert res.total_tools_evaluated == 13

        # Sublist3r MUST be STUB_ONLY
        assert res.tool_records[\"sublist3r\"].status == ToolValidationStatus.STUB_ONLY

        # Nmap & Gobuster MUST be BLOCKED_POLICY
        assert res.tool_records[\"nmap\"].status == ToolValidationStatus.BLOCKED_POLICY
        assert res.tool_records[\"gobuster\"].status == ToolValidationStatus.BLOCKED_POLICY

        # Nuclei & Dalfox MUST be NOT_SELECTED_RECON_ONLY
        assert res.tool_records[\"nuclei\"].status == ToolValidationStatus.NOT_SELECTED_RECON_ONLY
        assert res.tool_records[\"dalfox\"].status == ToolValidationStatus.NOT_SELECTED_RECON_ONLY

        # Uninstalled CLI tools MUST report BINARY_UNAVAILABLE (truthful reporting, zero false success)
        for t in [\"subfinder\", \"amass\", \"gau\", \"whatweb\"]:
            assert res.tool_records[t].status == ToolValidationStatus.BINARY_UNAVAILABLE

        # Native providers (crtsh, dns_recon, http_probe, wayback) execute through boundary/engine
        assert res.recon_snapshot is not None
        assert res.attack_surface_graph is not None
        assert res.safety_audit_passed is True
"""

with open('backend/tests/test_phase26_tool_validation.py', 'w', encoding='utf-8') as f:
    f.writelines(lines)
    f.write(clean_code)
