"""Agent 0 — Scope/Auth: deterministic scope validation and authorization gating."""

import json
from typing import Any

from backend.agents.base_agent import BaseAgent
from backend.core.scope_validator import ScopeDecision, ScopeValidator
from backend.models.database import ProgramScope, Scan, ScanConfig


class ScopeAgent(BaseAgent):
    agent_id = 0

    async def execute(self) -> dict[str, Any]:
        target_url = self.config.get("target_url") or ""
        scope_notes = self.config.get("scope_notes") or ""
        authorization_confirmed = self.config.get("authorization_confirmed", False)
        program_id = self.config.get("program_id")

        # 1. Strict Product Safety Gate: Authorization Confirmation
        if not authorization_confirmed:
            await self.publish_update(
                "error",
                0,
                "Authorization confirmation is required before scanning. Please confirm you have written permission.",
            )
            raise ValueError(
                "Authorization confirmation is required before scanning."
            )

        await self.check_cancelled()
        await self.publish_update("running", 10, "Validating authorization scope...")

        # 2. Build ScopeValidator from Program or explicit Scan config
        validator: ScopeValidator
        if program_id:
            prog_scope = self.db.query(ProgramScope).filter_by(program_id=program_id).first()
            if prog_scope:
                in_assets = json.loads(prog_scope.in_scope_assets or "[]")
                out_assets = json.loads(prog_scope.out_of_scope_assets or "[]")
                allowed_p = json.loads(prog_scope.allowed_ports or "[]")
                excluded_p = json.loads(prog_scope.excluded_ports or "[]")
                allowed_s = json.loads(prog_scope.allowed_schemes or '["http", "https"]')
                excluded_paths = json.loads(prog_scope.excluded_paths or "[]")
                notes = prog_scope.scope_notes or scope_notes
                validator = ScopeValidator(
                    in_scope_assets=in_assets,
                    out_of_scope_assets=out_assets,
                    allowed_ports=allowed_p if allowed_p else None,
                    excluded_ports=excluded_p if excluded_p else None,
                    allowed_schemes=allowed_s,
                    excluded_paths=excluded_paths,
                    scope_notes=notes,
                )
            else:
                validator = ScopeValidator(
                    in_scope_assets=[target_url] if target_url else [],
                    scope_notes=scope_notes,
                )
        elif self.config.get("in_scope_assets") or self.config.get("out_of_scope_assets"):
            validator = ScopeValidator(
                in_scope_assets=self.config.get("in_scope_assets"),
                out_of_scope_assets=self.config.get("out_of_scope_assets"),
                allowed_ports=self.config.get("allowed_ports"),
                excluded_ports=self.config.get("excluded_ports"),
                allowed_schemes=self.config.get("allowed_schemes"),
                excluded_paths=self.config.get("excluded_paths"),
                scope_notes=scope_notes,
            )
        else:
            # Standard single target mode: target URL itself is in-scope
            validator = ScopeValidator(
                in_scope_assets=[target_url] if target_url else [],
                scope_notes=scope_notes,
            )

        # 3. Deterministic Scope Evaluation
        decision: ScopeDecision = validator.is_url_in_scope(target_url)
        if not decision.allowed:
            err_msg = f"Scope violation: Target '{target_url}' is not in authorized scope ({decision.reason})."
            await self.publish_update("error", 0, err_msg)
            scan = self.db.query(Scan).filter_by(id=self.scan_id).first()
            if scan:
                scan.status = "failed"
                self.db.commit()
            raise ValueError(err_msg)

        # 4. Store authorization records
        if scope_notes:
            scan_config = self.db.query(ScanConfig).filter_by(scan_id=self.scan_id).first()
            if scan_config:
                scan_config.authorization_notes = scope_notes
                self.db.commit()

        scan = self.db.query(Scan).filter_by(id=self.scan_id).first()
        if scan:
            scan.status = "running"
            self.db.commit()

        await self.publish_update("complete", 100, f"Authorization scope validated: {decision.reason}")
        return {
            "authorization_confirmed": True,
            "scope_notes": scope_notes,
            "scope_decision": decision.to_dict(),
        }
