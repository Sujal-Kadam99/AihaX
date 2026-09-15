"""Base agent class for the AihaX 9-agent pipeline."""

import json
import traceback
from abc import ABC, abstractmethod
from datetime import datetime
from typing import Any, Optional

from sqlalchemy.orm import Session

from backend.core.redis_client import (
    get_scan_status,
    publish_update,
    set_agent_state,
)
from backend.models.database import AgentLog


AGENT_NAMES = {
    0: "Scope Agent",
    1: "Recon Agent",
    2: "Authentication Agent",
    3: "Vulnerability Testing Agent",
    4: "Verification Agent",
    5: "Learning Agent",
    6: "Exploit Chain Agent",
    7: "Remediation Agent",
    8: "Business Impact Agent",
    9: "Report Generation Agent",
    10: "Bug Bounty Export Agent",
}


class ScanCancelledException(Exception):
    """Raised when a scan has been cancelled by the user."""


class BaseAgent(ABC):
    agent_id: int = 0
    agent_name: str = "Base Agent"

    def __init__(self, scan_id: str, db: Session, config: dict[str, Any]):
        self.scan_id = scan_id
        self.db = db
        self.config = config
        self.agent_name = AGENT_NAMES.get(self.agent_id, self.agent_name)

    async def check_cancelled(self) -> None:
        status = await get_scan_status(self.scan_id)
        if status == "cancelled":
            raise ScanCancelledException(f"Scan {self.scan_id} was cancelled")

    async def publish_update(
        self,
        status: str,
        progress: int,
        message: str,
        finding: Optional[dict[str, Any]] = None,
    ) -> None:
        await set_agent_state(self.scan_id, self.agent_id, status, progress, message)
        await publish_update(self.scan_id, {
            "scan_id": self.scan_id,
            "agent_id": self.agent_id,
            "agent_name": self.agent_name,
            "status": status,
            "progress": progress,
            "message": message,
            "finding": finding,
        })

    def log(
        self,
        level: str,
        message: str,
        raw_output: Optional[str] = None,
    ) -> None:
        entry = AgentLog(
            scan_id=self.scan_id,
            agent_id=self.agent_id,
            level=level,
            message=message,
            raw_output=raw_output,
        )
        self.db.add(entry)
        self.db.commit()

    async def run(self) -> dict[str, Any]:
        """Execute the agent with error handling."""
        try:
            await self.publish_update("running", 0, f"Starting {self.agent_name}...")
            result = await self.execute()
            await self.publish_update("complete", 100, f"{self.agent_name} completed")
            self.log("info", f"{self.agent_name} completed successfully")
            return result
        except ScanCancelledException:
            await self.publish_update("error", 0, "Scan cancelled")
            self.log("warning", f"{self.agent_name} cancelled by user")
            raise
        except Exception as e:
            error_msg = f"{self.agent_name} failed: {str(e)}"
            await self.publish_update("error", 0, error_msg)
            self.log("error", error_msg, traceback.format_exc())
            return {"error": str(e)}

    @abstractmethod
    async def execute(self) -> dict[str, Any]:
        """Agent-specific implementation. Override in subclasses."""
        ...
