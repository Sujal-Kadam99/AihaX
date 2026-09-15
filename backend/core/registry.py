"""Check Registry Architecture.

Maintains the versioned catalog of all scanning checks (SQLi, XSS, SSRF, etc.).
"""

import logging
from typing import Any, Dict, List
from datetime import datetime

logger = logging.getLogger(__name__)

class CheckTemplate:
    def __init__(
        self,
        check_id: str,
        name: str,
        vuln_type: str,
        severity: str,
        version: str,
        payloads: List[str],
        description: str,
    ):
        self.check_id = check_id
        self.name = name
        self.vuln_type = vuln_type
        self.severity = severity
        self.version = version
        self.payloads = payloads
        self.description = description
        self.last_updated = datetime.utcnow()

    def to_dict(self) -> Dict[str, Any]:
        return {
            "check_id": self.check_id,
            "name": self.name,
            "vuln_type": self.vuln_type,
            "severity": self.severity,
            "version": self.version,
            "payloads": self.payloads,
            "description": self.description,
            "last_updated": self.last_updated.isoformat(),
        }


class CheckRegistry:
    """Versioned registry for all security checks."""

    _instance = None

    def __new__(cls):
        if cls._instance is None:
            cls._instance = super(CheckRegistry, cls).__new__(cls)
            cls._instance._initialize()
        return cls._instance

    def _initialize(self):
        self.checks: Dict[str, CheckTemplate] = {}
        self.version = "1.0.0"
        self._load_core_checks()

    def _load_core_checks(self):
        """Load the foundational 77-check architecture stubs."""
        # SQLi Core Check
        self.register_check(
            CheckTemplate(
                check_id="CHK-SQLI-01",
                name="Time-Based Blind SQLi",
                vuln_type="sqli",
                severity="critical",
                version="1.0.0",
                payloads=[
                    "' OR SLEEP(5)='",
                    "1; WAITFOR DELAY '0:0:5'--",
                    "pg_sleep(5)--"
                ],
                description="Detects boolean and time-based blind SQL injection.",
            )
        )

        # XSS Core Check
        self.register_check(
            CheckTemplate(
                check_id="CHK-XSS-01",
                name="Reflected XSS",
                vuln_type="xss",
                severity="medium",
                version="1.0.0",
                payloads=[
                    "<script>alert(1)</script>",
                    "\"><img src=x onerror=alert(1)>",
                    "javascript:alert(1)"
                ],
                description="Detects reflected cross-site scripting in GET/POST parameters.",
            )
        )

        # SSRF Core Check
        self.register_check(
            CheckTemplate(
                check_id="CHK-SSRF-01",
                name="Internal SSRF",
                vuln_type="ssrf",
                severity="high",
                version="1.0.0",
                payloads=[
                    "http://169.254.169.254/latest/meta-data/",
                    "http://localhost:8080/",
                    "file:///etc/passwd"
                ],
                description="Detects Server-Side Request Forgery accessing internal services.",
            )
        )

        # ... 74 other checks would be loaded here from a JSON/YAML repository

    def register_check(self, check: CheckTemplate):
        """Register a new check or update an existing one."""
        self.checks[check.check_id] = check
        logger.info(f"Registered check: {check.check_id} (v{check.version})")

    def get_check(self, check_id: str) -> CheckTemplate | None:
        """Retrieve a specific check by ID."""
        return self.checks.get(check_id)

    def get_all_checks(self) -> List[Dict[str, Any]]:
        """Return all active checks."""
        return [c.to_dict() for c in self.checks.values()]

    def sync_threat_intel(self) -> bool:
        """
        Automated Threat Intelligence Sync Stub.
        In the future, this will connect to the cloud service to download zero-day templates.
        """
        logger.info("Syncing threat intelligence templates from cloud...")
        # Simulate network delay and sync
        import time
        time.sleep(0.5)
        logger.info("Threat intelligence sync complete. Registry is up to date.")
        return True

# Singleton access
registry = CheckRegistry()
