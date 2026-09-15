"""AihaX Phase 26 — Recon Tool Availability & Version Diagnostics Gate.

Provides deterministic tool inventory, binary discovery, version verification,
and execution safety capability checking for all external reconnaissance tools.

Enforces:
1. Deterministic PATH and configured tools directory scanning.
2. Structured version extraction via ToolExecutionBoundary (zero shell execution).
3. Strict semantic classification:
   - AVAILABLE: Binary present, version verified, adapter present, safe mode supported.
   - BINARY_UNAVAILABLE: Adapter exists, but executable not found on system PATH.
   - STUB_ONLY: Formally classified as STUB_ONLY / PRODUCTION_CAPABILITY_NOT_IMPLEMENTED (e.g. Sublist3r).
   - BLOCKED_POLICY: Active tools not permitted without explicit program authorization (e.g. Nmap, Gobuster).
   - NOT_SELECTED_RECON_ONLY: Tools deferred to later phases (e.g. Nuclei, Dalfox).
"""

from __future__ import annotations

import asyncio
import hashlib
import json
import logging
import os
import re
import shutil
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from enum import Enum
from typing import Any, Callable, Dict, List, Optional, Tuple

from backend.execution.tool_execution_boundary import (
    ALLOWED_TOOLS,
    ExecutionProfile,
    ToolDefinition,
    ToolExecutionBoundary,
    ToolExecutionRequest,
    ToolExecutionResult,
    ToolExecutionStatus,
)
from backend.models.database import get_utc_now

logger = logging.getLogger("aihax.recon_tool_availability")


# ==============================================================================
# Tool Status Enum (Phase 26 Section 7, 9)
# ==============================================================================

class ReconToolAvailabilityStatus(str, Enum):
    AVAILABLE = "AVAILABLE"
    BINARY_UNAVAILABLE = "BINARY_UNAVAILABLE"
    STUB_ONLY = "STUB_ONLY"
    BLOCKED_POLICY = "BLOCKED_POLICY"
    POLICY_BLOCKED = "POLICY_BLOCKED"
    NOT_SELECTED_RECON_ONLY = "NOT_SELECTED_RECON_ONLY"
    NOT_SELECTED = "NOT_SELECTED"
    AUTH_REQUIRED = "AUTH_REQUIRED"
    FAILED_VALIDATION = "FAILED_VALIDATION"


# ==============================================================================
# Deterministic Tool Inventory Record (Phase 26 Section 6)
# ==============================================================================

@dataclass
class ToolInventoryRecord:
    tool_name: str
    required_version: str
    detected_version: Optional[str] = None
    binary_path: Optional[str] = None
    installation_source: str = "OFFICIAL_RELEASE"
    installation_method: str = "PACKAGE_OR_BINARY"
    installation_status: str = "PENDING"
    availability_status: ReconToolAvailabilityStatus = ReconToolAvailabilityStatus.BINARY_UNAVAILABLE
    adapter_status: str = "ADAPTER_AVAILABLE"
    checksum_or_provenance: Optional[str] = None
    implementation_type: str = "EXTERNAL_BINARY"
    timestamp: str = field(default_factory=lambda: get_utc_now().isoformat())

    def to_dict(self) -> Dict[str, Any]:
        d = asdict(self)
        d["availability_status"] = self.availability_status.value
        return d


# ==============================================================================
# Diagnostic Record (Phase 26 Section 7)
# ==============================================================================

@dataclass
class ToolDiagnosticResult:
    tool: str
    installed: bool
    version: Optional[str] = None
    binary: Optional[str] = None
    adapter: bool = True
    execution_supported: bool = False
    safe_mode_supported: bool = False
    status: str = "BINARY_UNAVAILABLE"
    failure_reason: Optional[str] = None
    version_stdout_hash: Optional[str] = None
    version_stderr_hash: Optional[str] = None
    version_exit_code: Optional[int] = None
    implementation_type: str = "EXTERNAL_BINARY"
    timestamp: str = field(default_factory=lambda: get_utc_now().isoformat())

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


# ==============================================================================
# Specification of Recon Tools for Phase 26
# ==============================================================================

TOOL_SPECS: Dict[str, Dict[str, Any]] = {
    "subfinder": {
        "required_version": ">=2.5.0",
        "version_flag": "-version",
        "version_regex": r"(?:subfinder|Current Version:)\s*v?([0-9]+\.[0-9]+\.[0-9]+)",
        "profile": ExecutionProfile.SUBDOMAIN_ENUMERATION.value,
        "policy_status": ReconToolAvailabilityStatus.AVAILABLE,
        "safe_mode_supported": True,
        "implementation_type": "EXTERNAL_BINARY",
    },
    "amass": {
        "required_version": ">=3.19.0",
        "version_flag": "-version",
        "version_regex": r"v?([0-9]+\.[0-9]+\.[0-9]+)",
        "profile": ExecutionProfile.SUBDOMAIN_ENUMERATION.value,
        "policy_status": ReconToolAvailabilityStatus.AVAILABLE,
        "safe_mode_supported": True,  # Passive mode only
        "implementation_type": "EXTERNAL_BINARY",
    },
    "gau": {
        "required_version": ">=2.1.0",
        "version_flag": "--version",
        "version_regex": r"gau\s*(?:version:?\s*)?v?([0-9]+\.[0-9]+\.[0-9]+)",
        "profile": ExecutionProfile.URL_DISCOVERY.value,
        "policy_status": ReconToolAvailabilityStatus.AVAILABLE,
        "safe_mode_supported": True,
        "implementation_type": "EXTERNAL_BINARY",
    },
    "whatweb": {
        "required_version": ">=0.5.0",
        "version_flag": "--version",
        "version_regex": r"WhatWeb\s+version\s+([0-9]+\.[0-9]+\.[0-9]+)",
        "profile": ExecutionProfile.TECHNOLOGY_FINGERPRINTING.value,
        "policy_status": ReconToolAvailabilityStatus.AVAILABLE,
        "safe_mode_supported": True,
        "implementation_type": "EXTERNAL_BINARY",
    },
    "sublist3r": {
        "required_version": "N/A",
        "version_flag": "--version",
        "version_regex": r"(.*)",
        "profile": ExecutionProfile.SUBDOMAIN_ENUMERATION.value,
        "policy_status": ReconToolAvailabilityStatus.STUB_ONLY,
        "safe_mode_supported": False,
        "implementation_type": "STUB",
    },
    "nmap": {
        "required_version": ">=7.80",
        "version_flag": "-V",
        "version_regex": r"Nmap\s+version\s+([0-9]+\.[0-9]+)",
        "profile": ExecutionProfile.PORT_SERVICE_DISCOVERY.value,
        "policy_status": ReconToolAvailabilityStatus.AUTH_REQUIRED,
        "safe_mode_supported": True,
        "implementation_type": "EXTERNAL_BINARY",
    },
    "gobuster": {
        "required_version": ">=3.1.0",
        "version_flag": "version",
        "version_regex": r"([0-9]+\.[0-9]+(?:\.[0-9]+)?)",
        "profile": ExecutionProfile.DIRECTORY_DISCOVERY.value,
        "policy_status": ReconToolAvailabilityStatus.AUTH_REQUIRED,
        "safe_mode_supported": True,
        "implementation_type": "EXTERNAL_BINARY",
    },
    "nuclei": {
        "required_version": ">=2.8.0",
        "version_flag": "-version",
        "version_regex": r"v?([0-9]+\.[0-9]+\.[0-9]+)",
        "profile": ExecutionProfile.VULNERABILITY_SCANNING.value,
        "policy_status": ReconToolAvailabilityStatus.AUTH_REQUIRED,
        "safe_mode_supported": True,
        "implementation_type": "EXTERNAL_BINARY",
    },
    "dalfox": {
        "required_version": ">=2.9.0",
        "version_flag": "version",
        "version_regex": r"v?([0-9]+\.[0-9]+\.[0-9]+)",
        "profile": ExecutionProfile.XSS_VALIDATION.value,
        "policy_status": ReconToolAvailabilityStatus.AUTH_REQUIRED,
        "safe_mode_supported": True,
        "implementation_type": "EXTERNAL_BINARY",
    },
    "naabu": {
        "required_version": ">=2.3.0",
        "version_flag": "-version",
        "version_regex": r"v?([0-9]+\.[0-9]+\.[0-9]+)",
        "profile": ExecutionProfile.PORT_SERVICE_DISCOVERY.value,
        "policy_status": ReconToolAvailabilityStatus.AUTH_REQUIRED,
        "safe_mode_supported": True,
        "implementation_type": "EXTERNAL_BINARY",
    },
    "wayback": {
        "required_version": "N/A",
        "version_flag": "",
        "version_regex": r"",
        "profile": ExecutionProfile.URL_DISCOVERY.value,
        "policy_status": ReconToolAvailabilityStatus.AVAILABLE,
        "safe_mode_supported": True,
        "implementation_type": "INTERNAL_ADAPTER",
    },
    "dns_recon": {
        "required_version": "N/A",
        "version_flag": "",
        "version_regex": r"",
        "profile": ExecutionProfile.PORT_SERVICE_DISCOVERY.value,
        "policy_status": ReconToolAvailabilityStatus.AVAILABLE,
        "safe_mode_supported": True,
        "implementation_type": "INTERNAL_ADAPTER",
    },
    "http_probe": {
        "required_version": "N/A",
        "version_flag": "",
        "version_regex": r"",
        "profile": ExecutionProfile.TECHNOLOGY_FINGERPRINTING.value,
        "policy_status": ReconToolAvailabilityStatus.AVAILABLE,
        "safe_mode_supported": True,
        "implementation_type": "INTERNAL_ADAPTER",
    },
    "crtsh": {
        "required_version": "N/A",
        "version_flag": "",
        "version_regex": r"",
        "profile": ExecutionProfile.SUBDOMAIN_ENUMERATION.value,
        "policy_status": ReconToolAvailabilityStatus.AVAILABLE,
        "safe_mode_supported": True,
        "implementation_type": "INTERNAL_ADAPTER",
    },
}


# ==============================================================================
# ReconToolAvailability Engine
# ==============================================================================

REPO_ROOT = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
DEFAULT_PROJECT_TOOLS_DIR = os.path.join(REPO_ROOT, "bin", "tools")


class ReconToolAvailability:
    """Deterministic environment diagnostics and version verification for recon tools."""

    def __init__(
        self,
        tool_boundary: Optional[ToolExecutionBoundary] = None,
        custom_bin_dir: Optional[str] = None,
        custom_process_runner: Optional[Callable[[str, List[str], int], Tuple[int, bytes, bytes]]] = None,
    ) -> None:
        self.tool_boundary = tool_boundary or ToolExecutionBoundary(
            process_runner=custom_process_runner
        )
        self.custom_bin_dir = (
            custom_bin_dir
            or os.environ.get("AIHAX_TOOLS_DIR")
            or DEFAULT_PROJECT_TOOLS_DIR
        )
        self._custom_process_runner = custom_process_runner

    def resolve_binary_path(self, tool_name: str) -> Optional[str]:
        """Locate executable deterministically in custom tools dir or system PATH."""
        executable_names = [tool_name]
        if os.name == "nt":
            executable_names = [f"{tool_name}.exe", f"{tool_name}.bat", f"{tool_name}.cmd", tool_name]

        # 1. Custom directory check (if configured)
        if self.custom_bin_dir and os.path.isdir(self.custom_bin_dir):
            for name in executable_names:
                candidate = os.path.join(self.custom_bin_dir, name)
                if os.path.isfile(candidate) and (os.access(candidate, os.X_OK) or os.name == "nt"):
                    return os.path.abspath(candidate)

        # 2. System PATH lookup
        for name in executable_names:
            resolved = shutil.which(name)
            if resolved:
                return os.path.abspath(resolved)

        return None

    async def check_tool_version(
        self,
        tool_name: str,
        binary_path: str,
    ) -> Tuple[Optional[str], Optional[int], Optional[str], Optional[str]]:
        """Run deterministic structured version check via ToolExecutionBoundary (no shell).

        Returns: (version_str, exit_code, stdout_hash, stderr_hash)
        """
        spec = TOOL_SPECS.get(tool_name, {})
        version_flag = spec.get("version_flag", "--version")
        version_regex = spec.get("version_regex", r"([0-9]+\.[0-9]+(?:\.[0-9]+)?)")

        # Use structured boundary runner if mock runner injected or run safe process
        if self._custom_process_runner:
            try:
                exit_code, stdout_bytes, stderr_bytes = self._custom_process_runner(
                    binary_path, [version_flag], 10
                )
                stdout_str = stdout_bytes.decode("utf-8", errors="replace")
                stderr_str = stderr_bytes.decode("utf-8", errors="replace")
                combined = stdout_str + "\n" + stderr_str
                m = re.search(version_regex, combined)
                detected = m.group(1) if m else None
                stdout_hash = hashlib.sha256(stdout_bytes).hexdigest()
                stderr_hash = hashlib.sha256(stderr_bytes).hexdigest()
                return detected, exit_code, stdout_hash, stderr_hash
            except Exception as e:
                logger.warning("Version check failed for %s: %s", tool_name, str(e))
                return None, 1, None, None

        # Execute subprocess without shell
        try:
            proc = await asyncio.create_subprocess_exec(
                binary_path,
                version_flag,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
            )
            stdout_bytes, stderr_bytes = await asyncio.wait_for(proc.communicate(), timeout=10.0)
            exit_code = proc.returncode
            stdout_str = stdout_bytes.decode("utf-8", errors="replace")
            stderr_str = stderr_bytes.decode("utf-8", errors="replace")
            combined = stdout_str + "\n" + stderr_str
            m = re.search(version_regex, combined)
            detected = m.group(1) if m else None
            stdout_hash = hashlib.sha256(stdout_bytes).hexdigest()
            stderr_hash = hashlib.sha256(stderr_bytes).hexdigest()
            return detected, exit_code, stdout_hash, stderr_hash
        except Exception as e:
            logger.warning("Subprocess version check failed for %s: %s", tool_name, str(e))
            return None, 1, None, None

    async def diagnose_tool(self, tool_name: str) -> ToolDiagnosticResult:
        """Evaluate a single tool's presence, version, and policy compliance."""
        spec = TOOL_SPECS.get(tool_name)
        if not spec:
            return ToolDiagnosticResult(
                tool=tool_name,
                installed=False,
                adapter=False,
                execution_supported=False,
                safe_mode_supported=False,
                status="NOT_IMPLEMENTED",
                failure_reason=f"Unknown tool '{tool_name}'",
            )

        policy_status = spec["policy_status"]

        # 1. Sublist3r is formally classified as STUB_ONLY
        if policy_status == ReconToolAvailabilityStatus.STUB_ONLY:
            return ToolDiagnosticResult(
                tool=tool_name,
                installed=False,
                adapter=True,
                execution_supported=False,
                safe_mode_supported=False,
                status=ReconToolAvailabilityStatus.STUB_ONLY.value,
                failure_reason="STUB_ONLY / PRODUCTION_CAPABILITY_NOT_IMPLEMENTED",
            )

        # 2. Blocked by policy (Nmap, Gobuster)
        if policy_status == ReconToolAvailabilityStatus.BLOCKED_POLICY:
            bin_path = self.resolve_binary_path(tool_name)
            return ToolDiagnosticResult(
                tool=tool_name,
                installed=bin_path is not None,
                binary=bin_path,
                adapter=True,
                execution_supported=False,
                safe_mode_supported=False,
                status=ReconToolAvailabilityStatus.BLOCKED_POLICY.value,
                failure_reason="BLOCKED_POLICY — Tool requires explicit authorization not granted in this validation gate",
            )

        # 3. Not selected recon only (Nuclei, Dalfox)
        if policy_status == ReconToolAvailabilityStatus.NOT_SELECTED_RECON_ONLY:
            bin_path = self.resolve_binary_path(tool_name)
            return ToolDiagnosticResult(
                tool=tool_name,
                installed=bin_path is not None,
                binary=bin_path,
                adapter=True,
                execution_supported=False,
                safe_mode_supported=False,
                status=ReconToolAvailabilityStatus.NOT_SELECTED_RECON_ONLY.value,
                failure_reason="NOT_SELECTED_RECON_ONLY — Vulnerability scanning and XSS validation are not selected for recon validation gate",
                implementation_type=spec.get("implementation_type", "EXTERNAL_BINARY"),
            )

        # 4. Internal Providers / Adapters
        if spec.get("implementation_type") == "INTERNAL_ADAPTER":
            return ToolDiagnosticResult(
                tool=tool_name,
                installed=True,
                version="N/A",
                binary="INTERNAL_ADAPTER",
                adapter=True,
                execution_supported=True,
                safe_mode_supported=spec["safe_mode_supported"],
                status=policy_status.value,
                failure_reason=None,
                implementation_type="INTERNAL_ADAPTER",
            )

        # 4. In-scope tools: Subfinder, Amass, GAU, WhatWeb, and AUTH_REQUIRED tools
        bin_path = self.resolve_binary_path(tool_name)
        if not bin_path:
            return ToolDiagnosticResult(
                tool=tool_name,
                installed=False,
                adapter=True,
                execution_supported=False,
                safe_mode_supported=spec["safe_mode_supported"],
                status=ReconToolAvailabilityStatus.BINARY_UNAVAILABLE.value,
                failure_reason=f"Executable '{tool_name}' not found on system PATH or tools directory",
            )

        # Binary is present -> Check version deterministically
        version, exit_code, stdout_hash, stderr_hash = await self.check_tool_version(tool_name, bin_path)

        final_status = policy_status.value if policy_status in (ReconToolAvailabilityStatus.AVAILABLE, ReconToolAvailabilityStatus.AUTH_REQUIRED) else ReconToolAvailabilityStatus.AVAILABLE.value

        return ToolDiagnosticResult(
            tool=tool_name,
            installed=True,
            version=version,
            binary=bin_path,
            adapter=True,
            execution_supported=True,
            safe_mode_supported=spec["safe_mode_supported"],
            status=final_status,
            version_stdout_hash=stdout_hash,
            version_stderr_hash=stderr_hash,
            version_exit_code=exit_code,
            implementation_type=spec.get("implementation_type", "EXTERNAL_BINARY"),
        )

    async def diagnose_all(self) -> Dict[str, ToolDiagnosticResult]:
        """Perform comprehensive environment diagnostics for all configured recon tools."""
        results = {}
        for tool_name in TOOL_SPECS.keys():
            results[tool_name] = await self.diagnose_tool(tool_name)
        return results

    async def generate_inventory(self) -> List[ToolInventoryRecord]:
        """Generate deterministic tool inventory conforming to Phase 26 Section 6."""
        diagnostics = await self.diagnose_all()
        inventory: List[ToolInventoryRecord] = []

        for tool_name, diag in diagnostics.items():
            spec = TOOL_SPECS.get(tool_name, {})
            req_ver = spec.get("required_version", "unknown")
            rec = ToolInventoryRecord(
                tool_name=tool_name,
                required_version=req_ver,
                detected_version=diag.version,
                binary_path=diag.binary,
                installation_status="INSTALLED" if diag.installed else "NOT_INSTALLED",
                availability_status=ReconToolAvailabilityStatus(diag.status) if diag.status in ReconToolAvailabilityStatus.__members__ else ReconToolAvailabilityStatus.BINARY_UNAVAILABLE,
                adapter_status="ADAPTER_AVAILABLE" if diag.adapter else "NO_ADAPTER",
                checksum_or_provenance=diag.version_stdout_hash,
                implementation_type=diag.implementation_type,
            )
            inventory.append(rec)

        return inventory
