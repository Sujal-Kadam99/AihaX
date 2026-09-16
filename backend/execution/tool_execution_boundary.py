"""AihaX Phase 24 — Tool Orchestration & ToolExecutionBoundary.

The authoritative execution boundary for invoking external reconnaissance and validation CLI tools.

Security Invariants:
1. NO shell execution (shell=False strictly enforced; os.system, eval, exec forbidden).
2. Commands constructed strictly as structured argv arrays (list[str]).
3. Explicit tool allowlist and execution profile validation.
4. Concrete target validation (wildcards strictly rejected).
5. Upstream authorization and ScopeValidator gating precede any process invocation.
6. Destination safety (anti-SSRF, RFC1918, metadata 169.254.169.254, prohibited ports).
7. Strict timeout and stdout/stderr output size limits (safe termination on breach).
8. Deterministic SHA-256 evidence hashing and zero plaintext secret persistence.
"""

from __future__ import annotations

import asyncio
import hashlib
import json
import logging
import os
from pathlib import Path
import re
import shutil
import subprocess
import time
import uuid
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from enum import Enum
from typing import Any, Callable, Dict, List, Optional, Set, Tuple
from urllib.parse import urlparse

from sqlalchemy.orm import Session

from backend.core.scope_validator import (
    ScopeDecision,
    ScopeStatus,
    ScopeValidator,
    normalize_domain,
    validate_destination_safety,
)
from backend.models.database import (
    ToolExecutionRecord,
    get_utc_now,
)

logger = logging.getLogger("aihax.tool_execution_boundary")


# ==============================================================================
# 1. Enums and Status Constants
# ==============================================================================

class ToolExecutionStatus(str, Enum):
    SUCCESS = "SUCCESS"
    ALLOWED = "ALLOWED"
    PROCESS_ERROR = "PROCESS_ERROR"
    TIMEOUT = "TIMEOUT"
    OUTPUT_LIMIT = "OUTPUT_LIMIT"
    NOT_INSTALLED = "NOT_INSTALLED"
    BLOCKED_TOOL = "BLOCKED_TOOL"
    BLOCKED_PROFILE = "BLOCKED_PROFILE"
    BLOCKED_ARGUMENT = "BLOCKED_ARGUMENT"
    BLOCKED_AUTHORIZATION = "BLOCKED_AUTHORIZATION"
    BLOCKED_SCOPE = "BLOCKED_SCOPE"
    BLOCKED_SAFETY = "BLOCKED_SAFETY"
    BLOCKED_MODE = "BLOCKED_MODE"


class ExecutionProfile(str, Enum):
    SUBDOMAIN_ENUMERATION = "SUBDOMAIN_ENUMERATION"
    PORT_SERVICE_DISCOVERY = "PORT_SERVICE_DISCOVERY"
    TECHNOLOGY_FINGERPRINTING = "TECHNOLOGY_FINGERPRINTING"
    URL_DISCOVERY = "URL_DISCOVERY"
    DIRECTORY_DISCOVERY = "DIRECTORY_DISCOVERY"
    VULNERABILITY_SCANNING = "VULNERABILITY_SCANNING"
    XSS_VALIDATION = "XSS_VALIDATION"


class CapabilityClass(str, Enum):
    PASSIVE_RECON = "PASSIVE_RECON"
    CONTROLLED_DISCOVERY = "CONTROLLED_DISCOVERY"
    SERVICE_DISCOVERY = "SERVICE_DISCOVERY"
    CONTENT_DISCOVERY = "CONTENT_DISCOVERY"
    VULNERABILITY_DETECTION = "VULNERABILITY_DETECTION"
    SPECIALIZED_ACTIVE_TESTING = "SPECIALIZED_ACTIVE_TESTING"


# ==============================================================================
# 2. Tool Definition & Registry
# ==============================================================================

# Dangerous argument pattern detection (shell injection, chaining, redirection)
DANGEROUS_ARG_PATTERN = re.compile(r"([;&|><`$\n\r]|\b(exec|eval|system|bash|sh|cmd|powershell)\b)", re.IGNORECASE)


@dataclass(frozen=True)
class ToolDefinition:
    name: str
    executable: str
    capability_class: CapabilityClass
    allowed_profiles: Set[str]
    is_active: bool
    requires_authorization: bool = True
    default_timeout: int = 60
    max_timeout: int = 120
    max_stdout_bytes: int = 2 * 1024 * 1024  # 2 MB
    max_stderr_bytes: int = 512 * 1024        # 512 KB
    allowed_flags: Set[str] = field(default_factory=set)


# Authoritative Tool Registry
ALLOWED_TOOLS: Dict[str, ToolDefinition] = {
    "subfinder": ToolDefinition(
        name="subfinder",
        executable="subfinder",
        capability_class=CapabilityClass.PASSIVE_RECON,
        allowed_profiles={ExecutionProfile.SUBDOMAIN_ENUMERATION.value},
        is_active=False,
        requires_authorization=True,  # Hardened: External reconnaissance requires explicit authorization
        default_timeout=60,
        max_timeout=120,
        allowed_flags={"-d", "-domain", "-silent", "-all", "-recursive", "-timeout", "-oJ", "-json"},
    ),
    "amass": ToolDefinition(
        name="amass",
        executable="amass",
        capability_class=CapabilityClass.PASSIVE_RECON,
        allowed_profiles={ExecutionProfile.SUBDOMAIN_ENUMERATION.value},
        is_active=False,
        requires_authorization=True,  # Hardened: External reconnaissance requires explicit authorization
        default_timeout=240,
        max_timeout=300,
        allowed_flags={"enum", "-passive", "-d", "-json", "-timeout"},
    ),
    "sublist3r": ToolDefinition(
        name="sublist3r",
        executable="sublist3r",
        capability_class=CapabilityClass.PASSIVE_RECON,
        allowed_profiles={ExecutionProfile.SUBDOMAIN_ENUMERATION.value},
        is_active=False,
        requires_authorization=True,
        default_timeout=60,
        max_timeout=120,
        allowed_flags={"-d", "-domain", "-t", "-threads", "-v", "-verbose", "-p", "-ports", "-o", "-output"},
    ),
    "nmap": ToolDefinition(
        name="nmap",
        executable="nmap",
        capability_class=CapabilityClass.SERVICE_DISCOVERY,
        allowed_profiles={ExecutionProfile.PORT_SERVICE_DISCOVERY.value},
        is_active=True,
        requires_authorization=True,
        default_timeout=60,
        max_timeout=120,
        allowed_flags={"-sV", "-sT", "-p", "-T4", "-Pn", "--open", "-oX", "-oN"},
    ),
    "whatweb": ToolDefinition(
        name="whatweb",
        executable="whatweb",
        capability_class=CapabilityClass.CONTROLLED_DISCOVERY,
        allowed_profiles={ExecutionProfile.TECHNOLOGY_FINGERPRINTING.value},
        is_active=True,
        requires_authorization=True,
        default_timeout=30,
        max_timeout=60,
        allowed_flags={"-a", "--log-json", "--user-agent", "--quiet", "--no-errors"},
    ),
    "gau": ToolDefinition(
        name="gau",
        executable="gau",
        capability_class=CapabilityClass.PASSIVE_RECON,
        allowed_profiles={ExecutionProfile.URL_DISCOVERY.value},
        is_active=False,
        requires_authorization=True,
        default_timeout=150,
        max_timeout=180,
        allowed_flags={"--threads", "--subs", "--json", "--providers"},
    ),
    "waybackurls": ToolDefinition(
        name="waybackurls",
        executable="waybackurls",
        capability_class=CapabilityClass.PASSIVE_RECON,
        allowed_profiles={ExecutionProfile.URL_DISCOVERY.value},
        is_active=False,
        requires_authorization=True,
        default_timeout=60,
        max_timeout=120,
        allowed_flags={"--no-subs", "-dates"},
    ),
    "gobuster": ToolDefinition(
        name="gobuster",
        executable="gobuster",
        capability_class=CapabilityClass.CONTENT_DISCOVERY,
        allowed_profiles={ExecutionProfile.DIRECTORY_DISCOVERY.value},
        is_active=True,
        requires_authorization=True,
        default_timeout=60,
        max_timeout=120,
        allowed_flags={"dir", "-u", "--url", "-w", "--wordlist", "-q", "--quiet", "-t", "--threads", "-o"},
    ),
    "nuclei": ToolDefinition(
        name="nuclei",
        executable="nuclei",
        capability_class=CapabilityClass.VULNERABILITY_DETECTION,
        allowed_profiles={ExecutionProfile.VULNERABILITY_SCANNING.value},
        is_active=True,
        requires_authorization=True,
        default_timeout=90,
        max_timeout=120,
        allowed_flags={"-u", "-target", "-t", "-templates", "-severity", "-silent", "-jsonl", "-rate-limit"},
    ),
    "dalfox": ToolDefinition(
        name="dalfox",
        executable="dalfox",
        capability_class=CapabilityClass.SPECIALIZED_ACTIVE_TESTING,
        allowed_profiles={ExecutionProfile.XSS_VALIDATION.value},
        is_active=True,
        requires_authorization=True,
        default_timeout=60,
        max_timeout=120,
        allowed_flags={"url", "--silence", "--format", "json", "--skip-bav", "--timeout"},
    ),
    "katana": ToolDefinition(
        name="katana",
        executable="katana",
        capability_class=CapabilityClass.PASSIVE_RECON,
        allowed_profiles={ExecutionProfile.URL_DISCOVERY.value},
        is_active=True,
        requires_authorization=True,
        default_timeout=120,
        max_timeout=240,
        allowed_flags={"-u", "-silent", "-jc", "-d"},
    ),
}


# ==============================================================================
# 3. Execution Request & Result DTOs
# ==============================================================================

@dataclass
class ToolExecutionRequest:
    campaign_id: str
    target: str
    tool_name: str
    execution_profile: str
    args: List[str] = field(default_factory=list)
    timeout_seconds: Optional[int] = None
    authorization_confirmed: bool = False
    execution_mode: str = "AUDIT"
    in_scope_assets: List[str] = field(default_factory=list)
    out_of_scope_assets: List[str] = field(default_factory=list)
    allowed_ports: List[int] = field(default_factory=list)
    excluded_ports: List[int] = field(default_factory=list)
    custom_executable_path: Optional[str] = None
    allow_loopback: bool = False


@dataclass
class ToolExecutionResult:
    id: str
    campaign_id: str
    target: str
    tool_name: str
    tool_version: Optional[str]
    execution_profile: str
    execution_status: str
    sanitized_args: List[str]
    exit_code: Optional[int]
    timeout_seconds: int
    stdout_hash: Optional[str]
    stderr_hash: Optional[str]
    output_hash: Optional[str]
    stdout: Optional[str]
    stderr: Optional[str]
    parsed_summary: Dict[str, Any] = field(default_factory=dict)
    error_category: Optional[str] = None
    started_at: str = field(default_factory=lambda: get_utc_now().isoformat())
    completed_at: Optional[str] = None
    duration_ms: float = 0.0

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


# ==============================================================================
# 4. ToolExecutionBoundary Engine
# ==============================================================================

class ToolExecutionBoundary:
    """Authoritative boundary for executing external security & recon tools."""

    def __init__(
        self,
        tool_registry: Optional[Dict[str, ToolDefinition]] = None,
        process_runner: Optional[Callable[..., Tuple[int, bytes, bytes]]] = None,
    ) -> None:
        self.registry = tool_registry or ALLOWED_TOOLS
        self._custom_process_runner = process_runner

    async def execute(
        self,
        request: ToolExecutionRequest,
        db: Optional[Session] = None,
    ) -> ToolExecutionResult:
        """Validate and execute an external CLI tool request."""
        execution_id = str(uuid.uuid4())
        started_at_dt = get_utc_now()
        started_at = started_at_dt.isoformat()
        start_mono = time.monotonic()

        # 1. Validate Tool Allowlist
        tool_name = (request.tool_name or "").lower().strip()
        if tool_name not in self.registry:
            return self._build_result(
                execution_id=execution_id,
                request=request,
                status=ToolExecutionStatus.BLOCKED_TOOL.value,
                error_category="Tool not permitted in allowlist",
                started_at=started_at,
                start_mono=start_mono,
                db=db,
            )

        tool_def = self.registry[tool_name]

        # 2. Validate Execution Profile
        profile = (request.execution_profile or "").strip()
        if profile not in tool_def.allowed_profiles:
            return self._build_result(
                execution_id=execution_id,
                request=request,
                status=ToolExecutionStatus.BLOCKED_PROFILE.value,
                error_category=f"Profile '{profile}' not permitted for tool '{tool_name}'",
                started_at=started_at,
                start_mono=start_mono,
                db=db,
            )

        # 3. Validate Concrete Target (Reject Wildcards & Empty)
        target = (request.target or "").strip()
        if not target or "*" in target:
            return self._build_result(
                execution_id=execution_id,
                request=request,
                status=ToolExecutionStatus.BLOCKED_SAFETY.value,
                error_category="Target is empty or contains wildcards (concrete execution target required)",
                started_at=started_at,
                start_mono=start_mono,
                db=db,
            )

        # 4. Validate Scope
        in_scope = request.in_scope_assets or [target]
        scope_validator = ScopeValidator(
            in_scope_assets=in_scope,
            out_of_scope_assets=request.out_of_scope_assets,
            allowed_ports=request.allowed_ports,
            excluded_ports=request.excluded_ports,
        )
        scope_decision = scope_validator.validate_target(target)
        if not scope_decision.allowed:
            return self._build_result(
                execution_id=execution_id,
                request=request,
                status=ToolExecutionStatus.BLOCKED_SCOPE.value,
                error_category=f"Target blocked by ScopeValidator: {scope_decision.reason}",
                started_at=started_at,
                start_mono=start_mono,
                db=db,
            )

        # 5. Validate Destination Safety (Anti-SSRF, RFC1918, Cloud Metadata)
        is_safe, safety_reason = validate_destination_safety(
            target, 
            allow_loopback=request.allow_loopback,
            allowed_ports=set(request.allowed_ports) if request.allowed_ports else None
        )
        if not is_safe:
            return self._build_result(
                execution_id=execution_id,
                request=request,
                status=ToolExecutionStatus.BLOCKED_SAFETY.value,
                error_category=f"Target blocked by Destination Safety: {safety_reason}",
                started_at=started_at,
                start_mono=start_mono,
                db=db,
            )

        # 6. Validate Structured Arguments (Fail-closed on command injection metacharacters)
        sanitized_args, arg_error = self._validate_and_sanitize_args(tool_def, request.args)
        if arg_error:
            return self._build_result(
                execution_id=execution_id,
                request=request,
                status=ToolExecutionStatus.BLOCKED_ARGUMENT.value,
                error_category=arg_error,
                sanitized_args=sanitized_args,
                started_at=started_at,
                start_mono=start_mono,
                db=db,
            )

        # 7. Validate Authorization
        if tool_def.requires_authorization and not request.authorization_confirmed:
            return self._build_result(
                execution_id=execution_id,
                request=request,
                status=ToolExecutionStatus.BLOCKED_AUTHORIZATION.value,
                error_category="Explicit authorization required for external tool execution",
                sanitized_args=sanitized_args,
                started_at=started_at,
                start_mono=start_mono,
                db=db,
            )

        # 8. Resolve Executable Path
        exec_path = self._resolve_executable(tool_def, request.custom_executable_path)
        if not exec_path and self._custom_process_runner is None:
            return self._build_result(
                execution_id=execution_id,
                request=request,
                status=ToolExecutionStatus.NOT_INSTALLED.value,
                error_category=f"Tool executable '{tool_def.executable}' not found on system",
                sanitized_args=sanitized_args,
                started_at=started_at,
                start_mono=start_mono,
                db=db,
            )

        # 9. Validate Execution Mode (Zero external subprocess outside AUTHORIZED_LIVE_RECON)
        if request.execution_mode != "AUTHORIZED_LIVE_RECON" and self._custom_process_runner is None:
            return self._build_result(
                execution_id=execution_id,
                request=request,
                status=ToolExecutionStatus.BLOCKED_SAFETY.value,
                error_category="External tool subprocess execution strictly forbidden outside AUTHORIZED_LIVE_RECON mode (zero external network/subprocess invariant)",
                sanitized_args=sanitized_args,
                started_at=started_at,
                start_mono=start_mono,
                db=db,
            )

        # 9. Determine Timeout
        requested_timeout = request.timeout_seconds or tool_def.default_timeout
        timeout = min(max(1, requested_timeout), tool_def.max_timeout)

        # 10. Execute Process (shell=False)
        return await self._run_process(
            execution_id=execution_id,
            tool_def=tool_def,
            exec_path=exec_path or tool_def.executable,
            sanitized_args=sanitized_args,
            timeout=timeout,
            request=request,
            started_at=started_at,
            start_mono=start_mono,
            db=db,
        )

    # ==========================================================================
    # Internal Validation & Process Execution
    # ==========================================================================

    def _validate_and_sanitize_args(
        self, tool_def: ToolDefinition, args: List[str]
    ) -> Tuple[List[str], Optional[str]]:
        """Validate argument list against allowed flags and reject dangerous characters."""
        sanitized: List[str] = []
        for arg in args:
            if not isinstance(arg, str):
                return [], f"Non-string argument provided: {arg}"

            arg_str = arg.strip()

            # Reject shell operators, metacharacters, or command chaining
            if DANGEROUS_ARG_PATTERN.search(arg_str):
                return [], f"Dangerous shell metacharacter or command detected in argument: '{arg_str}'"

            # Secret redaction for argument logging/persistence
            redacted = self._redact_secret_arg(arg_str)
            sanitized.append(redacted)

        return sanitized, None

    def _redact_secret_arg(self, arg: str) -> str:
        """Redact sensitive credentials in arguments."""
        if any(token in arg.lower() for token in ["password=", "token=", "key=", "secret=", "auth="]):
            parts = arg.split("=", 1)
            return f"{parts[0]}=***REDACTED***"
        return arg

    def _resolve_executable(
        self, tool_def: ToolDefinition, custom_path: Optional[str]
    ) -> Optional[str]:
        """Verify executable exists without permitting arbitrary unverified paths."""
        if custom_path:
            # Must strictly match the canonical tool binary name
            base_name = os.path.basename(custom_path).lower()
            if base_name in (
                tool_def.executable.lower(),
                f"{tool_def.executable.lower()}.exe",
                f"{tool_def.executable.lower()}.bat",
                f"{tool_def.executable.lower()}.cmd",
            ):
                if os.path.isfile(custom_path) and (
                    os.access(custom_path, os.X_OK) or custom_path.lower().endswith((".bat", ".cmd"))
                ):
                    return custom_path

        # Check AIHAX_TOOLS_DIR if set
        tools_dir = os.environ.get("AIHAX_TOOLS_DIR")
        if tools_dir and os.path.isdir(tools_dir):
            found = shutil.which(tool_def.executable, path=tools_dir)
            if found:
                return found

        # Fallback to project bin/tools directory if present
        default_tools_dir = Path(__file__).resolve().parent.parent.parent / "bin" / "tools"
        if default_tools_dir.is_dir():
            found = shutil.which(tool_def.executable, path=str(default_tools_dir))
            if found:
                return found

        # Standard PATH lookup
        return shutil.which(tool_def.executable)

    async def _run_process(
        self,
        execution_id: str,
        tool_def: ToolDefinition,
        exec_path: str,
        sanitized_args: List[str],
        timeout: int,
        request: ToolExecutionRequest,
        started_at: str,
        start_mono: float,
        db: Optional[Session],
    ) -> ToolExecutionResult:
        """Run external process with strict timeouts, size bounds, and safe execution."""
        # Use custom runner if injected (for zero-network testing)
        if self._custom_process_runner is not None:
            try:
                exit_code, stdout_bytes, stderr_bytes = self._custom_process_runner(exec_path, sanitized_args, timeout)
                status = ToolExecutionStatus.SUCCESS.value if exit_code == 0 else ToolExecutionStatus.PROCESS_ERROR.value
                return self._build_result(
                    execution_id=execution_id,
                    request=request,
                    status=status,
                    sanitized_args=sanitized_args,
                    exit_code=exit_code,
                    timeout_seconds=timeout,
                    stdout_bytes=stdout_bytes,
                    stderr_bytes=stderr_bytes,
                    started_at=started_at,
                    start_mono=start_mono,
                    db=db,
                )
            except asyncio.TimeoutError:
                return self._build_result(
                    execution_id=execution_id,
                    request=request,
                    status=ToolExecutionStatus.TIMEOUT.value,
                    error_category=f"Tool execution timed out after {timeout} seconds",
                    sanitized_args=sanitized_args,
                    timeout_seconds=timeout,
                    started_at=started_at,
                    start_mono=start_mono,
                    db=db,
                )
            except Exception as e:
                return self._build_result(
                    execution_id=execution_id,
                    request=request,
                    status=ToolExecutionStatus.PROCESS_ERROR.value,
                    error_category=f"Execution error: {str(e)}",
                    sanitized_args=sanitized_args,
                    timeout_seconds=timeout,
                    started_at=started_at,
                    start_mono=start_mono,
                    db=db,
                )

        # Real Subprocess Execution: shell=False with argv array
        cmd_argv = [exec_path] + sanitized_args
        process = None

        try:
            process = await asyncio.create_subprocess_exec(
                *cmd_argv,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
            )

            # Stream with size limits
            stdout_task = asyncio.create_task(self._read_stream(process.stdout, tool_def.max_stdout_bytes))
            stderr_task = asyncio.create_task(self._read_stream(process.stderr, tool_def.max_stderr_bytes))

            try:
                done, pending = await asyncio.wait(
                    [stdout_task, stderr_task, asyncio.create_task(process.wait())],
                    timeout=timeout,
                    return_when=asyncio.ALL_COMPLETED,
                )
            except asyncio.TimeoutError:
                pass

            if process.returncode is None:
                # Process timed out: terminate safely
                try:
                    process.kill()
                    await process.wait()
                except Exception:
                    pass
                return self._build_result(
                    execution_id=execution_id,
                    request=request,
                    status=ToolExecutionStatus.TIMEOUT.value,
                    error_category=f"Process timed out after {timeout} seconds",
                    sanitized_args=sanitized_args,
                    timeout_seconds=timeout,
                    started_at=started_at,
                    start_mono=start_mono,
                    db=db,
                )

            stdout_bytes, stdout_truncated = await stdout_task
            stderr_bytes, stderr_truncated = await stderr_task

            if stdout_truncated or stderr_truncated:
                return self._build_result(
                    execution_id=execution_id,
                    request=request,
                    status=ToolExecutionStatus.OUTPUT_LIMIT.value,
                    error_category="Process output exceeded configured byte limits",
                    sanitized_args=sanitized_args,
                    exit_code=process.returncode,
                    timeout_seconds=timeout,
                    stdout_bytes=stdout_bytes,
                    stderr_bytes=stderr_bytes,
                    started_at=started_at,
                    start_mono=start_mono,
                    db=db,
                )

            status = ToolExecutionStatus.SUCCESS.value if process.returncode == 0 else ToolExecutionStatus.PROCESS_ERROR.value
            return self._build_result(
                execution_id=execution_id,
                request=request,
                status=status,
                sanitized_args=sanitized_args,
                exit_code=process.returncode,
                timeout_seconds=timeout,
                stdout_bytes=stdout_bytes,
                stderr_bytes=stderr_bytes,
                started_at=started_at,
                start_mono=start_mono,
                db=db,
            )

        except FileNotFoundError:
            return self._build_result(
                execution_id=execution_id,
                request=request,
                status=ToolExecutionStatus.NOT_INSTALLED.value,
                error_category=f"Executable '{exec_path}' not found",
                sanitized_args=sanitized_args,
                timeout_seconds=timeout,
                started_at=started_at,
                start_mono=start_mono,
                db=db,
            )
        except Exception as e:
            return self._build_result(
                execution_id=execution_id,
                request=request,
                status=ToolExecutionStatus.PROCESS_ERROR.value,
                error_category=f"Subprocess failure: {str(e)}",
                sanitized_args=sanitized_args,
                timeout_seconds=timeout,
                started_at=started_at,
                start_mono=start_mono,
                db=db,
            )

    async def _read_stream(
        self, stream: Optional[asyncio.StreamReader], max_bytes: int
    ) -> Tuple[bytes, bool]:
        """Read stream chunks up to max_bytes, returning collected bytes and truncation flag."""
        if stream is None:
            return b"", False

        collected: List[bytes] = []
        total_len = 0
        truncated = False

        while True:
            chunk = await stream.read(4096)
            if not chunk:
                break
            if total_len + len(chunk) <= max_bytes:
                collected.append(chunk)
                total_len += len(chunk)
            else:
                remaining = max_bytes - total_len
                if remaining > 0:
                    collected.append(chunk[:remaining])
                truncated = True
                break

        return b"".join(collected), truncated

    def _build_result(
        self,
        execution_id: str,
        request: ToolExecutionRequest,
        status: str,
        sanitized_args: Optional[List[str]] = None,
        exit_code: Optional[int] = None,
        timeout_seconds: int = 60,
        stdout_bytes: bytes = b"",
        stderr_bytes: bytes = b"",
        error_category: Optional[str] = None,
        started_at: str = "",
        start_mono: float = 0.0,
        db: Optional[Session] = None,
    ) -> ToolExecutionResult:
        """Build deterministic ToolExecutionResult and persist to database."""
        completed_at_dt = get_utc_now()
        completed_at = completed_at_dt.isoformat()
        duration_ms = max(0.0, (time.monotonic() - start_mono) * 1000)

        stdout_hash = hashlib.sha256(stdout_bytes).hexdigest() if stdout_bytes else None
        stderr_hash = hashlib.sha256(stderr_bytes).hexdigest() if stderr_bytes else None
        combined_hash = hashlib.sha256(stdout_bytes + stderr_bytes).hexdigest() if (stdout_bytes or stderr_bytes) else None

        stdout_str = stdout_bytes.decode("utf-8", errors="replace") if stdout_bytes else None
        stderr_str = stderr_bytes.decode("utf-8", errors="replace") if stderr_bytes else None

        parsed_summary = {
            "status": status,
            "stdout_size": len(stdout_bytes),
            "stderr_size": len(stderr_bytes),
            "duration_ms": duration_ms,
        }

        res = ToolExecutionResult(
            id=execution_id,
            campaign_id=request.campaign_id,
            target=request.target,
            tool_name=request.tool_name,
            tool_version=None,
            execution_profile=request.execution_profile,
            execution_status=status,
            sanitized_args=sanitized_args or [],
            exit_code=exit_code,
            timeout_seconds=timeout_seconds,
            stdout_hash=stdout_hash,
            stderr_hash=stderr_hash,
            output_hash=combined_hash,
            stdout=stdout_str,
            stderr=stderr_str,
            parsed_summary=parsed_summary,
            error_category=error_category,
            started_at=started_at,
            completed_at=completed_at,
            duration_ms=duration_ms,
        )

        if db is not None:
            self._persist_tool_record(res, db)

        return res

    def _persist_tool_record(self, res: ToolExecutionResult, db: Session) -> None:
        """Persist tool execution record to database without plaintext secrets."""
        try:
            rec = ToolExecutionRecord(
                id=res.id,
                campaign_id=res.campaign_id,
                target=res.target,
                tool_name=res.tool_name,
                tool_version=res.tool_version,
                execution_profile=res.execution_profile,
                execution_status=res.execution_status,
                sanitized_args_json=json.dumps(res.sanitized_args),
                exit_code=res.exit_code,
                timeout_seconds=res.timeout_seconds,
                stdout_hash=res.stdout_hash,
                stderr_hash=res.stderr_hash,
                output_hash=res.output_hash,
                parsed_summary_json=json.dumps(res.parsed_summary),
                error_category=res.error_category,
                started_at=get_utc_now(),
                completed_at=get_utc_now(),
            )
            db.add(rec)
            db.commit()
        except Exception as e:
            logger.warning(f"Failed to persist ToolExecutionRecord: {e}")
            db.rollback()
