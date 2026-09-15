"""AihaX Deterministic Canary Generator & Negative Control Framework."""

from __future__ import annotations

import hashlib
import random
import uuid
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from enum import Enum
from typing import Any, Dict, Optional


class CanaryCategory(str, Enum):
    REFLECTION = "REFLECTION"
    ARITHMETIC = "ARITHMETIC"
    SSTI = "SSTI"
    SQL_SYNTAX = "SQL_SYNTAX"
    SQL_BOOLEAN = "SQL_BOOLEAN"
    PATH_TRAVERSAL = "PATH_TRAVERSAL"
    HEADER_INJECTION = "HEADER_INJECTION"
    SAFE_UPLOAD = "SAFE_UPLOAD"
    IDOR_OBJECT = "IDOR_OBJECT"


@dataclass(frozen=True)
class CanaryRecord:
    """Represents a deterministic, non-destructive test canary with paired negative control."""

    canary_id: str
    check_id: str
    category: CanaryCategory
    payload: str
    expected_signal: str
    negative_control_payload: str
    negative_control_expected: str
    description: str
    created_at: str = field(
        default_factory=lambda: datetime.now(timezone.utc).isoformat()
    )

    def to_dict(self) -> dict[str, Any]:
        d = asdict(self)
        d["category"] = self.category.value
        return d


class CanaryGenerator:
    """Generates unique, non-destructive test canaries and paired controls."""

    @classmethod
    def generate_reflection_canary(cls, check_id: str = "C037") -> CanaryRecord:
        token = uuid.uuid4().hex[:10]
        payload = f"<aihax_refl_{check_id.lower()}_{token}>"
        ctrl_token = uuid.uuid4().hex[:10]
        ctrl_payload = f"<aihax_ctrl_{ctrl_token}>"
        return CanaryRecord(
            canary_id=f"canary-refl-{token[:8]}",
            check_id=check_id,
            category=CanaryCategory.REFLECTION,
            payload=payload,
            expected_signal=payload,
            negative_control_payload=ctrl_payload,
            negative_control_expected=ctrl_payload,
            description="Unique high-entropy string for reflection and XSS context verification",
        )

    @classmethod
    def generate_arithmetic_canary(cls, check_id: str = "C027") -> CanaryRecord:
        n1 = random.randint(11000, 49000)
        n2 = random.randint(11, 89)
        result = n1 * n2
        payload = f"$(( {n1} * {n2} ))"
        expected_signal = str(result)
        ctrl_payload = f"text_{n1}_{n2}_literal"
        return CanaryRecord(
            canary_id=f"canary-math-{uuid.uuid4().hex[:8]}",
            check_id=check_id,
            category=CanaryCategory.ARITHMETIC,
            payload=payload,
            expected_signal=expected_signal,
            negative_control_payload=ctrl_payload,
            negative_control_expected=ctrl_payload,
            description="Safe mathematical evaluation canary without executing OS commands",
        )

    @classmethod
    def generate_ssti_canary(cls, check_id: str = "C028") -> CanaryRecord:
        n1 = random.randint(1000, 9999)
        n2 = random.randint(100, 999)
        result = n1 * n2
        payload = f"{{{{{n1}*{n2}}}}}"
        expected_signal = str(result)
        ctrl_payload = f"STATIC_{n1}_{n2}"
        return CanaryRecord(
            canary_id=f"canary-ssti-{uuid.uuid4().hex[:8]}",
            check_id=check_id,
            category=CanaryCategory.SSTI,
            payload=payload,
            expected_signal=expected_signal,
            negative_control_payload=ctrl_payload,
            negative_control_expected=ctrl_payload,
            description="Safe template engine arithmetic expression without OS or filesystem access",
        )

    @classmethod
    def generate_sql_syntax_canary(cls, check_id: str = "C023") -> CanaryRecord:
        token = uuid.uuid4().hex[:8]
        payload = f"'{token}"
        ctrl_payload = f"safe_{token}"
        return CanaryRecord(
            canary_id=f"canary-sqli-{token}",
            check_id=check_id,
            category=CanaryCategory.SQL_SYNTAX,
            payload=payload,
            expected_signal="SQL_SYNTAX_ERROR",
            negative_control_payload=ctrl_payload,
            negative_control_expected="NORMAL_RESPONSE",
            description="Non-destructive syntactic quote probe comparing against clean control input",
        )

    @classmethod
    def generate_sql_boolean_canary(cls, check_id: str = "C024") -> CanaryRecord:
        cid = uuid.uuid4().hex[:8]
        true_probe = "1' OR '1'='1"
        false_probe = "1' OR '1'='2"
        return CanaryRecord(
            canary_id=f"canary-sqlbool-{cid}",
            check_id=check_id,
            category=CanaryCategory.SQL_BOOLEAN,
            payload=true_probe,
            expected_signal="DIFFERENTIAL_MATCH",
            negative_control_payload=false_probe,
            negative_control_expected="DIFFERENTIAL_MISMATCH",
            description="Deterministic boolean differential pair without destructive SQL modifications",
        )

    @classmethod
    def generate_path_traversal_canary(cls, check_id: str = "C031") -> CanaryRecord:
        cid = uuid.uuid4().hex[:8]
        payload = "../../../../etc/passwd"
        ctrl_payload = "valid_resource_safe"
        return CanaryRecord(
            canary_id=f"canary-lfi-{cid}",
            check_id=check_id,
            category=CanaryCategory.PATH_TRAVERSAL,
            payload=payload,
            expected_signal="root:x:0:0",
            negative_control_payload=ctrl_payload,
            negative_control_expected="NORMAL_CONTENT",
            description="Bounded traversal probe checking for standard OS marker without accessing sensitive keys",
        )

    @classmethod
    def generate_header_injection_canary(cls, check_id: str = "C029") -> CanaryRecord:
        token = uuid.uuid4().hex[:8]
        payload = f"valid%0d%0aX-AihaX-Test:{token}"
        ctrl_payload = f"valid_header_{token}"
        return CanaryRecord(
            canary_id=f"canary-crlf-{token}",
            check_id=check_id,
            category=CanaryCategory.HEADER_INJECTION,
            payload=payload,
            expected_signal=f"x-aihax-test: {token}",
            negative_control_payload=ctrl_payload,
            negative_control_expected="ABSENT",
            description="Harmless CRLF header probe verifying whether injected header appears in response headers",
        )

    @classmethod
    def generate_safe_upload_canary(cls, check_id: str = "C055") -> CanaryRecord:
        token = uuid.uuid4().hex[:8]
        payload = f"AihaX Safe Security Verification Artifact {token}\nNon-executable test payload.\n"
        return CanaryRecord(
            canary_id=f"canary-upload-{token}",
            check_id=check_id,
            category=CanaryCategory.SAFE_UPLOAD,
            payload=payload,
            expected_signal=token,
            negative_control_payload="STANDARD_TEXT_CONTENT",
            negative_control_expected="STANDARD_RESPONSE",
            description="Benign text file payload testing upload validation behavior without web shells",
        )

    @classmethod
    def generate_for_check(cls, check_id: str) -> CanaryRecord:
        """Route check ID to the appropriate deterministic canary record."""
        cid = check_id.upper()
        if "C037" in cid or "C038" in cid or "C04" in cid:
            return cls.generate_reflection_canary(check_id)
        if "C027" in cid or "COMMAND" in cid:
            return cls.generate_arithmetic_canary(check_id)
        if "C028" in cid or "SSTI" in cid:
            return cls.generate_ssti_canary(check_id)
        if "C023" in cid:
            return cls.generate_sql_syntax_canary(check_id)
        if "C024" in cid:
            return cls.generate_sql_boolean_canary(check_id)
        if "C031" in cid or "C032" in cid or "TRAVERSAL" in cid:
            return cls.generate_path_traversal_canary(check_id)
        if "C029" in cid or "C030" in cid or "CRLF" in cid:
            return cls.generate_header_injection_canary(check_id)
        if "C055" in cid or "UPLOAD" in cid:
            return cls.generate_safe_upload_canary(check_id)
        # Default reflection canary for general injection/tampering
        return cls.generate_reflection_canary(check_id)
