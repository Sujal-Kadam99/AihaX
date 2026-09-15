"""Pydantic request/response models for FastAPI."""

from datetime import datetime, timedelta
from enum import Enum
from typing import Any, Generic, Literal, Optional, TypeVar

from pydantic import BaseModel, Field, field_validator

T = TypeVar("T")

class APIError(BaseModel):
    code: str
    message: str
    details: dict[str, Any] | None = None

class APIResponse(BaseModel, Generic[T]):
    success: bool
    data: T | None = None
    error: APIError | None = None


class CredentialPair(BaseModel):
    username: str
    password: str


class GoogleLoginPayload(BaseModel):
    id_token: str


class TokenRefreshPayload(BaseModel):
    refresh_token: str


class UserResponse(BaseModel):
    id: str
    google_sub: str
    email: str
    email_verified: bool = False
    name: str | None = None
    picture: str | None = None
    account_status: str = "active"
    created_at: datetime
    last_login_at: datetime


class AuthSessionResponse(BaseModel):
    access_token: str
    refresh_token: str
    expires_in: int = 900
    token_type: str = "Bearer"
    user: UserResponse



class EmailCredentials(BaseModel):
    email: str
    password: str
    imap_server: str | None = "imap.gmail.com"
    imap_port: int | None = 993


class TwoFAConfig(BaseModel):
    totp_secret: str | None = None
    twilio_sid: str | None = None
    twilio_token: str | None = None
    phone_number: str | None = None


class APIAuth(BaseModel):
    api_key: str | None = None
    api_secret: str | None = None
    base_url: str | None = None
    bearer_token: str | None = None
    cookie_string: str | None = None
    admin_url: str | None = None
    admin_username: str | None = None
    admin_password: str | None = None


class RateLimitConfig(BaseModel):
    requests_per_second: int = Field(default=10, ge=1, le=100)
    max_concurrency: int = Field(default=5, ge=1, le=20)


class ScopeDefinitionSchema(BaseModel):
    in_scope_assets: list[str] = Field(default_factory=list)
    out_of_scope_assets: list[str] = Field(default_factory=list)
    allowed_ports: list[int] = Field(default_factory=list)
    excluded_ports: list[int] = Field(default_factory=list)
    allowed_schemes: list[str] = Field(default_factory=lambda: ["http", "https"])
    excluded_paths: list[str] = Field(default_factory=list)
    scope_notes: str | None = None


class ProgramCreate(BaseModel):
    name: str = Field(min_length=1, max_length=120)
    description: str | None = None
    scope: ScopeDefinitionSchema | None = None


class ProgramResponse(BaseModel):
    id: str
    name: str
    description: str | None = None
    user_id: str | None = None
    status: str = "AUTHORIZED"
    active_campaigns_count: int = 0
    total_campaigns_count: int = 0
    campaigns: list[dict[str, Any]] = Field(default_factory=list)
    scope: ScopeDefinitionSchema | None = None
    created_at: datetime


class ScopeValidationRequest(BaseModel):
    target: str
    port: int | None = None


class ScopeValidationResponse(BaseModel):
    allowed: bool
    status: str
    reason: str
    asset: str
    matched_rule: str | None = None


class ScanConfig(BaseModel):
    target_url: str
    program_id: str | None = None
    industry: str | None = None
    primary_creds: CredentialPair | None = None
    secondary_creds: CredentialPair | None = None
    email_creds: EmailCredentials | None = None
    two_fa_type: Literal["none", "email", "sms", "totp"] = "none"
    two_fa_config: TwoFAConfig | None = None
    api_auth: APIAuth | None = None
    scan_depth: Literal["light", "normal", "deep"] = "normal"
    threads: int = Field(default=5, ge=1, le=20)
    rate_limit: RateLimitConfig | None = None
    waf_bypass: bool = False
    stealth_mode: bool = False
    authorization_confirmed: bool = False
    scope_notes: str | None = None
    scan_mode: Literal["passive", "safe", "standard", "bugbounty", "compliance", "watch"] = "safe"
    report_format: Literal["executive", "bugbounty", "full"] = "full"
    admin_mode: bool = False

    @field_validator("target_url")
    @classmethod
    def validate_target(cls, v: str) -> str:
        from backend.core.url_validator import URLValidationError, validate_target_url
        try:
            return validate_target_url(v)
        except URLValidationError as e:
            raise ValueError(str(e))


class WatchSchedulePayload(BaseModel):
    target_url: str
    watch_name: str | None = None
    schedule_type: Literal["daily", "weekly", "after_deploy"] = "daily"
    scan_config: dict[str, Any]
    scope_notes: str | None = None
    alert_webhook: str | None = None
    alert_email: str | None = None

    @property
    def interval_delta(self) -> timedelta:
        return {
            "daily": timedelta(days=1),
            "weekly": timedelta(weeks=1),
            "after_deploy": timedelta(hours=1),
        }.get(self.schedule_type, timedelta(days=1))


class WatchScheduleItem(BaseModel):
    id: str
    target_url: str
    watch_name: str
    schedule_type: str
    last_run: datetime | None = None
    next_run: datetime | None = None
    active: bool = True
    alert_webhook: str | None = None
    alert_email: str | None = None
    delta_summary: str | None = None


class FindingsCount(BaseModel):
    critical: int = 0
    high: int = 0
    medium: int = 0
    low: int = 0
    info: int = 0


class AgentStatus(BaseModel):
    agent_id: int
    agent_name: str
    status: Literal["pending", "running", "complete", "error"] = "pending"
    progress: int = 0
    message: str = ""


class ScanStatus(BaseModel):
    scan_id: str
    target_url: str
    status: str
    agents: list[AgentStatus]
    findings_count: FindingsCount
    elapsed_seconds: int = 0
    risk_score: int | None = None
    created_at: datetime | None = None
    admin_mode: bool = False


class FindingResponse(BaseModel):
    id: str
    scan_id: str
    title: str
    vuln_type: str
    category: str
    severity: Literal["critical", "high", "medium", "low", "info"]
    cvss_score: float | None = None
    cwe_id: str | None = None
    cve_id: str | None = None
    affected_url: str
    affected_param: str | None = None
    payload: str | None = None
    proof_response: str | None = None
    screenshot_path: str | None = None
    confidence: int
    verdict: str
    verification_status: str | None = "CANDIDATE"
    verification_reason_code: str | None = None
    verification_method: str | None = None
    verification_timestamp: datetime | None = None
    false_positive: bool
    agent_id: int
    remediation: dict[str, Any] | None = None
    business_impact: dict[str, Any] | None = None
    human_review_status: str | None = "PENDING"
    human_reviewed_by: str | None = None
    human_reviewed_at: datetime | None = None
    human_review_notes: str | None = None
    duplicate_of: str | None = None
    finding_fingerprint: str | None = None
    finding_disposition: str | None = "INCONCLUSIVE"
    condition_confidence: float | None = 0.0
    impact_confidence: float | None = 0.0
    reproducibility_confidence: float | None = 0.0
    exploitability_confidence: float | None = 0.0
    policy_eligibility_confidence: float | None = 0.0
    bounty_eligibility: str | None = "UNKNOWN"
    verification_explanation: str | None = None
    created_at: datetime


class ReviewDecision(str, Enum):
    APPROVE = "APPROVE"
    REJECT = "REJECT"
    REVERIFY = "REVERIFY"


class ReviewFindingRequest(BaseModel):
    decision: ReviewDecision
    notes: Optional[str] = None
    actor: Optional[str] = "operator"


class ScanHistoryItem(BaseModel):
    id: str
    target_url: str
    created_at: datetime
    completed_at: datetime | None = None
    status: str
    scan_depth: str
    scan_mode: str
    total_findings: int = 0
    risk_score: int | None = None
    admin_mode: bool = False


class SubscriptionCreate(BaseModel):
    email: str
    plan_name: str
    duration_days: int = 30


class SubscriptionResponse(BaseModel):
    id: str
    email: str
    plan_name: str
    status: str
    start_date: datetime
    end_date: datetime
    last_notified: datetime | None = None
    created_at: datetime



class SettingsPayload(BaseModel):
    claude_api_key: str | None = None
    shodan_api_key: str | None = None
    virustotal_api_key: str | None = None
    twilio_sid: str | None = None
    twilio_token: str | None = None
    default_scan_depth: str | None = "normal"
    default_threads: int | None = 5
    report_branding_company: str | None = None
    report_branding_logo: str | None = None
    alert_email: str | None = None
    slack_webhook: str | None = None
    auto_open_report: bool | None = True
    stripe_public_key: str | None = None
    stripe_price_pro_monthly: str | None = None
    stripe_price_pro_onetime: str | None = None
    stripe_price_team_monthly: str | None = None
    stripe_price_agency_monthly: str | None = None
    stripe_price_enterprise_monthly: str | None = None


class HealthResponse(BaseModel):
    status: str
    version: str
    redis: str = "unknown"
    database: str = "unknown"


class WebSocketMessage(BaseModel):
    scan_id: str
    agent_id: int
    agent_name: str
    status: str
    progress: int
    message: str
    finding: dict[str, Any] | None = None


class BugBountyPoCDTO(BaseModel):
    description: str = "Not available from collected evidence."
    request: str = "Not available from collected evidence."
    response: str = "Not available from collected evidence."
    payload: str = "Not available from collected evidence."

class BugBountyFindingDTO(BaseModel):
    title: str
    summary: str
    severity: str
    confidence: int
    vulnerability_type: str
    cwe: str | None = None
    owasp_category: str | None = None
    target: str
    affected_url: str
    steps_to_reproduce: list[str] = []
    impact_confirmed: str = "Not available from collected evidence."
    impact_potential: str = "Not available from collected evidence."
    proof_of_concept: BugBountyPoCDTO
    suggested_fix: str = "Not available from collected evidence."
    references: list[str] = []
