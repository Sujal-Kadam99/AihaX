"""Settings API routes."""

import json
from pathlib import Path

from fastapi import APIRouter, Depends

from backend.core.config import get_settings
from backend.core.encryption import CredentialVault
from backend.models.schemas import SettingsPayload

router = APIRouter(prefix="/api/settings", tags=["settings"])

SETTINGS_FILE = "settings.json"


@router.post("")
async def save_settings(payload: SettingsPayload):
    settings = get_settings()
    config_dir = Path(settings.config_path)
    config_dir.mkdir(parents=True, exist_ok=True)

    vault = CredentialVault(settings.config_path)
    vault_data = vault.load()

    api_keys = {
        "claude_api_key": payload.claude_api_key,
        "shodan_api_key": payload.shodan_api_key,
        "virustotal_api_key": payload.virustotal_api_key,
        "twilio_sid": payload.twilio_sid,
        "twilio_token": payload.twilio_token,
    }
    for key, value in api_keys.items():
        if value is not None:
            vault_data[key] = value
    vault.save(vault_data)

    user_settings = {
        "app_version": settings.app_version,
        "default_scan_depth": payload.default_scan_depth,
        "default_threads": payload.default_threads,
        "report_branding": {
            "company_name": payload.report_branding_company or "",
            "logo_path": payload.report_branding_logo or "",
        },
        "alert_email": payload.alert_email or "",
        "slack_webhook": payload.slack_webhook or "",
        "ui_theme": "dark",
        "auto_open_report": payload.auto_open_report,
        "stripe_public_key": payload.stripe_public_key or "",
        "stripe_price_pro_monthly": payload.stripe_price_pro_monthly or "",
        "stripe_price_pro_onetime": payload.stripe_price_pro_onetime or "",
        "stripe_price_team_monthly": payload.stripe_price_team_monthly or "",
        "stripe_price_agency_monthly": payload.stripe_price_agency_monthly or "",
        "stripe_price_enterprise_monthly": payload.stripe_price_enterprise_monthly or "",
    }

    settings_path = config_dir / SETTINGS_FILE
    settings_path.write_text(json.dumps(user_settings, indent=2))

    return {"status": "saved", "message": "Settings saved successfully"}


@router.get("")
async def get_settings_endpoint():
    settings = get_settings()
    config_dir = Path(settings.config_path)
    settings_path = config_dir / SETTINGS_FILE

    user_settings = {}
    if settings_path.exists():
        user_settings = json.loads(settings_path.read_text())

    vault = CredentialVault(settings.config_path)
    vault_data = vault.load()

    return {
        "app_version": settings.app_version,
        "settings": user_settings,
        "api_keys_configured": {
            "claude": bool(vault_data.get("claude_api_key")),
            "shodan": bool(vault_data.get("shodan_api_key")),
            "virustotal": bool(vault_data.get("virustotal_api_key")),
            "twilio": bool(vault_data.get("twilio_sid")),
        },
    }
