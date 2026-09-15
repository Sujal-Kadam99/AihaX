"""Seeds the active AihaX database with the Eternal program and Eternal-Zomato-Web-001 campaign."""

import json
import logging
import os
import sys
import uuid
from datetime import datetime, timezone

sys.path.insert(0, os.path.abspath("."))

from backend.models.database import Base, Program, ProgramScope, get_engine, get_session_factory
from backend.persistence.models import AuthorizationRecord, Campaign, CampaignTarget
from backend.persistence.repository import CampaignRepository
from backend.services.campaign_operations import CampaignOperationsService

logging.basicConfig(level=logging.INFO, format="%(message)s")


def seed_eternal_zomato():
    engine = get_engine()
    Base.metadata.create_all(bind=engine)
    SessionLocal = get_session_factory()
    session = SessionLocal()

    try:
        # 1. Check or Create Eternal Program
        prog = session.query(Program).filter_by(name="Eternal").first()
        in_scope_assets = ["https://*.zomato.com/*", "http://*.zomato.com/*", "*.zomato.com", "zomato.com"]
        out_of_scope_assets = [
            "https://evil.com/*",
            "*.blinkit.com",
            "*.feedingindia.org",
            "*.hyperpure.com",
            "*.external.com",
        ]
        allowed_ports = [80, 443]
        excluded_ports = [22, 25, 445, 3389, 8080]

        if not prog:
            prog_id = str(uuid.uuid4())
            prog = Program(
                id=prog_id,
                name="Eternal",
                description="Eternal HackerOne Bug Bounty Program — Authorized Scope (*.zomato.com)",
                created_at=datetime.now(timezone.utc),
            )
            session.add(prog)

            scope = ProgramScope(
                id=str(uuid.uuid4()),
                program_id=prog_id,
                in_scope_assets=json.dumps(in_scope_assets),
                out_of_scope_assets=json.dumps(out_of_scope_assets),
                allowed_ports=json.dumps(allowed_ports),
                excluded_ports=json.dumps(excluded_ports),
                allowed_schemes=json.dumps(["http", "https"]),
                excluded_paths=json.dumps(["/admin/destructive/*", "/internal/debug/*"]),
                scope_notes="Authorized eligible wildcard: *.zomato.com. Strictly isolated.",
            )
            session.add(scope)
            session.commit()
            print(f"[+] Created Program: Eternal ({prog.id})")
        else:
            print(f"[*] Program Eternal already exists ({prog.id})")

        # 2. Check or Create Campaign
        existing_camp = session.query(Campaign).filter_by(name="Eternal-Zomato-Web-001").first()
        if not existing_camp:
            repo = CampaignRepository(session)
            ops = CampaignOperationsService(repo)

            camp = ops.create_campaign(
                name="Eternal-Zomato-Web-001",
                target_url="https://www.zomato.com",
                mode="CONTROLLED_HUMAN_IN_THE_LOOP",
                program_id=prog.id,
                campaign_budget=250,
                target_budget=50,
                check_budget=10,
                max_concurrency=2,
                in_scope_assets=in_scope_assets,
            )
            session.commit()

            ops.authorize_campaign(
                campaign_id=camp.id,
                authorized_by="lead_security_operator",
                authorization_type="explicit_scope_consent",
                authorization_reference="H1-ETERNAL-ZOMATO-AUTH-001",
                duration_days=30,
            )
            session.commit()
            print(f"[+] Created & Authorized Campaign: Eternal-Zomato-Web-001 ({camp.id})")
        else:
            print(f"[*] Campaign Eternal-Zomato-Web-001 already exists ({existing_camp.id})")

    finally:
        session.close()


if __name__ == "__main__":
    seed_eternal_zomato()
