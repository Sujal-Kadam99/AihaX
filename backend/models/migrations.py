"""Transactional embedded database migration runner with checksum validation and backup recovery."""

import hashlib
import logging
import shutil
from datetime import datetime, timezone
from pathlib import Path
from typing import TypedDict
from sqlalchemy import Engine, text

logger = logging.getLogger(__name__)


class MigrationEntry(TypedDict):
    version: int
    name: str
    up_sql: list[str]

# List of deterministic, versioned migrations
# Each migration is a dict: { "version": int, "name": str, "up_sql": list[str] }
MIGRATIONS: list[MigrationEntry] = [
    {
        "version": 1,
        "name": "001_initial_schema",
        "up_sql": [
            """
            CREATE TABLE IF NOT EXISTS schema_migrations (
                version INTEGER PRIMARY KEY,
                name TEXT NOT NULL,
                checksum TEXT NOT NULL,
                applied_at DATETIME NOT NULL
            );
            """,
            """
            CREATE TABLE IF NOT EXISTS scans (
                id VARCHAR PRIMARY KEY,
                target_url VARCHAR NOT NULL,
                created_at DATETIME NOT NULL,
                completed_at DATETIME,
                status VARCHAR NOT NULL DEFAULT 'pending',
                scan_depth VARCHAR NOT NULL DEFAULT 'normal',
                scan_mode VARCHAR NOT NULL DEFAULT 'standard',
                threads INTEGER NOT NULL DEFAULT 5,
                waf_bypass BOOLEAN NOT NULL DEFAULT 0,
                stealth_mode BOOLEAN NOT NULL DEFAULT 0,
                industry VARCHAR,
                tech_stack TEXT,
                total_findings INTEGER DEFAULT 0,
                risk_score INTEGER,
                report_path VARCHAR,
                schedule_id VARCHAR,
                admin_mode BOOLEAN NOT NULL DEFAULT 0
            );
            """,
            """
            CREATE TABLE IF NOT EXISTS findings (
                id VARCHAR PRIMARY KEY,
                scan_id VARCHAR NOT NULL,
                agent_id INTEGER NOT NULL,
                title VARCHAR NOT NULL,
                vuln_type VARCHAR NOT NULL,
                category VARCHAR NOT NULL,
                severity VARCHAR NOT NULL,
                cvss_score FLOAT,
                cwe_id VARCHAR,
                cve_id VARCHAR,
                affected_url VARCHAR NOT NULL,
                affected_param VARCHAR,
                payload TEXT,
                proof_response TEXT,
                screenshot_path VARCHAR,
                confidence INTEGER NOT NULL DEFAULT 0,
                false_positive BOOLEAN DEFAULT 0,
                remediation TEXT,
                business_impact TEXT,
                chain_id VARCHAR,
                created_at DATETIME NOT NULL,
                FOREIGN KEY(scan_id) REFERENCES scans(id) ON DELETE CASCADE
            );
            """,
            """
            CREATE TABLE IF NOT EXISTS agent_logs (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                scan_id VARCHAR NOT NULL,
                agent_id INTEGER NOT NULL,
                level VARCHAR NOT NULL,
                message TEXT NOT NULL,
                raw_output TEXT,
                created_at DATETIME NOT NULL,
                FOREIGN KEY(scan_id) REFERENCES scans(id) ON DELETE CASCADE
            );
            """,
            """
            CREATE TABLE IF NOT EXISTS exploit_chains (
                id VARCHAR PRIMARY KEY,
                scan_id VARCHAR NOT NULL,
                chain_name VARCHAR NOT NULL,
                severity_final VARCHAR NOT NULL,
                steps TEXT NOT NULL,
                impact_summary TEXT,
                diagram_path VARCHAR,
                created_at DATETIME NOT NULL,
                FOREIGN KEY(scan_id) REFERENCES scans(id) ON DELETE CASCADE
            );
            """,
            """
            CREATE TABLE IF NOT EXISTS scan_configs (
                id VARCHAR PRIMARY KEY,
                scan_id VARCHAR NOT NULL,
                primary_creds TEXT,
                secondary_creds TEXT,
                email_creds TEXT,
                two_fa_type VARCHAR,
                two_fa_config TEXT,
                api_auth TEXT,
                authorization_confirmed BOOLEAN NOT NULL DEFAULT 0,
                authorization_notes TEXT,
                created_at DATETIME NOT NULL,
                FOREIGN KEY(scan_id) REFERENCES scans(id) ON DELETE CASCADE
            );
            """,
            """
            CREATE TABLE IF NOT EXISTS watch_schedules (
                id VARCHAR PRIMARY KEY,
                target_url VARCHAR NOT NULL,
                schedule_type VARCHAR NOT NULL,
                last_run DATETIME,
                next_run DATETIME,
                base_scan_id VARCHAR,
                last_scan_id VARCHAR,
                watch_name VARCHAR,
                scan_payload TEXT,
                scope_notes TEXT,
                alert_webhook VARCHAR,
                alert_email VARCHAR,
                delta_summary TEXT,
                active BOOLEAN DEFAULT 1,
                created_at DATETIME
            );
            """,
            """
            CREATE TABLE IF NOT EXISTS subscriptions (
                id VARCHAR PRIMARY KEY,
                email VARCHAR NOT NULL,
                plan_name VARCHAR NOT NULL,
                status VARCHAR NOT NULL DEFAULT 'active',
                start_date DATETIME NOT NULL,
                end_date DATETIME NOT NULL,
                last_notified DATETIME,
                created_at DATETIME NOT NULL
            );
            """,
            """
            CREATE TABLE IF NOT EXISTS users (
                id VARCHAR PRIMARY KEY,
                google_sub VARCHAR UNIQUE NOT NULL,
                email VARCHAR UNIQUE NOT NULL,
                email_verified BOOLEAN NOT NULL DEFAULT 0,
                name VARCHAR,
                picture VARCHAR,
                account_status VARCHAR NOT NULL DEFAULT 'active',
                created_at DATETIME NOT NULL,
                last_login_at DATETIME NOT NULL
            );
            """,
            """
            CREATE TABLE IF NOT EXISTS refresh_tokens (
                id VARCHAR PRIMARY KEY,
                user_id VARCHAR NOT NULL,
                token_hash VARCHAR UNIQUE NOT NULL,
                family_id VARCHAR NOT NULL,
                revoked BOOLEAN NOT NULL DEFAULT 0,
                expires_at DATETIME NOT NULL,
                created_at DATETIME NOT NULL,
                FOREIGN KEY(user_id) REFERENCES users(id) ON DELETE CASCADE
            );
            """,
        ],
    },
    {
        "version": 2,
        "name": "002_scans_and_watch_columns",
        "up_sql": [
            "ALTER TABLE scans ADD COLUMN admin_mode BOOLEAN DEFAULT 0;",
            "ALTER TABLE watch_schedules ADD COLUMN base_scan_id VARCHAR;",
            "ALTER TABLE watch_schedules ADD COLUMN last_scan_id VARCHAR;",
            "ALTER TABLE watch_schedules ADD COLUMN watch_name VARCHAR;",
            "ALTER TABLE watch_schedules ADD COLUMN scan_payload TEXT;",
            "ALTER TABLE watch_schedules ADD COLUMN scope_notes TEXT;",
            "ALTER TABLE watch_schedules ADD COLUMN alert_webhook VARCHAR;",
            "ALTER TABLE watch_schedules ADD COLUMN alert_email VARCHAR;",
            "ALTER TABLE watch_schedules ADD COLUMN delta_summary TEXT;",
            "ALTER TABLE watch_schedules ADD COLUMN active BOOLEAN DEFAULT 1;",
            "ALTER TABLE watch_schedules ADD COLUMN created_at DATETIME;",
        ],
    },
    {
        "version": 3,
        "name": "003_performance_indexes",
        "up_sql": [
            "CREATE INDEX IF NOT EXISTS idx_findings_scan_id ON findings(scan_id);",
            "CREATE INDEX IF NOT EXISTS idx_findings_severity ON findings(severity);",
            "CREATE INDEX IF NOT EXISTS idx_findings_vuln_type ON findings(vuln_type);",
            "CREATE INDEX IF NOT EXISTS idx_scans_status ON scans(status);",
            "CREATE INDEX IF NOT EXISTS idx_scans_created_at ON scans(created_at);",
            "CREATE INDEX IF NOT EXISTS idx_agent_logs_scan_id ON agent_logs(scan_id);",
            "CREATE INDEX IF NOT EXISTS idx_watch_schedules_next_run ON watch_schedules(next_run);",
        ],
    },
    {
        "version": 4,
        "name": "004_add_user_tracking",
        "up_sql": [
            "ALTER TABLE scans ADD COLUMN user_id VARCHAR;",
            "ALTER TABLE scans ADD COLUMN user_email VARCHAR;",
            "CREATE INDEX IF NOT EXISTS idx_scans_user_id ON scans(user_id);",
            "CREATE INDEX IF NOT EXISTS idx_scans_user_email ON scans(user_email);",
        ],
    },
    {
        "version": 5,
        "name": "005_add_schedule_id_to_scans",
        "up_sql": [
            "ALTER TABLE scans ADD COLUMN schedule_id VARCHAR;",
        ],
    },
    {
        "version": 6,
        "name": "006_audit_logs",
        "up_sql": [
            """
            CREATE TABLE IF NOT EXISTS audit_logs (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                entity_type VARCHAR NOT NULL,
                entity_id VARCHAR NOT NULL,
                action VARCHAR NOT NULL,
                old_value VARCHAR,
                new_value VARCHAR,
                user_id VARCHAR,
                metadata_json TEXT,
                created_at DATETIME NOT NULL
            );
            """,
            "CREATE INDEX IF NOT EXISTS idx_audit_logs_entity ON audit_logs(entity_type, entity_id);",
            "CREATE INDEX IF NOT EXISTS idx_audit_logs_action ON audit_logs(action);",
            "CREATE INDEX IF NOT EXISTS idx_audit_logs_user ON audit_logs(user_id);",
            "CREATE INDEX IF NOT EXISTS idx_audit_logs_created ON audit_logs(created_at);",
        ],
    },
    {
        "version": 7,
        "name": "007_entitlement_cache",
        "up_sql": [
            """
            CREATE TABLE IF NOT EXISTS entitlement_cache (
                id VARCHAR PRIMARY KEY,
                user_id VARCHAR UNIQUE NOT NULL,
                plan_name VARCHAR NOT NULL,
                entitlement_jwt TEXT NOT NULL,
                features_json TEXT,
                synced_at DATETIME NOT NULL,
                expires_at DATETIME NOT NULL
            );
            """,
            "CREATE INDEX IF NOT EXISTS idx_entitlement_expires ON entitlement_cache(expires_at);",
        ],
    },
    {
        "version": 8,
        "name": "008_composite_indexes",
        "up_sql": [
            "CREATE INDEX IF NOT EXISTS idx_scans_user_status ON scans(user_id, status);",
            "CREATE INDEX IF NOT EXISTS idx_findings_scan_severity ON findings(scan_id, severity);",
            "CREATE INDEX IF NOT EXISTS idx_findings_scan_category ON findings(scan_id, category);",
            "CREATE INDEX IF NOT EXISTS idx_agent_logs_scan_agent ON agent_logs(scan_id, agent_id);",
        ],
    },
    {
        "version": 9,
        "name": "009_scan_configs_auth",
        "up_sql": [
            "ALTER TABLE scan_configs ADD COLUMN authorization_confirmed BOOLEAN NOT NULL DEFAULT 0;",
            "ALTER TABLE scan_configs ADD COLUMN authorization_notes TEXT;",
        ],
    },
    {
        "version": 10,
        "name": "010_bug_bounty_reporting",
        "up_sql": [
            "ALTER TABLE findings ADD COLUMN proof_request TEXT;",
            "ALTER TABLE findings ADD COLUMN verification_method VARCHAR;",
            "ALTER TABLE findings ADD COLUMN verification_timestamp DATETIME;",
        ],
    },
    {
        "version": 11,
        "name": "011_scans_report_format",
        "up_sql": [
            "ALTER TABLE scans ADD COLUMN report_format VARCHAR NOT NULL DEFAULT 'full';",
        ],
    },
    {
        "version": 12,
        "name": "012_add_findings_verdict",
        "up_sql": [
            "ALTER TABLE findings ADD COLUMN verdict VARCHAR NOT NULL DEFAULT 'Inconclusive';",
        ],
    },
    {
        "version": 13,
        "name": "013_bug_bounty_programs_and_scope",
        "up_sql": [
            """
            CREATE TABLE IF NOT EXISTS programs (
                id VARCHAR PRIMARY KEY,
                name VARCHAR NOT NULL,
                description TEXT,
                user_id VARCHAR,
                created_at DATETIME NOT NULL
            );
            """,
            "CREATE INDEX IF NOT EXISTS idx_programs_name ON programs(name);",
            "CREATE INDEX IF NOT EXISTS idx_programs_user_id ON programs(user_id);",
            """
            CREATE TABLE IF NOT EXISTS program_scopes (
                id VARCHAR PRIMARY KEY,
                program_id VARCHAR UNIQUE NOT NULL,
                in_scope_assets TEXT NOT NULL DEFAULT '[]',
                out_of_scope_assets TEXT NOT NULL DEFAULT '[]',
                allowed_ports TEXT DEFAULT '[]',
                excluded_ports TEXT DEFAULT '[]',
                allowed_schemes TEXT DEFAULT '["http", "https"]',
                excluded_paths TEXT DEFAULT '[]',
                scope_notes TEXT,
                created_at DATETIME NOT NULL,
                updated_at DATETIME NOT NULL,
                FOREIGN KEY(program_id) REFERENCES programs(id) ON DELETE CASCADE
            );
            """,
            "CREATE INDEX IF NOT EXISTS idx_program_scopes_program_id ON program_scopes(program_id);",
            "ALTER TABLE scans ADD COLUMN program_id VARCHAR;",
            "ALTER TABLE scans ADD COLUMN rate_limit_rps INTEGER NOT NULL DEFAULT 10;",
            "ALTER TABLE scans ADD COLUMN max_concurrency INTEGER NOT NULL DEFAULT 5;",
            "ALTER TABLE scan_configs ADD COLUMN program_id VARCHAR;",
            "ALTER TABLE scan_configs ADD COLUMN rate_limit_rps INTEGER NOT NULL DEFAULT 10;",
            "ALTER TABLE scan_configs ADD COLUMN max_concurrency INTEGER NOT NULL DEFAULT 5;",
        ],
    },
    {
        "version": 14,
        "name": "014_bug_bounty_verification_engine",
        "up_sql": [
            "ALTER TABLE findings ADD COLUMN verification_status VARCHAR DEFAULT 'CANDIDATE';",
            "ALTER TABLE findings ADD COLUMN verification_reason_code VARCHAR;",
            "ALTER TABLE findings ADD COLUMN evidence_ids TEXT DEFAULT '[]';",
            "ALTER TABLE findings ADD COLUMN request_ids TEXT DEFAULT '[]';",
            "CREATE INDEX IF NOT EXISTS idx_findings_verification_status ON findings(verification_status);",
        ],
    },
    {
        "version": 15,
        "name": "015_passive_asset_discovery",
        "up_sql": [
            """
            CREATE TABLE IF NOT EXISTS discovery_sources (
                id VARCHAR PRIMARY KEY,
                source_code VARCHAR NOT NULL UNIQUE,
                name VARCHAR NOT NULL,
                description TEXT,
                enabled BOOLEAN NOT NULL DEFAULT 1,
                created_at DATETIME NOT NULL
            );
            """,
            "CREATE UNIQUE INDEX IF NOT EXISTS idx_discovery_sources_source_code ON discovery_sources(source_code);",
            """
            CREATE TABLE IF NOT EXISTS assets (
                id VARCHAR PRIMARY KEY,
                program_id VARCHAR NOT NULL,
                asset_type VARCHAR NOT NULL,
                normalized_value VARCHAR NOT NULL,
                scope_status VARCHAR NOT NULL DEFAULT 'UNKNOWN',
                active_testing_allowed BOOLEAN NOT NULL DEFAULT 0,
                authorization_confirmed BOOLEAN NOT NULL DEFAULT 0,
                dns_records TEXT,
                created_at DATETIME NOT NULL,
                updated_at DATETIME NOT NULL,
                FOREIGN KEY(program_id) REFERENCES programs(id) ON DELETE CASCADE
            );
            """,
            "CREATE INDEX IF NOT EXISTS idx_assets_program_id ON assets(program_id);",
            "CREATE INDEX IF NOT EXISTS idx_assets_asset_type ON assets(asset_type);",
            "CREATE INDEX IF NOT EXISTS idx_assets_normalized_value ON assets(normalized_value);",
            "CREATE INDEX IF NOT EXISTS idx_assets_scope_status ON assets(scope_status);",
            "CREATE INDEX IF NOT EXISTS idx_assets_active_testing ON assets(active_testing_allowed);",
            "CREATE INDEX IF NOT EXISTS idx_assets_auth_confirmed ON assets(authorization_confirmed);",
            "CREATE UNIQUE INDEX IF NOT EXISTS idx_assets_program_type_value ON assets(program_id, asset_type, normalized_value);",
            """
            CREATE TABLE IF NOT EXISTS asset_observations (
                id VARCHAR PRIMARY KEY,
                asset_id VARCHAR NOT NULL,
                source_id VARCHAR NOT NULL,
                request_id VARCHAR,
                evidence_id VARCHAR,
                raw_data TEXT,
                confidence INTEGER NOT NULL DEFAULT 0,
                observed_at DATETIME NOT NULL,
                FOREIGN KEY(asset_id) REFERENCES assets(id) ON DELETE CASCADE,
                FOREIGN KEY(source_id) REFERENCES discovery_sources(id)
            );
            """,
            "CREATE INDEX IF NOT EXISTS idx_asset_observations_asset_id ON asset_observations(asset_id);",
            "CREATE INDEX IF NOT EXISTS idx_asset_observations_source_id ON asset_observations(source_id);",
            "CREATE INDEX IF NOT EXISTS idx_asset_observations_request_id ON asset_observations(request_id);",
            "CREATE INDEX IF NOT EXISTS idx_asset_observations_evidence_id ON asset_observations(evidence_id);",
            """
            CREATE TABLE IF NOT EXISTS endpoints (
                id VARCHAR PRIMARY KEY,
                program_id VARCHAR NOT NULL,
                asset_id VARCHAR NOT NULL,
                normalized_url VARCHAR NOT NULL,
                path VARCHAR NOT NULL,
                query_parameters TEXT,
                source_id VARCHAR,
                created_at DATETIME NOT NULL,
                FOREIGN KEY(program_id) REFERENCES programs(id) ON DELETE CASCADE,
                FOREIGN KEY(asset_id) REFERENCES assets(id) ON DELETE CASCADE,
                FOREIGN KEY(source_id) REFERENCES discovery_sources(id)
            );
            """,
            "CREATE INDEX IF NOT EXISTS idx_endpoints_program_id ON endpoints(program_id);",
            "CREATE INDEX IF NOT EXISTS idx_endpoints_asset_id ON endpoints(asset_id);",
            "CREATE INDEX IF NOT EXISTS idx_endpoints_normalized_url ON endpoints(normalized_url);",
            "CREATE UNIQUE INDEX IF NOT EXISTS idx_endpoints_asset_url ON endpoints(asset_id, normalized_url);",
            """
            CREATE TABLE IF NOT EXISTS technology_fingerprints (
                id VARCHAR PRIMARY KEY,
                asset_id VARCHAR NOT NULL,
                technology VARCHAR NOT NULL,
                version VARCHAR,
                detection_rule VARCHAR,
                source_id VARCHAR,
                confidence INTEGER NOT NULL DEFAULT 0,
                created_at DATETIME NOT NULL,
                FOREIGN KEY(asset_id) REFERENCES assets(id) ON DELETE CASCADE,
                FOREIGN KEY(source_id) REFERENCES discovery_sources(id)
            );
            """,
            "CREATE INDEX IF NOT EXISTS idx_tech_fingerprints_asset_id ON technology_fingerprints(asset_id);",
            "CREATE INDEX IF NOT EXISTS idx_tech_fingerprints_technology ON technology_fingerprints(technology);",
        ],
    },
    {
        "version": 16,
        "name": "016_phase8_persistent_campaign_vault",
        "up_sql": [
            """
            CREATE TABLE IF NOT EXISTS campaigns (
                id VARCHAR PRIMARY KEY,
                name VARCHAR NOT NULL,
                target_url VARCHAR NOT NULL,
                mode VARCHAR NOT NULL DEFAULT 'SAFE_SCAN',
                status VARCHAR NOT NULL DEFAULT 'DRAFT',
                program_id VARCHAR,
                user_id VARCHAR,
                created_at DATETIME NOT NULL,
                started_at DATETIME,
                completed_at DATETIME,
                paused_at DATETIME,
                scope_snapshot_hash VARCHAR,
                config_hash VARCHAR,
                registry_hash VARCHAR,
                manifest_hash VARCHAR,
                campaign_budget INTEGER NOT NULL DEFAULT 500,
                target_budget INTEGER NOT NULL DEFAULT 100,
                check_budget INTEGER NOT NULL DEFAULT 20,
                requests_used INTEGER NOT NULL DEFAULT 0,
                max_concurrency INTEGER NOT NULL DEFAULT 5,
                rate_limit_rps INTEGER NOT NULL DEFAULT 10,
                FOREIGN KEY(program_id) REFERENCES programs(id) ON DELETE SET NULL
            );
            """,
            "CREATE INDEX IF NOT EXISTS idx_campaigns_status ON campaigns(status);",
            "CREATE INDEX IF NOT EXISTS idx_campaigns_program_id ON campaigns(program_id);",
            "CREATE INDEX IF NOT EXISTS idx_campaigns_user_id ON campaigns(user_id);",
            "CREATE INDEX IF NOT EXISTS idx_campaigns_created_at ON campaigns(created_at);",
            """
            CREATE TABLE IF NOT EXISTS campaign_targets (
                id VARCHAR PRIMARY KEY,
                campaign_id VARCHAR NOT NULL,
                normalized_url VARCHAR NOT NULL,
                scope_status VARCHAR NOT NULL DEFAULT 'IN_SCOPE',
                auth_status VARCHAR NOT NULL DEFAULT 'PENDING',
                target_status VARCHAR NOT NULL DEFAULT 'PENDING',
                recon_status VARCHAR NOT NULL DEFAULT 'PENDING',
                execution_status VARCHAR NOT NULL DEFAULT 'PENDING',
                requests_used INTEGER NOT NULL DEFAULT 0,
                created_at DATETIME NOT NULL,
                FOREIGN KEY(campaign_id) REFERENCES campaigns(id) ON DELETE CASCADE
            );
            """,
            "CREATE INDEX IF NOT EXISTS idx_campaign_targets_campaign_id ON campaign_targets(campaign_id);",
            "CREATE INDEX IF NOT EXISTS idx_campaign_targets_normalized_url ON campaign_targets(normalized_url);",
            "CREATE UNIQUE INDEX IF NOT EXISTS idx_campaign_targets_campaign_url ON campaign_targets(campaign_id, normalized_url);",
            """
            CREATE TABLE IF NOT EXISTS campaign_tasks (
                id VARCHAR PRIMARY KEY,
                campaign_id VARCHAR NOT NULL,
                target_id VARCHAR,
                target_url VARCHAR NOT NULL,
                check_id VARCHAR NOT NULL,
                endpoint_url VARCHAR NOT NULL,
                parameter_name VARCHAR,
                status VARCHAR NOT NULL DEFAULT 'PENDING',
                attempt_count INTEGER NOT NULL DEFAULT 0,
                max_retries INTEGER NOT NULL DEFAULT 3,
                budget_reservation INTEGER NOT NULL DEFAULT 1,
                worker_id VARCHAR,
                lease_expires_at DATETIME,
                created_at DATETIME NOT NULL,
                started_at DATETIME,
                completed_at DATETIME,
                failure_reason TEXT,
                idempotency_key VARCHAR UNIQUE,
                FOREIGN KEY(campaign_id) REFERENCES campaigns(id) ON DELETE CASCADE
            );
            """,
            "CREATE INDEX IF NOT EXISTS idx_campaign_tasks_campaign_id ON campaign_tasks(campaign_id);",
            "CREATE INDEX IF NOT EXISTS idx_campaign_tasks_status ON campaign_tasks(status);",
            "CREATE INDEX IF NOT EXISTS idx_campaign_tasks_worker_lease ON campaign_tasks(worker_id, lease_expires_at);",
            "CREATE INDEX IF NOT EXISTS idx_campaign_tasks_idempotency ON campaign_tasks(idempotency_key);",
            """
            CREATE TABLE IF NOT EXISTS authorization_records (
                id VARCHAR PRIMARY KEY,
                campaign_id VARCHAR NOT NULL,
                authorized_by VARCHAR NOT NULL,
                authorization_type VARCHAR NOT NULL DEFAULT 'explicit_scope_consent',
                authorization_reference TEXT,
                authorized_at DATETIME NOT NULL,
                expires_at DATETIME NOT NULL,
                scope_hash VARCHAR NOT NULL,
                status VARCHAR NOT NULL DEFAULT 'ACTIVE',
                FOREIGN KEY(campaign_id) REFERENCES campaigns(id) ON DELETE CASCADE
            );
            """,
            "CREATE INDEX IF NOT EXISTS idx_authorization_records_campaign_id ON authorization_records(campaign_id);",
            "CREATE INDEX IF NOT EXISTS idx_authorization_records_status ON authorization_records(status);",
            """
            CREATE TABLE IF NOT EXISTS evidence_records (
                id VARCHAR PRIMARY KEY,
                campaign_id VARCHAR NOT NULL,
                finding_id VARCHAR,
                task_id VARCHAR,
                request_id VARCHAR,
                evidence_type VARCHAR NOT NULL,
                target_url VARCHAR NOT NULL,
                method VARCHAR NOT NULL DEFAULT 'GET',
                sanitized_request TEXT,
                sanitized_response TEXT,
                payload_summary TEXT,
                content_hash VARCHAR NOT NULL,
                chain_hash VARCHAR,
                created_at DATETIME NOT NULL,
                FOREIGN KEY(campaign_id) REFERENCES campaigns(id) ON DELETE CASCADE
            );
            """,
            "CREATE INDEX IF NOT EXISTS idx_evidence_records_campaign_id ON evidence_records(campaign_id);",
            "CREATE INDEX IF NOT EXISTS idx_evidence_records_finding_id ON evidence_records(finding_id);",
            "CREATE INDEX IF NOT EXISTS idx_evidence_records_task_id ON evidence_records(task_id);",
            "CREATE INDEX IF NOT EXISTS idx_evidence_records_content_hash ON evidence_records(content_hash);",
            """
            CREATE TABLE IF NOT EXISTS audit_trail_events (
                id VARCHAR PRIMARY KEY,
                campaign_id VARCHAR NOT NULL,
                timestamp DATETIME NOT NULL,
                actor VARCHAR NOT NULL DEFAULT 'system',
                event_type VARCHAR NOT NULL,
                object_id VARCHAR,
                metadata_json TEXT,
                previous_event_hash VARCHAR,
                event_hash VARCHAR NOT NULL,
                FOREIGN KEY(campaign_id) REFERENCES campaigns(id) ON DELETE CASCADE
            );
            """,
            "CREATE INDEX IF NOT EXISTS idx_audit_trail_campaign_id ON audit_trail_events(campaign_id);",
            "CREATE INDEX IF NOT EXISTS idx_audit_trail_event_type ON audit_trail_events(event_type);",
            "CREATE INDEX IF NOT EXISTS idx_audit_trail_timestamp ON audit_trail_events(timestamp);",
            """
            CREATE TABLE IF NOT EXISTS campaign_snapshots (
                id VARCHAR PRIMARY KEY,
                campaign_id VARCHAR NOT NULL UNIQUE,
                snapshot_json TEXT NOT NULL,
                snapshot_hash VARCHAR NOT NULL,
                created_at DATETIME NOT NULL,
                FOREIGN KEY(campaign_id) REFERENCES campaigns(id) ON DELETE CASCADE
            );
            """,
            "CREATE INDEX IF NOT EXISTS idx_campaign_snapshots_campaign_id ON campaign_snapshots(campaign_id);",
        ],
    },
    {
        "version": 19,
        "name": "019_phase16_production_assessment",
        "up_sql": [
            "ALTER TABLE programs ADD COLUMN platform VARCHAR DEFAULT 'hackerone';",
            "ALTER TABLE programs ADD COLUMN policy_url VARCHAR;",
            "ALTER TABLE programs ADD COLUMN policy_version VARCHAR;",
            "ALTER TABLE programs ADD COLUMN policy_updated_at DATETIME;",
            "ALTER TABLE programs ADD COLUMN bounty_eligible BOOLEAN DEFAULT 0;",
            "ALTER TABLE campaigns ADD COLUMN assessment_mode VARCHAR DEFAULT 'CONTROLLED';",
            "ALTER TABLE campaigns ADD COLUMN awaiting_target BOOLEAN DEFAULT 0;",
            """
            CREATE TABLE IF NOT EXISTS bug_bounty_scope_assets (
                id VARCHAR PRIMARY KEY,
                program_id VARCHAR NOT NULL,
                asset_name VARCHAR NOT NULL,
                asset_type VARCHAR NOT NULL DEFAULT 'DOMAIN',
                scope_type VARCHAR NOT NULL DEFAULT 'IN_SCOPE',
                severity VARCHAR,
                bounty_eligible BOOLEAN NOT NULL DEFAULT 0,
                raw_scope_definition TEXT NOT NULL,
                normalized_scope_definition TEXT NOT NULL,
                created_at DATETIME NOT NULL,
                FOREIGN KEY(program_id) REFERENCES programs(id) ON DELETE CASCADE,
                UNIQUE(program_id, raw_scope_definition, scope_type)
            );
            """,
            "CREATE INDEX IF NOT EXISTS idx_bug_bounty_scope_assets_program_id ON bug_bounty_scope_assets(program_id);",
            "CREATE INDEX IF NOT EXISTS idx_bug_bounty_scope_assets_scope_type ON bug_bounty_scope_assets(scope_type);",
        ],
    },
    {
        "version": 20,
        "name": "020_phase18_finding_verification_hardening",
        "up_sql": [
            "ALTER TABLE findings ADD COLUMN confidence_reason VARCHAR;",
            "ALTER TABLE findings ADD COLUMN verifier_version VARCHAR;",
            "ALTER TABLE findings ADD COLUMN impact_record TEXT;",
            "ALTER TABLE findings ADD COLUMN evidence_hashes TEXT;",
        ],
    },
    {
        "version": 21,
        "name": "021_phase19_controlled_hunting_workflow",
        "up_sql": [
            "ALTER TABLE findings ADD COLUMN human_review_status VARCHAR DEFAULT 'PENDING';",
            "ALTER TABLE findings ADD COLUMN human_reviewed_by VARCHAR;",
            "ALTER TABLE findings ADD COLUMN human_reviewed_at DATETIME;",
            "ALTER TABLE findings ADD COLUMN human_review_notes TEXT;",
            "ALTER TABLE findings ADD COLUMN duplicate_of VARCHAR;",
            "ALTER TABLE findings ADD COLUMN deduplication_reason VARCHAR;",
            "ALTER TABLE findings ADD COLUMN finding_fingerprint VARCHAR;",
            "CREATE INDEX IF NOT EXISTS idx_findings_human_review_status ON findings(human_review_status);",
            "CREATE INDEX IF NOT EXISTS idx_findings_duplicate_of ON findings(duplicate_of);",
            "CREATE INDEX IF NOT EXISTS idx_findings_fingerprint ON findings(finding_fingerprint);",
        ],
    },
    {
        "version": 22,
        "name": "022_phase20_hunting_intelligence",
        "up_sql": [
            "ALTER TABLE findings ADD COLUMN quality_score FLOAT;",
            "ALTER TABLE findings ADD COLUMN quality_band VARCHAR;",
            "ALTER TABLE findings ADD COLUMN impact_confirmed TEXT;",
            "ALTER TABLE findings ADD COLUMN impact_potential TEXT;",
            """
            CREATE TABLE IF NOT EXISTS check_effectiveness (
                id VARCHAR PRIMARY KEY,
                check_id VARCHAR NOT NULL UNIQUE,
                executions INTEGER DEFAULT 0,
                candidates INTEGER DEFAULT 0,
                verified INTEGER DEFAULT 0,
                rejected INTEGER DEFAULT 0,
                inconclusive INTEGER DEFAULT 0,
                duplicates INTEGER DEFAULT 0,
                evidence_complete INTEGER DEFAULT 0,
                evidence_incomplete INTEGER DEFAULT 0,
                total_requests INTEGER DEFAULT 0,
                average_requests FLOAT DEFAULT 0.0,
                verification_rate FLOAT DEFAULT 0.0,
                evidence_quality FLOAT DEFAULT 0.0,
                uniqueness FLOAT DEFAULT 0.0,
                impact_signal FLOAT DEFAULT 0.0,
                utility FLOAT DEFAULT 0.0,
                updated_at DATETIME NOT NULL
            );
            """,
            "CREATE INDEX IF NOT EXISTS idx_check_effectiveness_check_id ON check_effectiveness(check_id);",
            "CREATE INDEX IF NOT EXISTS idx_check_effectiveness_utility ON check_effectiveness(utility);",
            """
            CREATE TABLE IF NOT EXISTS negative_evidence (
                id VARCHAR PRIMARY KEY,
                target VARCHAR NOT NULL,
                endpoint VARCHAR NOT NULL,
                check_id VARCHAR NOT NULL,
                timestamp DATETIME NOT NULL,
                request_hash VARCHAR NOT NULL,
                response_hash VARCHAR NOT NULL,
                verdict VARCHAR NOT NULL,
                verification_state VARCHAR NOT NULL,
                scope_snapshot_hash VARCHAR,
                verifier_version VARCHAR,
                details TEXT
            );
            """,
            "CREATE INDEX IF NOT EXISTS idx_negative_evidence_target ON negative_evidence(target);",
            "CREATE INDEX IF NOT EXISTS idx_negative_evidence_check ON negative_evidence(check_id);",
            "CREATE INDEX IF NOT EXISTS idx_negative_evidence_endpoint ON negative_evidence(endpoint);",
            """
            CREATE TABLE IF NOT EXISTS surface_inventory (
                id VARCHAR PRIMARY KEY,
                target VARCHAR NOT NULL,
                endpoint VARCHAR NOT NULL,
                http_method VARCHAR NOT NULL,
                normalized_path VARCHAR NOT NULL,
                parameters TEXT DEFAULT '[]',
                content_type VARCHAR,
                auth_state VARCHAR DEFAULT 'ANONYMOUS',
                status_code INTEGER,
                interesting_headers TEXT DEFAULT '{}',
                observed_findings TEXT DEFAULT '[]',
                negative_evidence TEXT DEFAULT '[]',
                discovered_at DATETIME NOT NULL,
                updated_at DATETIME NOT NULL
            );
            """,
            "CREATE INDEX IF NOT EXISTS idx_surface_target ON surface_inventory(target);",
            "CREATE INDEX IF NOT EXISTS idx_surface_endpoint ON surface_inventory(endpoint);",
            "CREATE INDEX IF NOT EXISTS idx_surface_norm_path ON surface_inventory(normalized_path);",
            """
            CREATE TABLE IF NOT EXISTS assessment_memory (
                id VARCHAR PRIMARY KEY,
                campaign_id VARCHAR,
                target VARCHAR NOT NULL,
                lesson_type VARCHAR NOT NULL,
                key VARCHAR NOT NULL,
                value TEXT NOT NULL,
                metadata_json TEXT DEFAULT '{}',
                created_at DATETIME NOT NULL
            );
            """,
            "CREATE INDEX IF NOT EXISTS idx_assessment_memory_target ON assessment_memory(target);",
            "CREATE INDEX IF NOT EXISTS idx_assessment_memory_type ON assessment_memory(lesson_type);",
            """
            CREATE TABLE IF NOT EXISTS operator_decisions (
                id VARCHAR PRIMARY KEY,
                recommendation_id VARCHAR NOT NULL,
                campaign_id VARCHAR NOT NULL,
                target VARCHAR NOT NULL,
                check_id VARCHAR NOT NULL,
                operator_id VARCHAR NOT NULL,
                decision VARCHAR NOT NULL,
                timestamp DATETIME NOT NULL,
                reason TEXT,
                remaining_budget INTEGER NOT NULL,
                plan_hash VARCHAR,
                audit_hash VARCHAR NOT NULL
            );
            """,
            "CREATE INDEX IF NOT EXISTS idx_operator_decisions_campaign ON operator_decisions(campaign_id);",
            "CREATE INDEX IF NOT EXISTS idx_operator_decisions_check ON operator_decisions(check_id);",
            "CREATE INDEX IF NOT EXISTS idx_operator_decisions_audit ON operator_decisions(audit_hash);",
            """
            CREATE TABLE IF NOT EXISTS hunting_recommendations (
                id VARCHAR PRIMARY KEY,
                campaign_id VARCHAR NOT NULL,
                target VARCHAR NOT NULL,
                check_id VARCHAR NOT NULL,
                reason TEXT NOT NULL,
                expected_evidence TEXT NOT NULL,
                estimated_requests INTEGER NOT NULL,
                risk_level VARCHAR NOT NULL,
                confidence FLOAT NOT NULL,
                supporting_historical_evidence TEXT,
                authorization_status VARCHAR NOT NULL DEFAULT 'HUMAN_REVIEW_REQUIRED',
                status VARCHAR NOT NULL DEFAULT 'PENDING',
                created_at DATETIME NOT NULL
            );
            """,
            "CREATE INDEX IF NOT EXISTS idx_hunting_rec_campaign ON hunting_recommendations(campaign_id);",
            "CREATE INDEX IF NOT EXISTS idx_hunting_rec_check ON hunting_recommendations(check_id);",
            "CREATE INDEX IF NOT EXISTS idx_hunting_rec_status ON hunting_recommendations(status);",
        ],
    },
    {
        "version": 23,
        "name": "023_phase21_controlled_exploit_validation",
        "up_sql": [
            """
            CREATE TABLE IF NOT EXISTS vulnerability_hypotheses (
                id VARCHAR PRIMARY KEY,
                campaign_id VARCHAR NOT NULL,
                target VARCHAR NOT NULL,
                endpoint VARCHAR NOT NULL,
                method VARCHAR NOT NULL DEFAULT 'GET',
                parameter VARCHAR,
                vulnerability_class VARCHAR NOT NULL,
                hypothesis TEXT NOT NULL,
                rationale TEXT NOT NULL,
                prerequisite_observations TEXT NOT NULL DEFAULT '[]',
                expected_evidence TEXT NOT NULL,
                verification_strategy TEXT NOT NULL,
                estimated_requests INTEGER NOT NULL DEFAULT 1,
                risk_level VARCHAR NOT NULL DEFAULT 'SAFE_ACTIVE',
                confidence FLOAT NOT NULL DEFAULT 0.5,
                authorization_status VARCHAR NOT NULL DEFAULT 'HUMAN_REVIEW_REQUIRED',
                source_observations TEXT DEFAULT '[]',
                status VARCHAR NOT NULL DEFAULT 'PENDING',
                created_at DATETIME NOT NULL,
                engine_version VARCHAR NOT NULL DEFAULT '1.0.0-phase21'
            );
            """,
            "CREATE INDEX IF NOT EXISTS idx_vuln_hyp_campaign ON vulnerability_hypotheses(campaign_id);",
            "CREATE INDEX IF NOT EXISTS idx_vuln_hyp_target ON vulnerability_hypotheses(target);",
            "CREATE INDEX IF NOT EXISTS idx_vuln_hyp_endpoint ON vulnerability_hypotheses(endpoint);",
            "CREATE INDEX IF NOT EXISTS idx_vuln_hyp_class ON vulnerability_hypotheses(vulnerability_class);",
            "CREATE INDEX IF NOT EXISTS idx_vuln_hyp_status ON vulnerability_hypotheses(status);",
            """
            CREATE TABLE IF NOT EXISTS verification_strategies (
                id VARCHAR PRIMARY KEY,
                strategy_id VARCHAR NOT NULL UNIQUE,
                vulnerability_class VARCHAR NOT NULL,
                prerequisite_evidence TEXT NOT NULL DEFAULT '[]',
                request_budget INTEGER NOT NULL DEFAULT 1,
                allowed_methods TEXT NOT NULL DEFAULT '["GET", "HEAD", "OPTIONS"]',
                expected_observations TEXT NOT NULL DEFAULT '[]',
                success_conditions TEXT NOT NULL DEFAULT '[]',
                failure_conditions TEXT NOT NULL DEFAULT '[]',
                inconclusive_conditions TEXT NOT NULL DEFAULT '[]',
                safety_constraints TEXT NOT NULL DEFAULT '[]',
                created_at DATETIME NOT NULL
            );
            """,
            "CREATE INDEX IF NOT EXISTS idx_verif_strat_strategy_id ON verification_strategies(strategy_id);",
            "CREATE INDEX IF NOT EXISTS idx_verif_strat_class ON verification_strategies(vulnerability_class);",
            """
            CREATE TABLE IF NOT EXISTS verification_runs (
                id VARCHAR PRIMARY KEY,
                campaign_id VARCHAR NOT NULL,
                hypothesis_id VARCHAR NOT NULL,
                strategy_id VARCHAR NOT NULL,
                status VARCHAR NOT NULL,
                requests_consumed INTEGER NOT NULL DEFAULT 0,
                started_at DATETIME NOT NULL,
                completed_at DATETIME,
                result_details TEXT,
                finding_id VARCHAR
            );
            """,
            "CREATE INDEX IF NOT EXISTS idx_verif_runs_campaign ON verification_runs(campaign_id);",
            "CREATE INDEX IF NOT EXISTS idx_verif_runs_hypothesis ON verification_runs(hypothesis_id);",
            "CREATE INDEX IF NOT EXISTS idx_verif_runs_strategy ON verification_runs(strategy_id);",
            "CREATE INDEX IF NOT EXISTS idx_verif_runs_status ON verification_runs(status);",
            "CREATE INDEX IF NOT EXISTS idx_verif_runs_finding ON verification_runs(finding_id);",
            """
            CREATE TABLE IF NOT EXISTS verification_evidence (
                id VARCHAR PRIMARY KEY,
                verification_run_id VARCHAR NOT NULL,
                campaign_id VARCHAR NOT NULL,
                hypothesis_id VARCHAR NOT NULL,
                strategy_id VARCHAR NOT NULL,
                target VARCHAR NOT NULL,
                endpoint VARCHAR NOT NULL,
                method VARCHAR NOT NULL,
                request_hash VARCHAR NOT NULL,
                response_hash VARCHAR NOT NULL,
                status_code INTEGER,
                response_size INTEGER,
                timestamp DATETIME NOT NULL,
                scope_snapshot_hash VARCHAR,
                verifier_version VARCHAR NOT NULL DEFAULT '1.0.0-phase21',
                authorization_decision VARCHAR NOT NULL DEFAULT 'APPROVE',
                relevant_headers TEXT DEFAULT '{}',
                sanitized_request TEXT,
                sanitized_response TEXT,
                comparison_hash VARCHAR,
                authentication_context_id VARCHAR,
                baseline_evidence_id VARCHAR,
                created_at DATETIME NOT NULL
            );
            """,
            "CREATE INDEX IF NOT EXISTS idx_verif_evid_run ON verification_evidence(verification_run_id);",
            "CREATE INDEX IF NOT EXISTS idx_verif_evid_campaign ON verification_evidence(campaign_id);",
            "CREATE INDEX IF NOT EXISTS idx_verif_evid_hypothesis ON verification_evidence(hypothesis_id);",
            "CREATE INDEX IF NOT EXISTS idx_verif_evid_target ON verification_evidence(target);",
            "CREATE INDEX IF NOT EXISTS idx_verif_evid_endpoint ON verification_evidence(endpoint);",
            """
            CREATE TABLE IF NOT EXISTS verification_budget_entries (
                id VARCHAR PRIMARY KEY,
                campaign_id VARCHAR NOT NULL,
                verification_run_id VARCHAR NOT NULL,
                request_number INTEGER NOT NULL,
                request_cost INTEGER NOT NULL DEFAULT 1,
                remaining_budget INTEGER NOT NULL,
                strategy_id VARCHAR NOT NULL,
                operator_decision_id VARCHAR NOT NULL,
                timestamp DATETIME NOT NULL
            );
            """,
            "CREATE INDEX IF NOT EXISTS idx_verif_budget_campaign ON verification_budget_entries(campaign_id);",
            "CREATE INDEX IF NOT EXISTS idx_verif_budget_run ON verification_budget_entries(verification_run_id);",
            "CREATE INDEX IF NOT EXISTS idx_verif_budget_decision ON verification_budget_entries(operator_decision_id);",
            """
            CREATE TABLE IF NOT EXISTS hypothesis_decisions (
                id VARCHAR PRIMARY KEY,
                decision_id VARCHAR NOT NULL UNIQUE,
                operator_id VARCHAR NOT NULL,
                campaign_id VARCHAR NOT NULL,
                hypothesis_id VARCHAR NOT NULL,
                strategy_id VARCHAR NOT NULL,
                decision VARCHAR NOT NULL,
                rationale TEXT,
                timestamp DATETIME NOT NULL,
                previous_hash VARCHAR NOT NULL,
                event_hash VARCHAR NOT NULL
            );
            """,
            "CREATE INDEX IF NOT EXISTS idx_hyp_dec_decision_id ON hypothesis_decisions(decision_id);",
            "CREATE INDEX IF NOT EXISTS idx_hyp_dec_campaign ON hypothesis_decisions(campaign_id);",
            "CREATE INDEX IF NOT EXISTS idx_hyp_dec_hypothesis ON hypothesis_decisions(hypothesis_id);",
            "CREATE INDEX IF NOT EXISTS idx_hyp_dec_event_hash ON hypothesis_decisions(event_hash);",
        ],
    },
    {
        "version": 24,
        "name": "024_phase22_real_world_exploitation",
        "up_sql": [
            """
            CREATE TABLE IF NOT EXISTS real_verification_runs (
                id VARCHAR PRIMARY KEY,
                campaign_id VARCHAR NOT NULL,
                hypothesis_id VARCHAR NOT NULL,
                strategy_id VARCHAR NOT NULL,
                target VARCHAR NOT NULL,
                execution_mode VARCHAR NOT NULL DEFAULT 'PRODUCTION',
                status VARCHAR NOT NULL,
                authorization_status VARCHAR NOT NULL DEFAULT 'HUMAN_REVIEW_REQUIRED',
                operator_approval_id VARCHAR,
                requests_consumed INTEGER NOT NULL DEFAULT 0,
                started_at DATETIME NOT NULL,
                completed_at DATETIME,
                result_details TEXT,
                correlation_verdict VARCHAR,
                impact_summary TEXT,
                finding_id VARCHAR,
                error_code VARCHAR,
                executor_version VARCHAR NOT NULL DEFAULT '1.0.0-phase22',
                created_at DATETIME NOT NULL
            );
            """,
            "CREATE INDEX IF NOT EXISTS idx_rverif_runs_camp ON real_verification_runs(campaign_id);",
            "CREATE INDEX IF NOT EXISTS idx_rverif_runs_hyp ON real_verification_runs(hypothesis_id);",
            "CREATE INDEX IF NOT EXISTS idx_rverif_runs_strat ON real_verification_runs(strategy_id);",
            "CREATE INDEX IF NOT EXISTS idx_rverif_runs_stat ON real_verification_runs(status);",
            "CREATE INDEX IF NOT EXISTS idx_rverif_runs_finding ON real_verification_runs(finding_id);",
            """
            CREATE TABLE IF NOT EXISTS real_verification_evidence (
                id VARCHAR PRIMARY KEY,
                verification_run_id VARCHAR NOT NULL,
                campaign_id VARCHAR NOT NULL,
                hypothesis_id VARCHAR NOT NULL,
                target VARCHAR NOT NULL,
                endpoint VARCHAR NOT NULL,
                method VARCHAR NOT NULL,
                request_hash VARCHAR NOT NULL,
                response_hash VARCHAR NOT NULL,
                status_code INTEGER,
                response_size INTEGER,
                timestamp DATETIME NOT NULL,
                scope_snapshot_hash VARCHAR,
                verifier_version VARCHAR NOT NULL DEFAULT '1.0.0-phase22',
                authorization_decision VARCHAR NOT NULL DEFAULT 'APPROVE',
                sanitized_request TEXT,
                sanitized_response TEXT,
                relevant_headers TEXT DEFAULT '{}',
                baseline_evidence_id VARCHAR,
                comparison_hash VARCHAR,
                chain_hash VARCHAR,
                authentication_context_id VARCHAR,
                created_at DATETIME NOT NULL
            );
            """,
            "CREATE INDEX IF NOT EXISTS idx_rverif_evid_run ON real_verification_evidence(verification_run_id);",
            "CREATE INDEX IF NOT EXISTS idx_rverif_evid_camp ON real_verification_evidence(campaign_id);",
            "CREATE INDEX IF NOT EXISTS idx_rverif_evid_hyp ON real_verification_evidence(hypothesis_id);",
            "CREATE INDEX IF NOT EXISTS idx_rverif_evid_target ON real_verification_evidence(target);",
            "CREATE INDEX IF NOT EXISTS idx_rverif_evid_endpoint ON real_verification_evidence(endpoint);",
            """
            CREATE TABLE IF NOT EXISTS real_exploit_events (
                id VARCHAR PRIMARY KEY,
                campaign_id VARCHAR NOT NULL,
                verification_run_id VARCHAR NOT NULL,
                event_type VARCHAR NOT NULL,
                event_details TEXT,
                operator_id VARCHAR NOT NULL,
                timestamp DATETIME NOT NULL,
                previous_hash VARCHAR NOT NULL,
                event_hash VARCHAR NOT NULL
            );
            """,
            "CREATE INDEX IF NOT EXISTS idx_rexploit_event_camp ON real_exploit_events(campaign_id);",
            "CREATE INDEX IF NOT EXISTS idx_rexploit_event_run ON real_exploit_events(verification_run_id);",
            "CREATE INDEX IF NOT EXISTS idx_rexploit_event_type ON real_exploit_events(event_type);",
            "CREATE INDEX IF NOT EXISTS idx_rexploit_event_hash ON real_exploit_events(event_hash);",
            """
            CREATE TABLE IF NOT EXISTS real_operator_approvals (
                id VARCHAR PRIMARY KEY,
                approval_id VARCHAR NOT NULL UNIQUE,
                campaign_id VARCHAR NOT NULL,
                hypothesis_id VARCHAR NOT NULL,
                strategy_id VARCHAR NOT NULL,
                operator_id VARCHAR NOT NULL,
                target VARCHAR NOT NULL,
                decision VARCHAR NOT NULL,
                acknowledgement TEXT,
                rationale TEXT,
                timestamp DATETIME NOT NULL,
                previous_hash VARCHAR NOT NULL,
                event_hash VARCHAR NOT NULL
            );
            """,
            "CREATE INDEX IF NOT EXISTS idx_rappr_approval_id ON real_operator_approvals(approval_id);",
            "CREATE INDEX IF NOT EXISTS idx_rappr_camp ON real_operator_approvals(campaign_id);",
            "CREATE INDEX IF NOT EXISTS idx_rappr_hyp ON real_operator_approvals(hypothesis_id);",
            "CREATE INDEX IF NOT EXISTS idx_rappr_hash ON real_operator_approvals(event_hash);",
            """
            CREATE TABLE IF NOT EXISTS real_evidence_chains (
                id VARCHAR PRIMARY KEY,
                campaign_id VARCHAR NOT NULL,
                verification_run_id VARCHAR NOT NULL,
                baseline_hash VARCHAR NOT NULL,
                verification_hash VARCHAR NOT NULL,
                comparison_hash VARCHAR NOT NULL,
                correlation_hash VARCHAR NOT NULL,
                chain_hash VARCHAR NOT NULL,
                previous_chain_hash VARCHAR NOT NULL,
                created_at DATETIME NOT NULL
            );
            """,
            "CREATE INDEX IF NOT EXISTS idx_rev_chain_camp ON real_evidence_chains(campaign_id);",
            "CREATE INDEX IF NOT EXISTS idx_rev_chain_run ON real_evidence_chains(verification_run_id);",
            "CREATE INDEX IF NOT EXISTS idx_rev_chain_hash ON real_evidence_chains(chain_hash);",
            """
            CREATE TABLE IF NOT EXISTS real_impact_assessments (
                id VARCHAR PRIMARY KEY,
                verification_run_id VARCHAR NOT NULL,
                confirmed_impact TEXT NOT NULL,
                potential_impact TEXT NOT NULL,
                inference_labels TEXT DEFAULT '[]',
                cvss_score FLOAT NOT NULL,
                confidence INTEGER NOT NULL DEFAULT 100,
                evidence_basis TEXT,
                created_at DATETIME NOT NULL
            );
            """,
            "CREATE INDEX IF NOT EXISTS idx_rimpact_run ON real_impact_assessments(verification_run_id);",
        ],
    },
    {
        "version": 25,
        "name": "025_phase23_advanced_authorized_validation",
        "up_sql": [
            """
            CREATE TABLE IF NOT EXISTS attack_surface_nodes (
                id VARCHAR PRIMARY KEY,
                campaign_id VARCHAR NOT NULL,
                target VARCHAR NOT NULL,
                node_type VARCHAR NOT NULL,
                canonical_url VARCHAR NOT NULL,
                endpoint VARCHAR,
                parameter VARCHAR,
                method VARCHAR,
                source VARCHAR NOT NULL,
                observation_hash VARCHAR NOT NULL,
                confidence FLOAT NOT NULL DEFAULT 1.0,
                status VARCHAR NOT NULL DEFAULT 'OBSERVED',
                created_at DATETIME NOT NULL
            );
            """,
            "CREATE INDEX IF NOT EXISTS idx_as_nodes_camp ON attack_surface_nodes(campaign_id);",
            "CREATE INDEX IF NOT EXISTS idx_as_nodes_type ON attack_surface_nodes(node_type);",
            "CREATE INDEX IF NOT EXISTS idx_as_nodes_hash ON attack_surface_nodes(observation_hash);",
            "CREATE INDEX IF NOT EXISTS idx_as_nodes_url ON attack_surface_nodes(canonical_url);",
            """
            CREATE TABLE IF NOT EXISTS attack_surface_edges (
                id VARCHAR PRIMARY KEY,
                campaign_id VARCHAR NOT NULL,
                source_node_id VARCHAR NOT NULL,
                destination_node_id VARCHAR NOT NULL,
                edge_type VARCHAR NOT NULL,
                evidence_id VARCHAR,
                confidence FLOAT NOT NULL DEFAULT 1.0,
                created_at DATETIME NOT NULL
            );
            """,
            "CREATE INDEX IF NOT EXISTS idx_as_edges_camp ON attack_surface_edges(campaign_id);",
            "CREATE INDEX IF NOT EXISTS idx_as_edges_src ON attack_surface_edges(source_node_id);",
            "CREATE INDEX IF NOT EXISTS idx_as_edges_dst ON attack_surface_edges(destination_node_id);",
            "CREATE INDEX IF NOT EXISTS idx_as_edges_type ON attack_surface_edges(edge_type);",
            """
            CREATE TABLE IF NOT EXISTS validation_plans (
                id VARCHAR PRIMARY KEY,
                campaign_id VARCHAR NOT NULL,
                hypothesis_id VARCHAR NOT NULL,
                target VARCHAR NOT NULL,
                plan_version VARCHAR NOT NULL DEFAULT '1.0.0',
                steps_json TEXT NOT NULL DEFAULT '[]',
                estimated_requests INTEGER NOT NULL DEFAULT 1,
                allowed_methods TEXT NOT NULL DEFAULT '["GET","HEAD","OPTIONS"]',
                success_conditions TEXT NOT NULL DEFAULT '[]',
                failure_conditions TEXT NOT NULL DEFAULT '[]',
                inconclusive_conditions TEXT NOT NULL DEFAULT '[]',
                safety_constraints TEXT NOT NULL DEFAULT '{}',
                authorization_status VARCHAR NOT NULL DEFAULT 'HUMAN_REVIEW_REQUIRED',
                status VARCHAR NOT NULL DEFAULT 'DRAFT',
                operator_approval_id VARCHAR,
                created_at DATETIME NOT NULL
            );
            """,
            "CREATE INDEX IF NOT EXISTS idx_val_plans_camp ON validation_plans(campaign_id);",
            "CREATE INDEX IF NOT EXISTS idx_val_plans_hyp ON validation_plans(hypothesis_id);",
            "CREATE INDEX IF NOT EXISTS idx_val_plans_status ON validation_plans(status);",
            """
            CREATE TABLE IF NOT EXISTS validation_plan_steps (
                id VARCHAR PRIMARY KEY,
                validation_plan_id VARCHAR NOT NULL,
                step_number INTEGER NOT NULL,
                method VARCHAR NOT NULL DEFAULT 'GET',
                endpoint VARCHAR NOT NULL,
                request_template TEXT NOT NULL DEFAULT '{}',
                prerequisite_step INTEGER,
                expected_observation TEXT,
                success_condition TEXT,
                failure_condition TEXT,
                request_cost INTEGER NOT NULL DEFAULT 1,
                status VARCHAR NOT NULL DEFAULT 'PENDING',
                created_at DATETIME NOT NULL
            );
            """,
            "CREATE INDEX IF NOT EXISTS idx_val_steps_plan ON validation_plan_steps(validation_plan_id);",
            "CREATE INDEX IF NOT EXISTS idx_val_steps_num ON validation_plan_steps(step_number);",
            "CREATE INDEX IF NOT EXISTS idx_val_steps_status ON validation_plan_steps(status);",
            """
            CREATE TABLE IF NOT EXISTS validation_observations (
                id VARCHAR PRIMARY KEY,
                validation_plan_id VARCHAR NOT NULL,
                step_id VARCHAR NOT NULL,
                request_number INTEGER NOT NULL,
                status VARCHAR NOT NULL,
                status_code INTEGER,
                response_hash VARCHAR,
                normalized_response_hash VARCHAR,
                observation_type VARCHAR NOT NULL,
                observation_details TEXT,
                comparison_result TEXT,
                created_at DATETIME NOT NULL
            );
            """,
            "CREATE INDEX IF NOT EXISTS idx_val_obs_plan ON validation_observations(validation_plan_id);",
            "CREATE INDEX IF NOT EXISTS idx_val_obs_step ON validation_observations(step_id);",
            "CREATE INDEX IF NOT EXISTS idx_val_obs_type ON validation_observations(observation_type);",
            """
            CREATE TABLE IF NOT EXISTS validation_reproductions (
                id VARCHAR PRIMARY KEY,
                validation_plan_id VARCHAR NOT NULL,
                finding_id VARCHAR NOT NULL,
                attempt_number INTEGER NOT NULL,
                result VARCHAR NOT NULL,
                evidence_hash VARCHAR NOT NULL,
                reproducibility_score FLOAT NOT NULL DEFAULT 0.0,
                created_at DATETIME NOT NULL
            );
            """,
            "CREATE INDEX IF NOT EXISTS idx_val_repro_plan ON validation_reproductions(validation_plan_id);",
            "CREATE INDEX IF NOT EXISTS idx_val_repro_find ON validation_reproductions(finding_id);",
            """
            CREATE TABLE IF NOT EXISTS phase23_confidence_assessments (
                id VARCHAR PRIMARY KEY,
                validation_plan_id VARCHAR NOT NULL,
                finding_id VARCHAR NOT NULL,
                evidence_score FLOAT NOT NULL,
                consistency_score FLOAT NOT NULL,
                reproducibility_score FLOAT NOT NULL,
                scope_score FLOAT NOT NULL,
                authorization_score FLOAT NOT NULL,
                overall_score FLOAT NOT NULL,
                confidence_level VARCHAR NOT NULL,
                rationale TEXT NOT NULL,
                created_at DATETIME NOT NULL
            );
            """,
            "CREATE INDEX IF NOT EXISTS idx_p23_conf_plan ON phase23_confidence_assessments(validation_plan_id);",
            "CREATE INDEX IF NOT EXISTS idx_p23_conf_find ON phase23_confidence_assessments(finding_id);",
            "CREATE INDEX IF NOT EXISTS idx_p23_conf_lvl ON phase23_confidence_assessments(confidence_level);",
            """
            CREATE TABLE IF NOT EXISTS phase23_audit_events (
                id VARCHAR PRIMARY KEY,
                campaign_id VARCHAR NOT NULL,
                operator_id VARCHAR NOT NULL,
                event_type VARCHAR NOT NULL,
                event_payload TEXT,
                previous_hash VARCHAR NOT NULL,
                event_hash VARCHAR NOT NULL,
                timestamp DATETIME NOT NULL
            );
            """,
            "CREATE INDEX IF NOT EXISTS idx_p23_audit_camp ON phase23_audit_events(campaign_id);",
            "CREATE INDEX IF NOT EXISTS idx_p23_audit_type ON phase23_audit_events(event_type);",
            "CREATE INDEX IF NOT EXISTS idx_p23_audit_hash ON phase23_audit_events(event_hash);",
        ],
    },
    {
        "version": 26,
        "name": "026_phase24_e2e_orchestration_and_tools",
        "up_sql": [
            """
            CREATE TABLE IF NOT EXISTS pre_scan_results (
                id VARCHAR PRIMARY KEY,
                campaign_id VARCHAR NOT NULL,
                target VARCHAR NOT NULL,
                overall_status VARCHAR NOT NULL DEFAULT 'READY',
                dns_status VARCHAR NOT NULL DEFAULT 'PENDING',
                http_status VARCHAR NOT NULL DEFAULT 'PENDING',
                https_status VARCHAR NOT NULL DEFAULT 'PENDING',
                tls_status VARCHAR NOT NULL DEFAULT 'PENDING',
                account1_status VARCHAR NOT NULL DEFAULT 'NOT_APPLICABLE',
                account2_status VARCHAR NOT NULL DEFAULT 'NOT_APPLICABLE',
                email_otp_status VARCHAR NOT NULL DEFAULT 'NOT_APPLICABLE',
                api_key_status VARCHAR NOT NULL DEFAULT 'NOT_APPLICABLE',
                config_status VARCHAR NOT NULL DEFAULT 'READY',
                authorization_status VARCHAR NOT NULL DEFAULT 'READY',
                check_details_json TEXT NOT NULL DEFAULT '{}',
                warnings_json TEXT NOT NULL DEFAULT '[]',
                errors_json TEXT NOT NULL DEFAULT '[]',
                created_at DATETIME NOT NULL,
                updated_at DATETIME NOT NULL
            );
            """,
            "CREATE INDEX IF NOT EXISTS idx_prescan_camp ON pre_scan_results(campaign_id);",
            "CREATE INDEX IF NOT EXISTS idx_prescan_status ON pre_scan_results(overall_status);",
            """
            CREATE TABLE IF NOT EXISTS tool_execution_records (
                id VARCHAR PRIMARY KEY,
                campaign_id VARCHAR NOT NULL,
                target VARCHAR NOT NULL,
                tool_name VARCHAR NOT NULL,
                tool_version VARCHAR,
                execution_profile VARCHAR NOT NULL,
                execution_status VARCHAR NOT NULL DEFAULT 'PENDING',
                sanitized_args_json TEXT NOT NULL DEFAULT '[]',
                exit_code INTEGER,
                timeout_seconds INTEGER NOT NULL DEFAULT 60,
                stdout_hash VARCHAR,
                stderr_hash VARCHAR,
                output_hash VARCHAR,
                parsed_summary_json TEXT NOT NULL DEFAULT '{}',
                error_category VARCHAR,
                started_at DATETIME NOT NULL,
                completed_at DATETIME
            );
            """,
            "CREATE INDEX IF NOT EXISTS idx_tool_exec_camp ON tool_execution_records(campaign_id);",
            "CREATE INDEX IF NOT EXISTS idx_tool_exec_name ON tool_execution_records(tool_name);",
            "CREATE INDEX IF NOT EXISTS idx_tool_exec_prof ON tool_execution_records(execution_profile);",
            "CREATE INDEX IF NOT EXISTS idx_tool_exec_status ON tool_execution_records(execution_status);",
            "CREATE INDEX IF NOT EXISTS idx_tool_exec_outhash ON tool_execution_records(output_hash);",
            """
            CREATE TABLE IF NOT EXISTS auth_context_records (
                id VARCHAR PRIMARY KEY,
                campaign_id VARCHAR NOT NULL,
                account_id INTEGER NOT NULL,
                auth_status VARCHAR NOT NULL DEFAULT 'UNAUTHENTICATED',
                session_handle VARCHAR NOT NULL,
                auth_method VARCHAR NOT NULL DEFAULT 'CREDENTIALS',
                username_hint VARCHAR,
                expires_at DATETIME,
                last_authenticated_at DATETIME,
                refresh_status VARCHAR NOT NULL DEFAULT 'NONE',
                metadata_json TEXT NOT NULL DEFAULT '{}',
                created_at DATETIME NOT NULL,
                updated_at DATETIME NOT NULL,
                UNIQUE(campaign_id, account_id)
            );
            """,
            "CREATE INDEX IF NOT EXISTS idx_auth_ctx_camp ON auth_context_records(campaign_id);",
            "CREATE INDEX IF NOT EXISTS idx_auth_ctx_acct ON auth_context_records(account_id);",
            "CREATE INDEX IF NOT EXISTS idx_auth_ctx_status ON auth_context_records(auth_status);",
            """
            CREATE TABLE IF NOT EXISTS exploitability_records (
                id VARCHAR PRIMARY KEY,
                campaign_id VARCHAR NOT NULL,
                target VARCHAR NOT NULL,
                finding_id VARCHAR NOT NULL,
                hypothesis_id VARCHAR,
                strategy_id VARCHAR NOT NULL,
                strategy_version VARCHAR NOT NULL DEFAULT '1.0.0',
                verification_state VARCHAR NOT NULL DEFAULT 'DETECTED',
                proof_type VARCHAR NOT NULL,
                impact_classification VARCHAR NOT NULL,
                evidence_hash VARCHAR NOT NULL,
                reproducibility_score FLOAT NOT NULL DEFAULT 0.0,
                operator_approval_id VARCHAR,
                proof_details_json TEXT NOT NULL DEFAULT '{}',
                verified_at DATETIME NOT NULL,
                created_at DATETIME NOT NULL
            );
            """,
            "CREATE INDEX IF NOT EXISTS idx_exploit_camp ON exploitability_records(campaign_id);",
            "CREATE INDEX IF NOT EXISTS idx_exploit_find ON exploitability_records(finding_id);",
            "CREATE INDEX IF NOT EXISTS idx_exploit_hyp ON exploitability_records(hypothesis_id);",
            "CREATE INDEX IF NOT EXISTS idx_exploit_state ON exploitability_records(verification_state);",
            "CREATE INDEX IF NOT EXISTS idx_exploit_evhash ON exploitability_records(evidence_hash);",
            """
            CREATE TABLE IF NOT EXISTS agent_orchestrator_runs (
                id VARCHAR PRIMARY KEY,
                campaign_id VARCHAR NOT NULL,
                target VARCHAR NOT NULL,
                current_stage VARCHAR NOT NULL DEFAULT 'PRECHECK',
                overall_status VARCHAR NOT NULL DEFAULT 'INITIALIZED',
                stages_json TEXT NOT NULL DEFAULT '{}',
                warnings_json TEXT NOT NULL DEFAULT '[]',
                errors_json TEXT NOT NULL DEFAULT '[]',
                audit_trail_hash VARCHAR,
                started_at DATETIME NOT NULL,
                completed_at DATETIME,
                created_at DATETIME NOT NULL,
                updated_at DATETIME NOT NULL
            );
            """,
            "CREATE INDEX IF NOT EXISTS idx_agent_run_camp ON agent_orchestrator_runs(campaign_id);",
            "CREATE INDEX IF NOT EXISTS idx_agent_run_stage ON agent_orchestrator_runs(current_stage);",
            "CREATE INDEX IF NOT EXISTS idx_agent_run_status ON agent_orchestrator_runs(overall_status);",
        ],
    },
    {
        "version": 27,
        "name": "027_finding_quality_and_disposition",
        "up_sql": [
            "ALTER TABLE findings ADD COLUMN finding_disposition VARCHAR NOT NULL DEFAULT 'INCONCLUSIVE';",
            "ALTER TABLE findings ADD COLUMN condition_confidence FLOAT NOT NULL DEFAULT 0.0;",
            "ALTER TABLE findings ADD COLUMN impact_confidence FLOAT NOT NULL DEFAULT 0.0;",
            "ALTER TABLE findings ADD COLUMN reproducibility_confidence FLOAT NOT NULL DEFAULT 0.0;",
            "ALTER TABLE findings ADD COLUMN exploitability_confidence FLOAT NOT NULL DEFAULT 0.0;",
            "ALTER TABLE findings ADD COLUMN bounty_eligibility VARCHAR NOT NULL DEFAULT 'UNKNOWN';",
            "ALTER TABLE findings ADD COLUMN parent_finding_id VARCHAR;",
            "CREATE INDEX IF NOT EXISTS idx_findings_disposition ON findings(finding_disposition);",
            "CREATE INDEX IF NOT EXISTS idx_findings_bounty_elig ON findings(bounty_eligibility);",
            "CREATE INDEX IF NOT EXISTS idx_findings_parent ON findings(parent_finding_id);",
        ],
    },
    {
        "version": 28,
        "name": "028_policy_confidence_and_verification_explanation",
        "up_sql": [
            "ALTER TABLE findings ADD COLUMN policy_eligibility_confidence FLOAT NOT NULL DEFAULT 0.0;",
            "ALTER TABLE findings ADD COLUMN verification_explanation TEXT;",
        ],
    },
    {
        "version": 29,
        "name": "029_add_needs_human_review_disposition",
        "up_sql": [
            "SELECT 1;"
        ],
    },
    {
        "version": 30,
        "name": "030_t001_watchschedule_user_ownership_and_webhook_encryption",
        "up_sql": [
            # T-001: Add user_id ownership column to watch_schedules.
            # Nullable to preserve existing rows; new rows always populated by router.
            "ALTER TABLE watch_schedules ADD COLUMN user_id VARCHAR REFERENCES users(id);",
            "CREATE INDEX IF NOT EXISTS idx_watch_schedules_user_id ON watch_schedules(user_id);",
            # SQLite cannot ALTER COLUMN type. EncryptedText handles encryption at the ORM layer.
            "SELECT 'T-001: alert_webhook encrypted at ORM layer via EncryptedText TypeDecorator';",
        ],
    },
    {
        "version": 31,
        "name": "031_stripe_subscription_webhook_state",
        "up_sql": [
            "ALTER TABLE subscriptions ADD COLUMN stripe_subscription_id VARCHAR;",
            "ALTER TABLE subscriptions ADD COLUMN stripe_customer_id VARCHAR;",
            "ALTER TABLE subscriptions ADD COLUMN stripe_checkout_session_id VARCHAR;",
            "CREATE UNIQUE INDEX IF NOT EXISTS idx_subscriptions_stripe_subscription ON subscriptions(stripe_subscription_id);",
            "CREATE UNIQUE INDEX IF NOT EXISTS idx_subscriptions_stripe_checkout ON subscriptions(stripe_checkout_session_id);",
            "CREATE TABLE IF NOT EXISTS stripe_webhook_events (event_id VARCHAR PRIMARY KEY, event_type VARCHAR NOT NULL, received_at VARCHAR NOT NULL);",
        ],
    },
    {
        "version": 32,
        "name": "032_team_workspaces_and_campaign_membership",
        "up_sql": [
            "CREATE TABLE IF NOT EXISTS organizations (id VARCHAR PRIMARY KEY, name VARCHAR(120) NOT NULL, created_by_user_id VARCHAR NOT NULL, created_at DATETIME NOT NULL, FOREIGN KEY(created_by_user_id) REFERENCES users(id) ON DELETE RESTRICT);",
            "CREATE INDEX IF NOT EXISTS idx_organizations_creator ON organizations(created_by_user_id);",
            "CREATE TABLE IF NOT EXISTS organization_members (id VARCHAR PRIMARY KEY, organization_id VARCHAR NOT NULL, user_id VARCHAR NOT NULL, role VARCHAR(16) NOT NULL DEFAULT 'member', invited_by_user_id VARCHAR, created_at DATETIME NOT NULL, CONSTRAINT uq_organization_member_user UNIQUE(organization_id, user_id), CONSTRAINT ck_organization_member_role CHECK(role IN ('owner', 'admin', 'member', 'viewer')), FOREIGN KEY(organization_id) REFERENCES organizations(id) ON DELETE CASCADE, FOREIGN KEY(user_id) REFERENCES users(id) ON DELETE CASCADE, FOREIGN KEY(invited_by_user_id) REFERENCES users(id) ON DELETE SET NULL);",
            "CREATE INDEX IF NOT EXISTS idx_organization_members_organization ON organization_members(organization_id);",
            "CREATE INDEX IF NOT EXISTS idx_organization_members_user ON organization_members(user_id);",
            "ALTER TABLE campaigns ADD COLUMN organization_id VARCHAR REFERENCES organizations(id) ON DELETE SET NULL;",
            "CREATE INDEX IF NOT EXISTS idx_campaigns_organization ON campaigns(organization_id);",
        ],
    },
    {
        "version": 33,
        "name": "033_durable_campaign_recon_runs",
        "up_sql": [
            "CREATE TABLE IF NOT EXISTS campaign_recon_runs (id VARCHAR PRIMARY KEY, campaign_id VARCHAR NOT NULL UNIQUE, campaign_mode VARCHAR NOT NULL, assessment_mode VARCHAR NOT NULL DEFAULT 'CONTROLLED', state VARCHAR NOT NULL DEFAULT 'PENDING', authorization_id VARCHAR, scope_hash VARCHAR, selected_capabilities_json TEXT NOT NULL DEFAULT '[]', result_json TEXT, failure_reason TEXT, worker_id VARCHAR, lease_expires_at DATETIME, created_at DATETIME NOT NULL, started_at DATETIME, completed_at DATETIME, FOREIGN KEY(campaign_id) REFERENCES campaigns(id) ON DELETE CASCADE);",
            "CREATE INDEX IF NOT EXISTS idx_campaign_recon_runs_campaign ON campaign_recon_runs(campaign_id);",
            "CREATE INDEX IF NOT EXISTS idx_campaign_recon_runs_state ON campaign_recon_runs(state);",
            "CREATE INDEX IF NOT EXISTS idx_campaign_recon_runs_lease ON campaign_recon_runs(lease_expires_at);",
        ],
    },
]


def _compute_checksum(up_sql: list[str]) -> str:
    """Compute SHA-256 checksum for a migration script."""
    content = "\n".join(statement.strip() for statement in up_sql)
    return hashlib.sha256(content.encode("utf-8")).hexdigest()


def run_migrations(engine: Engine, db_path: str | None = None) -> None:
    """Execute all pending database migrations transactionally with checksum validation.

    Creates a pre-migration backup (aihax.db.bak) before applying pending migrations.
    """
    backup_file = None
    if db_path and Path(db_path).exists() and Path(db_path).is_file():
        backup_file = Path(db_path).with_suffix(".db.bak")
        try:
            shutil.copy2(db_path, backup_file)
            logger.info(f"Created pre-migration backup at {backup_file}")
        except Exception as e:
            logger.warning(f"Could not create database backup: {e}")

    try:
        with engine.begin() as conn:
            # Ensure schema_migrations table exists
            conn.execute(
                text(
                    """
                CREATE TABLE IF NOT EXISTS schema_migrations (
                    version INTEGER PRIMARY KEY,
                    name TEXT NOT NULL,
                    checksum TEXT NOT NULL,
                    applied_at DATETIME NOT NULL
                );
            """
                )
            )

            # Query applied migrations
            applied_rows = conn.execute(
                text("SELECT version, name, checksum FROM schema_migrations ORDER BY version ASC")
            ).fetchall()
            applied_dict = {row[0]: (row[1], row[2]) for row in applied_rows}

            # Check integrity of previously applied migrations
            for m in MIGRATIONS:
                v = m["version"]
                current_checksum = _compute_checksum(m["up_sql"])
                if v in applied_dict:
                    applied_name, applied_checksum = applied_dict[v]
                    if applied_checksum != current_checksum:
                        raise RuntimeError(
                            f"Migration integrity validation failed for version {v} ({applied_name})! "
                            f"Expected checksum {applied_checksum}, computed {current_checksum}."
                        )

            # Apply pending migrations transactionally
            for m in MIGRATIONS:
                v = m["version"]
                if v in applied_dict:
                    continue

                logger.info(f"Applying database migration {v}: {m['name']}...")
                checksum = _compute_checksum(m["up_sql"])
                now_utc_str = datetime.now(timezone.utc).isoformat()

                for statement in m["up_sql"]:
                    # Safely check if column exists before ALTER TABLE to handle idempotent execution
                    if "ADD COLUMN" in statement.upper():
                        parts = statement.split()
                        table_name = parts[2]
                        col_name = parts[5]
                        cols = {
                            r[1]
                            for r in conn.execute(
                                text(f"PRAGMA table_info('{table_name}')")
                            ).fetchall()
                        }
                        if col_name in cols:
                            continue

                    conn.execute(text(statement))

                conn.execute(
                    text(
                        "INSERT INTO schema_migrations (version, name, checksum, applied_at) VALUES (:v, :n, :c, :a)"
                    ),
                    {"v": v, "n": m["name"], "c": checksum, "a": now_utc_str},
                )

                logger.info(f"Successfully applied migration {v}: {m['name']}")

    except Exception as err:
        logger.error(f"Database migration failed: {err}")
        if backup_file and backup_file.exists() and db_path:
            try:
                shutil.copy2(backup_file, db_path)
                logger.info(f"Restored database from backup {backup_file} after migration failure.")
            except Exception as restore_err:
                logger.critical(f"Failed to restore database backup: {restore_err}")
        raise err
