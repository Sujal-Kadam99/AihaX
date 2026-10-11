"""AihaX Intelligence Package — Phase 7.

Provides deterministic finding intelligence:
- FindingClassifier:         normalizes verified findings into categories
- SeverityEngine:           evidence-driven severity assessment
- ConfidenceEngine:         multi-path confidence scoring
- EvidenceCorrelator:       immutable evidence chain assembly
- FindingClusterer:         root-cause clustering without hallucination
- ReproducibilityEngine:    sanitized reproduction package generation
- RemediationEngine:        deterministic remediation guidance
- CampaignIntelligenceEngine: campaign-level aggregated intelligence
"""

from backend.intelligence.campaign_intelligence import (
    CampaignIntelligenceEngine,
    CampaignIntelligenceReport,
)
from backend.intelligence.confidence_engine import ConfidenceAssessment, ConfidenceEngine
from backend.intelligence.evidence_correlator import EvidenceChain, EvidenceCorrelator
from backend.intelligence.finding_classifier import FindingClassification, FindingClassifier
from backend.intelligence.finding_clusterer import (
    ClusterRelationType,
    FindingCluster,
    FindingClusterer,
)
from backend.intelligence.remediation import RemediationEngine, RemediationGuidance
from backend.intelligence.report_guards import (
    ReportGenerationBlockedError,
    ReportGuard,
    ReportGuardReport,
)
from backend.intelligence.reproducibility import ReproducibilityEngine, ReproductionPackage
from backend.intelligence.severity_engine import SeverityAssessment, SeverityEngine

__all__ = [
    "FindingClassifier",
    "FindingClassification",
    "SeverityEngine",
    "SeverityAssessment",
    "ConfidenceEngine",
    "ConfidenceAssessment",
    "EvidenceCorrelator",
    "EvidenceChain",
    "FindingClusterer",
    "FindingCluster",
    "ClusterRelationType",
    "ReproducibilityEngine",
    "ReproductionPackage",
    "RemediationEngine",
    "RemediationGuidance",
    "CampaignIntelligenceEngine",
    "CampaignIntelligenceReport",
    "ReportGuard",
    "ReportGuardReport",
    "ReportGenerationBlockedError",
]

