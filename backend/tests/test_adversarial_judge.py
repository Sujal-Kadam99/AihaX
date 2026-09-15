import pytest
from backend.services.adversarial_judge import AdversarialJudge, Claim
from backend.models.database import FindingDisposition

def test_adversarial_judge_high_high():
    prosecutor = Claim("PROSECUTOR", "REAL", 0.9)
    skeptic = Claim("SKEPTIC", "FALSE_POSITIVE", 0.9)
    res = AdversarialJudge.reconcile(prosecutor, skeptic)
    assert res.disposition == FindingDisposition.NEEDS_HUMAN_REVIEW.value
    assert res.confidence_score == 50

def test_adversarial_judge_high_medium():
    prosecutor = Claim("PROSECUTOR", "REAL", 0.9)
    skeptic = Claim("SKEPTIC", "FALSE_POSITIVE", 0.4)
    res = AdversarialJudge.reconcile(prosecutor, skeptic)
    assert res.disposition == FindingDisposition.VALIDATED.value
    assert res.confidence_score == 80

def test_adversarial_judge_high_low():
    prosecutor = Claim("PROSECUTOR", "REAL", 0.9)
    skeptic = Claim("SKEPTIC", "NEUTRAL", 0.1)
    res = AdversarialJudge.reconcile(prosecutor, skeptic)
    assert res.disposition == FindingDisposition.VALIDATED.value
    assert res.confidence_score == 95

def test_adversarial_judge_medium_high():
    prosecutor = Claim("PROSECUTOR", "REAL", 0.4)
    skeptic = Claim("SKEPTIC", "FALSE_POSITIVE", 0.9)
    res = AdversarialJudge.reconcile(prosecutor, skeptic)
    assert res.disposition == FindingDisposition.FALSE_POSITIVE.value
    assert res.confidence_score == 10

def test_adversarial_judge_medium_medium():
    prosecutor = Claim("PROSECUTOR", "REAL", 0.4)
    skeptic = Claim("SKEPTIC", "FALSE_POSITIVE", 0.4)
    res = AdversarialJudge.reconcile(prosecutor, skeptic)
    assert res.disposition == FindingDisposition.INCONCLUSIVE.value
    assert res.confidence_score == 40

def test_adversarial_judge_medium_low():
    prosecutor = Claim("PROSECUTOR", "REAL", 0.4)
    skeptic = Claim("SKEPTIC", "NEUTRAL", 0.2)
    res = AdversarialJudge.reconcile(prosecutor, skeptic)
    assert res.disposition == FindingDisposition.HARDENING_ONLY.value
    assert res.confidence_score == 50

def test_adversarial_judge_low_high():
    prosecutor = Claim("PROSECUTOR", "NEUTRAL", 0.2)
    skeptic = Claim("SKEPTIC", "FALSE_POSITIVE", 0.9)
    res = AdversarialJudge.reconcile(prosecutor, skeptic)
    assert res.disposition == FindingDisposition.FALSE_POSITIVE.value
    assert res.confidence_score == 10

def test_adversarial_judge_low_medium():
    prosecutor = Claim("PROSECUTOR", "NEUTRAL", 0.2)
    skeptic = Claim("SKEPTIC", "FALSE_POSITIVE", 0.4)
    res = AdversarialJudge.reconcile(prosecutor, skeptic)
    assert res.disposition == FindingDisposition.FALSE_POSITIVE.value
    assert res.confidence_score == 10

def test_adversarial_judge_low_low():
    prosecutor = Claim("PROSECUTOR", "NEUTRAL", 0.2)
    skeptic = Claim("SKEPTIC", "NEUTRAL", 0.2)
    res = AdversarialJudge.reconcile(prosecutor, skeptic)
    assert res.disposition == FindingDisposition.INCONCLUSIVE.value
    assert res.confidence_score == 30

def test_adversarial_judge_hard_rule_override():
    prosecutor = Claim("PROSECUTOR", "REAL", 0.99) # Very strong prosecutor
    skeptic = Claim("SKEPTIC", "FALSE_POSITIVE", 1.0, is_hard_rule=True)
    res = AdversarialJudge.reconcile(prosecutor, skeptic)
    # Even with strong prosecutor, hard rule makes it a deterministic FALSE_POSITIVE
    assert res.disposition == FindingDisposition.FALSE_POSITIVE.value
    assert res.confidence_score == 10
    assert "deterministic false positive" in res.explanation.lower()
