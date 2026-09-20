from backend.risk_engine import analyze_rules, calculate_risk
from backend.threat_intelligence import ThreatIntelEvidence


def test_threat_intel_evidence_is_added_to_risk_indicators():
    rule_result = analyze_rules("https://example.com/login")
    evidence = ThreatIntelEvidence(
        matched=True,
        provider="test",
        indicators=[
            {
                "type": "known_malicious_domain",
                "severity": "high",
                "message": "Domain matched test intelligence.",
            }
        ],
    )

    risk_result = calculate_risk(
        ml_probability=0.2,
        rule_result=rule_result,
        threat_intel=evidence,
    )

    assert risk_result["indicators"][-1] == evidence.indicators[0]