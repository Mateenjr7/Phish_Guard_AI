from copy import deepcopy

from backend.risk_engine import (
    MAX_THREAT_INTEL_SCORE,
    analyze_rules,
    calculate_risk,
)
from backend.threat_intelligence import ThreatIntelEvidence


def test_no_rules_and_ml_only_results_are_low_risk():
    result = calculate_risk(
        ml_probability=0.95,
        rule_result={"rule_score": 0, "indicators": []},
    )

    assert result["risk_score"] == 25
    assert result["risk_level"] == "LOW"
    assert result["indicators"] == []


def test_rule_only_and_combined_results_include_rule_evidence():
    rule_result = {
        "rule_score": 60,
        "indicators": [
            {
                "type": "suspicious_url",
                "severity": "high",
                "message": "Suspicious URL evidence.",
            }
        ],
    }

    rule_only = calculate_risk(0.0, rule_result)
    combined = calculate_risk(0.8, rule_result)

    assert rule_only["risk_score"] == 70
    assert rule_only["risk_level"] == "HIGH"
    assert combined["risk_score"] == 70
    assert combined["risk_level"] == "HIGH"
    assert combined["indicators"] == rule_result["indicators"]


def test_individual_and_combined_url_rules_are_meaningful():
    insecure = analyze_rules("http://example.com")
    suspicious = analyze_rules("http://secure-account-verify.xyz/login")

    assert insecure["rule_score"] == 10
    assert {indicator["type"] for indicator in insecure["indicators"]} == {
        "insecure_protocol"
    }
    assert suspicious["rule_score"] >= 50
    assert {
        "insecure_protocol",
        "suspicious_tld",
        "suspicious_keywords",
        "sensitive_actions",
    }.issubset(
        {indicator["type"] for indicator in suspicious["indicators"]}
    )


def test_multiple_threat_indicators_are_capped_and_retained():
    evidence = ThreatIntelEvidence(
        matched=True,
        provider="test",
        indicators=[
            {
                "type": "indicator-one",
                "severity": "critical",
                "message": "Critical match.",
            },
            {
                "type": "indicator-two",
                "severity": "high",
                "message": "High match.",
            },
        ],
    )

    result = calculate_risk(
        0.0,
        {"rule_score": 0, "indicators": []},
        evidence,
    )

    assert result["risk_score"] == 80
    assert MAX_THREAT_INTEL_SCORE == 30
    assert result["risk_level"] == "HIGH"
    assert result["indicators"] == evidence.indicators


def test_unknown_threat_severity_is_ignored_without_crashing():
    result = calculate_risk(
        0.1,
        {"rule_score": 0, "indicators": []},
        ThreatIntelEvidence(
            matched=True,
            provider="test",
            indicators=[
                {
                    "type": "malformed",
                    "severity": "unknown",
                    "message": "Unrecognized severity.",
                }
            ],
        ),
    )

    assert result["risk_score"] == 3
    assert result["risk_level"] == "LOW"
    assert result["indicators"][0]["type"] == "malformed"


def test_risk_calculation_does_not_mutate_rule_or_threat_inputs():
    rule_result = {
        "rule_score": 25,
        "indicators": [
            {
                "type": "duplicate",
                "severity": "medium",
                "message": "Duplicate indicator.",
            },
            {
                "type": "duplicate",
                "severity": "medium",
                "message": "Duplicate indicator.",
            },
        ],
    }
    threat_intel = ThreatIntelEvidence(
        matched=True,
        provider="test",
        indicators=[
            {
                "type": "known-match",
                "severity": "high",
                "message": "Known match.",
            }
        ],
    )
    original_rule_result = deepcopy(rule_result)
    original_indicators = deepcopy(threat_intel.indicators)

    result = calculate_risk(0.2, rule_result, threat_intel)

    assert rule_result == original_rule_result
    assert threat_intel.indicators == original_indicators
    assert len(result["indicators"]) == 2