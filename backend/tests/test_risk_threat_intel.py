from backend.main import URLAnalysisRequest, analyze_url, app
from backend.risk_engine import (
    MAX_THREAT_INTEL_SCORE,
    analyze_rules,
    calculate_risk,
)
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
    assert risk_result["risk_score"] > calculate_risk(
        ml_probability=0.2,
        rule_result=rule_result,
    )["risk_score"]


def test_no_threat_intel_match_does_not_change_risk_result():
    rule_result = analyze_rules("https://github.com")

    without_threat_intel = calculate_risk(
        ml_probability=0.2,
        rule_result=rule_result,
    )
    with_no_match = calculate_risk(
        ml_probability=0.2,
        rule_result=rule_result,
        threat_intel=ThreatIntelEvidence(
            matched=False,
            provider="local",
            indicators=[],
        ),
    )

    assert with_no_match == without_threat_intel


def test_threat_intel_severity_uses_bounded_adjustments():
    rule_result = {"rule_score": 0, "indicators": []}
    baseline = calculate_risk(0.1, rule_result)["risk_score"]

    for severity, expected in {
        "low": 5,
        "medium": 10,
        "high": 20,
        "critical": 30,
    }.items():
        result = calculate_risk(
            0.1,
            rule_result,
            ThreatIntelEvidence(
                matched=True,
                provider="test",
                indicators=[
                    {
                        "type": f"{severity}_match",
                        "severity": severity,
                        "message": "Test match.",
                    }
                ],
            ),
        )

        if severity == "high":
            assert result["risk_score"] >= 70
            assert result["risk_level"] == "HIGH"
        elif severity == "critical":
            assert result["risk_score"] >= 80
            assert result["risk_level"] == "HIGH"
        else:
            assert result["risk_score"] == baseline + expected


def test_threat_intel_score_is_capped():
    result = calculate_risk(
        0.1,
        {"rule_score": 0, "indicators": []},
        ThreatIntelEvidence(
            matched=True,
            provider="test",
            indicators=[
                {
                    "type": f"match-{index}",
                    "severity": "medium",
                    "message": "Test match.",
                }
                for index in range(5)
            ],
        ),
    )

    assert result["risk_score"] == 3 + MAX_THREAT_INTEL_SCORE


def test_critical_threat_intel_guarantees_high_risk():
    result = calculate_risk(
        0.1,
        {"rule_score": 0, "indicators": []},
        ThreatIntelEvidence(
            matched=True,
            provider="test",
            indicators=[
                {
                    "type": "known_malicious_url",
                    "severity": "critical",
                    "message": "Confirmed malicious URL.",
                }
            ],
        ),
    )

    assert result["risk_score"] >= 80
    assert result["risk_level"] == "HIGH"


def test_ml_only_false_positive_protection_is_preserved_without_ti():
    result = calculate_risk(
        0.95,
        {"rule_score": 0, "indicators": []},
    )

    assert result["risk_score"] == 25
    assert result["risk_level"] == "LOW"


def test_confirmed_ti_bypasses_ml_only_false_positive_protection():
    result = calculate_risk(
        0.95,
        {"rule_score": 0, "indicators": []},
        ThreatIntelEvidence(
            matched=True,
            provider="test",
            indicators=[
                {
                    "type": "known_malicious_domain",
                    "severity": "high",
                    "message": "Confirmed malicious domain.",
                }
            ],
        ),
    )

    assert result["risk_level"] == "HIGH"
    assert result["risk_score"] > 25


def test_duplicate_indicators_are_kept_once_without_mutating_input():
    duplicate = {
        "type": "suspicious_tld",
        "severity": "high",
        "message": "Domain uses a commonly abused TLD.",
    }
    rule_indicators = [duplicate, duplicate.copy()]
    rule_result = {"rule_score": 25, "indicators": rule_indicators}

    result = calculate_risk(
        0.1,
        rule_result,
        ThreatIntelEvidence(
            matched=True,
            provider="test",
            indicators=[duplicate.copy()],
        ),
    )

    assert result["indicators"] == [duplicate]
    assert rule_result["indicators"] == rule_indicators


def test_existing_url_analysis_still_works():
    result = analyze_url(
        URLAnalysisRequest(
            url="https://github.com"
        )
    )

    assert {"url", "prediction", "risk", "url_analysis"}.issubset(
        result
    )
    assert set(result["prediction"]) == {
        "ml_probability",
        "ml_label",
    }
    assert "risk_score" in result["risk"]
    assert "indicators" in result["risk"]
    assert result["url_analysis"]["hostname"] == "github.com"


def test_fastapi_import_and_routes_remain_unchanged():
    routes = {route.path for route in app.routes}

    assert {"/", "/health", "/api/analyze/url", "/api/analyze/sms", "/api/analyze/email"}.issubset(routes)
