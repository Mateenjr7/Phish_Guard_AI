from backend.email_risk import calculate_email_risk
from backend.email_risk_engine import (
    analyze_email_rules,
    deduplicate_indicators,
)
from backend.main import EmailAnalysisRequest, analyze_email


def indicator_types(result: dict) -> set[str]:
    return {indicator["type"] for indicator in result["indicators"]}


def test_legitimate_newsletter_remains_low_risk():
    result = calculate_email_risk(
        "Monthly Newsletter",
        "Here are this week's product updates and reading recommendations.",
    )

    assert result["risk_level"] == "LOW"
    assert result["risk_score"] < 40


def test_credential_phishing_email_has_credential_evidence():
    result = analyze_email_rules(
        "Urgent account verification",
        "Enter your username and password to keep your account active.",
    )

    assert "credentials" in indicator_types(result)


def test_urgent_account_verification_has_combination_evidence():
    result = analyze_email_rules(
        "Urgent account verification",
        "Your account is suspended. Verify immediately to restore access.",
    )

    assert {"urgency", "account", "verification", "account_verification"}.issubset(
        indicator_types(result)
    )


def test_suspicious_url_is_explained():
    result = analyze_email_rules(
        "Security notice",
        "Verify your account at https://secure-account-verify.xyz/login",
    )

    types = indicator_types(result)

    assert "suspicious_url" in types
    assert "email_suspicious_tld" in types
    assert any(
        "secure-account-verify.xyz" in indicator["message"]
        for indicator in result["indicators"]
    )


def test_url_shortener_is_detected():
    result = analyze_email_rules(
        "Link inside message",
        "Open https://bit.ly/example to continue.",
    )

    assert "email_url_shortener" in indicator_types(result)


def test_ip_address_url_is_detected():
    result = analyze_email_rules(
        "Verify now",
        "Continue at https://192.168.1.1/login",
    )

    assert "email_ip_address" in indicator_types(result)


def test_financial_phishing_email_has_financial_evidence():
    result = analyze_email_rules(
        "Payment required",
        "Urgent payment is required to prevent account suspension.",
    )

    assert "financial" in indicator_types(result)
    assert "financial_urgency" in indicator_types(result)


def test_duplicate_indicators_are_removed():
    duplicate = {
        "type": "urgency",
        "severity": "medium",
        "message": "Urgency detected.",
    }

    result = deduplicate_indicators([duplicate, duplicate.copy()])

    assert result == [duplicate]


def test_existing_email_api_response_fields_remain_present():
    response = analyze_email(
        EmailAnalysisRequest(
            subject="Urgent verification",
            body="Verify your account at https://secure-account-verify.xyz/login",
        )
    )

    assert set(response) == {"subject", "body", "prediction", "risk"}
    assert set(response["prediction"]) == {
        "ml_probability",
        "ml_label",
    }
    assert {
        "risk_score",
        "risk_level",
        "ml_probability",
        "rule_score",
        "indicators",
    }.issubset(response["risk"])


def test_existing_email_analyzer_returns_hybrid_result():
    result = calculate_email_risk(
        "Account update",
        "Please review the latest account information.",
    )

    assert 0 <= result["ml_probability"] <= 1
    assert 0 <= result["rule_score"] <= 100
    assert 0 <= result["risk_score"] <= 100
    assert result["risk_level"] in {"LOW", "MEDIUM", "HIGH"}
