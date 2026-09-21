from backend.main import SMSAnalysisRequest, analyze_sms
from backend.sms_risk import calculate_sms_risk
from backend.sms_risk_engine import (
    _deduplicate_indicators,
    analyze_sms_rules,
)


def indicator_types(result: dict) -> set[str]:
    return {indicator["type"] for indicator in result["indicators"]}


def test_normal_personal_sms_remains_low_risk():
    result = calculate_sms_risk(
        "Hey, are we still meeting for lunch today?"
    )

    assert result["risk_level"] == "LOW"
    assert result["risk_score"] < 40


def test_legitimate_otp_message_remains_low_risk():
    result = calculate_sms_risk(
        "Your verification code is 482913. Do not share it with anyone."
    )

    assert result["risk_level"] == "LOW"
    assert result["risk_score"] < 40
    assert "verification" in indicator_types(result)


def test_delivery_notification_is_not_escalated():
    result = calculate_sms_risk(
        "Your package will arrive today between 2 and 5 PM."
    )

    assert result["risk_level"] == "LOW"
    assert result["risk_score"] < 40


def test_promotional_sms_remains_bounded():
    result = calculate_sms_risk(
        "Enjoy 20% off your next order this weekend. Shop in store."
    )

    assert 0 <= result["risk_score"] <= 100
    assert result["risk_level"] in {"LOW", "MEDIUM", "HIGH"}


def test_credential_phishing_sms_has_credential_evidence():
    result = analyze_sms_rules(
        "Your account is locked. Enter your password and PIN now."
    )

    assert "credentials" in indicator_types(result)


def test_account_verification_phishing_sms_has_combination_evidence():
    result = analyze_sms_rules(
        "URGENT! Your account is suspended. Verify now to restore access."
    )

    assert {
        "urgency",
        "account_terms",
        "verification",
        "account_verification_combination",
        "threat_verification_combination",
    }.issubset(indicator_types(result))


def test_financial_phishing_sms_has_financial_evidence():
    result = analyze_sms_rules(
        "Urgent payment required to prevent your bank account from closing."
    )

    assert "account_terms" in indicator_types(result)
    assert "urgency" in indicator_types(result)
    assert "financial_request" in indicator_types(result)


def test_suspicious_url_is_explained():
    result = analyze_sms_rules(
        "Verify your account at https://secure-account-verify.xyz/login"
    )

    types = indicator_types(result)

    assert "suspicious_url" in types
    assert "sms_suspicious_tld" in types
    assert any(
        "secure-account-verify.xyz" in indicator["message"]
        for indicator in result["indicators"]
    )


def test_shortened_url_is_detected():
    result = analyze_sms_rules(
        "Claim your reward now: https://bit.ly/example"
    )

    assert "sms_url_shortener" in indicator_types(result)


def test_ip_address_url_is_detected():
    result = analyze_sms_rules(
        "Continue at https://192.168.1.1/login"
    )

    assert "sms_ip_address" in indicator_types(result)
    assert "phone_number" not in indicator_types(result)


def test_duplicate_indicators_are_removed():
    duplicate = {
        "type": "urgency",
        "severity": "medium",
        "message": "Urgency detected.",
    }

    assert _deduplicate_indicators([duplicate, duplicate.copy()]) == [
        duplicate
    ]


def test_existing_sms_api_response_fields_remain_present():
    response = analyze_sms(
        SMSAnalysisRequest(
            text="URGENT! Verify your account at https://secure-account-verify.xyz/login"
        )
    )

    assert set(response) == {"text", "prediction", "risk"}
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


def test_existing_sms_analyzer_returns_hybrid_result():
    result = calculate_sms_risk(
        "Your appointment is confirmed for tomorrow at 10 AM."
    )

    assert 0 <= result["ml_probability"] <= 1
    assert 0 <= result["rule_score"] <= 100
    assert 0 <= result["risk_score"] <= 100
    assert result["risk_level"] in {"LOW", "MEDIUM", "HIGH"}
