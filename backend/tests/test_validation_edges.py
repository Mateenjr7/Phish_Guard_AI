import pytest
from pydantic import ValidationError

from backend.main import (
    EmailAnalysisRequest,
    SMSAnalysisRequest,
    UnifiedAnalysisRequest,
    URLAnalysisRequest,
)
from backend.email_risk_engine import analyze_email_rules
from backend.sms_risk_engine import analyze_sms_rules
from backend.url_analysis import analyze_url_structure


def test_request_models_enforce_url_and_sms_boundaries():
    with pytest.raises(ValidationError):
        URLAnalysisRequest(url="ab")
    with pytest.raises(ValidationError):
        URLAnalysisRequest(url="x" * 4097)
    with pytest.raises(ValidationError):
        SMSAnalysisRequest(text="")
    with pytest.raises(ValidationError):
        SMSAnalysisRequest(text="x" * 10001)


def test_request_models_enforce_email_boundaries():
    with pytest.raises(ValidationError):
        EmailAnalysisRequest(subject="x" * 1001)
    with pytest.raises(ValidationError):
        EmailAnalysisRequest(body="x" * 100001)


def test_unified_request_reuses_branch_field_limits():
    with pytest.raises(ValidationError):
        UnifiedAnalysisRequest(input_type="url", url="x" * 4097)
    with pytest.raises(ValidationError):
        UnifiedAnalysisRequest(input_type="sms", text="x" * 10001)
    with pytest.raises(ValidationError):
        UnifiedAnalysisRequest(input_type="email", subject="x" * 1001)
    with pytest.raises(ValidationError):
        UnifiedAnalysisRequest(input_type="email", body="x" * 100001)


def test_malformed_url_metadata_remains_safe_and_observable():
    result = analyze_url_structure("https://example.com:not-a-port/path")

    assert result["hostname"] == "example.com"
    assert result["port"] is None
    assert result["path"] == "/path"


def test_sms_phone_detection_ignores_digits_inside_urls():
    phone_result = analyze_sms_rules("Call +1 (555) 123-4567 for help.")
    url_result = analyze_sms_rules(
        "Continue at https://192.168.1.1/login"
    )

    assert "phone_number" in {
        indicator["type"] for indicator in phone_result["indicators"]
    }
    assert "phone_number" not in {
        indicator["type"] for indicator in url_result["indicators"]
    }


def test_email_html_script_content_is_detected():
    result = analyze_email_rules(
        "Account notice",
        '<script>alert("verify")</script><p>Open the account page.</p>',
    )

    assert result["rule_score"] >= 20
    assert "html_script_content" in {
        indicator["type"] for indicator in result["indicators"]
    }


def test_legitimate_and_phishing_regression_signals_remain_distinct():
    legitimate_sms = analyze_sms_rules(
        "Your delivery is scheduled for tomorrow afternoon."
    )
    phishing_sms = analyze_sms_rules(
        "URGENT! Your account is suspended. Verify your password now."
    )
    legitimate_email = analyze_email_rules(
        "Monthly newsletter",
        "Here are this month's product updates and reading recommendations.",
    )
    phishing_email = analyze_email_rules(
        "Urgent account verification",
        "Your account is suspended. Verify your password immediately.",
    )

    assert legitimate_sms["rule_score"] < 40
    assert phishing_sms["rule_score"] >= 40
    assert legitimate_email["rule_score"] < 40
    assert phishing_email["rule_score"] >= 40