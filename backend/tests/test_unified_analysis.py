import pytest
from fastapi import HTTPException
from pydantic import ValidationError

from backend.main import (
    EmailAnalysisRequest,
    SMSAnalysisRequest,
    URLAnalysisRequest,
    UnifiedAnalysisRequest,
    analyze_email,
    analyze_sms,
    analyze_unified,
    analyze_url,
)


def test_unified_url_analysis_preserves_url_fields():
    result = analyze_unified(
        UnifiedAnalysisRequest(input_type="url", url="https://github.com")
    )

    assert result["input_type"] == "url"
    assert result["url"] == "https://github.com"
    assert "prediction" in result
    assert "risk" in result
    assert "url_analysis" in result


def test_unified_sms_analysis_preserves_prediction_and_risk():
    result = analyze_unified(
        UnifiedAnalysisRequest(
            input_type="sms",
            text="Your account has been suspended. Verify now.",
        )
    )

    assert result["input_type"] == "sms"
    assert result["text"]
    assert "prediction" in result
    assert "risk" in result


def test_unified_email_analysis_preserves_prediction_and_risk():
    result = analyze_unified(
        UnifiedAnalysisRequest(
            input_type="email",
            subject="Urgent verification",
            body="Please verify your account immediately.",
        )
    )

    assert result["input_type"] == "email"
    assert result["subject"] == "Urgent verification"
    assert result["body"]
    assert "prediction" in result
    assert "risk" in result


def test_invalid_input_type_is_rejected():
    with pytest.raises(ValidationError):
        UnifiedAnalysisRequest(input_type="video", url="https://example.com")


def test_missing_input_type_is_rejected():
    with pytest.raises(ValidationError):
        UnifiedAnalysisRequest(url="https://example.com")


def test_unified_url_requires_url():
    with pytest.raises(HTTPException) as error:
        analyze_unified(UnifiedAnalysisRequest(input_type="url"))

    assert error.value.status_code == 400


def test_unified_sms_requires_text():
    with pytest.raises(HTTPException) as error:
        analyze_unified(UnifiedAnalysisRequest(input_type="sms"))

    assert error.value.status_code == 400


def test_unified_email_rejects_empty_subject_and_body():
    with pytest.raises(HTTPException) as error:
        analyze_unified(UnifiedAnalysisRequest(input_type="email"))

    assert error.value.status_code == 400


def test_unified_email_accepts_subject_only():
    result = analyze_unified(
        UnifiedAnalysisRequest(input_type="email", subject="Status update")
    )

    assert result["subject"] == "Status update"
    assert result["body"] == ""


def test_unified_email_accepts_body_only():
    result = analyze_unified(
        UnifiedAnalysisRequest(input_type="email", body="Please review this.")
    )

    assert result["subject"] == ""
    assert result["body"] == "Please review this."


def test_existing_url_endpoint_still_works():
    result = analyze_url(URLAnalysisRequest(url="https://github.com"))

    assert {"prediction", "risk", "url_analysis"}.issubset(result)


def test_existing_sms_endpoint_still_works():
    result = analyze_sms(SMSAnalysisRequest(text="Your package arrives today."))

    assert {"prediction", "risk"}.issubset(result)


def test_existing_email_endpoint_still_works():
    result = analyze_email(
        EmailAnalysisRequest(subject="Hello", body="A message.")
    )

    assert {"prediction", "risk"}.issubset(result)