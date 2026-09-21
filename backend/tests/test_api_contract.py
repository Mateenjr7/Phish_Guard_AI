from fastapi.testclient import TestClient

from backend.main import app


client = TestClient(app)


def assert_analysis_contract(
    response,
    expected_fields: set[str],
) -> dict:
    assert response.status_code == 200
    assert response.headers["content-type"].startswith("application/json")

    payload = response.json()

    assert expected_fields.issubset(payload)
    assert {"prediction", "risk"}.issubset(payload)
    assert {
        "ml_probability",
        "ml_label",
    }.issubset(payload["prediction"])
    assert {
        "risk_level",
        "risk_score",
        "indicators",
    }.issubset(payload["risk"])
    assert isinstance(payload["risk"]["indicators"], list)

    return payload


def test_url_endpoint_contract_and_risk_fields():
    payload = assert_analysis_contract(
        client.post(
            "/api/analyze/url",
            json={"url": "https://github.com"},
        ),
        {"url", "url_analysis"},
    )

    assert payload["url_analysis"]["hostname"] == "github.com"
    assert payload["risk"]["risk_level"] in {
        "LOW",
        "MEDIUM",
        "HIGH",
        "UNCERTAIN",
    }


def test_sms_endpoint_contract_and_risk_fields():
    payload = assert_analysis_contract(
        client.post(
            "/api/analyze/sms",
            json={"text": "Your account has been suspended. Verify now."},
        ),
        {"text"},
    )

    assert payload["text"]
    assert payload["risk"]["risk_score"] >= 0


def test_email_endpoint_contract_and_risk_fields():
    payload = assert_analysis_contract(
        client.post(
            "/api/analyze/email",
            json={
                "subject": "Urgent verification",
                "body": "Please verify your account immediately.",
            },
        ),
        {"subject", "body"},
    )

    assert payload["subject"] == "Urgent verification"
    assert payload["risk"]["risk_score"] >= 0


def test_unified_url_dispatch_preserves_specialized_analysis():
    specialized = client.post(
        "/api/analyze/url",
        json={"url": "https://github.com"},
    )
    unified = client.post(
        "/api/analyze",
        json={"input_type": "url", "url": "https://github.com"},
    )

    unified_payload = assert_analysis_contract(
        unified,
        {"input_type", "url", "url_analysis"},
    )

    assert unified_payload["input_type"] == "url"
    assert unified_payload["url_analysis"] == specialized.json()[
        "url_analysis"
    ]
    assert unified_payload["risk"] == specialized.json()["risk"]


def test_unified_sms_and_email_dispatch_include_input_type():
    specialized_sms = client.post(
        "/api/analyze/sms",
        json={"text": "Your account has been suspended. Verify now."},
    )
    specialized_email = client.post(
        "/api/analyze/email",
        json={
            "subject": "Urgent verification",
            "body": "Please verify your account immediately.",
        },
    )
    sms_payload = assert_analysis_contract(
        client.post(
            "/api/analyze",
            json={
                "input_type": "sms",
                "text": "Your account has been suspended. Verify now.",
            },
        ),
        {"input_type", "text"},
    )
    email_payload = assert_analysis_contract(
        client.post(
            "/api/analyze",
            json={
                "input_type": "email",
                "subject": "Urgent verification",
                "body": "Please verify your account immediately.",
            },
        ),
        {"input_type", "subject", "body"},
    )

    assert sms_payload["input_type"] == "sms"
    assert email_payload["input_type"] == "email"
    assert sms_payload["prediction"] == specialized_sms.json()["prediction"]
    assert sms_payload["risk"] == specialized_sms.json()["risk"]
    assert email_payload["prediction"] == specialized_email.json()["prediction"]
    assert email_payload["risk"] == specialized_email.json()["risk"]


def test_detection_regressions_remain_meaningful():
    github = client.post(
        "/api/analyze/url",
        json={"url": "https://github.com"},
    ).json()
    suspicious_url = client.post(
        "/api/analyze/url",
        json={"url": "http://secure-account-verify.xyz/login"},
    ).json()
    legitimate_sms = client.post(
        "/api/analyze/sms",
        json={"text": "Your delivery is scheduled for tomorrow."},
    ).json()
    phishing_sms = client.post(
        "/api/analyze/sms",
        json={
            "text": "URGENT! Your account is suspended. Verify your password now."
        },
    ).json()
    legitimate_email = client.post(
        "/api/analyze/email",
        json={
            "subject": "Monthly newsletter",
            "body": "Here are this month's product updates.",
        },
    ).json()
    phishing_email = client.post(
        "/api/analyze/email",
        json={
            "subject": "Urgent account verification",
            "body": "Your account is suspended. Verify your password immediately.",
        },
    ).json()

    assert github["risk"]["risk_level"] == "LOW"
    assert suspicious_url["risk"]["risk_level"] == "HIGH"
    assert legitimate_sms["risk"]["risk_level"] == "LOW"
    assert phishing_sms["risk"]["risk_level"] == "HIGH"
    assert legitimate_email["risk"]["risk_level"] == "LOW"
    assert phishing_email["risk"]["risk_level"] == "HIGH"


def test_unified_validation_errors_are_clean():
    cases = [
        ({"input_type": "url"}, 400),
        ({"input_type": "sms"}, 400),
        ({"input_type": "email"}, 400),
        ({"input_type": "video", "url": "https://example.com"}, 422),
        ({"url": "https://example.com"}, 422),
    ]

    for payload, expected_status in cases:
        response = client.post("/api/analyze", json=payload)

        assert response.status_code == expected_status
        assert response.headers["content-type"].startswith("application/json")
        assert response.json().get("detail")


def test_specialized_endpoints_reject_empty_inputs():
    assert client.post(
        "/api/analyze/url",
        json={"url": "   "},
    ).status_code == 400
    assert client.post(
        "/api/analyze/sms",
        json={"text": "   "},
    ).status_code == 400
    assert client.post(
        "/api/analyze/email",
        json={"subject": "", "body": ""},
    ).status_code == 400