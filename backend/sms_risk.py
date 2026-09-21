from backend.sms_service import predict_sms
from backend.sms_risk_engine import analyze_sms_rules

def calculate_sms_risk(text: str) -> dict:
    ml_result = predict_sms(text)
    rule_result = analyze_sms_rules(text)

    ml_probability = ml_result["phishing_probability"]
    rule_score = rule_result["rule_score"]

    # ML contributes 40%, rules contribute 60%.
    combined_score = (ml_probability * 100 * 0.40) + (rule_score * 0.60)

    combined_score = round(
        min(combined_score, 100),
        1,
    )

    # Strong rule combinations should not be hidden
    # by a relatively low ML probability.
    critical_indicator = any(
        indicator["severity"] == "critical" for indicator in rule_result["indicators"]
    )

    high_indicator = any(
        indicator["severity"] == "high" for indicator in rule_result["indicators"]
    )

    if critical_indicator:
        combined_score = max(combined_score, 80)

    elif high_indicator and rule_score >= 50:
        combined_score = max(combined_score, 70)

    if combined_score >= 70:
        risk_level = "HIGH"

    elif combined_score >= 40:
        risk_level = "MEDIUM"

    else:
        risk_level = "LOW"

    return {
        "ml_probability": ml_probability,
        "ml_label": ml_result["label"],
        "rule_score": rule_score,
        "risk_score": combined_score,
        "risk_level": risk_level,
        "indicators": rule_result["indicators"],
    }
