from pathlib import Path

from backend.sms_risk import calculate_sms_risk


test_messages = [
    "Hey, are we still meeting for lunch today?",

    "Your appointment is confirmed for tomorrow at 10 AM.",

    "URGENT! Your bank account has been suspended. "
    "Verify immediately by clicking this link.",

    "Congratulations! You have won a prize. "
    "Call now to claim your reward.",

    "Your account will be closed. "
    "Click here immediately to verify your details.",
]


print("=" * 60)
print("PhishGuard AI - Combined SMS Risk Test")
print("=" * 60)


for message in test_messages:

    result = calculate_sms_risk(message)

    print("\nMessage:")
    print(message)

    print(
        "ML Probability:",
        f"{result['ml_probability'] * 100:.2f}%"
    )

    print(
        "Rule Score:",
        result["rule_score"]
    )

    print(
        "Final Risk Score:",
        result["risk_score"]
    )

    print(
        "Risk Level:",
        result["risk_level"]
    )

    print("ML Label:", result["ml_label"])

    print("Indicators:")

    if result["indicators"]:
        for indicator in result["indicators"]:
            print(
                f"  [{indicator['severity'].upper()}] "
                f"{indicator['message']}"
            )
    else:
        print("  None")

    print("-" * 60)