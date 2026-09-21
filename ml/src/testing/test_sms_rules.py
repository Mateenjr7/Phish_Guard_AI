from pathlib import Path

from backend.sms_risk_engine import analyze_sms_rules


test_messages = [
    (
        "legitimate",
        "Hey, are we still meeting for lunch today?"
    ),
    (
        "legitimate",
        "Your appointment is confirmed for tomorrow at 10 AM."
    ),
    (
        "phishing",
        "URGENT! Your bank account has been suspended. "
        "Verify immediately by clicking this link."
    ),
    (
        "phishing",
        "Congratulations! You have won a prize. "
        "Call now to claim your reward."
    ),
    (
        "phishing",
        "Your account will be closed. "
        "Click here immediately to verify your details."
    ),
]


print("=" * 60)
print("PhishGuard AI - SMS Rule Engine Test")
print("=" * 60)


for expected, message in test_messages:

    result = analyze_sms_rules(message)

    print("\nMessage:")
    print(message)

    print("Expected:", expected)
    print("Rule Score:", result["rule_score"])

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