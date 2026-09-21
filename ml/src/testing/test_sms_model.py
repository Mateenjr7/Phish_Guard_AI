from pathlib import Path

from backend.sms_service import predict_sms


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
print("PhishGuard AI - SMS Model Test")
print("=" * 60)


for expected, message in test_messages:

    result = predict_sms(message)

    print("\nMessage:")
    print(message)

    print("Expected :", expected)
    print("Predicted :", result["label"])
    print(
        "Probability:",
        f"{result['phishing_probability']:.4f}"
    )

    print("-" * 60)