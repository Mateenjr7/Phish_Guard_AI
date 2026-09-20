import joblib
import pandas as pd

from pathlib import Path

from feature_extractor import extract_features


# ==========================================
# PATH
# ==========================================

PROJECT_ROOT = Path(__file__).resolve().parent.parent

MODEL_PATH = (
    PROJECT_ROOT
    / "models"
    / "url_phishing_model_v2.joblib"
)


# ==========================================
# LOAD MODEL
# ==========================================

print("Loading V2 model...")

print("Model:", MODEL_PATH)

model = joblib.load(MODEL_PATH)

print("Model loaded successfully.")

print("Expected features:", model.n_features_in_)


# ==========================================
# TEST URLS
# ==========================================

test_urls = [

    # Major legitimate websites
    "https://www.google.com",
    "https://www.wikipedia.org",
    "https://github.com",
    "https://github.com/login",
    "https://www.microsoft.com",
    "https://www.amazon.com",
    "https://www.apple.com",
    "https://www.youtube.com",
    "https://www.linkedin.com",
    "https://www.facebook.com",

    # Suspicious URLs
    "http://192.168.1.1/login",
    "https://secure-account-verify.xyz/login",
    "https://paypal-account-verification.xyz/login",
    "http://google-login-security.example.com",
    "https://bit.ly/example",
]


# ==========================================
# TEST
# ==========================================

for url in test_urls:

    print("\n========================================")
    print("URL:", url)
    print("========================================")

    features = extract_features(url)

    # V2 was trained without IsHTTPS
    features_for_model = {
        key: value
        for key, value in features.items()
        if key != "IsHTTPS"
    }

    X = pd.DataFrame([features_for_model])

    prediction = int(
        model.predict(X)[0]
    )

    probability = float(
        model.predict_proba(X)[0][1]
    )

    if prediction == 1:
        verdict = "PHISHING"
    else:
        verdict = "LEGITIMATE"

    print("Prediction:", verdict)

    print(
        f"Phishing probability: {probability:.6f}"
    )

    print(
        f"Risk percentage: {probability * 100:.2f}%"
    )

    print("\nKey features:")

    print(
        "DomainLength:",
        features["DomainLength"]
    )

    print(
        "PathLength:",
        features["PathLength"]
    )

    print(
        "DigitCount:",
        features["DigitCount"]
    )

    print(
        "SubdomainCount:",
        features["SubdomainCount"]
    )

    print(
        "SuspiciousWordCount:",
        features["SuspiciousWordCount"]
    )

    print(
        "IsSuspiciousTLD:",
        features["IsSuspiciousTLD"]
    )

    print(
        "URLEntropy:",
        round(
            features["URLEntropy"],
            4
        )
    )


# ==========================================
# COMPLETE
# ==========================================

print("\n========================================")
print("V2 DIAGNOSTIC TEST COMPLETED")
print("========================================")