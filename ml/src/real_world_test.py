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

model = joblib.load(MODEL_PATH)

print("Model loaded successfully.")
print("Expected features:", model.n_features_in_)


# ==========================================
# TEST CASES
# ==========================================

test_cases = [

    # --------------------------------------
    # LEGITIMATE WEBSITES
    # --------------------------------------

    (
        "LEGITIMATE",
        "https://www.google.com"
    ),

    (
        "LEGITIMATE",
        "https://github.com"
    ),

    (
        "LEGITIMATE",
        "https://www.microsoft.com"
    ),

    (
        "LEGITIMATE",
        "https://www.amazon.com"
    ),

    (
        "LEGITIMATE",
        "https://www.apple.com"
    ),

    (
        "LEGITIMATE",
        "https://www.youtube.com"
    ),

    (
        "LEGITIMATE",
        "https://www.linkedin.com"
    ),

    (
        "LEGITIMATE",
        "https://www.facebook.com"
    ),

    (
        "LEGITIMATE",
        "https://www.reddit.com"
    ),

    (
        "LEGITIMATE",
        "https://www.openai.com"
    ),


    # --------------------------------------
    # SUSPICIOUS URL STRUCTURES
    # --------------------------------------

    (
        "SUSPICIOUS",
        "http://192.168.1.1/login"
    ),

    (
        "SUSPICIOUS",
        "https://secure-account-verify.xyz/login"
    ),

    (
        "SUSPICIOUS",
        "https://paypal-account-verification.xyz/login"
    ),

    (
        "SUSPICIOUS",
        "http://google-login-security.example.com"
    ),

    (
        "SUSPICIOUS",
        "https://bit.ly/example"
    ),

    (
        "SUSPICIOUS",
        "https://account-verify-login.top/security"
    ),

    (
        "SUSPICIOUS",
        "https://secure-payment-confirmation.click/login"
    ),

    (
        "SUSPICIOUS",
        "http://login.verify-account.example.com"
    ),

    (
        "SUSPICIOUS",
        "https://user-login-password-security.xyz"
    ),

    (
        "SUSPICIOUS",
        "https://192.168.0.10/secure/login"
    ),
]


# ==========================================
# RESULTS
# ==========================================

results = []


for category, url in test_cases:

    features = extract_features(url)

    # V2 excludes IsHTTPS
    features_for_model = {
        key: value
        for key, value in features.items()
        if key != "IsHTTPS"
    }

    X = pd.DataFrame([
        features_for_model
    ])

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

    results.append({
        "Category": category,
        "URL": url,
        "Prediction": verdict,
        "Probability": probability
    })


# ==========================================
# DISPLAY RESULTS
# ==========================================

print("\n========================================")
print("        REAL-WORLD SANITY TEST")
print("========================================")

for result in results:

    print("\n----------------------------------------")

    print(
        "Expected category:",
        result["Category"]
    )

    print(
        "URL:",
        result["URL"]
    )

    print(
        "Prediction:",
        result["Prediction"]
    )

    print(
        f"Phishing probability: "
        f"{result['Probability']:.4f}"
    )


# ==========================================
# SUMMARY
# ==========================================

print("\n========================================")
print("              SUMMARY")
print("========================================")

legitimate_results = [
    r for r in results
    if r["Category"] == "LEGITIMATE"
]

suspicious_results = [
    r for r in results
    if r["Category"] == "SUSPICIOUS"
]


legitimate_correct = sum(
    r["Prediction"] == "LEGITIMATE"
    for r in legitimate_results
)

suspicious_correct = sum(
    r["Prediction"] == "PHISHING"
    for r in suspicious_results
)


print(
    f"Legitimate correctly classified: "
    f"{legitimate_correct}/"
    f"{len(legitimate_results)}"
)

print(
    f"Suspicious correctly classified: "
    f"{suspicious_correct}/"
    f"{len(suspicious_results)}"
)


# ==========================================
# COMPLETE
# ==========================================

print("\n========================================")
print("REAL-WORLD TEST COMPLETED")
print("========================================")