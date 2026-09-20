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
# TEST URLS
# ==========================================

test_urls = [
    "https://www.google.com",
    "https://github.com",
    "https://www.microsoft.com",
    "https://www.amazon.com",
    "https://secure-account-verify.xyz/login",
    "https://paypal-account-verification.xyz/login",
]


# ==========================================
# MODEL FEATURE IMPORTANCE
# ==========================================

feature_importance = pd.Series(
    model.feature_importances_,
    index=model.feature_names_in_
).sort_values(ascending=False)


print("\n========================================")
print("       GLOBAL MODEL FEATURE IMPORTANCE")
print("========================================")

for feature, importance in feature_importance.items():

    print(
        f"{feature:<25} "
        f"{importance:.6f}"
    )


# ==========================================
# URL FEATURE COMPARISON
# ==========================================

print("\n========================================")
print("          URL FEATURE ANALYSIS")
print("========================================")


for url in test_urls:

    features = extract_features(url)

    # V2 was trained without IsHTTPS
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


    print("\n----------------------------------------")

    print("URL:")
    print(url)

    print("\nPrediction:")
    print(verdict)

    print(
        f"Phishing probability: "
        f"{probability:.6f}"
    )

    print("\nFeatures:")

    for feature in model.feature_names_in_:

        value = features_for_model[feature]

        print(
            f"{feature:<25} {value}"
        )


# ==========================================
# COMPLETE
# ==========================================

print("\n========================================")
print("       FEATURE ANALYSIS COMPLETED")
print("========================================")