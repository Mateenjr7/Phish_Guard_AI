import joblib
import pandas as pd

from pathlib import Path

from feature_extractor import extract_features


# ==========================================
# PATHS
# ==========================================

PROJECT_ROOT = Path(__file__).resolve().parent.parent

MODEL_PATH = (
    PROJECT_ROOT
    / "models"
    / "url_phishing_model.joblib"
)


# ==========================================
# LOAD MODEL
# ==========================================

print("Loading model...")
print("Model:", MODEL_PATH)

model = joblib.load(MODEL_PATH)

print("Model loaded successfully.")
print("Expected features:", model.n_features_in_)

# ==========================================
# TEST URLS
# ==========================================

test_urls = [
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
]


# ==========================================
# ANALYZE EACH URL
# ==========================================

for url in test_urls:

    print("\n")
    print("=" * 70)
    print("URL:", url)
    print("=" * 70)

    # --------------------------------------
    # Extract features
    # --------------------------------------

    features = extract_features(url)

    X = pd.DataFrame([features])

    # --------------------------------------
    # Prediction
    # --------------------------------------

    prediction = model.predict(X)[0]

    probability = model.predict_proba(X)[0][1]

    verdict = (
        "PHISHING"
        if prediction == 1
        else "LEGITIMATE"
    )

    # --------------------------------------
    # Result
    # --------------------------------------

    print("\nPrediction:", verdict)
    print(f"Phishing probability: {probability:.6f}")
    print(f"Risk percentage: {probability * 100:.2f}%")

    # --------------------------------------
    # Feature values
    # --------------------------------------

    print("\nFeatures:")

    for feature_name, value in features.items():

        print(
            f"{feature_name:25} : {value}"
        )


# ==========================================
# FEATURE IMPORTANCE
# ==========================================

print("\n")
print("=" * 70)
print("TOP MODEL FEATURES")
print("=" * 70)

feature_importance = pd.Series(
    model.feature_importances_,
    index=model.feature_names_in_
).sort_values(ascending=False)

print(
    feature_importance.to_string()
)


# ==========================================
# COMPLETE
# ==========================================

print("\n")
print("=" * 70)
print("DIAGNOSTIC TEST COMPLETED")
print("=" * 70)