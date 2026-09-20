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
print("Model path:", MODEL_PATH)

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
    "http://192.168.1.1/login",
    "https://secure-account-verify.xyz/login",
    "https://bit.ly/example"
]


# ==========================================
# PREDICT
# ==========================================

for url in test_urls:

    print("\n========================================")
    print("URL:", url)
    print("========================================")

    # --------------------------------------
    # Extract URL features
    # --------------------------------------

    features = extract_features(url)

    # --------------------------------------
    # Convert features to DataFrame
    # --------------------------------------

    X = pd.DataFrame([features])

    # --------------------------------------
    # Prediction
    # --------------------------------------

    prediction = model.predict(X)[0]

    # --------------------------------------
    # Phishing probability
    # --------------------------------------

    probability = model.predict_proba(X)[0][1]

    # --------------------------------------
    # Verdict
    # --------------------------------------

    if prediction == 1:
        verdict = "PHISHING"
    else:
        verdict = "LEGITIMATE"

    # --------------------------------------
    # Display results
    # --------------------------------------

    print("Prediction:", verdict)
    print(f"Phishing probability: {probability:.4f}")
    print(f"Risk percentage: {probability * 100:.2f}%")


# ==========================================
# COMPLETE
# ==========================================

print("\n========================================")
print("URL TESTING COMPLETED")
print("========================================")