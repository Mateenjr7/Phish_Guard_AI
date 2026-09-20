from pathlib import Path

import joblib


# ============================================================
# Paths
# ============================================================

PROJECT_ROOT = Path(__file__).resolve().parents[1]

MODEL_PATH = (
    PROJECT_ROOT
    / "ml"
    / "models"
    / "sms"
    / "sms_phishing_model.joblib"
)

VECTORIZER_PATH = (
    PROJECT_ROOT
    / "ml"
    / "models"
    / "sms"
    / "sms_tfidf_vectorizer.joblib"
)


# ============================================================
# Load model once
# ============================================================

model = joblib.load(MODEL_PATH)
vectorizer = joblib.load(VECTORIZER_PATH)


# ============================================================
# SMS prediction
# ============================================================

def predict_sms(text: str) -> dict:
    """
    Predict whether an SMS is legitimate or phishing/spam.
    """

    text = text.strip()

    if not text:
        raise ValueError("SMS text cannot be empty.")

    features = vectorizer.transform([text])

    probability = float(
        model.predict_proba(features)[0][1]
    )

    prediction = int(
        model.predict(features)[0]
    )

    return {
        "prediction": prediction,
        "phishing_probability": probability,
        "label": (
            "phishing/spam"
            if prediction == 1
            else "legitimate"
        ),
    }