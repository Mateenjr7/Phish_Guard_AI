from pathlib import Path

import joblib


PROJECT_ROOT = Path(__file__).resolve().parents[1]

MODEL_PATH = (
    PROJECT_ROOT
    / "ml"
    / "models"
    / "email"
    / "email_phishing_model.joblib"
)

VECTORIZER_PATH = (
    PROJECT_ROOT
    / "ml"
    / "models"
    / "email"
    / "email_tfidf_vectorizer.joblib"
)


model = joblib.load(MODEL_PATH)
vectorizer = joblib.load(VECTORIZER_PATH)


def predict_email(subject: str, body: str) -> dict:
    subject = (subject or "").strip()
    body = (body or "").strip()

    text = f"{subject}\n{body}".strip()

    if not text:
        raise ValueError("Email subject or body cannot be empty.")

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