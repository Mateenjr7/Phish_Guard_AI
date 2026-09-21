from pathlib import Path

import joblib
import pandas as pd
from ml.src.features.feature_extractor_clean import extract_features


# =========================================================
# Paths
# =========================================================

BACKEND_DIR = Path(__file__).resolve().parent
PROJECT_ROOT = BACKEND_DIR.parent

ML_DIR = PROJECT_ROOT / "ml"
MODEL_PATH = ML_DIR / "models" / "url_phishing_model_clean_v3.joblib"
FEATURE_EXTRACTOR_DIR = ML_DIR / "src"


# Allow importing the shared feature extractor
sys.path.insert(0, str(FEATURE_EXTRACTOR_DIR))

from feature_extractor_clean import extract_features


# =========================================================
# V3 feature list
# =========================================================

FEATURES = [
    "URLLength",
    "DomainLength",
    "DomainDigitCount",
    "DomainDigitRatio",
    "DomainLetterRatio",
    "DomainSpecialCount",
    "DomainHyphenCount",
    "DomainDotCount",
    "DomainHasHyphen",
    "DomainEntropy",
    "SubdomainCount",
    "DigitCount",
    "DigitRatio",
    "LetterCount",
    "SpecialCharCount",
    "SpecialCharRatio",
    "DotCount",
    "HyphenCount",
    "UnderscoreCount",
    "SlashCount",
    "QuestionCount",
    "EqualCount",
    "AtCount",
    "AmpersandCount",
    "PercentCount",
    "URLEntropy",
    "PathDepth",
]


# =========================================================
# Load model once when backend starts
# =========================================================

if not MODEL_PATH.exists():
    raise FileNotFoundError(
        f"ML model not found: {MODEL_PATH}"
    )


model = joblib.load(MODEL_PATH)


if model.n_features_in_ != len(FEATURES):
    raise ValueError(
        f"Model expects {model.n_features_in_} features, "
        f"but V3 feature configuration contains {len(FEATURES)}."
    )


# =========================================================
# Prediction
# =========================================================

def predict_url(url: str) -> dict:
    """
    Generate the structural ML prediction for a URL.
    """

    features = extract_features(url)

    feature_row = {
        feature: features[feature]
        for feature in FEATURES
    }

    X = pd.DataFrame(
        [feature_row],
        columns=FEATURES,
    )

    probability = float(
        model.predict_proba(X)[0][1]
    )

    prediction = int(
        probability >= 0.5
    )

    return {
        "prediction": prediction,
        "phishing_probability": probability,
        "feature_count": len(FEATURES),
    }