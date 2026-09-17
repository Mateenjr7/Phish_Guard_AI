import pandas as pd
import joblib


# ============================================================
# Step 21: Load trained model
# ============================================================

MODEL_PATH = "../models/url_phishing_model.joblib"
DATA_PATH = "../data/processed/phiusiil_processed.csv"


print("Loading trained model...")

model = joblib.load(MODEL_PATH)

print("Model loaded successfully.")


# ============================================================
# Load processed dataset
# ============================================================

df = pd.read_csv(DATA_PATH)


# ============================================================
# Prepare features
# ============================================================

X = df.drop(columns=["label"])

X = X.select_dtypes(
    include=["int64", "float64"]
)


# ============================================================
# Test one sample
# ============================================================

sample = X.iloc[[0]]

prediction = model.predict(sample)[0]

probability = model.predict_proba(sample)[0][1]


# ============================================================
# Display result
# ============================================================

print("\n==============================")
print("       PREDICTION RESULT")
print("==============================")

print("Prediction:", prediction)

print(
    f"Phishing probability: "
    f"{probability * 100:.2f}%"
)


if prediction == 1:
    print("Verdict: PHISHING")
else:
    print("Verdict: LEGITIMATE")