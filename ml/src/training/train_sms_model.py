from pathlib import Path

import joblib
import pandas as pd
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.linear_model import LogisticRegression
from sklearn.metrics import (
    accuracy_score,
    classification_report,
    confusion_matrix,
    f1_score,
    precision_score,
    recall_score,
)
from sklearn.model_selection import train_test_split


# ============================================================
# Paths
# ============================================================

PROJECT_ROOT = Path(__file__).resolve().parents[2]

DATA_PATH = (
    PROJECT_ROOT
    / "ml"
    / "data"
    / "raw"
    / "sms"
    / "SMSSpamCollection"
)

MODEL_DIR = PROJECT_ROOT / "ml" / "models" / "sms"
MODEL_DIR.mkdir(parents=True, exist_ok=True)

MODEL_PATH = MODEL_DIR / "sms_phishing_model.joblib"
VECTORIZER_PATH = MODEL_DIR / "sms_tfidf_vectorizer.joblib"


# ============================================================
# Load dataset
# ============================================================

print("=" * 60)
print("PhishGuard AI - SMS Phishing Model")
print("=" * 60)

print("\nLoading dataset...")

df = pd.read_csv(
    DATA_PATH,
    sep="\t",
    header=None,
    names=["label", "text"],
    encoding="utf-8",
)

print(f"Dataset shape: {df.shape}")

# Remove missing/empty messages
df = df.dropna(subset=["label", "text"]).copy()
df["text"] = df["text"].astype(str).str.strip()

df = df[df["text"].str.len() > 0].copy()

# Convert:
# ham  -> 0 legitimate
# spam -> 1 phishing/spam
df["target"] = df["label"].map({
    "ham": 0,
    "spam": 1,
})

df = df.dropna(subset=["target"]).copy()
df["target"] = df["target"].astype(int)

print("\nClass distribution:")
print(df["label"].value_counts())

print("\nProject labels:")
print("0 = legitimate")
print("1 = phishing/spam")


# ============================================================
# Train/test split
# ============================================================

X = df["text"]
y = df["target"]

X_train, X_test, y_train, y_test = train_test_split(
    X,
    y,
    test_size=0.20,
    random_state=42,
    stratify=y,
)

print("\nTrain samples:", len(X_train))
print("Test samples:", len(X_test))


# ============================================================
# TF-IDF
# ============================================================

print("\nBuilding TF-IDF features...")

vectorizer = TfidfVectorizer(
    lowercase=True,
    strip_accents="unicode",
    ngram_range=(1, 2),
    min_df=2,
    max_df=0.98,
    sublinear_tf=True,
    max_features=50000,
)

X_train_tfidf = vectorizer.fit_transform(X_train)
X_test_tfidf = vectorizer.transform(X_test)

print("TF-IDF train shape:", X_train_tfidf.shape)
print("TF-IDF test shape:", X_test_tfidf.shape)


# ============================================================
# Logistic Regression
# ============================================================

print("\nTraining Logistic Regression...")

model = LogisticRegression(
    max_iter=1000,
    class_weight="balanced",
    random_state=42,
)

model.fit(X_train_tfidf, y_train)


# ============================================================
# Evaluation
# ============================================================

print("\nEvaluating model...")

y_pred = model.predict(X_test_tfidf)

accuracy = accuracy_score(y_test, y_pred)
precision = precision_score(y_test, y_pred)
recall = recall_score(y_test, y_pred)
f1 = f1_score(y_test, y_pred)

print("\n" + "=" * 60)
print("SMS MODEL RESULTS")
print("=" * 60)

print(f"Accuracy : {accuracy:.4f}")
print(f"Precision: {precision:.4f}")
print(f"Recall   : {recall:.4f}")
print(f"F1 Score : {f1:.4f}")

print("\nConfusion Matrix:")
print(confusion_matrix(y_test, y_pred))

print("\nClassification Report:")
print(
    classification_report(
        y_test,
        y_pred,
        target_names=["legitimate", "phishing/spam"],
    )
)


# ============================================================
# Save model
# ============================================================

joblib.dump(model, MODEL_PATH)
joblib.dump(vectorizer, VECTORIZER_PATH)

print("\n" + "=" * 60)
print("MODEL SAVED")
print("=" * 60)

print(f"Model     : {MODEL_PATH}")
print(f"Vectorizer: {VECTORIZER_PATH}")