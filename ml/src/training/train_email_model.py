from pathlib import Path

import pandas as pd
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.linear_model import LogisticRegression
from sklearn.metrics import (
    accuracy_score,
    classification_report,
    confusion_matrix,
    precision_score,
    recall_score,
    f1_score,
    roc_auc_score,
)
from sklearn.model_selection import train_test_split
import joblib


# ============================================================
# PATHS
# ============================================================

PROJECT_ROOT = Path(__file__).resolve().parents[2]

DATA_PATH = PROJECT_ROOT / "ml" / "data" / "raw" / "email" / "CEAS_08.csv"

MODEL_DIR = PROJECT_ROOT / "ml" / "models" / "email"
MODEL_PATH = MODEL_DIR / "email_phishing_model.joblib"
VECTORIZER_PATH = MODEL_DIR / "email_tfidf_vectorizer.joblib"


# ============================================================
# CONFIGURATION
# ============================================================

RANDOM_STATE = 42
TEST_SIZE = 0.20


# ============================================================
# LOAD DATA
# ============================================================

print("=" * 70)
print("PHISHGUARD EMAIL PHISHING MODEL")
print("=" * 70)

print("\nLoading dataset...")
print(f"Dataset: {DATA_PATH}")

df = pd.read_csv(
    DATA_PATH,
    low_memory=False,
)

print(f"Raw dataset shape: {df.shape}")


# ============================================================
# VERIFY COLUMNS
# ============================================================

required_columns = [
    "subject",
    "body",
    "label",
]

missing_columns = [
    column
    for column in required_columns
    if column not in df.columns
]

if missing_columns:
    raise ValueError(
        f"Missing required columns: {missing_columns}"
    )

print("\nColumns found:")
for column in df.columns:
    print(f"  - {column}")


# ============================================================
# CLEAN DATA
# ============================================================

print("\nCleaning dataset...")

df = df[required_columns].copy()

# Convert text columns to strings.
df["subject"] = df["subject"].fillna("").astype(str)
df["body"] = df["body"].fillna("").astype(str)

# Convert labels to numeric.
df["label"] = pd.to_numeric(
    df["label"],
    errors="coerce",
)

# Remove rows with invalid labels.
df = df.dropna(subset=["label"])

df["label"] = df["label"].astype(int)

# Keep only binary labels.
df = df[df["label"].isin([0, 1])].copy()

# Remove completely empty emails.
df["text"] = (
    df["subject"].str.strip()
    + "\n"
    + df["body"].str.strip()
)

df = df[df["text"].str.strip().str.len() > 0].copy()


# ============================================================
# DUPLICATE ANALYSIS
# ============================================================

print("\nChecking duplicates...")

duplicate_count = df["text"].duplicated().sum()

print(f"Exact duplicate emails: {duplicate_count}")

if duplicate_count > 0:
    print("Removing exact duplicate emails...")
    df = df.drop_duplicates(
        subset=["text"]
    ).copy()


# ============================================================
# DATASET SUMMARY
# ============================================================

print("\nDataset after cleaning:")
print(f"Total emails: {len(df)}")

label_counts = df["label"].value_counts().sort_index()

print("\nClass distribution:")

for label, count in label_counts.items():
    label_name = (
        "Legitimate"
        if label == 0
        else "Spam/Phishing"
    )

    percentage = count / len(df) * 100

    print(
        f"  {label} = {label_name}: "
        f"{count} ({percentage:.2f}%)"
    )


# ============================================================
# TRAIN / TEST SPLIT
# ============================================================

print("\nCreating stratified train/test split...")

X = df["text"]
y = df["label"]

X_train, X_test, y_train, y_test = train_test_split(
    X,
    y,
    test_size=TEST_SIZE,
    random_state=RANDOM_STATE,
    stratify=y,
)

print(f"Training samples: {len(X_train)}")
print(f"Testing samples : {len(X_test)}")


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

print(
    f"Training TF-IDF shape: "
    f"{X_train_tfidf.shape}"
)

print(
    f"Testing TF-IDF shape : "
    f"{X_test_tfidf.shape}"
)

print(
    f"Vocabulary size: "
    f"{len(vectorizer.vocabulary_)}"
)


# ============================================================
# TRAIN MODEL
# ============================================================

print("\nTraining Logistic Regression model...")

model = LogisticRegression(
    max_iter=1000,
    class_weight="balanced",
    random_state=RANDOM_STATE,
)

model.fit(
    X_train_tfidf,
    y_train,
)

print("Training complete.")


# ============================================================
# PREDICTIONS
# ============================================================

print("\nGenerating predictions...")

y_pred = model.predict(X_test_tfidf)

y_probability = model.predict_proba(
    X_test_tfidf
)[:, 1]


# ============================================================
# METRICS
# ============================================================

accuracy = accuracy_score(
    y_test,
    y_pred,
)

precision = precision_score(
    y_test,
    y_pred,
    zero_division=0,
)

recall = recall_score(
    y_test,
    y_pred,
    zero_division=0,
)

f1 = f1_score(
    y_test,
    y_pred,
    zero_division=0,
)

roc_auc = roc_auc_score(
    y_test,
    y_probability,
)


# ============================================================
# RESULTS
# ============================================================

print("\n" + "=" * 70)
print("EMAIL MODEL RESULTS")
print("=" * 70)

print(f"\nAccuracy : {accuracy:.4f}")
print(f"Precision: {precision:.4f}")
print(f"Recall   : {recall:.4f}")
print(f"F1 Score : {f1:.4f}")
print(f"ROC-AUC  : {roc_auc:.4f}")

print("\nClassification Report:")
print(
    classification_report(
        y_test,
        y_pred,
        target_names=[
            "Legitimate",
            "Spam/Phishing",
        ],
        zero_division=0,
    )
)

print("Confusion Matrix:")
print(
    confusion_matrix(
        y_test,
        y_pred,
    )
)


# ============================================================
# SAVE MODEL
# ============================================================

print("\nSaving model artifacts...")

MODEL_DIR.mkdir(
    parents=True,
    exist_ok=True,
)

joblib.dump(
    model,
    MODEL_PATH,
)

joblib.dump(
    vectorizer,
    VECTORIZER_PATH,
)

print(f"\nModel saved:")
print(MODEL_PATH)

print("\nVectorizer saved:")
print(VECTORIZER_PATH)


# ============================================================
# COMPLETE
# ============================================================

print("\n" + "=" * 70)
print("EMAIL MODEL TRAINING COMPLETE")
print("=" * 70)