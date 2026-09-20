import pandas as pd
import joblib

from pathlib import Path

from sklearn.ensemble import RandomForestClassifier
from sklearn.model_selection import GroupShuffleSplit
from sklearn.metrics import (
    accuracy_score,
    precision_score,
    recall_score,
    f1_score,
    roc_auc_score,
    confusion_matrix,
    classification_report,
)


# ============================================================
# PATHS
# ============================================================

PROJECT_ROOT = Path(__file__).resolve().parent.parent

DATA_PATH = (
    PROJECT_ROOT
    / "data"
    / "processed"
    / "url_features.csv"
)

MODEL_PATH = (
    PROJECT_ROOT
    / "models"
    / "url_phishing_model_v3_grouped.joblib"
)


# ============================================================
# LOAD DATA
# ============================================================

print("Loading processed dataset...")

df = pd.read_csv(DATA_PATH)

print("Dataset shape:", df.shape)


# ============================================================
# FEATURES
# ============================================================

TARGET = "label"

# V2 intentionally removed IsHTTPS
FEATURES = [
    column
    for column in df.columns
    if column not in [TARGET, "IsHTTPS"]
]

X = df[FEATURES]
y = df[TARGET]


# ============================================================
# RECONSTRUCT DOMAIN GROUPS
# ============================================================

# We need the original URLs to perform a domain-aware split.
RAW_DATA_PATH = (
    PROJECT_ROOT
    / "data"
    / "raw"
    / "PhiUSIIL_Phishing_URL_Dataset.csv"
)

raw_df = pd.read_csv(RAW_DATA_PATH)

if len(raw_df) != len(df):
    raise ValueError(
        "Processed and raw datasets have different row counts."
    )


def extract_domain(url):
    url = str(url).strip().lower()

    url = url.replace("https://", "", 1)
    url = url.replace("http://", "", 1)

    return url.split("/")[0]


groups = raw_df["URL"].apply(extract_domain)


# ============================================================
# GROUPED TRAIN / TEST SPLIT
# ============================================================

print("\nCreating domain-aware train/test split...")

splitter = GroupShuffleSplit(
    n_splits=1,
    test_size=0.20,
    random_state=42,
)

train_idx, test_idx = next(
    splitter.split(X, y, groups=groups)
)

X_train = X.iloc[train_idx]
X_test = X.iloc[test_idx]

y_train = y.iloc[train_idx]
y_test = y.iloc[test_idx]


print("\nTraining samples:", len(X_train))
print("Testing samples:", len(X_test))

print(
    "Training domains:",
    groups.iloc[train_idx].nunique()
)

print(
    "Testing domains:",
    groups.iloc[test_idx].nunique()
)

print(
    "Overlap between train/test domains:",
    len(
        set(groups.iloc[train_idx])
        & set(groups.iloc[test_idx])
    )
)


# ============================================================
# MODEL
# ============================================================

print("\nTraining Random Forest...")

model = RandomForestClassifier(
    n_estimators=300,
    random_state=42,
    n_jobs=-1,
    class_weight="balanced",
)

model.fit(X_train, y_train)


# ============================================================
# PREDICTIONS
# ============================================================

y_pred = model.predict(X_test)

y_probability = model.predict_proba(X_test)[:, 1]


# ============================================================
# METRICS
# ============================================================

accuracy = accuracy_score(y_test, y_pred)

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

cm = confusion_matrix(
    y_test,
    y_pred,
)


# ============================================================
# RESULTS
# ============================================================

print("\n========================================")
print("       V3 GROUPED MODEL RESULTS")
print("========================================")

print(f"Accuracy : {accuracy:.4f}")
print(f"Precision: {precision:.4f}")
print(f"Recall   : {recall:.4f}")
print(f"F1 Score : {f1:.4f}")
print(f"ROC-AUC  : {roc_auc:.4f}")

print("\nConfusion Matrix:")
print(cm)

print("\nClassification Report:")
print(
    classification_report(
        y_test,
        y_pred,
        target_names=[
            "Legitimate",
            "Phishing",
        ],
        zero_division=0,
    )
)


# ============================================================
# FEATURE IMPORTANCE
# ============================================================

importance = pd.Series(
    model.feature_importances_,
    index=FEATURES,
).sort_values(
    ascending=False
)

print("\n========================================")
print("       TOP FEATURE IMPORTANCE")
print("========================================")

print(
    importance.head(20).to_string()
)


# ============================================================
# SAVE MODEL
# ============================================================

MODEL_PATH.parent.mkdir(
    parents=True,
    exist_ok=True,
)

joblib.dump(
    model,
    MODEL_PATH,
)

print("\nModel saved to:")
print(MODEL_PATH)

print("\n========================================")
print("       V3 TRAINING COMPLETED")
print("========================================")