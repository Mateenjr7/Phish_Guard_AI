from pathlib import Path

import joblib
import pandas as pd

from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import (
    accuracy_score,
    classification_report,
    confusion_matrix,
    f1_score,
    precision_score,
    recall_score,
    roc_auc_score,
)
from sklearn.model_selection import GroupShuffleSplit


# =========================================================
# Paths
# =========================================================

ROOT = Path(__file__).resolve().parents[1]

FEATURES_PATH = ROOT / "data" / "processed" / "url_features_clean.csv"
RAW_PATH = ROOT / "data" / "raw" / "PhiUSIIL_Phishing_URL_Dataset.csv"
MODEL_PATH = ROOT / "models" / "url_phishing_model_clean_v3.joblib"


# =========================================================
# Load data
# =========================================================

print("=" * 80)
print("PHISHGUARD - CLEAN V3 URL MODEL")
print("=" * 80)

print("\nLoading processed features...")

df = pd.read_csv(FEATURES_PATH)

print(f"Dataset shape: {df.shape}")


# =========================================================
# V3 feature selection
#
# We deliberately remove path/query complexity features
# that showed strong dataset-specific behavior during
# external testing.
# =========================================================

FEATURES = [
    # URL-level structure
    "URLLength",

    # Domain structure
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

    # Global character statistics
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

    # URL entropy only
    "URLEntropy",

    # Basic path depth only
    "PathDepth",
]


print(f"\nV3 feature count: {len(FEATURES)}")

print("\nFeatures:")
for i, feature in enumerate(FEATURES, start=1):
    print(f"{i:02d}. {feature}")


# =========================================================
# Verify features
# =========================================================

missing = [feature for feature in FEATURES if feature not in df.columns]

if missing:
    raise ValueError(
        f"Missing features from dataset: {missing}"
    )


X = df[FEATURES]
y = df["label"]


print("\nLabel distribution:")
print(y.value_counts().sort_index())

print("\nLabel convention:")
print("0 = legitimate")
print("1 = phishing")


# =========================================================
# Load raw URLs for domain grouping
# =========================================================

print("\nLoading raw URLs for grouped splitting...")

raw_df = pd.read_csv(RAW_PATH)

URL_COLUMN = "URL"

if URL_COLUMN not in raw_df.columns:
    raise ValueError(
        f"Could not find '{URL_COLUMN}' column. "
        f"Available columns: {list(raw_df.columns)}"
    )


# Make sure row counts match
if len(raw_df) != len(df):
    raise ValueError(
        f"Row mismatch: processed={len(df)}, raw={len(raw_df)}"
    )


# =========================================================
# Extract domain groups
# =========================================================

from urllib.parse import urlparse


def get_domain(url):
    try:
        url = str(url).strip()

        if not url.startswith(("http://", "https://")):
            url = "http://" + url

        parsed = urlparse(url)

        domain = parsed.netloc.lower()

        # Remove credentials if present
        if "@" in domain:
            domain = domain.split("@")[-1]

        # Remove port
        domain = domain.split(":")[0]

        return domain

    except Exception:
        return ""


groups = raw_df[URL_COLUMN].apply(get_domain)

valid_groups = groups != ""

print(f"Rows with valid domains: {valid_groups.sum()}")
print(f"Unique domains: {groups.nunique()}")


# =========================================================
# Grouped train/test split
# =========================================================

print("\nCreating grouped train/test split...")

splitter = GroupShuffleSplit(
    n_splits=1,
    test_size=0.20,
    random_state=42,
)

train_idx, test_idx = next(
    splitter.split(
        X,
        y,
        groups=groups,
    )
)

X_train = X.iloc[train_idx]
X_test = X.iloc[test_idx]

y_train = y.iloc[train_idx]
y_test = y.iloc[test_idx]

train_domains = set(groups.iloc[train_idx])
test_domains = set(groups.iloc[test_idx])

overlap = train_domains.intersection(test_domains)


print(f"\nTraining rows: {len(X_train)}")
print(f"Testing rows:  {len(X_test)}")

print(f"Training domains: {len(train_domains)}")
print(f"Testing domains:  {len(test_domains)}")

print(f"Domain overlap: {len(overlap)}")


if len(overlap) != 0:
    raise ValueError(
        "Domain leakage detected! "
        f"{len(overlap)} domains appear in both splits."
    )


# =========================================================
# Train model
# =========================================================

print("\nTraining Random Forest...")

model = RandomForestClassifier(
    n_estimators=500,
    random_state=42,
    n_jobs=-1,
    class_weight="balanced",
    max_features="sqrt",
)

model.fit(X_train, y_train)


# =========================================================
# Evaluation
# =========================================================

print("\nEvaluating model...")

y_pred = model.predict(X_test)
y_probability = model.predict_proba(X_test)[:, 1]


accuracy = accuracy_score(y_test, y_pred)
precision = precision_score(y_test, y_pred)
recall = recall_score(y_test, y_pred)
f1 = f1_score(y_test, y_pred)
roc_auc = roc_auc_score(y_test, y_probability)

cm = confusion_matrix(y_test, y_pred)


print("\n" + "=" * 80)
print("CLEAN V3 RESULTS")
print("=" * 80)

print(f"\nAccuracy : {accuracy:.4f}")
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
    )
)


# =========================================================
# Feature importance
# =========================================================

importance = pd.DataFrame(
    {
        "feature": FEATURES,
        "importance": model.feature_importances_,
    }
).sort_values(
    "importance",
    ascending=False,
)


print("\n" + "=" * 80)
print("TOP FEATURE IMPORTANCES")
print("=" * 80)

print(
    importance.head(20).to_string(index=False)
)


# =========================================================
# Save model
# =========================================================

MODEL_PATH.parent.mkdir(
    parents=True,
    exist_ok=True,
)

joblib.dump(
    model,
    MODEL_PATH,
)

print("\n" + "=" * 80)
print("MODEL SAVED")
print("=" * 80)

print(MODEL_PATH)
print(f"\nModel expects {model.n_features_in_} features.")

print("\nClean V3 training complete.")