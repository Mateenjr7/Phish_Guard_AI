import pandas as pd
import joblib

from sklearn.ensemble import RandomForestClassifier
from sklearn.model_selection import GroupShuffleSplit
from sklearn.metrics import (
    accuracy_score,
    precision_score,
    recall_score,
    f1_score,
    roc_auc_score,
    confusion_matrix,
)

DATA_PATH = "data/processed/url_features_clean.csv"
MODEL_PATH = "models/url_phishing_model_clean_v2.joblib"

# Features deliberately selected to avoid strong
# PhiUSIIL-specific phishing shortcuts.
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
    "PathEntropy",
    "QueryEntropy",

    "PathDepth",
    "PathDigitCount",
    "PathSpecialCount",
    "QueryParameterCount",
    "QueryDigitCount",
    "DoubleSlashCount",
]

print("=" * 70)
print("PHISHGUARD URL MODEL - CLEAN V2")
print("=" * 70)

print("\nLoading dataset...")
df = pd.read_csv(DATA_PATH)

print(f"Dataset shape: {df.shape}")

# ---------------------------------------------------------
# Reconstruct domain groups from the original URL dataset
# ---------------------------------------------------------

raw_path = "data/raw/PhiUSIIL_Phishing_URL_Dataset.csv"

raw_df = pd.read_csv(raw_path, usecols=["URL"])

if len(raw_df) != len(df):
    raise ValueError(
        f"Row mismatch: processed={len(df)}, raw={len(raw_df)}"
    )

df["URL"] = raw_df["URL"]

from urllib.parse import urlparse


def extract_domain(url):
    try:
        if not isinstance(url, str):
            return ""

        if "://" not in url:
            url = "http://" + url

        parsed = urlparse(url)

        return parsed.netloc.lower().split("@")[-1].split(":")[0]

    except Exception:
        return ""


print("\nExtracting domain groups...")

df["DomainGroup"] = df["URL"].apply(extract_domain)

invalid_domains = (df["DomainGroup"] == "").sum()

if invalid_domains > 0:
    print(f"Warning: {invalid_domains} rows have empty domains.")

# ---------------------------------------------------------
# Validate feature columns
# ---------------------------------------------------------

missing_features = [
    feature for feature in FEATURES
    if feature not in df.columns
]

if missing_features:
    raise ValueError(
        f"Missing feature columns: {missing_features}"
    )

X = df[FEATURES]
y = df["label"]
groups = df["DomainGroup"]

print(f"\nUsing {len(FEATURES)} features.")

print("\nLabel distribution:")
print(y.value_counts().sort_index())

# ---------------------------------------------------------
# Grouped train/test split
# ---------------------------------------------------------

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

train_domains = set(groups.iloc[train_idx])
test_domains = set(groups.iloc[test_idx])

overlap = train_domains.intersection(test_domains)

print("\n" + "=" * 70)
print("GROUPED SPLIT")
print("=" * 70)

print(f"Training rows: {len(X_train)}")
print(f"Testing rows:  {len(X_test)}")

print(f"Training domains: {len(train_domains)}")
print(f"Testing domains:  {len(test_domains)}")

print(f"Domain overlap: {len(overlap)}")

if overlap:
    raise ValueError(
        "Domain leakage detected!"
    )

# ---------------------------------------------------------
# Train model
# ---------------------------------------------------------

print("\nTraining Random Forest...")

model = RandomForestClassifier(
    n_estimators=400,
    random_state=42,
    n_jobs=-1,
    class_weight="balanced",
    max_features="sqrt",
)

model.fit(X_train, y_train)

print("Training complete.")

# ---------------------------------------------------------
# Evaluation
# ---------------------------------------------------------

predictions = model.predict(X_test)
probabilities = model.predict_proba(X_test)[:, 1]

accuracy = accuracy_score(y_test, predictions)
precision = precision_score(y_test, predictions)
recall = recall_score(y_test, predictions)
f1 = f1_score(y_test, predictions)
roc_auc = roc_auc_score(y_test, probabilities)

cm = confusion_matrix(y_test, predictions)

print("\n" + "=" * 70)
print("MODEL PERFORMANCE")
print("=" * 70)

print(f"Accuracy : {accuracy:.4f}")
print(f"Precision: {precision:.4f}")
print(f"Recall   : {recall:.4f}")
print(f"F1 Score : {f1:.4f}")
print(f"ROC-AUC  : {roc_auc:.4f}")

print("\nConfusion Matrix:")
print(cm)

# ---------------------------------------------------------
# Feature importance
# ---------------------------------------------------------

importance = pd.DataFrame({
    "feature": FEATURES,
    "importance": model.feature_importances_,
})

importance = importance.sort_values(
    "importance",
    ascending=False,
)

print("\n" + "=" * 70)
print("TOP FEATURE IMPORTANCE")
print("=" * 70)

print(
    importance.head(20).to_string(index=False)
)

# ---------------------------------------------------------
# Save model
# ---------------------------------------------------------

joblib.dump(model, MODEL_PATH)

print("\n" + "=" * 70)
print("MODEL SAVED")
print("=" * 70)

print(MODEL_PATH)
print(f"Features: {len(FEATURES)}")
print(f"Model: {type(model).__name__}")
print("=" * 70)