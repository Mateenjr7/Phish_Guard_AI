import pandas as pd
import joblib

from sklearn.model_selection import GroupShuffleSplit
from sklearn.metrics import confusion_matrix
from urllib.parse import urlparse

DATA_PATH = "data/processed/url_features_clean.csv"
RAW_PATH = "data/raw/PhiUSIIL_Phishing_URL_Dataset.csv"
MODEL_PATH = "models/url_phishing_model_clean_v2.joblib"

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


print("=" * 70)
print("PHISHGUARD CLEAN V2 - ERROR ANALYSIS")
print("=" * 70)

# ---------------------------------------------------------
# Load data
# ---------------------------------------------------------

print("\nLoading processed dataset...")

df = pd.read_csv(DATA_PATH)
raw_df = pd.read_csv(RAW_PATH, usecols=["URL"])

if len(df) != len(raw_df):
    raise ValueError(
        f"Row mismatch: processed={len(df)}, raw={len(raw_df)}"
    )

df["URL"] = raw_df["URL"]

df["DomainGroup"] = df["URL"].apply(extract_domain)

X = df[FEATURES]
y = df["label"]
groups = df["DomainGroup"]

# ---------------------------------------------------------
# Recreate EXACT grouped split
# ---------------------------------------------------------

print("Recreating grouped train/test split...")

splitter = GroupShuffleSplit(
    n_splits=1,
    test_size=0.20,
    random_state=42,
)

train_idx, test_idx = next(
    splitter.split(X, y, groups=groups)
)

X_test = X.iloc[test_idx]
y_test = y.iloc[test_idx]

test_df = df.iloc[test_idx].copy()

# ---------------------------------------------------------
# Load model
# ---------------------------------------------------------

print("Loading Clean V2 model...")

model = joblib.load(MODEL_PATH)

print(f"Model loaded: {type(model).__name__}")

# ---------------------------------------------------------
# Predictions
# ---------------------------------------------------------

print("\nGenerating predictions...")

predictions = model.predict(X_test)
probabilities = model.predict_proba(X_test)[:, 1]

test_df["prediction"] = predictions
test_df["phishing_probability"] = probabilities

# ---------------------------------------------------------
# Error categories
# ---------------------------------------------------------

test_df["error_type"] = "correct"

test_df.loc[
    (test_df["label"] == 0) &
    (test_df["prediction"] == 1),
    "error_type"
] = "false_positive"

test_df.loc[
    (test_df["label"] == 1) &
    (test_df["prediction"] == 0),
    "error_type"
] = "false_negative"

# ---------------------------------------------------------
# Basic statistics
# ---------------------------------------------------------

fp = test_df[test_df["error_type"] == "false_positive"]
fn = test_df[test_df["error_type"] == "false_negative"]

print("\n" + "=" * 70)
print("ERROR SUMMARY")
print("=" * 70)

print(f"Test samples       : {len(test_df)}")
print(f"False positives    : {len(fp)}")
print(f"False negatives    : {len(fn)}")
print(f"Total errors       : {len(fp) + len(fn)}")

print("\nConfusion Matrix:")
print(confusion_matrix(y_test, predictions))

# ---------------------------------------------------------
# False positives
# ---------------------------------------------------------

print("\n" + "=" * 70)
print("TOP FALSE POSITIVES")
print("=" * 70)

fp_display = fp.sort_values(
    "phishing_probability",
    ascending=False
)

print(
    fp_display[
        [
            "URL",
            "DomainGroup",
            "label",
            "prediction",
            "phishing_probability",
        ]
    ].head(30).to_string(index=False)
)

# ---------------------------------------------------------
# False negatives
# ---------------------------------------------------------

print("\n" + "=" * 70)
print("TOP FALSE NEGATIVES")
print("=" * 70)

fn_display = fn.sort_values(
    "phishing_probability",
    ascending=True
)

print(
    fn_display[
        [
            "URL",
            "DomainGroup",
            "label",
            "prediction",
            "phishing_probability",
        ]
    ].head(30).to_string(index=False)
)

# ---------------------------------------------------------
# Most uncertain URLs
# ---------------------------------------------------------

test_df["uncertainty"] = abs(
    test_df["phishing_probability"] - 0.5
)

uncertain = test_df.sort_values(
    "uncertainty"
)

print("\n" + "=" * 70)
print("MOST UNCERTAIN PREDICTIONS")
print("=" * 70)

print(
    uncertain[
        [
            "URL",
            "label",
            "prediction",
            "phishing_probability",
            "uncertainty",
        ]
    ].head(30).to_string(index=False)
)

# ---------------------------------------------------------
# Save analysis files
# ---------------------------------------------------------

fp_path = "data/processed/clean_v2_false_positives.csv"
fn_path = "data/processed/clean_v2_false_negatives.csv"
uncertain_path = "data/processed/clean_v2_uncertain_urls.csv"

fp.to_csv(fp_path, index=False)
fn.to_csv(fn_path, index=False)
uncertain.to_csv(uncertain_path, index=False)

print("\n" + "=" * 70)
print("FILES SAVED")
print("=" * 70)

print(fp_path)
print(fn_path)
print(uncertain_path)

print("\n" + "=" * 70)
print("ERROR ANALYSIS COMPLETE")
print("=" * 70)