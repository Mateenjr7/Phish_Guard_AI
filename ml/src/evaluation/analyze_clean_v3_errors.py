from pathlib import Path
from urllib.parse import urlparse

import joblib
import pandas as pd
from sklearn.model_selection import GroupShuffleSplit


ROOT = Path(__file__).resolve().parents[1]

FEATURES_PATH = ROOT / "data" / "processed" / "url_features_clean.csv"
RAW_PATH = ROOT / "data" / "raw" / "PhiUSIIL_Phishing_URL_Dataset.csv"
MODEL_PATH = ROOT / "models" / "url_phishing_model_clean_v3.joblib"
OUTPUT_DIR = ROOT / "data" / "processed"


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


def get_domain(url):
    url = str(url).strip()

    if not url.startswith(("http://", "https://")):
        url = "http://" + url

    parsed = urlparse(url)

    domain = parsed.netloc.lower()

    if "@" in domain:
        domain = domain.split("@")[-1]

    domain = domain.split(":")[0]

    return domain


print("=" * 80)
print("PHISHGUARD - CLEAN V3 ERROR ANALYSIS")
print("=" * 80)


# ---------------------------------------------------------
# Load data
# ---------------------------------------------------------

df = pd.read_csv(FEATURES_PATH)
raw_df = pd.read_csv(RAW_PATH)

X = df[FEATURES]
y = df["label"]

groups = raw_df["URL"].apply(get_domain)


# ---------------------------------------------------------
# Recreate EXACT V3 grouped split
# ---------------------------------------------------------

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

X_test = X.iloc[test_idx]
y_test = y.iloc[test_idx]

urls_test = raw_df["URL"].iloc[test_idx].reset_index(drop=True)
y_test = y_test.reset_index(drop=True)


# ---------------------------------------------------------
# Load model
# ---------------------------------------------------------

print("\nLoading Clean V3 model...")

model = joblib.load(MODEL_PATH)

print(f"Model features: {model.n_features_in_}")


# ---------------------------------------------------------
# Predict
# ---------------------------------------------------------

probabilities = model.predict_proba(X_test)[:, 1]
predictions = (probabilities >= 0.5).astype(int)


results = pd.DataFrame({
    "url": urls_test,
    "true_label": y_test,
    "predicted_label": predictions,
    "phishing_probability": probabilities,
})


# ---------------------------------------------------------
# False positives
# ---------------------------------------------------------

false_positives = results[
    (results["true_label"] == 0) &
    (results["predicted_label"] == 1)
].sort_values(
    "phishing_probability",
    ascending=False,
)


# ---------------------------------------------------------
# False negatives
# ---------------------------------------------------------

false_negatives = results[
    (results["true_label"] == 1) &
    (results["predicted_label"] == 0)
].sort_values(
    "phishing_probability",
    ascending=True,
)


# ---------------------------------------------------------
# Uncertain predictions
# ---------------------------------------------------------

uncertain = results[
    (results["phishing_probability"] >= 0.45) &
    (results["phishing_probability"] <= 0.55)
].sort_values(
    "phishing_probability"
)


# ---------------------------------------------------------
# Save
# ---------------------------------------------------------

OUTPUT_DIR.mkdir(
    parents=True,
    exist_ok=True,
)

fp_path = OUTPUT_DIR / "clean_v3_false_positives.csv"
fn_path = OUTPUT_DIR / "clean_v3_false_negatives.csv"
uncertain_path = OUTPUT_DIR / "clean_v3_uncertain_urls.csv"

false_positives.to_csv(
    fp_path,
    index=False,
)

false_negatives.to_csv(
    fn_path,
    index=False,
)

uncertain.to_csv(
    uncertain_path,
    index=False,
)


# ---------------------------------------------------------
# Print summary
# ---------------------------------------------------------

print("\n" + "=" * 80)
print("SUMMARY")
print("=" * 80)

print(f"\nTest samples: {len(results)}")

print(f"False positives: {len(false_positives)}")
print(f"False negatives: {len(false_negatives)}")
print(f"Total errors: {len(false_positives) + len(false_negatives)}")
print(f"Uncertain predictions: {len(uncertain)}")


# ---------------------------------------------------------
# Print false positives
# ---------------------------------------------------------

print("\n" + "=" * 80)
print("TOP FALSE POSITIVES")
print("=" * 80)

if len(false_positives) > 0:
    print(
        false_positives.head(25).to_string(index=False)
    )
else:
    print("No false positives.")


# ---------------------------------------------------------
# Print false negatives
# ---------------------------------------------------------

print("\n" + "=" * 80)
print("TOP FALSE NEGATIVES")
print("=" * 80)

if len(false_negatives) > 0:
    print(
        false_negatives.head(25).to_string(index=False)
    )
else:
    print("No false negatives.")


# ---------------------------------------------------------
# Print uncertain
# ---------------------------------------------------------

print("\n" + "=" * 80)
print("UNCERTAIN PREDICTIONS")
print("=" * 80)

if len(uncertain) > 0:
    print(
        uncertain.head(30).to_string(index=False)
    )
else:
    print("No uncertain predictions.")


# ---------------------------------------------------------
# Output files
# ---------------------------------------------------------

print("\n" + "=" * 80)
print("FILES SAVED")
print("=" * 80)

print(fp_path)
print(fn_path)
print(uncertain_path)

print("\nClean V3 error analysis complete.")