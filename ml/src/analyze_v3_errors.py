import pandas as pd
import joblib

from pathlib import Path
from sklearn.model_selection import GroupShuffleSplit


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

RAW_DATA_PATH = (
    PROJECT_ROOT
    / "data"
    / "raw"
    / "PhiUSIIL_Phishing_URL_Dataset.csv"
)

MODEL_PATH = (
    PROJECT_ROOT
    / "models"
    / "url_phishing_model_v3_grouped.joblib"
)


# ============================================================
# LOAD DATA
# ============================================================

print("Loading data...")

df = pd.read_csv(DATA_PATH)
raw_df = pd.read_csv(RAW_DATA_PATH)

model = joblib.load(MODEL_PATH)

print("Processed dataset:", df.shape)
print("Raw dataset:", raw_df.shape)


# ============================================================
# FEATURES
# ============================================================

TARGET = "label"

FEATURES = [
    column
    for column in df.columns
    if column not in [TARGET, "IsHTTPS"]
]

X = df[FEATURES]
y = df[TARGET]


# ============================================================
# DOMAIN EXTRACTION
# ============================================================

def extract_domain(url):
    url = str(url).strip().lower()

    url = url.replace("https://", "", 1)
    url = url.replace("http://", "", 1)

    return url.split("/")[0]


groups = raw_df["URL"].apply(extract_domain)


# ============================================================
# RECREATE EXACT V3 SPLIT
# ============================================================

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

raw_test = raw_df.iloc[test_idx].copy()

raw_test["true_label"] = y_test.values


# ============================================================
# PREDICTIONS
# ============================================================

predictions = model.predict(X_test)

probabilities = model.predict_proba(X_test)[:, 1]

raw_test["prediction"] = predictions
raw_test["phishing_probability"] = probabilities


# ============================================================
# FALSE POSITIVES
# ============================================================

false_positives = raw_test[
    (raw_test["true_label"] == 0)
    & (raw_test["prediction"] == 1)
].copy()


# ============================================================
# FALSE NEGATIVES
# ============================================================

false_negatives = raw_test[
    (raw_test["true_label"] == 1)
    & (raw_test["prediction"] == 0)
].copy()


# ============================================================
# RESULTS
# ============================================================

print("\n========================================")
print("       V3 ERROR ANALYSIS")
print("========================================")

print("\nFalse Positives:", len(false_positives))
print("False Negatives:", len(false_negatives))


# ============================================================
# FALSE POSITIVES
# ============================================================

print("\n========================================")
print("       FALSE POSITIVES")
print("========================================")

if len(false_positives) > 0:

    print(
        false_positives[
            [
                "URL",
                "true_label",
                "prediction",
                "phishing_probability",
            ]
        ]
        .sort_values(
            "phishing_probability",
            ascending=False,
        )
        .head(50)
        .to_string(index=False)
    )

else:
    print("No false positives found.")


# ============================================================
# FALSE NEGATIVES
# ============================================================

print("\n========================================")
print("       FALSE NEGATIVES")
print("========================================")

if len(false_negatives) > 0:

    print(
        false_negatives[
            [
                "URL",
                "true_label",
                "prediction",
                "phishing_probability",
            ]
        ]
        .sort_values(
            "phishing_probability",
            ascending=True,
        )
        .head(50)
        .to_string(index=False)
    )

else:
    print("No false negatives found.")


# ============================================================
# MOST UNCERTAIN PREDICTIONS
# ============================================================

raw_test["confidence_distance"] = (
    abs(
        raw_test["phishing_probability"] - 0.5
    )
)

uncertain = raw_test.sort_values(
    "confidence_distance"
).head(30)


print("\n========================================")
print("       MOST UNCERTAIN URLS")
print("========================================")

print(
    uncertain[
        [
            "URL",
            "true_label",
            "prediction",
            "phishing_probability",
        ]
    ].to_string(index=False)
)


# ============================================================
# SAVE ERROR REPORT
# ============================================================

ERROR_DIR = PROJECT_ROOT / "data" / "processed"
ERROR_DIR.mkdir(
    parents=True,
    exist_ok=True,
)

false_positives.to_csv(
    ERROR_DIR / "v3_false_positives.csv",
    index=False,
)

false_negatives.to_csv(
    ERROR_DIR / "v3_false_negatives.csv",
    index=False,
)

uncertain.to_csv(
    ERROR_DIR / "v3_uncertain_urls.csv",
    index=False,
)

print("\n========================================")
print("       REPORTS SAVED")
print("========================================")

print(
    ERROR_DIR / "v3_false_positives.csv"
)

print(
    ERROR_DIR / "v3_false_negatives.csv"
)

print(
    ERROR_DIR / "v3_uncertain_urls.csv"
)

print("\nV3 ERROR ANALYSIS COMPLETED")