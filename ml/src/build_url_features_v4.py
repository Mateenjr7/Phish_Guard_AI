import sys
from pathlib import Path

import pandas as pd
from tqdm import tqdm

# ---------------------------------------------------------
# Project paths
# ---------------------------------------------------------

PROJECT_ROOT = Path(__file__).resolve().parent.parent

RAW_DATA_PATH = (
    PROJECT_ROOT
    / "data"
    / "raw"
    / "PhiUSIIL_Phishing_URL_Dataset.csv"
)

OUTPUT_PATH = (
    PROJECT_ROOT
    / "data"
    / "processed"
    / "url_features_v4.csv"
)

# Allow importing feature_extractor_v2.py
sys.path.insert(0, str(PROJECT_ROOT))

from src.feature_extractor_v2 import extract_features


# ---------------------------------------------------------
# Load dataset
# ---------------------------------------------------------

print("Loading raw dataset...")

df = pd.read_csv(RAW_DATA_PATH)

print("Dataset shape:", df.shape)

# ---------------------------------------------------------
# Validate required columns
# ---------------------------------------------------------

required_columns = {"URL", "label"}

missing_columns = required_columns - set(df.columns)

if missing_columns:
    raise ValueError(
        f"Missing required columns: {missing_columns}"
    )


# ---------------------------------------------------------
# Extract features
# ---------------------------------------------------------

print("\nExtracting V4 URL features...")

feature_rows = []
valid_indices = []

for index, url in tqdm(
    enumerate(df["URL"]),
    total=len(df),
    desc="Processing URLs",
):
    try:
        features = extract_features(url)

        feature_rows.append(features)
        valid_indices.append(index)

    except Exception as error:
        print(
            f"\nSkipping row {index}: {error}"
        )


features_df = pd.DataFrame(feature_rows)

# ---------------------------------------------------------
# Labels
# ---------------------------------------------------------

labels = df.loc[
    valid_indices,
    "label",
].reset_index(drop=True)

# Original PhiUSIIL:
#   1 = legitimate
#   0 = phishing
#
# Project convention:
#   0 = legitimate
#   1 = phishing

labels = labels.map({
    1: 0,
    0: 1,
})

features_df["label"] = labels

# ---------------------------------------------------------
# Remove invalid labels
# ---------------------------------------------------------

features_df = features_df.dropna(
    subset=["label"]
)

features_df["label"] = (
    features_df["label"]
    .astype(int)
)

# ---------------------------------------------------------
# Save
# ---------------------------------------------------------

OUTPUT_PATH.parent.mkdir(
    parents=True,
    exist_ok=True,
)

features_df.to_csv(
    OUTPUT_PATH,
    index=False,
)

# ---------------------------------------------------------
# Summary
# ---------------------------------------------------------

print("\n========================================")
print("V4 FEATURE DATASET CREATED")
print("========================================")

print("Shape:", features_df.shape)

print("\nNumber of features:")
print(len(features_df.columns) - 1)

print("\nLabel distribution:")
print(
    features_df["label"]
    .value_counts()
    .sort_index()
)

print("\nMissing values:")
print(
    features_df.isna().sum().sum()
)

print("\nSaved to:")
print(OUTPUT_PATH)

print("\nFeature names:")

for i, column in enumerate(
    features_df.columns.drop("label"),
    start=1,
):
    print(f"{i:02d}. {column}")

print("\n========================================")
print("V4 BUILD COMPLETED")
print("========================================")