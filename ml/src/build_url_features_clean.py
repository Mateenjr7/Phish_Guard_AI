from pathlib import Path
import pandas as pd
from tqdm import tqdm

from feature_extractor_clean import extract_features

# --------------------------------------------------
# Paths
# --------------------------------------------------

BASE_DIR = Path(__file__).resolve().parents[1]

RAW_FILE = BASE_DIR / "data" / "raw" / "PhiUSIIL_Phishing_URL_Dataset.csv"
OUTPUT_FILE = BASE_DIR / "data" / "processed" / "url_features_clean.csv"


# --------------------------------------------------
# Load dataset
# --------------------------------------------------

print("Loading dataset...")

df = pd.read_csv(RAW_FILE)

print(f"Original shape: {df.shape}")
print(f"Columns: {list(df.columns)}")


# --------------------------------------------------
# Validate required columns
# --------------------------------------------------

if "URL" not in df.columns:
    raise ValueError("Dataset does not contain a URL column.")

if "label" not in df.columns:
    raise ValueError("Dataset does not contain a label column.")


# --------------------------------------------------
# Extract clean URL features
# --------------------------------------------------

print("\nExtracting clean URL features...")

feature_rows = []
valid_indices = []

for idx, url in tqdm(
    enumerate(df["URL"]),
    total=len(df),
    desc="Extracting features"
):
    try:
        features = extract_features(url)
        feature_rows.append(features)
        valid_indices.append(idx)

    except Exception:
        continue


features_df = pd.DataFrame(feature_rows)

print(f"\nExtracted feature matrix: {features_df.shape}")


# --------------------------------------------------
# Add labels
# --------------------------------------------------

labels = df.iloc[valid_indices]["label"].reset_index(drop=True)

# PhiUSIIL:
# 1 = legitimate
# 0 = phishing
#
# Project convention:
# 0 = legitimate
# 1 = phishing

labels = labels.map({
    1: 0,
    0: 1
})

features_df["label"] = labels


# --------------------------------------------------
# Remove invalid labels
# --------------------------------------------------

features_df = features_df.dropna(subset=["label"])

features_df["label"] = features_df["label"].astype(int)


# --------------------------------------------------
# Save
# --------------------------------------------------

OUTPUT_FILE.parent.mkdir(parents=True, exist_ok=True)

features_df.to_csv(OUTPUT_FILE, index=False)


# --------------------------------------------------
# Summary
# --------------------------------------------------

print("\n========================================")
print("CLEAN FEATURE DATASET CREATED")
print("========================================")

print(f"Shape: {features_df.shape}")

print("\nLabel distribution:")
print(features_df["label"].value_counts().sort_index())

print("\nFeature count:")
print(len(features_df.columns) - 1)

print(f"\nSaved to:")
print(OUTPUT_FILE)
