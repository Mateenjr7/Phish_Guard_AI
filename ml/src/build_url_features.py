import pandas as pd
from pathlib import Path
from feature_extractor import extract_features


# ==========================================
# PATHS
# ==========================================

PROJECT_ROOT = Path(__file__).resolve().parent.parent

INPUT_PATH = (
    PROJECT_ROOT
    / "data"
    / "raw"
    / "PhiUSIIL_Phishing_URL_Dataset.csv"
)

OUTPUT_PATH = (
    PROJECT_ROOT
    / "data"
    / "processed"
    / "url_features.csv"
)


# ==========================================
# LOAD DATASET
# ==========================================

print("Loading dataset...")
print(f"Input: {INPUT_PATH}")

df = pd.read_csv(INPUT_PATH)

print(f"Dataset loaded: {df.shape}")
print(f"Total URLs: {len(df)}")


# ==========================================
# EXTRACT URL FEATURES
# ==========================================

print("\nExtracting URL features...")

features = []

for index, url in enumerate(df["URL"]):

    try:
        feature_dict = extract_features(str(url))
        features.append(feature_dict)

    except Exception as e:

        print(f"Error processing row {index}: {e}")
        features.append(None)

    if (index + 1) % 10000 == 0:
        print(f"Processed {index + 1}/{len(df)} URLs")


# ==========================================
# CREATE FEATURE DATAFRAME
# ==========================================

features_df = pd.DataFrame(features)


# ==========================================
# CONVERT LABEL
# ==========================================

# Original PhiUSIIL:
# 1 = legitimate
# 0 = phishing
#
# Our ML convention:
# 0 = legitimate
# 1 = phishing

features_df["label"] = df["label"].map({
    1: 0,
    0: 1
})


# ==========================================
# REMOVE INVALID ROWS
# ==========================================

before = len(features_df)

features_df = features_df.dropna()

after = len(features_df)

print(f"\nRemoved invalid rows: {before - after}")


# ==========================================
# SAVE DATASET
# ==========================================

OUTPUT_PATH.parent.mkdir(
    parents=True,
    exist_ok=True
)

features_df.to_csv(
    OUTPUT_PATH,
    index=False
)


# ==========================================
# SUMMARY
# ==========================================

print("\n================================")
print("FEATURE DATASET CREATED")
print("================================")

print("Shape:", features_df.shape)

print("\nFeatures:")
print(features_df.columns.tolist())

print("\nLabel distribution:")
print(features_df["label"].value_counts())

print(f"\nSaved to: {OUTPUT_PATH}")