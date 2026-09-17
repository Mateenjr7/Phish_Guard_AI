import pandas as pd
from pathlib import Path


INPUT_PATH = "../data/raw/phiusiil.csv"
OUTPUT_PATH = "../data/processed/phiusiil_processed.csv"


df = pd.read_csv(INPUT_PATH)


# Remove columns that should not be used for prediction
columns_to_drop = [
    "FILENAME"
]

for column in columns_to_drop:
    if column in df.columns:
        df = df.drop(columns=column)


# UCI:
# 1 = legitimate
# 0 = phishing
#
# Convert to:
# 0 = legitimate
# 1 = phishing

df["label"] = df["label"].map({
    1: 0,
    0: 1
})


# Remove duplicate rows
df = df.drop_duplicates()


# Remove rows with missing labels
df = df.dropna(subset=["label"])


Path("../data/processed").mkdir(parents=True, exist_ok=True)

df.to_csv(OUTPUT_PATH, index=False)


print("Data preprocessing completed.")
print(f"Shape: {df.shape}")

print("\nLabel distribution:")
print(df["label"].value_counts())

print(f"\nSaved to: {OUTPUT_PATH}")