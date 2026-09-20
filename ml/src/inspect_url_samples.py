import pandas as pd

from pathlib import Path


# ==========================================
# PATH
# ==========================================

PROJECT_ROOT = Path(__file__).resolve().parent.parent

DATA_PATH = (
    PROJECT_ROOT
    / "data"
    / "raw"
    / "PhiUSIIL_Phishing_URL_Dataset.csv"
)


# ==========================================
# LOAD DATA
# ==========================================

print("Loading dataset...")

df = pd.read_csv(DATA_PATH)

print("Dataset shape:", df.shape)


# ==========================================
# LEGITIMATE SAMPLES
# ==========================================

print("\n========================================")
print("      LEGITIMATE URL SAMPLES")
print("========================================")

legitimate = df[df["label"] == 1]

print(
    legitimate["URL"]
    .head(30)
    .to_string(index=False)
)


# ==========================================
# PHISHING SAMPLES
# ==========================================

print("\n========================================")
print("       PHISHING URL SAMPLES")
print("========================================")

phishing = df[df["label"] == 0]

print(
    phishing["URL"]
    .head(30)
    .to_string(index=False)
)


# ==========================================
# RANDOM LEGITIMATE SAMPLES
# ==========================================

print("\n========================================")
print("    RANDOM LEGITIMATE URL SAMPLES")
print("========================================")

print(
    legitimate["URL"]
    .sample(
        n=min(30, len(legitimate)),
        random_state=42
    )
    .to_string(index=False)
)


# ==========================================
# RANDOM PHISHING SAMPLES
# ==========================================

print("\n========================================")
print("     RANDOM PHISHING URL SAMPLES")
print("========================================")

print(
    phishing["URL"]
    .sample(
        n=min(30, len(phishing)),
        random_state=42
    )
    .to_string(index=False)
)


# ==========================================
# COMPLETE
# ==========================================

print("\n========================================")
print("URL SAMPLE INSPECTION COMPLETED")
print("========================================")
