import pandas as pd

from pathlib import Path


# ==========================================
# PATH
# ==========================================

PROJECT_ROOT = Path(__file__).resolve().parent.parent

DATA_PATH = (
    PROJECT_ROOT
    / "data"
    / "processed"
    / "url_features.csv"
)


# ==========================================
# LOAD DATASET
# ==========================================

print("Loading processed dataset...")

df = pd.read_csv(DATA_PATH)

print("Dataset shape:", df.shape)


# ==========================================
# LABEL DISTRIBUTION
# ==========================================

print("\n========================================")
print("LABEL DISTRIBUTION")
print("========================================")

print(
    df["label"]
    .value_counts()
    .sort_index()
)

print("\nPercentages:")

print(
    df["label"]
    .value_counts(normalize=True)
    .sort_index()
    .mul(100)
    .round(2)
)


# ==========================================
# HTTPS DISTRIBUTION
# ==========================================

print("\n========================================")
print("HTTPS DISTRIBUTION")
print("========================================")

print(
    df["IsHTTPS"]
    .value_counts()
    .sort_index()
)

print("\nPercentages:")

print(
    df["IsHTTPS"]
    .value_counts(normalize=True)
    .sort_index()
    .mul(100)
    .round(2)
)


# ==========================================
# HTTPS VS LABEL
# ==========================================

print("\n========================================")
print("HTTPS VS LABEL")
print("========================================")

cross_tab = pd.crosstab(
    df["IsHTTPS"],
    df["label"]
)

print(cross_tab)


# ==========================================
# ROW PERCENTAGES
# ==========================================

print("\n========================================")
print("LABEL PERCENTAGE WITHIN HTTPS GROUP")
print("========================================")

row_percent = pd.crosstab(
    df["IsHTTPS"],
    df["label"],
    normalize="index"
) * 100

print(
    row_percent.round(2)
)


# ==========================================
# PHISHING RATE BY HTTPS
# ==========================================

print("\n========================================")
print("PHISHING RATE BY HTTPS")
print("========================================")

phishing_rate = (
    df.groupby("IsHTTPS")["label"]
    .mean()
    * 100
)

print(
    phishing_rate.round(2)
)


# ==========================================
# LEGITIMATE / PHISHING HTTPS RATES
# ==========================================

print("\n========================================")
print("HTTPS RATE WITHIN EACH CLASS")
print("========================================")

class_https_rate = (
    df.groupby("label")["IsHTTPS"]
    .mean()
    * 100
)

print(
    class_https_rate.round(2)
)


# ==========================================
# SUMMARY
# ==========================================

print("\n========================================")
print("ANALYSIS COMPLETED")
print("========================================")

print(
    """
Interpretation:

label = 0 → Legitimate
label = 1 → Phishing

IsHTTPS = 0 → HTTP
IsHTTPS = 1 → HTTPS
"""
)