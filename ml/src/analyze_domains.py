import pandas as pd
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parent.parent
DATA_PATH = PROJECT_ROOT / "data" / "raw" / "PhiUSIIL_Phishing_URL_Dataset.csv"

print("Loading dataset...")
df = pd.read_csv(DATA_PATH)

print("Dataset shape:", df.shape)

# Extract domain
df["domain_clean"] = (
    df["URL"]
    .astype(str)
    .str.replace(r"^https?://", "", regex=True)
    .str.split("/")
    .str[0]
    .str.lower()
)

print("\n========================================")
print("UNIQUE DOMAINS")
print("========================================")

print("Unique domains:", df["domain_clean"].nunique())

print("\n========================================")
print("DUPLICATE URL ANALYSIS")
print("========================================")

duplicate_urls = df["URL"].duplicated().sum()

print("Duplicate URLs:", duplicate_urls)
print(
    "Duplicate percentage:",
    round((duplicate_urls / len(df)) * 100, 2),
    "%"
)

print("\n========================================")
print("DUPLICATE DOMAIN ANALYSIS")
print("========================================")

duplicate_domains = df["domain_clean"].duplicated().sum()

print("Duplicate domain rows:", duplicate_domains)
print(
    "Duplicate domain percentage:",
    round((duplicate_domains / len(df)) * 100, 2),
    "%"
)

print("\n========================================")
print("TOP DOMAINS")
print("========================================")

print(
    df["domain_clean"]
    .value_counts()
    .head(30)
    .to_string()
)

print("\n========================================")
print("TOP DOMAINS BY LABEL")
print("========================================")

for label, name in [(0, "LEGITIMATE"), (1, "PHISHING")]:
    print(f"\n--- {name} ---")

    subset = df[df["label"] == (1 if label == 0 else 0)]

    print(
        subset["domain_clean"]
        .value_counts()
        .head(20)
        .to_string()
    )

print("\n========================================")
print("DOMAIN LABEL CONFLICTS")
print("========================================")

domain_label_counts = (
    df.groupby("domain_clean")["label"]
    .nunique()
)

conflicting_domains = domain_label_counts[
    domain_label_counts > 1
]

print(
    "Domains appearing with both labels:",
    len(conflicting_domains)
)

print("\n========================================")
print("ANALYSIS COMPLETED")
print("========================================")