import pandas as pd
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parent.parent
DATA_PATH = (
    PROJECT_ROOT
    / "data"
    / "raw"
    / "PhiUSIIL_Phishing_URL_Dataset.csv"
)

print("Loading dataset...")
df = pd.read_csv(DATA_PATH)

# Extract domain
df["domain_clean"] = (
    df["URL"]
    .astype(str)
    .str.replace(r"^https?://", "", regex=True)
    .str.split("/")
    .str[0]
    .str.lower()
)

# label:
# original 1 = legitimate
# original 0 = phishing

domain_labels = (
    df.groupby("domain_clean")["label"]
    .nunique()
)

conflicting_domains = domain_labels[
    domain_labels > 1
].index

print("\n========================================")
print("CONFLICTING DOMAINS")
print("========================================")

print("Number of conflicting domains:", len(conflicting_domains))

for domain in sorted(conflicting_domains):

    subset = df[df["domain_clean"] == domain]

    print("\n----------------------------------------")
    print("DOMAIN:", domain)
    print("TOTAL:", len(subset))

    print("\nLabel distribution:")
    print(
        subset["label"]
        .value_counts()
        .sort_index()
        .to_string()
    )

    print("\nSample URLs:")

    print(
        subset[["URL", "label"]]
        .head(10)
        .to_string(index=False)
    )

print("\n========================================")
print("INSPECTION COMPLETED")
print("========================================")
