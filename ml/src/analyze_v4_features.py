import pandas as pd
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parent.parent

DATA_PATH = (
    PROJECT_ROOT
    / "data"
    / "processed"
    / "url_features_v4.csv"
)

print("Loading V4 dataset...")
df = pd.read_csv(DATA_PATH)

print("Dataset shape:", df.shape)

print("\n========================================")
print("LABEL DISTRIBUTION")
print("========================================")
print(df["label"].value_counts().sort_index())


def phishing_rate(series):
    return series.mean() * 100


def analyze_numeric_bins(column, bins):
    df[f"{column}Bin"] = pd.cut(
        df[column],
        bins=bins,
    )

    result = (
        df.groupby(
            f"{column}Bin",
            observed=True,
        )
        .agg(
            samples=("label", "size"),
            phishing_rate=("label", phishing_rate),
        )
    )

    print(result)


print("\n========================================")
print("DOMAIN LENGTH")
print("========================================")

analyze_numeric_bins(
    "DomainLength",
    [0, 10, 15, 20, 25, 30, 40, 60, 100, 1000],
)


print("\n========================================")
print("URL LENGTH")
print("========================================")

analyze_numeric_bins(
    "URLLength",
    [0, 20, 30, 40, 60, 100, 200, 500, 1000, 10000],
)


print("\n========================================")
print("PATH LENGTH")
print("========================================")

analyze_numeric_bins(
    "PathLength",
    [-1, 0, 5, 10, 20, 50, 100, 500, 5000],
)


print("\n========================================")
print("PATH DEPTH")
print("========================================")

print(
    df.groupby("PathDepth")
    .agg(
        samples=("label", "size"),
        phishing_rate=("label", phishing_rate),
    )
)


print("\n========================================")
print("SUBDOMAIN COUNT")
print("========================================")

print(
    df.groupby("SubdomainCount")
    .agg(
        samples=("label", "size"),
        phishing_rate=("label", phishing_rate),
    )
)


print("\n========================================")
print("URL ENTROPY")
print("========================================")

analyze_numeric_bins(
    "URLEntropy",
    [0, 2, 2.5, 3, 3.5, 4, 4.5, 5, 10],
)


print("\n========================================")
print("DOMAIN ENTROPY")
print("========================================")

analyze_numeric_bins(
    "DomainEntropy",
    [0, 2, 2.5, 3, 3.5, 4, 4.5, 5, 10],
)


print("\n========================================")
print("PATH ENTROPY")
print("========================================")

analyze_numeric_bins(
    "PathEntropy",
    [0, 2, 2.5, 3, 3.5, 4, 4.5, 5, 10],
)


print("\n========================================")
print("DIGIT RATIO")
print("========================================")

analyze_numeric_bins(
    "DigitRatio",
    [-0.001, 0, 0.05, 0.10, 0.20, 0.30, 0.50, 1],
)


print("\n========================================")
print("DOMAIN DIGIT RATIO")
print("========================================")

analyze_numeric_bins(
    "DomainDigitRatio",
    [-0.001, 0, 0.05, 0.10, 0.20, 0.30, 0.50, 1],
)


print("\n========================================")
print("SUSPICIOUS TLD")
print("========================================")

print(
    df.groupby("IsSuspiciousTLD")
    .agg(
        samples=("label", "size"),
        phishing_rate=("label", phishing_rate),
    )
)


print("\n========================================")
print("SUSPICIOUS WORD COUNT")
print("========================================")

print(
    df.groupby("SuspiciousWordCount")
    .agg(
        samples=("label", "size"),
        phishing_rate=("label", phishing_rate),
    )
)


print("\n========================================")
print("SUSPICIOUS FILE EXTENSION")
print("========================================")

print(
    df.groupby("SuspiciousFileExtension")
    .agg(
        samples=("label", "size"),
        phishing_rate=("label", phishing_rate),
    )
)


print("\n========================================")
print("BRAND + ACTION COMBINATION")
print("========================================")

print(
    df.groupby("BrandActionCombination")
    .agg(
        samples=("label", "size"),
        phishing_rate=("label", phishing_rate),
    )
)


print("\n========================================")
print("SHORTENED URL")
print("========================================")

print(
    df.groupby("IsShortened")
    .agg(
        samples=("label", "size"),
        phishing_rate=("label", phishing_rate),
    )
)


print("\n========================================")
print("DOMAIN HYPHEN")
print("========================================")

print(
    df.groupby("DomainHasHyphen")
    .agg(
        samples=("label", "size"),
        phishing_rate=("label", phishing_rate),
    )
)


print("\n========================================")
print("PERCENT ENCODING")
print("========================================")

print(
    df.groupby("HasPercentEncoding")
    .agg(
        samples=("label", "size"),
        phishing_rate=("label", phishing_rate),
    )
)


print("\n========================================")
print("FRAGMENT")
print("========================================")

print(
    df.groupby("HasFragment")
    .agg(
        samples=("label", "size"),
        phishing_rate=("label", phishing_rate),
    )
)


print("\n========================================")
print("FEATURE ANALYSIS COMPLETED")
print("========================================")   