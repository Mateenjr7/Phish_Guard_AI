import pandas as pd

from pathlib import Path


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


# ============================================================
# LOAD DATA
# ============================================================

print("Loading dataset...")

df = pd.read_csv(DATA_PATH)

print("Dataset shape:", df.shape)


# ============================================================
# LABEL DISTRIBUTION
# ============================================================

print("\n========================================")
print("LABEL DISTRIBUTION")
print("========================================")

print(
    df["label"]
    .value_counts()
    .sort_index()
)


# ============================================================
# HELPER
# ============================================================
def phishing_rate(group):
    return group.mean() * 100


# ============================================================
# DOMAIN LENGTH
# ============================================================

print("\n========================================")
print("DOMAIN LENGTH")
print("========================================")

df["DomainLengthBin"] = pd.cut(
    df["DomainLength"],
    bins=[0, 10, 15, 20, 25, 30, 40, 60, 100, 1000],
)

domain_stats = (
    df.groupby(
        "DomainLengthBin",
        observed=True,
    )
    .agg(
        samples=("label", "size"),
        phishing_rate=("label", phishing_rate),
    )
)

print(domain_stats)


# ============================================================
# URL LENGTH
# ============================================================

print("\n========================================")
print("URL LENGTH")
print("========================================")

df["URLLengthBin"] = pd.cut(
    df["URLLength"],
    bins=[0, 20, 30, 40, 60, 100, 200, 500, 1000, 10000],
)

url_stats = (
    df.groupby(
        "URLLengthBin",
        observed=True,
    )
    .agg(
        samples=("label", "size"),
        phishing_rate=("label", phishing_rate),
    )
)

print(url_stats)


# ============================================================
# SUBDOMAINS
# ============================================================

print("\n========================================")
print("SUBDOMAIN COUNT")
print("========================================")

subdomain_stats = (
    df.groupby("SubdomainCount")
    .agg(
        samples=("label", "size"),
        phishing_rate=("label", phishing_rate),
    )
)

print(subdomain_stats)


# ============================================================
# ENTROPY
# ============================================================

print("\n========================================")
print("URL ENTROPY")
print("========================================")

df["EntropyBin"] = pd.cut(
    df["URLEntropy"],
    bins=[
        0,
        2,
        2.5,
        3,
        3.5,
        4,
        4.5,
        5,
        10,
    ],
)

entropy_stats = (
    df.groupby(
        "EntropyBin",
        observed=True,
    )
    .agg(
        samples=("label", "size"),
        phishing_rate=("label", phishing_rate),
    )
)

print(entropy_stats)


# ============================================================
# SUSPICIOUS TLD
# ============================================================

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


# ============================================================
# SUSPICIOUS WORDS
# ============================================================

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


# ============================================================
# PATH LENGTH
# ============================================================

print("\n========================================")
print("PATH LENGTH")
print("========================================")

df["PathLengthBin"] = pd.cut(
    df["PathLength"],
    bins=[
        -1,
        0,
        5,
        10,
        20,
        50,
        100,
        500,
        5000,
    ],
)

path_stats = (
    df.groupby(
        "PathLengthBin",
        observed=True,
    )
    .agg(
        samples=("label", "size"),
        phishing_rate=("label", phishing_rate),
    )
)

print(path_stats)


# ============================================================
# HTTPS EXCLUDED
# ============================================================

print("\n========================================")
print("NOTE")
print("========================================")

print(
    "IsHTTPS is intentionally excluded from V3 "
    "feature analysis because of the dataset artifact "
    "identified earlier."
)

print("\n========================================")
print("FEATURE ANALYSIS COMPLETED")
print("========================================")