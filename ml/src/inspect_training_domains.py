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
# LOAD DATA
# ==========================================

print("Loading processed dataset...")

df = pd.read_csv(DATA_PATH)

print("Dataset shape:", df.shape)


# ==========================================
# DOMAIN LENGTH DISTRIBUTION
# ==========================================

print("\n========================================")
print("       DOMAIN LENGTH BY CLASS")
print("========================================")

domain_stats = (
    df.groupby("label")["DomainLength"]
    .describe()
)

print(domain_stats)


# ==========================================
# URL LENGTH DISTRIBUTION
# ==========================================

print("\n========================================")
print("         URL LENGTH BY CLASS")
print("========================================")

url_stats = (
    df.groupby("label")["URLLength"]
    .describe()
)

print(url_stats)


# ==========================================
# PATH LENGTH DISTRIBUTION
# ==========================================

print("\n========================================")
print("         PATH LENGTH BY CLASS")
print("========================================")

path_stats = (
    df.groupby("label")["PathLength"]
    .describe()
)

print(path_stats)


# ==========================================
# SLASH COUNT DISTRIBUTION
# ==========================================

print("\n========================================")
print("         SLASH COUNT BY CLASS")
print("========================================")

slash_stats = (
    df.groupby("label")["SlashCount"]
    .describe()
)

print(slash_stats)


# ==========================================
# SUBDOMAIN DISTRIBUTION
# ==========================================

print("\n========================================")
print("       SUBDOMAIN COUNT BY CLASS")
print("========================================")

subdomain_stats = (
    df.groupby("label")["SubdomainCount"]
    .describe()
)

print(subdomain_stats)


# ==========================================
# SHORT LEGITIMATE URLS
# ==========================================

print("\n========================================")
print(" SHORT LEGITIMATE URL FEATURE PATTERNS")
print("========================================")

legitimate = df[df["label"] == 0]

short_legitimate = legitimate[
    legitimate["URLLength"] <= 20
]

print(
    "Legitimate URLs with URLLength <= 20:",
    len(short_legitimate)
)

print(
    "\nDomainLength distribution:"
)

print(
    short_legitimate["DomainLength"]
    .value_counts()
    .sort_index()
    .head(30)
)


# ==========================================
# SHORT DOMAINS
# ==========================================

print("\n========================================")
print("       SHORT DOMAIN ANALYSIS")
print("========================================")

short_domains = legitimate[
    legitimate["DomainLength"] <= 12
]

print(
    "Legitimate URLs with DomainLength <= 12:",
    len(short_domains)
)

print(
    "\nURL length statistics:"
)

print(
    short_domains["URLLength"]
    .describe()
)


# ==========================================
# COMPLETE
# ==========================================

print("\n========================================")
print("TRAINING DOMAIN INSPECTION COMPLETED")
print("========================================")