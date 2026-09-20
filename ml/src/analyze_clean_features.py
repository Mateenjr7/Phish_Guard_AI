import pandas as pd


DATA_PATH = "data/processed/url_features_clean.csv"


def phishing_rate(series):
    return series.mean() * 100


print("=" * 70)
print("CLEAN FEATURE AUDIT")
print("=" * 70)

df = pd.read_csv(DATA_PATH)

print(f"\nDataset shape: {df.shape}")
print(f"Feature count: {len(df.columns) - 1}")

print("\nLabel distribution:")
print(df["label"].value_counts().sort_index())

print("\n" + "=" * 70)
print("FEATURE DISTRIBUTIONS")
print("=" * 70)


features_to_check = [
    "URLLength",
    "DomainLength",
    "DomainDigitRatio",
    "DomainHasHyphen",
    "SubdomainCount",
    "PathDepth",
    "PathDigitCount",
    "PathSpecialCount",
    "QueryParameterCount",
    "DigitRatio",
    "SpecialCharRatio",
    "URLEntropy",
    "DomainEntropy",
    "PathEntropy",
    "QueryEntropy",
    "IsDomainIP",
    "IsSuspiciousTLD",
    "IsShortened",
    "EncodedCharCount",
    "DoubleSlashCount",
    "HasAtSymbol",
    "SuspiciousTokenCount",
    "SensitiveActionCount",
    "BrandTokenCount",
    "BrandSensitiveCombination",
    "RepeatedCharacterCount",
    "SuspiciousFileExtension",
]


for feature in features_to_check:

    if feature not in df.columns:
        print(f"\n[SKIP] {feature} not found")
        continue

    print(f"\n--- {feature} ---")

    try:
        stats = (
            df.groupby(feature)["label"]
            .agg(
                Count="count",
                PhishingRate=phishing_rate
            )
            .reset_index()
        )

        print(stats.to_string(index=False))

    except Exception as e:
        print(f"Error analyzing {feature}: {e}")


print("\n" + "=" * 70)
print("POTENTIAL DATASET ARTIFACTS")
print("=" * 70)


binary_features = [
    "DomainHasHyphen",
    "IsDomainIP",
    "IsSuspiciousTLD",
    "IsShortened",
    "HasAtSymbol",
    "BrandSensitiveCombination",
    "SuspiciousFileExtension",
]


for feature in binary_features:

    if feature not in df.columns:
        continue

    print(f"\n{feature}:")

    table = (
        df.groupby(feature)["label"]
        .agg(
            Count="count",
            PhishingRate=phishing_rate
        )
        .reset_index()
    )

    print(table.to_string(index=False))


print("\n" + "=" * 70)
print("MISSING VALUES")
print("=" * 70)

missing = df.isnull().sum()

missing = missing[missing > 0]

if len(missing) == 0:
    print("No missing values.")
else:
    print(missing)


print("\n" + "=" * 70)
print("CLEAN FEATURE AUDIT COMPLETE")
print("=" * 70)