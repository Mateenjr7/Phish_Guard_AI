from pathlib import Path

import pandas as pd
import joblib

from ml.src.features.feature_extractor_clean import extract_features


PROJECT_ROOT = Path(__file__).resolve().parents[3]
MODEL_PATH = PROJECT_ROOT / "ml" / "models" / "url_phishing_model_clean_v3.joblib"


# ---------------------------------------------------------
# External sanity-test URLs
# These are NOT taken from the PhiUSIIL dataset.
# ---------------------------------------------------------

TEST_URLS = [
    # -----------------------------------------------------
    # Legitimate / normal
    # -----------------------------------------------------
    ("legitimate", "https://www.google.com"),
    ("legitimate", "https://github.com"),
    ("legitimate", "https://www.microsoft.com"),
    ("legitimate", "https://www.amazon.com"),
    ("legitimate", "https://www.apple.com"),
    ("legitimate", "https://www.youtube.com"),
    ("legitimate", "https://www.linkedin.com"),
    ("legitimate", "https://www.wikipedia.org"),
    ("legitimate", "https://www.openai.com"),
    ("legitimate", "https://www.sjsu.edu"),
    ("legitimate", "https://www.python.org"),
    ("legitimate", "https://www.nasa.gov"),
    ("legitimate", "https://www.ibm.com"),
    ("legitimate", "https://www.cloudflare.com"),
    ("legitimate", "https://www.khanacademy.org"),

    # -----------------------------------------------------
    # Complex but legitimate-looking URLs
    # -----------------------------------------------------
    ("legitimate_complex",
     "https://docs.python.org/3/library/urllib.parse.html"),

    ("legitimate_complex",
     "https://developer.mozilla.org/en-US/docs/Web/JavaScript"),

    ("legitimate_complex",
     "https://learn.microsoft.com/en-us/windows-server/"),

    ("legitimate_complex",
     "https://www.gov.uk/search/all?keywords=driving+licence"),

    ("legitimate_complex",
     "https://www.cam.ac.uk/research/news"),

    # -----------------------------------------------------
    # Suspicious / phishing-style URLs
    # -----------------------------------------------------
    ("suspicious",
     "https://secure-account-verify.xyz/login"),

    ("suspicious",
     "https://paypal-account-verification.xyz/login"),

    ("suspicious",
     "https://apple-id-confirmation.top/login"),

    ("suspicious",
     "https://microsoft-security-alert.click/verify"),

    ("suspicious",
     "https://google-account-security.xyz/signin"),

    ("suspicious",
     "https://amazon-payment-update.top/account"),

    ("suspicious",
     "https://bank-account-verify.xyz/login"),

    ("suspicious",
     "https://login-confirmation-account.work/verify"),

    # -----------------------------------------------------
    # Brand impersonation / nested domains
    # -----------------------------------------------------
    ("brand_impersonation",
     "https://paypal.security-check.example.com/login"),

    ("brand_impersonation",
     "https://paypal.kenkenuae.com/login"),

    ("brand_impersonation",
     "https://microsoft.account-security.example.com"),

    ("brand_impersonation",
     "https://apple.verify-account.example.com"),

    ("brand_impersonation",
     "https://amazon.security-login.example.com"),

    # -----------------------------------------------------
    # IP-based
    # -----------------------------------------------------
    ("ip_based",
     "http://192.168.1.1/login"),

    ("ip_based",
     "http://45.33.12.87/account/verify"),

    ("ip_based",
     "https://103.45.77.21/login"),

    # -----------------------------------------------------
    # Obfuscated / suspicious structure
    # -----------------------------------------------------
    ("obfuscated",
     "https://example.com/%6c%6f%67%69%6e"),

    ("obfuscated",
     "https://example.com/account/%76%65%72%69%66%79"),

    ("obfuscated",
     "https://user@example.com/login"),

    # -----------------------------------------------------
    # Long/random phishing-style URLs
    # -----------------------------------------------------
    ("random",
     "https://xj29dk39-account-verification.xyz/login"),

    ("random",
     "https://secure-login-4839201.top/verify/account"),

    ("random",
     "https://account-update-928374.click/security/login"),

    ("random",
     "https://verify-user-293847.work/authentication"),

    # -----------------------------------------------------
    # Shorteners
    # -----------------------------------------------------
    ("shortener",
     "https://bit.ly/example"),

    ("shortener",
     "https://tinyurl.com/example"),

    ("shortener",
     "https://t.co/example"),
]


print("=" * 80)
print("PHISHGUARD - EXTERNAL URL SANITY TEST")
print("=" * 80)

print("\nLoading Clean V2 model...")

model = joblib.load(MODEL_PATH)

print(f"Model: {type(model).__name__}")
print(f"Expected features: {model.n_features_in_}")

# ---------------------------------------------------------
# Build feature matrix
# ---------------------------------------------------------

rows = []

for category, url in TEST_URLS:
    features = extract_features(url)

    rows.append({
        "category": category,
        "url": url,
        **features,
    })

df = pd.DataFrame(rows)

feature_columns = [
    "URLLength",
    "DomainLength",
    "DomainDigitCount",
    "DomainDigitRatio",
    "DomainLetterRatio",
    "DomainSpecialCount",
    "DomainHyphenCount",
    "DomainDotCount",
    "DomainHasHyphen",
    "DomainEntropy",
    "SubdomainCount",
    "DigitCount",
    "DigitRatio",
    "LetterCount",
    "SpecialCharCount",
    "SpecialCharRatio",
    "DotCount",
    "HyphenCount",
    "UnderscoreCount",
    "SlashCount",
    "QuestionCount",
    "EqualCount",
    "AtCount",
    "AmpersandCount",
    "PercentCount",
    "URLEntropy",
    "PathDepth",
]

X = df[feature_columns]

# ---------------------------------------------------------
# Predict
# ---------------------------------------------------------

predictions = model.predict(X)
probabilities = model.predict_proba(X)[:, 1]

df["prediction"] = predictions
df["phishing_probability"] = probabilities

df["prediction_label"] = df["prediction"].map({
    0: "LEGITIMATE",
    1: "PHISHING",
})

# ---------------------------------------------------------
# Display results
# ---------------------------------------------------------

print("\n" + "=" * 80)
print("INDIVIDUAL RESULTS")
print("=" * 80)

for _, row in df.iterrows():

    print(
        f"\n[{row['category'].upper()}]"
    )

    print(f"URL: {row['url']}")

    print(
        f"Prediction: {row['prediction_label']} "
        f"| Phishing probability: "
        f"{row['phishing_probability']:.4f}"
    )

# ---------------------------------------------------------
# Category summary
# ---------------------------------------------------------

print("\n" + "=" * 80)
print("CATEGORY SUMMARY")
print("=" * 80)

summary = (
    df.groupby("category")
    .agg(
        URLs=("url", "count"),
        MeanPhishingProbability=(
            "phishing_probability",
            "mean"
        ),
        PhishingPredictions=(
            "prediction",
            "sum"
        ),
    )
    .reset_index()
)

print(summary.to_string(index=False))

# ---------------------------------------------------------
# Overall summary
# ---------------------------------------------------------

print("\n" + "=" * 80)
print("OVERALL SUMMARY")
print("=" * 80)

print(f"Total URLs tested: {len(df)}")

print(
    f"Predicted legitimate: "
    f"{(df['prediction'] == 0).sum()}"
)

print(
    f"Predicted phishing: "
    f"{(df['prediction'] == 1).sum()}"
)

# ---------------------------------------------------------
# Save results
# ---------------------------------------------------------

output_path = "data/processed/external_url_test_results.csv"

df[
    [
        "category",
        "url",
        "prediction",
        "prediction_label",
        "phishing_probability",
    ]
].to_csv(output_path, index=False)

print("\nResults saved to:")
print(output_path)

print("\n" + "=" * 80)
print("EXTERNAL URL TEST COMPLETE")
print("=" * 80)