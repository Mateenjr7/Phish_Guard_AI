from ucimlrepo import fetch_ucirepo
import pandas as pd
from pathlib import Path


# Load PhiUSIIL dataset from UCI
dataset = fetch_ucirepo(id=967)

X = dataset.data.features
y = dataset.data.targets


# Combine features and target
df = pd.concat([X, y], axis=1)


# Create output directory
output_dir = Path("../data/raw")
output_dir.mkdir(parents=True, exist_ok=True)


# Save dataset
output_path = output_dir / "phiusiil.csv"
df.to_csv(output_path, index=False)


print("Dataset downloaded successfully.")
print(f"Shape: {df.shape}")
print(f"Saved to: {output_path}")
print("\nColumns:")
print(df.columns.tolist())