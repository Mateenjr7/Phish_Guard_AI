import pandas as pd


DATA_PATH = "../data/raw/phiusiil.csv"


df = pd.read_csv(DATA_PATH)


print("\n===== DATASET SHAPE =====")
print(df.shape)


print("\n===== FIRST 5 ROWS =====")
print(df.head())


print("\n===== COLUMNS =====")
print(df.columns.tolist())


print("\n===== DATA TYPES =====")
print(df.dtypes)


print("\n===== MISSING VALUES =====")
print(df.isnull().sum())


print("\n===== DUPLICATES =====")
print(df.duplicated().sum())


print("\n===== TARGET DISTRIBUTION =====")
print(df["label"].value_counts())