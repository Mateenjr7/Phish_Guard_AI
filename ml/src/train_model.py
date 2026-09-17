import os
from pathlib import Path

import pandas as pd
import matplotlib.pyplot as plt
import seaborn as sns
import joblib

from sklearn.model_selection import train_test_split
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import (
    accuracy_score,
    precision_score,
    recall_score,
    f1_score,
    classification_report,
    confusion_matrix,
    roc_auc_score
)


# ============================================================
# Step 1: Load processed dataset
# ============================================================

DATA_PATH = "../data/processed/phiusiil_processed.csv"

df = pd.read_csv(DATA_PATH)

print("Dataset loaded successfully.")
print("Dataset shape:", df.shape)


# ============================================================
# Step 2: Separate features and target
# ============================================================

X = df.drop(columns=["label"])
y = df["label"]


# ============================================================
# Step 3: Keep numerical features
# ============================================================

X = X.select_dtypes(include=["int64", "float64"])

print("\nFeatures:", X.shape)
print("Target:", y.shape)


# ============================================================
# Step 12: Split the dataset
# ============================================================

X_train, X_test, y_train, y_test = train_test_split(
    X,
    y,
    test_size=0.20,
    random_state=42,
    stratify=y
)

print("\nTraining samples:", len(X_train))
print("Testing samples:", len(X_test))


# ============================================================
# Step 13: Create Random Forest model
# ============================================================

model = RandomForestClassifier(
    n_estimators=300,
    random_state=42,
    n_jobs=-1,
    class_weight="balanced"
)

print("\nRandom Forest model created.")


# ============================================================
# Step 14: Train the model
# ============================================================

print("\nTraining model...")

model.fit(X_train, y_train)

print("Model training completed.")


# ============================================================
# Step 15: Make predictions
# ============================================================

y_pred = model.predict(X_test)

y_probability = model.predict_proba(X_test)[:, 1]

print("\nPredictions completed.")


# ============================================================
# Step 16: Evaluate the model
# ============================================================

accuracy = accuracy_score(y_test, y_pred)
precision = precision_score(y_test, y_pred)
recall = recall_score(y_test, y_pred)
f1 = f1_score(y_test, y_pred)
roc_auc = roc_auc_score(y_test, y_probability)

print("\n==============================")
print("      MODEL PERFORMANCE")
print("==============================")

print(f"Accuracy : {accuracy:.4f}")
print(f"Precision: {precision:.4f}")
print(f"Recall   : {recall:.4f}")
print(f"F1 Score : {f1:.4f}")
print(f"ROC-AUC  : {roc_auc:.4f}")


print("\nClassification Report:")

print(
    classification_report(
        y_test,
        y_pred,
        target_names=["Legitimate", "Phishing"]
    )
)


# ============================================================
# Step 17: Confusion Matrix
# ============================================================

cm = confusion_matrix(y_test, y_pred)

plt.figure(figsize=(7, 5))

sns.heatmap(
    cm,
    annot=True,
    fmt="d",
    xticklabels=["Legitimate", "Phishing"],
    yticklabels=["Legitimate", "Phishing"]
)

plt.xlabel("Predicted")
plt.ylabel("Actual")
plt.title("Phishing URL Detection - Confusion Matrix")

plt.tight_layout()
plt.show()


# ============================================================
# Step 17: Feature Importance
# ============================================================

feature_importance = pd.Series(
    model.feature_importances_,
    index=X.columns
).sort_values(ascending=False)

print("\n==============================")
print("       TOP FEATURES")
print("==============================")

print(feature_importance.head(15))


plt.figure(figsize=(10, 6))

feature_importance.head(15).sort_values().plot(
    kind="barh"
)

plt.title("Top 15 Features Used by Random Forest")
plt.xlabel("Feature Importance")

plt.tight_layout()
plt.show()


# ============================================================
# Step 18: Save the trained model
# ============================================================

MODEL_DIR = Path("../models")

MODEL_DIR.mkdir(
    parents=True,
    exist_ok=True
)

MODEL_PATH = MODEL_DIR / "url_phishing_model.joblib"

joblib.dump(
    model,
    MODEL_PATH
)

print("\n==============================")
print("       MODEL SAVED")
print("==============================")

print(f"Model saved to: {MODEL_PATH}")


# ============================================================
# Step 19: Verify the saved model
# ============================================================

if os.path.exists(MODEL_PATH):

    print("\nModel file verified successfully.")
    print(f"File location: {MODEL_PATH}")

else:

    print("\nModel file was not created.")