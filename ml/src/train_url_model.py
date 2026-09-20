import pandas as pd
import joblib

from pathlib import Path

from sklearn.model_selection import train_test_split
from sklearn.ensemble import RandomForestClassifier

from sklearn.metrics import (
    accuracy_score,
    precision_score,
    recall_score,
    f1_score,
    roc_auc_score,
    classification_report,
    confusion_matrix
)


# ==========================================
# CONFIGURATION
# ==========================================

PROJECT_ROOT = Path(__file__).resolve().parent.parent

DATA_PATH = (
    PROJECT_ROOT
    / "data"
    / "processed"
    / "url_features.csv"
)

MODEL_PATH = (
    PROJECT_ROOT
    / "models"
    / "url_phishing_model.joblib"
)


# ==========================================
# LOAD DATA
# ==========================================

print("Loading feature dataset...")
print(f"Input: {DATA_PATH}")

df = pd.read_csv(DATA_PATH)

print("Dataset shape:", df.shape)


# ==========================================
# FEATURES AND TARGET
# ==========================================

X = df.drop(columns=["label"])
y = df["label"]

print("\nFeature shape:", X.shape)
print("Target shape:", y.shape)

print("\nFeatures:")
print(X.columns.tolist())


# ==========================================
# TRAIN / TEST SPLIT
# ==========================================

X_train, X_test, y_train, y_test = train_test_split(
    X,
    y,
    test_size=0.20,
    random_state=42,
    stratify=y
)

print("\nTraining samples:", len(X_train))
print("Testing samples:", len(X_test))


# ==========================================
# CREATE MODEL
# ==========================================

model = RandomForestClassifier(
    n_estimators=300,
    random_state=42,
    n_jobs=-1,
    class_weight="balanced"
)

print("\nRandom Forest created.")


# ==========================================
# TRAIN
# ==========================================

print("\nTraining model...")

model.fit(X_train, y_train)

print("Training completed.")


# ==========================================
# PREDICTIONS
# ==========================================

print("\nGenerating predictions...")

y_pred = model.predict(X_test)

y_probability = model.predict_proba(X_test)[:, 1]


# ==========================================
# EVALUATION
# ==========================================

accuracy = accuracy_score(y_test, y_pred)
precision = precision_score(y_test, y_pred)
recall = recall_score(y_test, y_pred)
f1 = f1_score(y_test, y_pred)
roc_auc = roc_auc_score(y_test, y_probability)


print("\n========================================")
print("       RAW URL MODEL PERFORMANCE")
print("========================================")

print(f"Accuracy : {accuracy:.4f}")
print(f"Precision: {precision:.4f}")
print(f"Recall   : {recall:.4f}")
print(f"F1 Score : {f1:.4f}")
print(f"ROC-AUC  : {roc_auc:.4f}")


# ==========================================
# CLASSIFICATION REPORT
# ==========================================

print("\nClassification Report:\n")

print(
    classification_report(
        y_test,
        y_pred,
        target_names=[
            "Legitimate",
            "Phishing"
        ]
    )
)


# ==========================================
# CONFUSION MATRIX
# ==========================================

print("\nConfusion Matrix:")

print(confusion_matrix(y_test, y_pred))


# ==========================================
# FEATURE IMPORTANCE
# ==========================================

feature_importance = pd.Series(
    model.feature_importances_,
    index=X.columns
).sort_values(ascending=False)


print("\n========================================")
print("       TOP URL FEATURES")
print("========================================")

print(feature_importance.head(15))


# ==========================================
# SAVE MODEL
# ==========================================

MODEL_PATH.parent.mkdir(
    parents=True,
    exist_ok=True
)

joblib.dump(model, MODEL_PATH)


print("\n========================================")
print("       MODEL SAVED")
print("========================================")

print(f"Model: {MODEL_PATH}")


# ==========================================
# VERIFY MODEL
# ==========================================

loaded_model = joblib.load(MODEL_PATH)

print("\nModel loaded successfully.")

print(
    "Number of features expected:",
    loaded_model.n_features_in_
)

print("\nTraining pipeline completed successfully.")