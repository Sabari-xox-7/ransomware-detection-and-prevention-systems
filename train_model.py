import numpy as np
import pandas as pd
from sklearn.ensemble import RandomForestClassifier
from sklearn.model_selection import train_test_split
from sklearn.metrics import classification_report, accuracy_score
import joblib
import os

print("=" * 60)
print("  Ransomware Detection - Model Training Script")
print("=" * 60)

np.random.seed(42)

def generate_benign(n):
    return {
        "file_size":       np.random.randint(1_000, 5_000_000, n),
        "entropy":         np.random.uniform(3.0, 6.5, n),
        "has_sus_strings": np.random.choice([0, 1], n, p=[0.92, 0.08]),
        "extension_risk":  np.random.choice([0, 1], n, p=[0.85, 0.15]),
        "string_count":    np.random.randint(50, 500, n),
        "url_count":       np.random.randint(0, 5, n),
        "ip_count":        np.random.randint(0, 2, n),
        "label":           np.zeros(n, dtype=int),
    }

def generate_malicious(n):
    return {
        "file_size":       np.random.randint(50_000, 10_000_000, n),
        "entropy":         np.random.uniform(6.8, 8.0, n),
        "has_sus_strings": np.random.choice([0, 1], n, p=[0.1, 0.9]),
        "extension_risk":  np.random.choice([0, 1], n, p=[0.2, 0.8]),
        "string_count":    np.random.randint(5, 100, n),
        "url_count":       np.random.randint(0, 20, n),
        "ip_count":        np.random.randint(0, 10, n),
        "label":           np.ones(n, dtype=int),
    }

df = pd.concat([
    pd.DataFrame(generate_benign(1000)),
    pd.DataFrame(generate_malicious(1000))
], ignore_index=True).sample(frac=1, random_state=42).reset_index(drop=True)

os.makedirs("dataset", exist_ok=True)
df.to_csv("dataset/ransomware_dataset.csv", index=False)
print(f"Dataset created: {len(df)} samples")

FEATURE_COLS = ["file_size", "entropy", "has_sus_strings",
                "extension_risk", "string_count", "url_count", "ip_count"]

X = df[FEATURE_COLS]
y = df["label"]
X_train, X_test, y_train, y_test = train_test_split(
    X, y, test_size=0.2, random_state=42, stratify=y)

print(f"Training: {len(X_train)} samples | Testing: {len(X_test)} samples")
print("Training Random Forest model...")

model = RandomForestClassifier(
    n_estimators=100, max_depth=10, random_state=42, n_jobs=-1)
model.fit(X_train, y_train)

y_pred = model.predict(X_test)
print(f"Accuracy: {accuracy_score(y_test, y_pred) * 100:.2f}%")
print(classification_report(y_test, y_pred, target_names=["Benign", "Malicious"]))

joblib.dump(model, "model.pkl")
print("Model saved to model.pkl")
print("Done! Now run: python app.py")
print("=" * 60)