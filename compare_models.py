import pandas as pd
import numpy as np
from sklearn.ensemble import IsolationForest, RandomForestClassifier
from sklearn.neighbors import LocalOutlierFactor
from sklearn.preprocessing import StandardScaler
from sklearn.model_selection import train_test_split
from sklearn.metrics import accuracy_score, classification_report
import pickle
import json
import os

print("═" * 50)
print("   SENTINEL - MODEL COMPARISON (Level 8)")
print("═" * 50)

# ─── Load Dataset ────────────────────────────────────
print("\n[1/5] Loading CICIDS2017 dataset...")
df = pd.read_csv("data/cicids2017.csv")
print(f"      Total records: {len(df)}")

# ─── Features ────────────────────────────────────────
features = [
    "Flow Duration",
    "Total Fwd Packets",
    "Total Bwd Packets",
    "Fwd Packet Length Max",
    "Bwd Packet Length Max",
    "Flow Bytes/s",
    "Flow Packets/s",
    "Flow IAT Mean",
    "Fwd IAT Mean",
    "Bwd IAT Mean",
    "Packet Length Mean",
    "Packet Length Std"
]

X = df[features]
y = df["Label"].apply(lambda x: 0 if x == "BENIGN" else 1)

# ─── Scale Data ───────────────────────────────────────
print("[2/5] Scaling data...")
scaler = StandardScaler()
X_scaled = scaler.fit_transform(X)

# Train/test split for supervised model
X_train, X_test, y_train, y_test = train_test_split(
    X_scaled, y, test_size=0.2, random_state=42
)

results = {}

# ─── Model 1: Isolation Forest ────────────────────────
print("[3/5] Training Isolation Forest...")
iso_model = IsolationForest(
    n_estimators=200,
    contamination=0.2,
    random_state=42,
    n_jobs=-1
)
iso_model.fit(X_scaled)
iso_preds = iso_model.predict(X_scaled)
iso_preds_binary = [1 if p == -1 else 0 for p in iso_preds]
iso_accuracy = accuracy_score(y, iso_preds_binary) * 100
results["Isolation Forest"] = round(iso_accuracy, 2)
print(f"      Accuracy: {iso_accuracy:.2f}%")

# ─── Model 2: Random Forest ───────────────────────────
print("[4/5] Training Random Forest...")
rf_model = RandomForestClassifier(
    n_estimators=100,
    random_state=42,
    n_jobs=-1
)
rf_model.fit(X_train, y_train)
rf_preds = rf_model.predict(X_test)
rf_accuracy = accuracy_score(y_test, rf_preds) * 100
results["Random Forest"] = round(rf_accuracy, 2)
print(f"      Accuracy: {rf_accuracy:.2f}%")

# ─── Model 3: Local Outlier Factor ────────────────────
print("[5/5] Training Local Outlier Factor...")
lof_model = LocalOutlierFactor(
    n_neighbors=20,
    contamination=0.2,
    novelty=True
)
lof_model.fit(X_scaled)
lof_preds = lof_model.predict(X_scaled)
lof_preds_binary = [1 if p == -1 else 0 for p in lof_preds]
lof_accuracy = accuracy_score(y, lof_preds_binary) * 100
results["Local Outlier Factor"] = round(lof_accuracy, 2)
print(f"      Accuracy: {lof_accuracy:.2f}%")

# ─── Compare Results ──────────────────────────────────
print("\n" + "═" * 50)
print("   MODEL COMPARISON RESULTS")
print("═" * 50)

best_model_name = max(results, key=results.get)

for name, acc in sorted(results.items(), key=lambda x: x[1], reverse=True):
    star = " ⭐ BEST" if name == best_model_name else ""
    print(f"   {name:<25} {acc:.2f}%{star}")

print("═" * 50)
print(f"\n   Winner: {best_model_name} ({results[best_model_name]:.2f}%)")

# ─── Save Best Model ──────────────────────────────────
print("\nSaving best model...")

if best_model_name == "Isolation Forest":
    best_model = iso_model
elif best_model_name == "Random Forest":
    best_model = rf_model
else:
    best_model = lof_model

with open("model.pkl", "wb") as f:
    pickle.dump(best_model, f)

with open("scaler.pkl", "wb") as f:
    pickle.dump(scaler, f)

with open("cicids_features.pkl", "wb") as f:
    pickle.dump(features, f)

# Save results for dashboard
with open("model_results.json", "w") as f:
    json.dump({
        "results": results,
        "best_model": best_model_name,
        "best_accuracy": results[best_model_name]
    }, f)

print(f"✅ Best model saved: {best_model_name}")
print(f"✅ model_results.json saved for dashboard")
print("\nLevel 8 Complete! 🎉")
print("═" * 50)
