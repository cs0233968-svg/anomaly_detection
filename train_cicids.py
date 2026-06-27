import pandas as pd
import numpy as np
from sklearn.ensemble import IsolationForest
from sklearn.preprocessing import StandardScaler
import pickle
import os

print("Loading CICIDS2017 dataset...")
df = pd.read_csv("data/cicids2017.csv")

print(f"Total records: {len(df)}")
print(f"Attack types:\n{df['Label'].value_counts()}\n")

# Features to train on
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

# Scale the data
print("Scaling data...")
scaler = StandardScaler()
X_scaled = scaler.fit_transform(X)

# Train Isolation Forest
print("Training Isolation Forest on CICIDS2017...")
model = IsolationForest(
    n_estimators=200,
    contamination=0.05,
    random_state=42,
    n_jobs=-1
)
model.fit(X_scaled)

# Test accuracy
df["prediction"] = model.predict(X_scaled)
df["predicted_label"] = df["prediction"].apply(
    lambda x: "ANOMALY" if x == -1 else "NORMAL"
)

# Real labels
df["real_label"] = df["Label"].apply(
    lambda x: "NORMAL" if x == "BENIGN" else "ANOMALY"
)

correct = len(df[df["predicted_label"] == df["real_label"]])
accuracy = (correct / len(df)) * 100

print(f"\nModel trained successfully!")
print(f"Accuracy: {accuracy:.2f}%")
print(f"Correct predictions: {correct}/{len(df)}")

# Save model and scaler together
print("\nSaving model...")
with open("model.pkl", "wb") as f:
    pickle.dump(model, f)

with open("scaler.pkl", "wb") as f:
    pickle.dump(scaler, f)

with open("cicids_features.pkl", "wb") as f:
    pickle.dump(features, f)

print("Saved: model.pkl")
print("Saved: scaler.pkl")
print("Saved: cicids_features.pkl")
print("\nLevel 7 Complete! Model is now trained on CICIDS2017 dataset 🎉")
