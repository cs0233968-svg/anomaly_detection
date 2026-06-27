import pickle
import pandas as pd
from sklearn.ensemble import IsolationForest
from sklearn.preprocessing import StandardScaler

print("Loading dataset...")
df = pd.read_csv("data/cicids2017.csv")
print(f"Total records: {len(df)}")

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

print("Scaling data...")
scaler = StandardScaler()
X_scaled = scaler.fit_transform(X)

print("Training Isolation Forest...")
model = IsolationForest(
    n_estimators=200,
    contamination=0.2,
    random_state=42,
    n_jobs=-1
)
model.fit(X_scaled)

# Test accuracy
y_true = df["Label"].apply(lambda x: 1 if x != "BENIGN" else 0)
preds = model.predict(X_scaled)
preds_binary = [1 if p == -1 else 0 for p in preds]
correct = sum(1 for a, b in zip(y_true, preds_binary) if a == b)
accuracy = (correct / len(df)) * 100

print(f"Accuracy: {accuracy:.2f}%")

# Save model
pickle.dump(model, open("model.pkl", "wb"))
pickle.dump(scaler, open("scaler.pkl", "wb"))
pickle.dump(features, open("cicids_features.pkl", "wb"))

print("Isolation Forest saved as model.pkl!")
print("Now restart live_capture.py to use new model.")
