import pandas as pd
import pickle

with open("model.pkl", "rb") as f:
    model = pickle.load(f)

df = pd.read_csv("company_data.csv")

features = ["login_attempts", "network_traffic_mb", "data_transfer_gb", "hour_of_day"]
X = df[features]

predictions = model.predict(X)
scores = model.decision_function(X)

def get_severity(score):
    if score > -0.1:
        return "LOW"
    elif score > -0.2:
        return "MEDIUM"
    else:
        return "HIGH"

df["status"] = ["ANOMALY" if p == -1 else "NORMAL" for p in predictions]
df["severity"] = [get_severity(s) if p == -1 else "-" for p, s in zip(predictions, scores)]

df.to_csv("kdd_results.csv", index=False)

total = len(df)
anomalies = len(df[df["status"] == "ANOMALY"])
normal = len(df[df["status"] == "NORMAL"])

print(f"Detection complete!")
print(f"Total: {total} | Normal: {normal} | Anomalies: {anomalies}")
print("\nSeverity breakdown:")
print(df[df["status"] == "ANOMALY"]["severity"].value_counts())
