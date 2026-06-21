import pandas as pd
from sklearn.ensemble import IsolationForest
import pickle

# Load the data we generated
df = pd.read_csv("company_data.csv")

# Select features for the model
features = ["login_attempts", "network_traffic_mb", "data_transfer_gb", "hour_of_day"]
X = df[features]

# Train Isolation Forest model
model = IsolationForest(
    n_estimators=100,
    contamination=0.02,
    random_state=42
)
model.fit(X)

# Save the model so we dont retrain every time
with open("model.pkl", "wb") as f:
    pickle.dump(model, f)

print("Model trained successfully!")
print("Model saved as model.pkl")