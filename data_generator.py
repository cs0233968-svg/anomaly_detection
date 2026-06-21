import pandas as pd
import numpy as np
import random

#set seed so data is same every time we run
np.random.seed(42)

#Number of records to generate
NUM_RECORDS = 1000

# Generate employee IDs
employees =[f"E{str(i).zfill(3)}" for i in range(1, 51)]

#generate normal data
data ={
    "employee_id": [random.choice(employees) for _ in range(NUM_RECORDS)],
    "login_attempts": np.random.randint(1, 5, NUM_RECORDS),
    "network_traffic_mb": np.random.uniform(10, 500, NUM_RECORDS),
    "data_transfer_gb": np.random.uniform(0.1, 2.0, NUM_RECORDS),
    "hour_of_day": np.random.randint(8, 18, NUM_RECORDS)
}

# Inject anomalies (suspicious behaviour)
for i in range(20):
    idx = random.randint(0, NUM_RECORDS - 1)
    data["login_attempts"][idx] = random.randint(20, 50)
    data["network_traffic_mb"][idx] = random.uniform(2000, 5000)
    data["data_transfer_gb"][idx] = random.uniform(10, 50)
    data["hour_of_day"][idx] = random.randint(0, 6)

# Convert to DataFrame
df = pd.DataFrame(data)

# Save to CSV
df.to_csv("company_data.csv", index=False)

print("Data generated successfully!")
print(df.head(10))
