import pandas as pd
import numpy as np
from sklearn.datasets import fetch_kddcup99

print("Loading real KDD Cup 99 dataset...")

# Load dataset
kdd = fetch_kddcup99(subset="SA", percent10=True, random_state=42)

# Convert to DataFrame
df = pd.DataFrame(kdd.data, columns=[
    "duration", "protocol_type", "service", "flag",
    "src_bytes", "dst_bytes", "land", "wrong_fragment",
    "urgent", "hot", "num_failed_logins", "logged_in",
    "num_compromised", "root_shell", "su_attempted",
    "num_root", "num_file_creations", "num_shells",
    "num_access_files", "num_outbound_cmds", "is_host_login",
    "is_guest_login", "count", "srv_count", "serror_rate",
    "srv_serror_rate", "rerror_rate", "srv_rerror_rate",
    "same_srv_rate", "diff_srv_rate", "srv_diff_host_rate",
    "dst_host_count", "dst_host_srv_count",
    "dst_host_same_srv_rate", "dst_host_diff_srv_rate",
    "dst_host_same_src_port_rate", "dst_host_srv_diff_host_rate",
    "dst_host_serror_rate", "dst_host_srv_serror_rate",
    "dst_host_rerror_rate", "dst_host_srv_rerror_rate"
])

# Add labels
df["attack_type"] = kdd.target.astype(str)

# Map to our project columns
df_mapped = pd.DataFrame()
df_mapped["employee_id"] = ["E" + str(i % 50).zfill(3) for i in range(len(df))]
df_mapped["login_attempts"] = pd.to_numeric(df["num_failed_logins"], errors="coerce").fillna(0)
df_mapped["network_traffic_mb"] = pd.to_numeric(df["src_bytes"], errors="coerce").fillna(0) / 1024
df_mapped["data_transfer_gb"] = pd.to_numeric(df["dst_bytes"], errors="coerce").fillna(0) / (1024 * 1024)
df_mapped["hour_of_day"] = np.random.randint(0, 24, len(df))
df_mapped["attack_type"] = df["attack_type"]

# Keep only 2000 records for speed
df_mapped = df_mapped.sample(2000, random_state=42).reset_index(drop=True)

# Save as company_data.csv (replaces fake data)
df_mapped.to_csv("company_data.csv", index=False)

print(f"Real data loaded successfully!")
print(f"Total records: {len(df_mapped)}")
print(f"\nAttack types found:")
print(df_mapped["attack_type"].value_counts())
print("\nSample data:")
print(df_mapped.head())