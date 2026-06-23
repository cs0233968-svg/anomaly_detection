import pandas as pd
import numpy as np
import os

print("Generating CICIDS2017 synthetic dataset...")

np.random.seed(42)
n_normal = 8000
n_attack = 2000
total = n_normal + n_attack

# Normal traffic
normal = pd.DataFrame({
    "Flow Duration":        np.random.randint(1000, 100000, n_normal),
    "Total Fwd Packets":    np.random.randint(1, 20, n_normal),
    "Total Bwd Packets":    np.random.randint(1, 15, n_normal),
    "Fwd Packet Length Max":np.random.randint(20, 500, n_normal),
    "Bwd Packet Length Max":np.random.randint(20, 400, n_normal),
    "Flow Bytes/s":         np.random.uniform(100, 50000, n_normal),
    "Flow Packets/s":       np.random.uniform(1, 500, n_normal),
    "Flow IAT Mean":        np.random.uniform(100, 10000, n_normal),
    "Fwd IAT Mean":         np.random.uniform(100, 8000, n_normal),
    "Bwd IAT Mean":         np.random.uniform(100, 8000, n_normal),
    "Fwd PSH Flags":        np.random.randint(0, 2, n_normal),
    "Bwd PSH Flags":        np.random.randint(0, 2, n_normal),
    "Fwd URG Flags":        np.zeros(n_normal),
    "Bwd URG Flags":        np.zeros(n_normal),
    "Fwd Header Length":    np.random.randint(20, 60, n_normal),
    "Bwd Header Length":    np.random.randint(20, 60, n_normal),
    "Fwd Packets/s":        np.random.uniform(1, 200, n_normal),
    "Bwd Packets/s":        np.random.uniform(1, 150, n_normal),
    "Packet Length Mean":   np.random.uniform(50, 500, n_normal),
    "Packet Length Std":    np.random.uniform(10, 200, n_normal),
    "Label": "BENIGN"
})

# Attack traffic (DDoS, Brute Force, Web Attack patterns)
attack = pd.DataFrame({
    "Flow Duration":        np.random.randint(1, 5000, n_attack),
    "Total Fwd Packets":    np.random.randint(50, 5000, n_attack),
    "Total Bwd Packets":    np.random.randint(0, 10, n_attack),
    "Fwd Packet Length Max":np.random.randint(1, 100, n_attack),
    "Bwd Packet Length Max":np.random.randint(0, 50, n_attack),
    "Flow Bytes/s":         np.random.uniform(100000, 10000000, n_attack),
    "Flow Packets/s":       np.random.uniform(1000, 100000, n_attack),
    "Flow IAT Mean":        np.random.uniform(1, 100, n_attack),
    "Fwd IAT Mean":         np.random.uniform(1, 50, n_attack),
    "Bwd IAT Mean":         np.random.uniform(1, 50, n_attack),
    "Fwd PSH Flags":        np.random.randint(0, 2, n_attack),
    "Bwd PSH Flags":        np.zeros(n_attack),
    "Fwd URG Flags":        np.random.randint(0, 2, n_attack),
    "Bwd URG Flags":        np.zeros(n_attack),
    "Fwd Header Length":    np.random.randint(20, 40, n_attack),
    "Bwd Header Length":    np.random.randint(0, 20, n_attack),
    "Fwd Packets/s":        np.random.uniform(1000, 50000, n_attack),
    "Bwd Packets/s":        np.random.uniform(0, 100, n_attack),
    "Packet Length Mean":   np.random.uniform(1, 100, n_attack),
    "Packet Length Std":    np.random.uniform(1, 50, n_attack),
    "Label": np.random.choice(
        ["DDoS", "DoS Hulk", "PortScan", "FTP-Patator", "SSH-Patator", "Web Attack"],
        n_attack
    )
})

# Combine and shuffle
df = pd.concat([normal, attack], ignore_index=True)
df = df.sample(frac=1, random_state=42).reset_index(drop=True)

# Save
os.makedirs("data", exist_ok=True)
df.to_csv("data/cicids2017.csv", index=False)

print(f"Dataset generated successfully!")
print(f"Total records : {len(df)}")
print(f"Normal traffic: {n_normal}")
print(f"Attack traffic: {n_attack}")
print(f"Attack types  : DDoS, DoS, PortScan, FTP-Patator, SSH-Patator, Web Attack")
print(f"Saved to      : data/cicids2017.csv")
