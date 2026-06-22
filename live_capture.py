from scapy.all import sniff, IP, TCP, UDP, ICMP, ARP
import pandas as pd
import pickle
import datetime
import os

# Load our trained model
with open("model.pkl", "rb") as f:
    model = pickle.load(f)

# Our WiFi interface
INTERFACE = "\\Device\\NPF_{F3F0FC89-D7FC-4801-8A5A-73C4354DF220}"

# Store captured packets
captured = []

def analyze_packet(packet):
    if IP in packet:
        src_ip = packet[IP].src
        dst_ip = packet[IP].dst
        size = len(packet)
        hour = datetime.datetime.now().hour

        if TCP in packet:
            protocol = "TCP"
        elif UDP in packet:
            protocol = "UDP"
        elif ICMP in packet:
            protocol = "ICMP"
        elif ARP in packet:
            protocol = "ARP"
        else:
            protocol = "OTHER"

        record = {
            "login_attempts": 0,
            "network_traffic_mb": size / 1024,
            "data_transfer_gb": size / (1024 * 1024),
            "hour_of_day": hour
        }

        df = pd.DataFrame([record])
        prediction = model.predict(df)[0]
        status = "ANOMALY" if prediction == -1 else "NORMAL"

        print(f"[{status}] {src_ip} → {dst_ip} | {protocol} | {size} bytes")

        record["employee_id"] = src_ip
        record["src_ip"] = src_ip
        record["dst_ip"] = dst_ip
        record["protocol"] = protocol
        record["status"] = status
        record["severity"] = "LOW"
        captured.append(record)

        if len(captured) % 10 == 0:
            new_df = pd.DataFrame(captured)
            if os.path.exists("live_results.csv"):
                existing_df = pd.read_csv("live_results.csv")
                combined_df = pd.concat([existing_df, new_df], ignore_index=True)
                combined_df.to_csv("live_results.csv", index=False)
            else:
                new_df.to_csv("live_results.csv", index=False)
            print(f"--- Saved {len(captured)} packets ---")

print("Starting live capture on your WiFi...")
print("Press Ctrl+C to stop\n")

sniff(iface=INTERFACE, prn=analyze_packet, store=0)