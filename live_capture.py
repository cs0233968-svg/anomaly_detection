from scapy.all import sniff, IP, TCP, UDP
import pandas as pd
import pickle
import datetime

# Load our trained model
with open("model.pkl", "rb") as f:
    model = pickle.load(f)

# Our WiFi interface
INTERFACE = "\\Device\\NPF_{F3F0FC89-D7FC-4801-8A5A-73C4354DF220}"

# Store captured packets
captured = []

def analyze_packet(packet):
    if IP in packet:
        # Extract packet info
        src_ip = packet[IP].src
        dst_ip = packet[IP].dst
        size = len(packet)
        protocol = "TCP" if TCP in packet else "UDP" if UDP in packet else "OTHER"
        hour = datetime.datetime.now().hour

        # Prepare for model
        record = {
            "login_attempts": 0,
            "network_traffic_mb": size / 1024,
            "data_transfer_gb": size / (1024 * 1024),
            "hour_of_day": hour
        }

        # Run detection
        df = pd.DataFrame([record])
        prediction = model.predict(df)[0]
        status = "ANOMALY" if prediction == -1 else "NORMAL"

        # Print result
        print(f"[{status}] {src_ip} → {dst_ip} | {protocol} | {size} bytes | Hour: {hour}")

        # Save result
        record["src_ip"] = src_ip
        record["dst_ip"] = dst_ip
        record["protocol"] = protocol
        record["status"] = status
        captured.append(record)

        # Save to CSV every 10 packets
        if len(captured) % 10 == 0:
            pd.DataFrame(captured).to_csv("live_results.csv", index=False)
            print(f"--- Saved {len(captured)} packets ---")

print("Starting live capture on your WiFi...")
print("Press Ctrl+C to stop\n")

sniff(iface=INTERFACE, prn=analyze_packet, store=0)