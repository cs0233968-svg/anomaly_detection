from scapy.all import sniff, IP, TCP, UDP, ICMP, ARP, get_if_list, get_if_addr
import pandas as pd
import pickle
import datetime
import os
import smtplib
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart

# ─── Email Config ───────────────────────────────────────────
SENDER_EMAIL = "cs0233968@gmail.com"
RECEIVER_EMAIL = "cs0233968@gmail.com"
APP_PASSWORD = "uuysetmckeighttm"

# ─── Load Model, Scaler and Features ────────────────────────
with open("model.pkl", "rb") as f:
    model = pickle.load(f)

with open("scaler.pkl", "rb") as f:
    scaler = pickle.load(f)

with open("cicids_features.pkl", "rb") as f:
    features = pickle.load(f)

print("Model loaded: CICIDS2017 Isolation Forest")
print(f"Features: {len(features)} features")

# ─── Auto Detect WiFi Interface ─────────────────────────────
def get_wifi_interface():
    interfaces = get_if_list()
    for iface in interfaces:
        try:
            ip = get_if_addr(iface)
            if ip.startswith("192.168."):
                return iface
        except:
            continue
    return interfaces[0]

INTERFACE = get_wifi_interface()
print(f"Using interface: {INTERFACE}")

# ─── Clear Old Data ─────────────────────────────────────────
if os.path.exists("live_results.csv"):
    os.remove("live_results.csv")
    print("Old data cleared!")

# ─── Email Alert Function ────────────────────────────────────
def send_alert_email(src_ip, dst_ip, protocol, severity):
    subject = "🚨 ANOMALY DETECTED - Sentinel Alert"
    body = f"""
⚠️ ANOMALY DETECTED on your network!

Source IP      : {src_ip}
Destination IP : {dst_ip}
Protocol       : {protocol}
Severity       : {severity}
Time           : {datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')}

-- Sentinel Anomaly Detection System (CICIDS2017 Model)
    """

    msg = MIMEMultipart()
    msg["From"] = SENDER_EMAIL
    msg["To"] = RECEIVER_EMAIL
    msg["Subject"] = subject
    msg.attach(MIMEText(body, "plain"))

    try:
        server = smtplib.SMTP("smtp.gmail.com", 587)
        server.starttls()
        server.login(SENDER_EMAIL, APP_PASSWORD)
        server.sendmail(SENDER_EMAIL, RECEIVER_EMAIL, msg.as_string())
        server.quit()
        print(f"📧 Alert email sent for {src_ip}!")
    except Exception as e:
        print(f"Email error: {e}")

# ─── Packet Storage ──────────────────────────────────────────
captured = []

# ─── Analyze Each Packet ─────────────────────────────────────
def analyze_packet(packet):
    if IP in packet:
        src_ip = packet[IP].src
        dst_ip = packet[IP].dst
        size = len(packet)
        hour = datetime.datetime.now().hour

        # Detect protocol
        if TCP in packet:
            protocol = "TCP"
            fwd_packets = packet[TCP].seq % 20 + 1
            bwd_packets = packet[TCP].ack % 15 + 1
        elif UDP in packet:
            protocol = "UDP"
            fwd_packets = 3
            bwd_packets = 2
        elif ICMP in packet:
            protocol = "ICMP"
            fwd_packets = 1
            bwd_packets = 1
        else:
            protocol = "OTHER"
            fwd_packets = 1
            bwd_packets = 0

        # Build CICIDS2017 style features
        record = {
            "Flow Duration":         size * 10,
            "Total Fwd Packets":     fwd_packets,
            "Total Bwd Packets":     bwd_packets,
            "Fwd Packet Length Max": size,
            "Bwd Packet Length Max": size // 2,
            "Flow Bytes/s":          size * 100.0,
            "Flow Packets/s":        fwd_packets * 10.0,
            "Flow IAT Mean":         size * 5.0,
            "Fwd IAT Mean":          size * 3.0,
            "Bwd IAT Mean":          size * 2.0,
            "Packet Length Mean":    size / 2.0,
            "Packet Length Std":     size / 4.0,
        }

        # Scale and predict
        df = pd.DataFrame([record])[features]
        df_scaled = scaler.transform(df)
        prediction = model.predict(df_scaled)[0]
        status = "ANOMALY" if prediction == -1 else "NORMAL"

        # Assign severity
        if size > 1000:
            severity = "HIGH"
        elif size > 500:
            severity = "MEDIUM"
        else:
            severity = "LOW"

        print(f"[{status}] {src_ip} → {dst_ip} | {protocol} | {size} bytes | {severity}")

        # Send email for anomalies
        if status == "ANOMALY":
            send_alert_email(src_ip, dst_ip, protocol, severity)

        # Store record
        full_record = {
            "employee_id": src_ip,
            "src_ip": src_ip,
            "dst_ip": dst_ip,
            "protocol": protocol,
            "network_traffic_mb": size / 1024,
            "data_transfer_gb": size / (1024 * 1024),
            "hour_of_day": hour,
            "status": status,
            "severity": severity
        }
        captured.append(full_record)

        # Save every 10 packets
        if len(captured) % 10 == 0:
            pd.DataFrame(captured).to_csv("live_results.csv", index=False)
            print(f"--- Saved {len(captured)} packets ---")

# ─── Start Capture ───────────────────────────────────────────
print("\nStarting live capture with CICIDS2017 model...")
print("Press Ctrl+C to stop\n")

try:
    sniff(iface=INTERFACE, prn=analyze_packet, store=0)
except KeyboardInterrupt:
    if captured:
        pd.DataFrame(captured).to_csv("live_results.csv", index=False)
        print(f"\nSaved {len(captured)} total packets. Goodbye!")
