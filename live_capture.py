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

# ─── Load Trained Model ─────────────────────────────────────
with open("model.pkl", "rb") as f:
    model = pickle.load(f)

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

-- Sentinel Anomaly Detection System
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
        elif UDP in packet:
            protocol = "UDP"
        elif ICMP in packet:
            protocol = "ICMP"
        elif ARP in packet:
            protocol = "ARP"
        else:
            protocol = "OTHER"

        # Prepare features for model
        record = {
            "login_attempts": 0,
            "network_traffic_mb": size / 1024,
            "data_transfer_gb": size / (1024 * 1024),
            "hour_of_day": hour
        }

        # Predict anomaly
        df = pd.DataFrame([record])
        prediction = model.predict(df)[0]
        status = "ANOMALY" if prediction == -1 else "NORMAL"

        # Assign severity based on packet size
        if size > 1000:
            severity = "HIGH"
        elif size > 500:
            severity = "MEDIUM"
        else:
            severity = "LOW"

        print(f"[{status}] {src_ip} → {dst_ip} | {protocol} | {size} bytes | {severity}")

        # Send email alert only for anomalies
        if status == "ANOMALY":
            send_alert_email(src_ip, dst_ip, protocol, severity)

        # Store full record
        record["employee_id"] = src_ip
        record["src_ip"] = src_ip
        record["dst_ip"] = dst_ip
        record["protocol"] = protocol
        record["status"] = status
        record["severity"] = severity
        captured.append(record)

        # Save every 10 packets
        if len(captured) % 10 == 0:
            pd.DataFrame(captured).to_csv("live_results.csv", index=False)
            print(f"--- Saved {len(captured)} packets ---")

# ─── Start Capture ───────────────────────────────────────────
print("Starting live capture...")
print("Press Ctrl+C to stop\n")

try:
    sniff(iface=INTERFACE, prn=analyze_packet, store=0)
except KeyboardInterrupt:
    if captured:
        pd.DataFrame(captured).to_csv("live_results.csv", index=False)
        print(f"\nSaved {len(captured)} total packets. Goodbye!")
