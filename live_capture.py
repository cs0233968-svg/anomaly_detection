from scapy.all import sniff, IP, TCP, UDP, ICMP, ARP, get_if_list, get_if_addr
import pandas as pd
import pickle
import datetime
import os
import time
import smtplib
import requests
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart

# ─── Email Config ───────────────────────────────────────────
SENDER_EMAIL = "cs0233968@gmail.com"
RECEIVER_EMAIL = "cs0233968@gmail.com"
APP_PASSWORD = "uuysetmckeighttm"

# ─── Email Cooldown ─────────────────────────────────────────
last_email_time = 0
EMAIL_COOLDOWN = 300

# ─── Geo IP Cache ───────────────────────────────────────────
geo_cache = {}

# ─── Load Model ─────────────────────────────────────────────
with open("model.pkl", "rb") as f:
    model = pickle.load(f)

with open("scaler.pkl", "rb") as f:
    scaler = pickle.load(f)

with open("cicids_features.pkl", "rb") as f:
    features = pickle.load(f)

print("Model loaded: CICIDS2017 Random Forest")

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

# ─── Flag Emoji ─────────────────────────────────────────────
def get_flag(country_code):
    flags = {
        "IN": "🇮🇳", "US": "🇺🇸", "CN": "🇨🇳", "RU": "🇷🇺",
        "DE": "🇩🇪", "GB": "🇬🇧", "FR": "🇫🇷", "JP": "🇯🇵",
        "KR": "🇰🇷", "BR": "🇧🇷", "AU": "🇦🇺", "CA": "🇨🇦",
        "NL": "🇳🇱", "SG": "🇸🇬", "HK": "🇭🇰", "IT": "🇮🇹",
        "ES": "🇪🇸", "SE": "🇸🇪", "NO": "🇳🇴", "PK": "🇵🇰",
        "IR": "🇮🇷", "UA": "🇺🇦", "TR": "🇹🇷", "LN": "🏠"
    }
    return flags.get(country_code, "🌐")

# ─── Geo IP Lookup ───────────────────────────────────────────
def get_geo_ip(ip):
    # Skip private IPs
    if (ip.startswith("192.168.") or
        ip.startswith("10.") or
        ip.startswith("172.") or
        ip.startswith("127.") or
        ip.startswith("224.") or
        ip.startswith("255.")):
        return {
            "country": "Local Network",
            "country_code": "LN",
            "city": "Private",
            "flag": "🏠"
        }

    # Check cache first
    if ip in geo_cache:
        return geo_cache[ip]

    try:
        response = requests.get(
            f"http://ip-api.com/json/{ip}",
            timeout=5
        )
        data = response.json()

        if data["status"] == "success":
            country_code = data.get("countryCode", "??")
            result = {
                "country": data.get("country", "Unknown"),
                "country_code": country_code,
                "city": data.get("city", "Unknown"),
                "flag": get_flag(country_code)
            }
        else:
            result = {
                "country": "Unknown",
                "country_code": "??",
                "city": "Unknown",
                "flag": "🌐"
            }

        geo_cache[ip] = result
        return result

    except:
        return {
            "country": "Unknown",
            "country_code": "??",
            "city": "Unknown",
            "flag": "🌐"
        }

# ─── High Risk Countries ─────────────────────────────────────
HIGH_RISK_COUNTRIES = ["CN", "RU", "KP", "IR"]

# ─── Email Alert ─────────────────────────────────────────────
def send_alert_email(src_ip, dst_ip, protocol, severity, country, city):
    global last_email_time

    current_time = time.time()
    if current_time - last_email_time < EMAIL_COOLDOWN:
        remaining = int(EMAIL_COOLDOWN - (current_time - last_email_time))
        print(f"📧 Cooldown active — next email in {remaining}s")
        return

    last_email_time = current_time

    subject = f"🚨 ANOMALY DETECTED - Sentinel Alert [{country}]"
    body = f"""
⚠️ ANOMALY DETECTED on your network!

Source IP      : {src_ip}
Location       : {city}, {country}
Destination IP : {dst_ip}
Protocol       : {protocol}
Severity       : {severity}
Time           : {datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')}

Note: Max 1 alert per 5 minutes.
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
        print(f"📧 Alert sent! [{country}] {src_ip}")
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

        # Geo IP lookup
        geo = get_geo_ip(src_ip)
        country = geo["country"]
        country_code = geo["country_code"]
        city = geo["city"]
        flag = geo["flag"]

        # ML prediction
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

        df = pd.DataFrame([record])[features]
        df_scaled = scaler.transform(df)
        prediction = model.predict(df_scaled)[0]

        if prediction not in [-1, 1]:
            status = "ANOMALY" if prediction == 1 else "NORMAL"
        else:
            status = "ANOMALY" if prediction == -1 else "NORMAL"

        # Auto HIGH for high risk countries
        if country_code in HIGH_RISK_COUNTRIES:
            severity = "HIGH"
            status = "ANOMALY"
        elif size > 1000:
            severity = "HIGH"
        elif size > 500:
            severity = "MEDIUM"
        else:
            severity = "LOW"

        print(f"[{status}] {flag} {src_ip} ({city}, {country}) → {dst_ip} | {protocol} | {size}b | {severity}")

        if status == "ANOMALY":
            send_alert_email(src_ip, dst_ip, protocol, severity, country, city)

        full_record = {
            "employee_id": src_ip,
            "src_ip": src_ip,
            "dst_ip": dst_ip,
            "protocol": protocol,
            "network_traffic_mb": size / 1024,
            "data_transfer_gb": size / (1024 * 1024),
            "hour_of_day": hour,
            "status": status,
            "severity": severity,
            "country": country,
            "country_code": country_code,
            "city": city,
            "flag": flag,
            "timestamp": datetime.datetime.now().strftime('%H:%M:%S')
        }
        captured.append(full_record)

        if len(captured) % 10 == 0:
            pd.DataFrame(captured).to_csv("live_results.csv", index=False)
            print(f"--- Saved {len(captured)} packets ---")

# ─── Start Capture ───────────────────────────────────────────
print("\nStarting live capture with Geo IP...")
print("Email cooldown: 1 alert per 5 minutes")
print("Press Ctrl+C to stop\n")

try:
    sniff(iface=INTERFACE, prn=analyze_packet, store=0)
except KeyboardInterrupt:
    if captured:
        pd.DataFrame(captured).to_csv("live_results.csv", index=False)
        print(f"\nSaved {len(captured)} total packets. Goodbye!")
