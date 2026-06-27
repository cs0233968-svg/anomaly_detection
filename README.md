# Sentinel — AI Network Anomaly Detection System

![Python](https://img.shields.io/badge/Python-3.10+-blue)
![Flask](https://img.shields.io/badge/Flask-2.0+-green)
![ML](https://img.shields.io/badge/ML-Random%20Forest-orange)
![Dataset](https://img.shields.io/badge/Dataset-CICIDS2017-red)
![License](https://img.shields.io/badge/License-MIT-yellow)

A real-time AI-powered network anomaly detection system built for corporate SOC environments. Sentinel captures live network packets, classifies them using machine learning, geolocates source IPs, and sends instant email alerts when threats are detected.

---

## Features

- Live Packet Capture — Real-time WiFi traffic monitoring using Scapy
- AI Detection — Random Forest model trained on CICIDS2017 dataset (100% accuracy)
- Geo IP Lookup — Real-time country and city identification for every packet
- Email Alerts — Instant Gmail alerts with 5-minute cooldown to prevent spam
- Live Dashboard — Dark-themed web dashboard with real-time charts
- Login Monitor — Windows Security Event Log monitoring for failed logins
- Multi-Model Comparison — Compared Isolation Forest, Random Forest, and LOF
- High Risk Detection — Auto-escalates traffic from high-risk countries

---

## ML Models Compared

| Model | Accuracy |
|---|---|
| Random Forest | 100.00% (Best) |
| Isolation Forest | 80.74% |
| Local Outlier Factor | 67.60% |

---

## Attack Types Detected

- DDoS (Distributed Denial of Service)
- DoS Hulk
- Port Scanning
- FTP Brute Force
- SSH Brute Force
- Web Attacks

---

## Project Structure

```
anomaly_detection/
├── templates/
│   └── dashboard.html        # Live web dashboard
├── data/
│   └── cicids2017.csv        # CICIDS2017 dataset
├── app.py                    # Flask backend
├── live_capture.py           # Scapy packet capture + ML detection
├── login_monitor.py          # Windows login event monitor
├── compare_models.py         # Multi-model comparison
├── train_cicids.py           # Model training script
├── generate_cicids.py        # Dataset generation
├── model.pkl                 # Trained ML model
├── scaler.pkl                # Feature scaler
├── cicids_features.pkl       # Feature list
├── model_results.json        # Model comparison results
├── start.bat                 # One-click Windows launcher
└── requirements.txt          # Python dependencies
```

---

## Installation

### Prerequisites
- Python 3.10+
- Windows OS (for login monitoring)
- Npcap (for packet capture)

### Step 1: Clone the repository
```bash
git clone https://github.com/cs0233968-svg/anomaly_detection.git
cd anomaly_detection
```

### Step 2: Install dependencies
```bash
pip install -r requirements.txt
```

### Step 3: Train the model
```bash
python generate_cicids.py
python train_cicids.py
```

### Step 4: Run model comparison
```bash
python compare_models.py
```

### Step 5: Start Sentinel
```bash
# Right click start.bat and select Run as Administrator
```

Or manually:
```bash
python app.py
```

Open browser at: http://localhost:8080

---

## Email Alert Setup

1. Enable 2-Step Verification on Gmail
2. Go to myaccount.google.com/apppasswords
3. Generate app password
4. Update SENDER_EMAIL and APP_PASSWORD in live_capture.py

---

## Geo IP

Sentinel uses ip-api.com for real-time IP geolocation.
- Free API, no account needed
- Returns country, city, ISP
- Auto-escalates HIGH severity for traffic from high-risk countries (CN, RU, KP, IR)

---

## Tech Stack

- Python
- Scikit-learn (Random Forest, Isolation Forest, LOF)
- Flask (Web Dashboard)
- Scapy (Live Packet Capture)
- Pandas and NumPy
- Chart.js (Visualizations)
- ip-api.com (Geo IP Lookup)
- Gmail SMTP (Email Alerts)

---

## Use Cases

- Corporate network monitoring
- SOC analyst tool
- Network intrusion detection
- Security research
- Academic cybersecurity projects

## License

Copyright (c) 2026 Chandveer Singh. All Rights Reserved.

This software and its source code are proprietary and confidential.
Unauthorized copying, modification, distribution, or use of this
software, in whole or in part, without written permission from the
author is strictly prohibited.

For licensing inquiries contact: cs0233968@gmail.com
