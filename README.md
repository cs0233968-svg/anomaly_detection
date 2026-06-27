Sentinel - AI-Powered Network Anomaly Detection System

Sentinel is a real-time AI-powered Network Anomaly Detection System designed to assist Security Operations Center (SOC) analysts in monitoring network traffic, detecting suspicious activity, and responding to potential threats.

The application captures live network packets using Scapy, extracts relevant traffic features, classifies packets using machine learning models trained on the CICIDS2017 dataset, visualizes traffic through a web dashboard, and generates automated security alerts.

---

Features

- Live packet capture using Scapy
- Real-time network traffic monitoring
- Machine learning-based anomaly detection
- Random Forest classifier trained on the CICIDS2017 dataset
- Comparison of Random Forest, Isolation Forest, and Local Outlier Factor models
- Real-time Flask web dashboard
- Live packet statistics and anomaly tracking
- Interactive traffic visualization
- Email alerts for detected threats
- Configurable alert cooldown mechanism
- Windows Security Event Log monitoring
- Failed login detection
- Login activity logging
- Geo-IP lookup with country, city, and ISP information
- Administrator-defined high-risk country prioritization
- Network traffic history and event logging

---

Attack Types Detected

- Distributed Denial of Service (DDoS)
- DoS Hulk
- Port Scanning
- FTP Brute Force
- SSH Brute Force
- Web Attacks
- Network Anomalies

---

Machine Learning Models

The following machine learning models were evaluated during development:

Model| Purpose
Random Forest| Primary detection model
Isolation Forest| Unsupervised anomaly detection
Local Outlier Factor| Anomaly detection comparison

Random Forest produced the best overall performance and was selected for deployment.

---

Technology Stack

Programming Language

- Python

Backend

- Flask

Machine Learning

- Scikit-learn
- Random Forest
- Isolation Forest
- Local Outlier Factor

Networking

- Scapy

Data Processing

- Pandas
- NumPy

Frontend

- HTML
- CSS
- JavaScript
- Chart.js

Additional Services

- Gmail SMTP
- ip-api.com

---

Project Structure

Sentinel/
│
├── templates/
│   └── dashboard.html
│
├── static/
│   ├── css/
│   ├── js/
│   └── images/
│
├── data/
│   └── cicids2017.csv
│
├── app.py
├── live_capture.py
├── login_monitor.py
├── train_cicids.py
├── compare_models.py
├── generate_cicids.py
├── model.pkl
├── scaler.pkl
├── cicids_features.pkl
├── model_results.json
├── requirements.txt
├── start.bat
└── README.md

---

Installation

Prerequisites

- Python 3.10 or later
- Windows Operating System
- Npcap

Clone the Repository

git clone https://github.com/cs0233968-svg/anomaly_detection.git

cd anomaly_detection

Install Dependencies

pip install -r requirements.txt

Train the Machine Learning Model

python generate_cicids.py

python train_cicids.py

Compare Machine Learning Models

python compare_models.py

Run the Application

python app.py

Or launch using:

start.bat

Open your browser and navigate to:

http://localhost:8080

---

Email Alert Configuration

1. Enable Two-Step Verification for your Gmail account.
2. Generate an App Password.
3. Update the following values in "live_capture.py":

SENDER_EMAIL = "your_email@gmail.com"

APP_PASSWORD = "your_app_password"

Email alerts include:

- Timestamp
- Source IP
- Destination IP
- Threat Severity
- Predicted Attack Type

A cooldown mechanism is implemented to prevent excessive alert generation.

---

Geo-IP Intelligence

The project uses the ip-api.com service to retrieve:

- Country
- City
- ISP

Traffic originating from administrator-defined watchlist countries can be assigned higher investigation priority.

---

Skills Demonstrated

- Network Security
- Packet Analysis
- Machine Learning
- Python Development
- Flask Development
- Dashboard Development
- Data Analysis
- Windows Event Monitoring
- Network Monitoring
- Security Automation
- Threat Detection

---

Use Cases

- Security Operations Center (SOC)
- Enterprise Network Monitoring
- Academic Cybersecurity Projects
- Security Research
- Threat Detection
- Intrusion Detection
- Cybersecurity Demonstrations

---

Future Improvements

- Deep Learning Models
- Docker Deployment
- REST API
- Elasticsearch Integration
- Kibana Dashboards
- Zeek Integration
- Suricata Integration
- SIEM Integration
- Threat Intelligence Feeds
- PDF Report Generation
- Multi-user Authentication
- Role-Based Access Control

---

Disclaimer

This project is intended for educational, research, and authorized network monitoring purposes only. Users are responsible for ensuring they have permission to monitor any network on which the software is deployed.

---

Author

Chandveer Singh

B.Sc. Cyber Security Student

GitHub: https://github.com/cs0233968-svg

Email: cs0233968@gmail.com

---

License

Copyright © 2026 Chandveer Singh.

All Rights Reserved.

This software and its source code are proprietary and confidential. Unauthorized copying, modification, distribution, reverse engineering, or commercial use of this software, in whole or in part, without prior written permission from the author is strictly prohibited.