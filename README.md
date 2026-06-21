# 🔐 AI-Based Corporate Anomaly Detection System

A real-time network anomaly detection system built with Python, Machine Learning, and Flask.

## 📌 What It Does
- Captures live WiFi network packets using Scapy
- Detects anomalies using Isolation Forest ML algorithm
- Trained on real KDD Cup 99 cybersecurity dataset
- Displays results on a professional web dashboard
- Auto refreshes every 5 seconds
- Shows severity levels (LOW/MEDIUM/HIGH)

## 🛠️ Tech Stack
- Python
- Scikit-learn (Isolation Forest)
- Flask (Web Dashboard)
- Scapy (Live Packet Capture)
- Pandas & NumPy
- Chart.js (Visualizations)

## 📊 Dataset
- KDD Cup 99 Network Intrusion Dataset
- Live WiFi packet capture

## 🚀 How To Run
1. Install requirements:
pip install pandas numpy scikit-learn flask scapy

2. Generate data:
python data_generator.py

3. Train model:
python model.py

4. Run detection:
python detector.py

5. Start dashboard:
python app.py

6. Open browser:
http://127.0.0.1:5000

## 👨‍💻 Author
Chandveer Singh
BSc Cyber Security — Chandigarh Group of Colleges