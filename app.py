from flask import Flask, render_template, jsonify
import pandas as pd
import os
import subprocess
import sys

app = Flask(__name__)
# Clear old data on every restart
if os.path.exists("live_results.csv"):
    os.remove("live_results.csv")
if os.path.exists("login_logs.csv"):
    os.remove("login_logs.csv")
    
capture_process = None

@app.route("/")
def dashboard():
    if os.path.exists("live_results.csv"):
        df = pd.read_csv("live_results.csv")
        if "src_ip" in df.columns:
            df["employee_id"] = df["src_ip"]
        if "severity" not in df.columns:
            df["severity"] = "LOW"
        df["source"] = "Live WiFi"
    else:
        df = pd.DataFrame(columns=["status", "severity", "employee_id",
                                   "dst_ip", "protocol", "network_traffic_mb",
                                   "data_transfer_gb", "hour_of_day"])

    total = len(df)
    anomalies = len(df[df["status"] == "ANOMALY"])
    normal = len(df[df["status"] == "NORMAL"])

    anomaly_df = df[df["status"] == "ANOMALY"]
    low_count = len(anomaly_df[anomaly_df["severity"] == "LOW"])
    medium_count = len(anomaly_df[anomaly_df["severity"] == "MEDIUM"])
    high_count = len(anomaly_df[anomaly_df["severity"] == "HIGH"])

    anomaly_records = anomaly_df.to_dict("records")

    anomalies_only = df[df["status"] == "ANOMALY"]
    normal_only = df[df["status"] == "NORMAL"].tail(100)
    all_records = pd.concat([anomalies_only, normal_only]).sort_index().to_dict("records")

    if os.path.exists("login_logs.csv"):
        login_df = pd.read_csv("login_logs.csv")
        login_records = login_df.tail(20).to_dict("records")
    else:
        login_records = []

    return render_template(
        "dashboard.html",
        total=total,
        anomalies=anomalies,
        normal=normal,
        anomaly_records=anomaly_records,
        all_records=all_records,
        low_count=low_count,
        medium_count=medium_count,
        high_count=high_count,
        login_records=login_records
    )

@app.route("/start_capture")
def start_capture():
    global capture_process
    if capture_process is None or capture_process.poll() is not None:
        capture_process = subprocess.Popen([sys.executable, "live_capture.py"])
        return jsonify({"status": "started"})
    return jsonify({"status": "already running"})

@app.route("/stop_capture")
def stop_capture():
    global capture_process
    if capture_process and capture_process.poll() is None:
        capture_process.terminate()
        capture_process = None
        return jsonify({"status": "stopped"})
    return jsonify({"status": "not running"})

if __name__ == "__main__":
  app.run(debug=True, port=8080)