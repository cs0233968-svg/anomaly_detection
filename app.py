from flask import Flask, render_template, jsonify
import pandas as pd
import os
import subprocess
import sys
import signal
import json
import psutil

app = Flask(__name__)

# Clear old data on every restart
if os.path.exists("live_results.csv"):
    os.remove("live_results.csv")
if os.path.exists("login_logs.csv"):
    os.remove("login_logs.csv")

capture_process = None
login_process = None

def kill_process(proc):
    """Force kill a process and all its children"""
    if proc is None:
        return
    try:
        parent = psutil.Process(proc.pid)
        children = parent.children(recursive=True)
        for child in children:
            child.kill()
        parent.kill()
    except Exception as e:
        print(f"Kill error: {e}")
        try:
            proc.kill()
        except:
            pass

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

    for record in all_records:
        if "data_transfer_gb" in record:
            record["data_transfer_gb"] = round(float(record["data_transfer_gb"]), 4)
        if "network_traffic_mb" in record:
            record["network_traffic_mb"] = round(float(record["network_traffic_mb"]), 4)

    if os.path.exists("login_logs.csv"):
        login_df = pd.read_csv("login_logs.csv")
        login_records = login_df.tail(20).to_dict("records")
    else:
        login_records = []

    capture_running = capture_process is not None and capture_process.poll() is None

    if os.path.exists("model_results.json"):
        with open("model_results.json") as f:
            model_data = json.load(f)
        model_results = model_data["results"]
        best_model = model_data["best_model"]
        best_accuracy = model_data["best_accuracy"]
    else:
        model_results = {}
        best_model = "Isolation Forest"
        best_accuracy = 80.74

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
        login_records=login_records,
        capture_running=capture_running,
        model_results=model_results,
        best_model=best_model,
        best_accuracy=best_accuracy,
    )

@app.route("/start_capture")
def start_capture():
    global capture_process, login_process

    if capture_process is None or capture_process.poll() is not None:
        capture_process = subprocess.Popen([sys.executable, "live_capture.py"])

    if login_process is None or login_process.poll() is not None:
        if os.path.exists("login_monitor.py"):
            login_process = subprocess.Popen([sys.executable, "login_monitor.py"])

    return jsonify({"status": "started"})

@app.route("/stop_capture")
def stop_capture():
    global capture_process, login_process

    kill_process(capture_process)
    capture_process = None

    kill_process(login_process)
    login_process = None

    # Extra safety - kill any remaining python processes running our scripts
    for proc in psutil.process_iter(['pid', 'name', 'cmdline']):
        try:
            cmdline = proc.info['cmdline']
            if cmdline and any('live_capture.py' in c or 'login_monitor.py' in c for c in cmdline):
                proc.kill()
        except:
            pass

    return jsonify({"status": "stopped"})

@app.route("/status")
def status():
    capture_running = capture_process is not None and capture_process.poll() is None
    return jsonify({"capture_running": capture_running})

if __name__ == "__main__":
    app.run(debug=True, port=8080)
