from flask import Flask, render_template
import pandas as pd
import os

app = Flask(__name__)

@app.route("/")
def dashboard():
    frames = []

    if os.path.exists("kdd_results.csv"):
        kdd = pd.read_csv("kdd_results.csv")
        kdd["source"] = "KDD Dataset"
        kdd["dst_ip"] = "-"
        kdd["protocol"] = "-"
        frames.append(kdd)

    if os.path.exists("live_results.csv"):
        live = pd.read_csv("live_results.csv")
        live["source"] = "Live WiFi"
        if "src_ip" in live.columns:
            live["employee_id"] = live["src_ip"]
        if "severity" not in live.columns:
            live["severity"] = "LOW"
        frames.append(live)

    if frames:
        df = pd.concat(frames, ignore_index=True)
    else:
        df = pd.DataFrame(columns=["status", "severity"])

    total = len(df)
    anomalies = len(df[df["status"] == "ANOMALY"])
    normal = len(df[df["status"] == "NORMAL"])

    anomaly_df = df[df["status"] == "ANOMALY"]
    low_count = len(anomaly_df[anomaly_df["severity"] == "LOW"])
    medium_count = len(anomaly_df[anomaly_df["severity"] == "MEDIUM"])
    high_count = len(anomaly_df[anomaly_df["severity"] == "HIGH"])

    anomaly_records = anomaly_df.to_dict("records")

    return render_template(
        "dashboard.html",
        total=total,
        anomalies=anomalies,
        normal=normal,
        anomaly_records=anomaly_records,
        low_count=low_count,
        medium_count=medium_count,
        high_count=high_count
    )

if __name__ == "__main__":
    app.run(debug=True)