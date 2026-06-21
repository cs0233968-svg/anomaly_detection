from flask import Flask, render_template
import pandas as pd
import os

app = Flask(__name__)

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
    all_records = df.to_dict("records")

    return render_template(
        "dashboard.html",
        total=total,
        anomalies=anomalies,
        normal=normal,
        anomaly_records=anomaly_records,
        all_records=all_records,
        low_count=low_count,
        medium_count=medium_count,
        high_count=high_count
    )

if __name__ == "__main__":
    app.run(debug=True)