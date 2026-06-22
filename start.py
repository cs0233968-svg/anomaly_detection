import subprocess
import sys
import time

print("Starting Anomaly Detection System...")

# Start live capture in background
capture = subprocess.Popen([sys.executable, "live_capture.py"])

# Wait 2 seconds
time.sleep(2)

# Start flask dashboard
print("Opening dashboard at http://127.0.0.1:5000")
subprocess.run([sys.executable, "app.py"])