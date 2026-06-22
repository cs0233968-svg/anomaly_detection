import win32evtlog
import win32evtlogutil
import win32con
import pandas as pd
from datetime import datetime
import time
import os

def get_login_events():
    logs = []
    
    server = None
    log_type = "Security"
    
    try:
        hand = win32evtlog.OpenEventLog(server, log_type)
        flags = win32evtlog.EVENTLOG_BACKWARDS_READ | win32evtlog.EVENTLOG_SEQUENTIAL_READ
        
        events = win32evtlog.ReadEventLog(hand, flags, 0)
        
        for event in events:
            # 4624 = successful login
            # 4625 = failed login
            if event.EventID in [4624, 4625]:
                status = "SUCCESS" if event.EventID == 4624 else "FAILED"
                
                try:
                    username = event.StringInserts[5] if event.StringInserts else "Unknown"
                    ip = event.StringInserts[18] if len(event.StringInserts) > 18 else "-"
                except:
                    username = "Unknown"
                    ip = "-"
                
                logs.append({
                    "time": event.TimeGenerated.Format(),
                    "username": username,
                    "ip_address": ip,
                    "status": status,
                    "event_id": event.EventID
                })
                
                if len(logs) >= 50:
                    break
        
        win32evtlog.CloseEventLog(hand)
        
    except Exception as e:
        print(f"Error: {e}")
    
    return logs

print("Reading Windows login events...")
while True:
    logs = get_login_events()
    if logs:
        df = pd.DataFrame(logs)
        df.to_csv("login_logs.csv", index=False)
        print(f"Saved {len(logs)} login events")
    time.sleep(30)