from flask import Flask, jsonify
import random
from datetime import datetime

app = Flask(__name__)

threats = [
    "C2 Communication",
    "Beaconing Activity",
    "DNS Tunneling",
    "Suspicious Connection",
    "Data Exfiltration Attempt"
]

severity_levels = [
    "LOW",
    "MEDIUM",
    "HIGH"
]

ips = [
    "45.33.21.9",
    "91.22.11.6",
    "102.54.33.1",
    "77.88.12.4",
    "185.44.76.2"
]

@app.route('/')
def home():
    return "DroidWatch AI Running"

@app.route('/network-analysis')
def network_analysis():

    logs = []

    for i in range(5):

        log = {
            "timestamp": datetime.now().strftime("%H:%M:%S"),
            "source_ip": f"192.168.1.{random.randint(2, 20)}",
            "destination_ip": random.choice(ips),
            "threat": random.choice(threats),
            "severity": random.choice(severity_levels),
            "action_taken": random.choice(["Blocked", "Monitored", "Quarantined"]),
            "threat_score": random.randint(50,100)
        }

        logs.append(log)

    return jsonify(logs)

if __name__ == '__main__':
    app.run(debug=True)