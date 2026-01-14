from flask import Flask, jsonify, render_template #type:ignore
from scapy.all import sniff, IP, TCP, UDP #type:ignore
import threading
import time
import os
import joblib #type:ignore
from preprocess_function import preprocess_function #type:ignore
import warnings

warnings.filterwarnings("ignore")

app = Flask(__name__)
alerts = []

# Load your ML model
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
model = joblib.load(os.path.join(BASE_DIR, "nidsModel.pkl"))

# Optional: keep track of recent packet info (like before)
port_scan_tracker = {}
arp_cache = {}

def process_packet(packet):
    try:
        if not packet.haslayer(IP):
            return

        protocol_type = 1 if packet.haslayer(TCP) else 2 if packet.haslayer(UDP) else 0
        src_bytes = len(packet[IP].payload)

        # Build feature dictionary (same as realtime_nids.py)
        data = {
            'duration': 0,
            'protocol_type': protocol_type,
            'service': 1,
            'flag': 1,
            'src_bytes': src_bytes,
            'dst_bytes': 0,
            'land': 0,
            'wrong_fragment': 0,
            'urgent': 0,
            'hot': 0,
            'num_failed_logins': 0,
            'logged_in': 0,
            'num_compromised': 0,
            'root_shell': 0,
            'su_attempted': 0,
            'num_root': 0,
            'num_file_creations': 0,
            'num_shells': 0,
            'num_access_files': 0,
            'num_outbound_cmds': 0,
            'is_host_login': 0,
            'is_guest_login': 0,
            'count': 0,
            'srv_count': 0,
            'serror_rate': 0.0,
            'srv_serror_rate': 0.0,
            'rerror_rate': 0.0,
            'srv_rerror_rate': 0.0,
            'same_srv_rate': 0.0,
            'diff_srv_rate': 0.0,
            'srv_diff_host_rate': 0.0,
            'dst_host_count': 0,
            'dst_host_srv_count': 0,
            'dst_host_same_srv_rate': 0.0,
            'dst_host_diff_srv_rate': 0.0,
            'dst_host_same_src_port_rate': 0.0,
            'dst_host_srv_diff_host_rate': 0.0,
            'dst_host_serror_rate': 0.0,
            'dst_host_srv_serror_rate': 0.0,
            'dst_host_rerror_rate': 0.0,
            'dst_host_srv_rerror_rate': 0.0
        }

        # Preprocess and predict
        processed = [preprocess_function(data)]
        prediction = model.predict(processed)[0]

        timestamp = time.strftime("%Y-%m-%d %H:%M:%S")
        alert = {
            "timestamp": timestamp,
            "src": packet[IP].src,
            "dst": packet[IP].dst,
            "msg": "Malicious Packet Detected" if prediction == 1 else "Normal Traffic"
        }

        if prediction == 1:
            print(f"🚨 Alert: Intrusion from {packet[IP].src}")
            alerts.append(alert)
        else:
            print(f"✅ Normal traffic from {packet[IP].src}")

        # Keep alerts list manageable
        if len(alerts) > 200:
            alerts.pop(0)

    except Exception as e:
        print(f"Error processing packet: {e}")

def start_sniffing():
    sniff(prn=process_packet, store=0, iface="wlan0")  # Change iface if needed

@app.route('/')
def dashboard():
    return render_template('index.html')

@app.route('/alerts')
def get_alerts():
    # Show most recent first
    return jsonify(alerts=alerts[::-1])

if __name__ == '__main__':
    t = threading.Thread(target=start_sniffing)
    t.daemon = True
    t.start()
    app.run(host='0.0.0.0', port=5000, debug=True)
