import joblib
from scapy.all import sniff, IP, TCP, UDP
from preprocess_function import preprocess_function  # Adjust if needed
import warnings
warnings.filterwarnings("ignore")
# realtime_nids.py

model = joblib.load('nids_model.pkl')

def process_packet(packet):
    try:
        if not packet.haslayer(IP):
            return

        protocol_type = 1 if packet.haslayer(TCP) else 2 if packet.haslayer(UDP) else 0
        src_bytes = len(packet[IP].payload)

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

        processed = [preprocess_function(data)]
        prediction = model.predict(processed)[0]

        if prediction == 1:
            print(f"🚨 Alert: Intrusion from {packet[IP].src}")
            with open('alerts.log', 'a') as f:
                f.write(f"[ALERT] Malicious packet from {packet[IP].src}\n")
        else:
            print(f"✅ Normal traffic from {packet[IP].src}")

    except Exception as e:
        print(f"Error: {e}")


if __name__ == '__main__':
    print("🔍 Starting NIDS real-time monitoring...")
    sniff(prn=process_packet, store=0, iface="wlan0")  # Change iface if needed
