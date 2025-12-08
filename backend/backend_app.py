from flask import Flask, request, jsonify
from flask_cors import CORS #type:ignore
import joblib
from preprocess_function import preprocess_function
from scapy.all import sniff
import threading

app = Flask(__name__)
CORS(app)

model = joblib.load('nids_model.pkl')
alerts = []  # Store alerts to fetch from frontend

@app.route('/detect', methods=['POST'])
def detect_intrusion():
    data = request.json
    features = preprocess_function(data)
    prediction = model.predict([features])
    return jsonify({'intrusion': bool(prediction[0])})

@app.route('/alerts', methods=['GET'])
def get_alerts():
    return jsonify({'alerts': alerts})

def process_packet(packet):
    try:
        data = {
            "duration": 0,
            "src_bytes": len(packet),
            "dst_bytes": len(packet.payload),
            "count": 1,
            "srv_count": 1
        }
        features = preprocess_function(data)
        prediction = model.predict([features])
        if prediction[0] == 1:
            alert = {
                "msg": "Intrusion detected!",
                "src": packet[0].src if hasattr(packet[0], 'src') else "Unknown"
            }
            print(alert)
            alerts.append(alert)
    except Exception as e:
        print("Error processing packet:", e)

# Run packet sniffer in background
def start_sniffing():
    sniff(prn=process_packet, store=False)

threading.Thread(target=start_sniffing, daemon=True).start()

if __name__ == '__main__':
    app.run(debug=True)
