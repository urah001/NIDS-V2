from flask import Flask, jsonify, render_template # type: ignore
from scapy.all import sniff, IP, TCP, UDP, ICMP, ARP # type: ignore
import threading
import time
import os

app = Flask(__name__)
alerts = []

port_scan_tracker = {}  # Track ports hit by each IP
arp_cache = {}          # Track ARP replies to detect spoofing

def detect_abnormal(packet):
    
    if packet.haslayer(IP):
        ip_layer = packet[IP]
        src = ip_layer.src
        dst = ip_layer.dst

        if packet.haslayer(TCP):
            tcp_layer = packet[TCP]
            flags = tcp_layer.flags

            # SYN Flood detection
            if flags == 'S':
                log_alert("SYN Flood Detected", src, dst)

            # Port Scan detection: Log if 10+ ports hit in 5 sec by the same IP
            port = tcp_layer.dport
            now = time.time()
            if src not in port_scan_tracker:
                port_scan_tracker[src] = []
            port_scan_tracker[src].append((port, now))

            # Remove old port records older than 5 sec
            port_scan_tracker[src] = [(p, t) for p, t in port_scan_tracker[src] if now - t < 5]

            # Check if 10+ unique ports were targeted
            unique_ports = set([p for p, t in port_scan_tracker[src]])
            if len(unique_ports) > 10:
                log_alert("Port Scan Detected", src, dst)

        if packet.haslayer(UDP):
            udp_layer = packet[UDP]
            if udp_layer.dport == 53:
                log_alert("UDP Flood on DNS Port 53", src, dst)

        if packet.haslayer(ICMP):
            icmp_layer = packet[ICMP]
            if icmp_layer.type == 8:  # Echo Request
                log_alert("ICMP Ping Request ( Ping Flood)", src, dst)

    if packet.haslayer(ARP):
        arp_layer = packet[ARP]
        if arp_layer.op == 2:  # ARP reply
            src_ip = arp_layer.psrc
            src_mac = arp_layer.hwsrc
            if src_ip in arp_cache and arp_cache[src_ip] != src_mac:
                log_alert("ARP Spoofing Detected", src_ip, "Broadcast")
            arp_cache[src_ip] = src_mac


def log_alert(msg, src, dst):
    timestamp = time.strftime("%Y-%m-%d %H:%M:%S")
    alert = {
        "timestamp": timestamp,
        "msg": msg,
        "src": src,
        "dst": dst
    }
    print(f"[ALERT] {msg} from {src} to {dst}")
    alerts.append(alert)
    if len(alerts) > 200:
        alerts.pop(0)


def start_sniffing():
    sniff(prn=detect_abnormal, store=0)


@app.route('/')
def dashboard():
    return render_template('index.html')


@app.route('/alerts')
def get_alerts():
    return jsonify(alerts=alerts[::-1])


if __name__ == '__main__':
    t = threading.Thread(target=start_sniffing)
    t.daemon = True
    t.start()
    app.run(host='0.0.0.0', port=5000, debug=True)
