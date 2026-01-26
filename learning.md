## **limitations** of system:

### 🔒 **Limitations of This NIDS System**

#### 1. **Signature-Based Detection Only**

- It detects specific types of known attacks (e.g., SYN flood, UDP flood, ICMP ping flood, ARP spoofing, port scan).
- **Limitation**: Cannot detect new (zero-day) or unknown attack patterns that do not match predefined rules.

#### 2. **No Machine Learning or Anomaly Detection**

- The current logic is rule-based and manually coded.
- **Limitation**: It lacks the intelligence to learn from new traffic patterns or detect subtle anomalies over time.

#### 3. **No Packet Storage or Deep Analysis**

- Packets are not saved or deeply inspected.
- **Limitation**: You can't perform forensics, payload inspection, or trace detailed attack behaviors after detection.

#### 4. **Local Network Only**

- It’s currently designed for monitoring **only the local network**.
- **Limitation**: It won’t scale for large enterprise networks or cloud environments.

#### 5. **Single Interface Monitoring**

- The `sniff()` function listens to traffic on the default interface.
- **Limitation**: It may miss traffic if multiple interfaces (WiFi, Ethernet, etc.) are involved and not explicitly specified.

#### 6. **Runs with Root Privileges**

- Packet sniffing requires `sudo`/root.
- **Limitation**: This introduces **security risks** if the code is compromised or misused.

#### 7. **Web Interface is Basic and Not Secured**

- Uses Flask’s development server.
- **Limitation**: Not suitable for production or public access. No HTTPS, no authentication, no access control.

#### 8. **Possible High CPU Usage**

- Sniffing and real-time processing on busy networks could be resource-intensive.
- **Limitation**: May slow down the host machine under high traffic conditions.

#### 9. **Alert Overload (False Positives)**

Normal DNS or ping usage could still be flagged in noisy networks.
Limitation: Without context or thresholds tuning, you may receive too many alerts.

The system works **efficiently for small-scale, educational, or local networks**, but would need more advanced features like:

- Machine Learning for anomaly detection
- Secure & scalable deployment
- Real-time response (like blocking IPs)
- Deep packet inspection
- User management and log analysis dashboard

fix wireshark
