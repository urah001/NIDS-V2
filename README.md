# README OR UNDERSTANDING THE SYSTEM

# how to run

- to run the system or program , user first needs to navigate to the dir where the dashboard_server.py is located
- then write this command : sudo "$(which python)" -u "/home/w3b/Documents/400Project/project/web-NIDS/backend/dashboard_server.py"
- ps this system was built in a kali linux eniviroment , which the reason for the `sudo`
- the user needs to go to their localhost:5000 on their broswer or any server rendering application to view the ip causing intrusion on their network
- this system has been trained by a dataset varified and collected for keggle and tested with CUSTECH wifi and it proved to very effective
- this system detect and report intrusion
- this system report : timestamp alert source-ip destination-ip

13-1-26

# to run :

> sudo "$(which python)" -u "/home/w3b/Documents/400Project/project/web-NIDS/backend/realtime_nids.py" : this file doesnt show the logs in the broswer
> `dashboard_server.py works` :

to run this file , user needs sudo/root priviledge to run this file therefore use this command in user is in linux :

```
> sudo "$(which python)" -u "/home/w3b/Documents/400Project/project/web-NIDS/backend/realtime_nids.py"

```

### how it works:

- It's **sniffing packets** from your `wlan0` interface.
- For each packet, it's extract few features like `src_bytes`, `protocol_type`.
- It passes those features through your `preprocess_function`.
- Then it uses the trained `RandomForestClassifier` to **predict whether it's normal or an intrusion**.
- If it's malicious (`prediction == 1`), it prints an alert and writes to `alerts.log`.
- the intrusion/abnormal traffic it detect is :

- SYN Flood hping3 -S --flood -p 80 <target-ip>
- UDP Flood (Port 53) hping3 --udp --flood -p 53 <target-ip>
- ICMP Flood (Ping Flood) hping3 --icmp --flood <target-ip> OR ping -f <target-ip>
- Port Scan (Stealth) nmap -sS <target-ip>
- Port Scan (Full) nmap -p 1-1000 <target-ip>
- ARP Spoofing arpspoof -i <iface> -t <target> <gateway>

---

### 🔍 Want to test it?

You can generate traffic using tools like:

`ping` or `curl` for normal packets.
`nmap`, `hping3`, or `msfconsole` for simulating suspicious activity (e.g., port scans, DoS).

Example:

```
sudo nmap -sS 192.168.1.x

```

how to generate **abnormal/malicious-looking traffic** for testing The NIDS:

---

1. **Port Scanning** (SYN scan)

```

sudo nmap -sS <target-ip>

```

This sends stealthy SYN packets (common for intrusion attempts).

---

### 🧨 2. **TCP SYN Flood (DoS Simulation)**

```
sudo hping3 -S <target-ip> -p 80 --flood
```

Explanation:

- `-S` = SYN flag
- `-p 80` = target port
- `--flood` = send as fast as possible (DoS-like behavior)

Stop with `Ctrl + C`.

---

### 🐍 3. **Ping of Death (ICMP flood)**

```
sudo hping3 -1 <target-ip> --flood
```

This uses ICMP (like ping), but floods it.

---

### 🔥 4. **Scan All Open Ports**

```bash
sudo nmap -p- <target-ip>
```

---

### 🦠 5. **XMAS Tree Scan (odd flags set)**

```bash
sudo nmap -sX <target-ip>
```

This sends packets with FIN, URG, and PSH flags — unusual behavior that some NIDS detect.

---

### ✅ To test against localhost:

If you're running your NIDS on the same system, you can test with:

```bash
sudo nmap -sS 127.0.0.1
```

Or target a device on your LAN:

```bash
sudo nmap -sS 192.168.1.5
```

# todo

- remember to find a good dataset for the ML model for new test
- check if dev can merge two or more dataset together to make a hybrid dataset to test and train the network
- try and make the system show normal data ( but think about this , it might not be part of this methodology)

# incase of environment problem

deactivate # if you are in venv
rm -rf venv

## Make sure your desired pyenv version is active:

pyenv global 3.x.x # (replace with your real version)
how to get ip address : ip addr show

## Check:

python --version # ensure it's the pyenv version

## Recreate venv:

python -m venv venv
source venv/bin/activate

## Upgrade pip to prevent this ever happening again:

python -m ensurepip --upgrade
pip install --upgrade pip

## Install Flask again:

pip install flask
to gert

# simulation

| **Attack/Detection**        | **Testing Command (Kali/Parrot etc.)**                                           |
| --------------------------- | -------------------------------------------------------------------------------- |
| **SYN Flood**               | `hping3 -S --flood -p 80 <target-ip>`                                            |
| **UDP Flood (Port 53)**     | `hping3 --udp --flood -p 53 <target-ip>`                                         |
| **ICMP Flood (Ping Flood)** | `hping3 --icmp --flood <target-ip>` OR `ping -f <target-ip>` (careful with this) |
| **Port Scan** (Stealth)     | `nmap -sS <target-ip>`                                                           |
| **Port Scan** (Full)        | `nmap -p 1-1000 <target-ip>`                                                     |
| **ARP Spoofing**            | `arpspoof -i <iface> -t <target> <gateway>` (requires `dsniff`)                  |

# REMEMBER

turn back to the version you used to create your model/enviroment before you run this
