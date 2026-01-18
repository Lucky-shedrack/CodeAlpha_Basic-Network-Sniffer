# Network Traffic Packet Sniffer (Linux / Scapy)

A lightweight Python-based network packet sniffer built using **Scapy**, designed to capture and analyze live network traffic on Linux systems. This project helps beginners understand how data flows across the network, including packet structure, protocols, and payloads.

---

##  Features

1 Captures real-time network traffic
2 Displays source & destination IP addresses
3 Identifies protocol types (TCP, UDP, ICMP)
4 Extracts ports for TCP & UDP
5 Shows partial payload data (when available)
6 Runs directly in the terminal
7 Supports sudo-based raw packet sniffing
8 Lightweight — no heavy dependencies

---

## Tech Stack

| Component | Technology                   
| --------- | ---------------------------- 
| Language  | Python 3                     
| Library   | Scapy                        
| OS Target | Linux (tested on Kali Linux) 

---

##  Installation

### 1. Install Scapy

It is recommended to install inside a virtual environment:

```sh
python3 -m venv sniffer-env
source sniffer-env/bin/activate
pip install scapy
```

---

##  Running the Sniffer

Run with root privileges to access raw packets:

```sh
sudo python3 network_sniffer.py
```

Then generate test traffic, for example:

```sh
www.douane.gov.tn
```

---

##  Project Structure

```
├── network_sniffer.py
└── README.md
```

---

## Example Output

```
=== PACKET CAPTURED ===
Source IP:      192.168.1.10
Destination IP: 8.8.8.8
Protocol:       ICMP
```

---

## Educational Purpose

This project is suitable for:

1. Cybersecurity students
2. Ethical hacking training
3. Networking fundamentals
4. Traffic analysis learning
5. Packet inspection practice

---

## Legal Disclaimer

This tool is intended for **educational and authorized use only**.
Do not sniff networks you do not own or have permission to analyze.

---



