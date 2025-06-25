# 🌐 DNS Query Logger (Python + Scapy)

A lightweight DNS query logger built in Python using Scapy, developed on Kali Linux. This tool captures DNS requests sent over UDP port 53 and logs the queried domain names with timestamps.

## 🔍 Features

- 🛰️ Captures real-time DNS traffic (UDP port 53)
- 🔎 Extracts and logs domain names from DNS queries
- 🧾 Saves logs to `logs/dns_queries.log`
- 🛠️ Lightweight and easy to extend for further analysis

## 📁 Project Structure

DNSQueryLogger/

├── logs/

│ └── dns_queries.log # Output log file (created automatically)

├── dns_logger.py # Main Python script

└── README.md # This documentation


## ⚙️ Requirements

- Python 3.x
- Scapy (install via pip if missing)

```bash
sudo apt update
pip3 install scapy
```

## 📚 Concepts Covered
DNS Query logging (UDP port 53)

Application-layer protocol sniffing

Packet inspection using Scapy

Timestamps and log formatting in Python

## 🧠 Learning Goals
This project was created to deepen my understanding of:

DNS packet structure

Filtering and parsing real-time traffic

Logging and lightweight network monitoring

## 🔒 Disclaimer
This tool is intended for educational and authorized testing only.
Do not use this on networks you do not own or have explicit permission to monitor.