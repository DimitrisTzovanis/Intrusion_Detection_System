# Real-Time Intrusion Detection System (IDS) 


The **Real-Time Intrusion Detection System (IDS)** is a **JavaFX-based network security tool** that monitors live network traffic, detects suspicious activities, and provides real-time alerts. It uses **Pcap4J** to capture packets, analyze network behavior, and visualize data using a dynamic line chart.

## Features 
- **Live Network Packet Capture** – Captures packets using **Pcap4J** and displays real-time traffic logs.
- **Traffic Visualization** – Uses JavaFX **LineChart** to dynamically track packet flow per time frame.
- **Port Scan Detection** – Monitors for excessive SYN packets from a single source to identify scanning attempts.
- **Brute-Force Attack Detection** – Detects multiple failed login attempts on critical ports (SSH, FTP, RDP).
- **Real-Time Alerts** – Notifies users with GUI alerts when an attack is detected.
- **Efficient Log Management** – Prevents excessive memory usage by limiting stored logs.

## How It Works
This **Intrusion Detection System** analyzes live packets and looks for **patterns of malicious activity**. It applies two primary detection mechanisms:

1. **Port Scan Detection**: If an IP sends multiple SYN packets within a short period **without completing the handshake**, it is flagged as a potential **port scan attack**.
2. **Brute-Force Detection**: If an IP repeatedly tries to connect to sensitive ports (like **SSH: 22, RDP: 3389, FTP: 21**) within a **time window**, it is flagged for **brute-force attempts**.

When a threat is detected, the system:
- Logs the **attacker’s IP** in the console.
- Displays an **on-screen alert** for immediate attention.

### Prerequisites:
- **Pcap4J** dependency added.
- Windows/Linux system with **WinPcap/libpcap** installed.

