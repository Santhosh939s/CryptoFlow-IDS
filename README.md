Catching Data Breaches Without Breaking Encryption on Network Traffic

📌 Project Overview

As cyber threats continually evolve, attackers increasingly utilize encrypted channels like HTTPS, TLS, or VPNs to smuggle data out of systems undetected. Traditional security tools often fail because they cannot inspect these encapsulated data packages.

This project implements a hybrid Intrusion Detection System (IDS) that integrates network traffic flow analysis with lightweight machine learning (Random Forest). By analyzing cryptographic side-channel metadata—specifically Shannon Entropy, Packet Size, and Destination Port—the system identifies malicious exfiltration in real-time without ever decrypting or compromising the privacy of the payload.

✨ Key Features

Packet-Level Detection: Analyzes traffic packet-by-packet to instantly catch slow, dripping exfiltration attacks.

Privacy-Preserving: Operates entirely on metadata; no payloads are decrypted.

High Accuracy: Achieves over 99.8% accuracy with an inference latency of less than 5 ms per packet.

🛠️ Prerequisites & Tech Stack

This project is built and tested on Ubuntu Linux.

Language: Python 3

Machine Learning: Scikit-learn (Random Forest Classifier)

Network Analysis: Scapy, tcpdump

Data Handling: Pandas, NumPy

🚀 Installation & Setup Guide

1. Clone the Repository

Open your terminal and clone this project:


cd YOUR_FOLDER_NAME
`git clone https://github.com/Santhosh939s/CryptoFlow-IDS`





2. Install System Dependencies

Update your package list and install the required system-level networking tools and virtual environment managers:

a.`sudo apt update`

b.`sudo apt install python3-venv tcpdump netcat-traditional`


3. Set Up the Python Virtual Environment

To avoid conflicts with Ubuntu's system packages, create and activate an isolated Python environment:

a.`python3 -m venv exfil_env`

b.`source exfil_env/bin/activate`


(You must run source exfil_env/bin/activate every time you open a new terminal to work on this project).

4. Install Python Libraries

With the environment activated, install the required Python packages:

`pip install scapy scikit-learn pandas numpy joblib`


🗄️ Dataset Collection

This model requires a hybrid dataset consisting of malicious botnet traffic and benign user traffic to train effectively.

Step 1: Download the Malicious Dataset (Neris Botnet CTU-42)

We use the CTU-42 Neris Botnet dataset from the Stratosphere Laboratory. Download the raw .pcap file directly into your project folder:

wget [https://mcfp.felk.cvut.cz/publicDatasets/CTU-Malware-Capture-Botnet-42/botnet-capture-20110810-neris.pcap](https://mcfp.felk.cvut.cz/publicDatasets/CTU-Malware-Capture-Botnet-42/botnet-capture-20110810-neris.pcap)


Step 2: Capture Benign User Traffic

Capture your own standard web browsing (e.g., watching YouTube, browsing forums) to serve as the "Safe" dataset.

Find your active Wi-Fi interface name (usually wlo1 or wlan0) using the ip a command.

Run a packet capture for 5-10 minutes while browsing the web:

`sudo tcpdump -i wlo1 -w my_benign_traffic.pcap`


Press Ctrl+C to stop the capture.

🧠 Execution Pipeline

Phase 1: Data Processing & Model Training

Before the detector can run, you must extract the side-channel features and train the Random Forest AI.

1. Extract Features: Run the extraction script to calculate Shannon Entropy, Size, and Port, and compile them into a balanced dataset.csv:

`python3 pcap_to_csv.py`


2. Train the Model:
Train the Random Forest Classifier. The script will save the trained model as traffic_classifier.pkl if the accuracy exceeds 95%.

`python3 train_model.py`


Phase 2: Real-Time Detection Simulation Lab

To test the real-time detection capabilities, you will simulate a local network attack. You need three separate terminal windows open for this. Remember to activate the virtual environment (source exfil_env/bin/activate) in the attacker terminal.

Terminal 1: The Target Server
Set up a dummy server to listen for the exfiltrated data:

`nc -l 8443`


Terminal 2: The Hybrid AI Detector
Start the real-time packet sniffer. It will monitor both the local loopback interface (lo) for the simulation, and your live Wi-Fi interface (wlo1) for real traffic:

`sudo ./exfil_env/bin/python detector.py`


Note: The detector will print [SAFE] for normal traffic. Once a threat is detected, it will suppress safe logs to highlight the [RED ALERT] warnings to prevent alert fatigue.

Terminal 3: The Attacker Simulation
Run the victim script, which generates highly random, cryptographically simulated payloads (high entropy) and attempts to exfiltrate them to the target server:

`python3 victim.py`


Watch Terminal 2 instantly detect and flag the malicious packets with red alerts!

👨‍💻 Author

Santosh Kumar B.Tech Computer Science & Engineering (Cyber Security)
