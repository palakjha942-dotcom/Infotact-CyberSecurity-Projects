# CAN-Sentinel: Automotive CAN Bus Intrusion Detection and Mitigation System

A lightweight, machine-learning-driven Intrusion Detection System (IDS) and inline packet firewall designed to secure Controller Area Network (CAN) bus architectures against automotive cyber threats.

---

## Project Overview

Modern connected vehicles rely heavily on the CAN bus protocol for inter-ECU (Electronic Control Unit) communication. However, standard CAN bus lacks inherent authentication and encryption, leaving it vulnerable to frame injection, spoofing, and Denial of Service (DoS) attacks.

**CAN-Sentinel** addresses these vulnerabilities by simulating automotive telemetry, injecting malicious traffic patterns, classifying anomalous frames using machine learning (Isolation Forest), and enforcing real-time firewall mitigation rules.

---

## System Architecture & Workflow

1. **Virtual CAN Infrastructure (`vcan0`):** SocketCAN interface simulating an in-vehicle network bus.
2. **ECU Telemetry Simulation (`ecu_engine.c`):** Generates legitimate vehicle telemetry (Engine Speed, RPM, Coolant Temp).
3. **Attack Injection Framework (`attack_injector.py`):** Simulates high-priority zero-ID DoS flooding and out-of-bounds RPM spoofing attacks.
4. **Offline ML Classifier (`detector.py`):** Uses an Unsupervised Isolation Forest model trained on multi-feature vectors (`Time_Delta`, `ID_Int`, `Payload_Val`) to classify normal vs malicious frames.
5. **Real-Time Detection Engine (`realtime_detector.py`):** Monitors live frames on `vcan0` with sub-millisecond inference latency.
6. **Inline Mitigation Firewall (`firewall_filter.py`):** Intercepts and drops malicious frames matching signature and threshold anomalies.

---

## Repository Structure

├── ecu_engine.c                 # C-based ECU telemetry generator
├── logger.py                    # Telemetry capture utility (Normal)
├── can_dataset.csv              # Baseline normal CAN traffic dataset
├── attack_injector.py           # Attack framework (DoS & RPM Spoofing)
├── attack_logger.py             # Attacked telemetry capture utility
├── attacked_dataset.csv         # Labeled malicious telemetry dataset
├── detector.py                  # Isolation Forest ML detection model
├── realtime_detector.py         # Live SocketCAN stream IDS
├── firewall_filter.py           # Real-time packet filtering engine
├── README.md                    # Project documentation
└── Week3_Week4_Final_Report.md  # Final performance evaluation report

---

## Setup and Execution

### Prerequisites
* Kali Linux / Ubuntu (Linux Kernel with SocketCAN support)
* Python 3.10+
* GCC Compiler (`build-essential`)
* `can-utils`, `python-can`, `pandas`, `scikit-learn`

### 1. Initialize Virtual CAN
```bash
sudo modprobe vcan
sudo ip link add dev vcan0 type vcan
sudo ip link set up vcan0

python3 detector.py

# Terminal 1: Start ECU simulator
./ecu_engine > /dev/null 2>&1 &

# Terminal 2: Start inline firewall
python3 firewall_filter.py

# Terminal 3: Inject attack traffic
python3 attack_injector.py

Performance & Evaluation Summary
Anomaly Detection Algorithm: Isolation Forest (Unsupervised)

Dataset Size: 1,894 processed frames

Anomalies Detected (Offline): 284 frames

Real-Time Firewall Performance:

DoS Frames Dropped (0x000): 490 frames (100% mitigation)

RPM Spoofed Frames Dropped (0x120 > 8000 RPM): 30 frames (100% mitigation)

Total Malicious Frames Dropped: 520 frames

---
