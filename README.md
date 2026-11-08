# 🛡️ NetSentinel - Real-Time Network Intrusion Detection System

**NetSentinel** is a real-time Network Intrusion Detection System (NIDS) dashboard built with Streamlit. It monitors live network traffic, uses a pre-trained Random Forest model for inference, and provides a cybersecurity-themed interactive interface with MITRE ATT&CK mapping and SOAR playbook recommendations.

## ✨ Features

- **Real-Time Inference**: Continuously monitors `live_traffic.csv`, automatically detecting new network flows and performing classification.
- **Random Forest Classifier**: Achieves high accuracy using a pre-trained model (trained on CICIDS2017).
- **Cyberpunk Dark UI**: Custom CSS with glassmorphism effects, neon glowing KPIs, and dynamic threat level indicators (DEFCON).
- **MITRE ATT&CK Mapping**: Automatically maps detected attacks to MITRE tactics, with recommended SOAR response playbooks.
- **Interactive Visualizations**: Live flow timeline, attack type distribution, top talkers, and target port analysis.
- **Deep Packet Inspection (DPI) Table**: Displays the latest 15 flows with filtering, search, and CSV export support.

## 🏗️ Architecture

The system operates on a dual-pipeline architecture:

1.  **Terminal 1 (Admin)**: `cicflowmeter` sniffs packets on the `Wi-Fi` interface and appends flow features to `live_traffic.csv`.
2.  **Terminal 2**: The Streamlit app (`netsentinal-frontend.py`) reads new rows, preprocesses them, and runs inference.

## 🚀 Quick Start (Local)

### Prerequisites
- Python 3.9+
- A working Npcap installation (for CICFlowMeter on Windows)

### Installation

1. Clone the repository:
   ```bash
   git clone https://github.com/Jeet-Kaswala/netsentinal-nids.git
   netsentinal-nids_NAME

### Access the Deployment

https://netsentinal.streamlit.app/