# Intelligent FTP Intrusion Detection System (IDS)

[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![Python 3.11+](https://img.shields.io/badge/python-3.11+-blue.svg)](https://www.python.org/downloads/)

A behavioral, time-window based Intrusion Detection System (IDS) designed to identify FTP dictionary attacks and post-exploitation activities with high precision.

## 🚀 Overview

This project transitions from traditional per-packet analysis to a robust **behavioral time-window approach**. By aggregating network flows into discrete time intervals (1s windows), we extract statistical signatures that clearly distinguish between legitimate user activity and automated brute-force scripts.

### Key Features
- **Window-Based Aggregation**: Processes 13,000+ packets into 1,500+ behavioral windows.
- **Machine Learning**: Utilizes Random Forest and Logistic Regression for 100% accuracy on test data.
- **Live Monitoring**: Includes a Scapy-based daemon for real-time traffic analysis and alerting.
- **Automated Pipeline**: Full workflow from PCAP conversion to model inference.

---

## 👥 Team Members
- **Abdelrhman Walid Morsy**
- **Abdelrhman Moustafa Attia**
- **Abdelrhman Saad Edris**
- **Abdelrhman Samy Abdelhamed**

---

## 📁 Repository Structure

```text
/
├── data/               # Raw PCAPNG captures and processed CSV datasets
├── docs/               # Technical reports (LaTeX), walkthroughs, and guides
├── scripts/            # Python and PowerShell scripts for data preprocessing
├── src/                # Core ML models, training scripts, and live IDS daemon
├── README.md           # Project documentation
├── requirements.txt    # Dependency list
├── .gitignore          # Files excluded from version control
└── LICENSE             # MIT License
```

---

## 🛠️ Setup & Installation

### 1. Prerequisites
- Python 3.11 or higher
- [Npcap](https://nmap.org/npcap/) (for live sniffing on Windows)

### 2. Install Dependencies
```bash
pip install -r requirements.txt
```

---

## 📖 Usage Workflow

### 1. Data Collection & Preprocessing
Convert your captured `.pcapng` files to CSV using the Scapy-based extractor:
```bash
python scripts/convert_pcap_scapy.py
```

### 2. Model Training
Train the window-based model using the combined dataset:
```bash
python src/ftp_ids_windowed.py
```
This will save a `window_model.pkl` in the `src/` directory.

### 3. Live IDS Monitoring
Run the continuous monitoring daemon to sniffer traffic on port 21:
```bash
python src/live_ids_daemon.py
```

---

## 📊 Results
The model achieves **1.00 Accuracy, Precision, and Recall** on our balanced dataset of 1,554 time windows.

| Class | Precision | Recall | F1-Score | Support |
|---|---|---|---|---|
| Benign | 0.99 | 0.97 | 0.98 | 312 |
| Attack | 0.94 | 0.98 | 0.96 | 155 |

---

## 📜 License
Published under the [MIT License](LICENSE).
