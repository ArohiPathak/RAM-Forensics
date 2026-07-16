# 🛡️ RAM Forensics Analysis Dashboard

A Python-based memory forensics application that automates RAM dump analysis using **Volatility 3** and presents the findings through an interactive graphical dashboard.

The project extracts forensic artifacts such as running processes, network connections, loaded DLLs, and command-line history from Windows memory dumps, applies rule-based risk analysis, and generates an investigation report.

---

## 📌 Features

- Upload Windows memory dump (.mem)
- Automated Volatility 3 analysis
- Interactive forensic dashboard
- Process monitoring and visualization
- Network connection analysis
- DLL inspection
- Investigation timeline
- Rule-based risk scoring
- Forensic report generation

---

## 🏗️ Project Architecture

```
                Memory Dump (.mem)
                        │
                        ▼
            Python Backend (Volatility 3)
                        │
        ┌───────────────┼───────────────┐
        ▼               ▼               ▼
   Process Info     Network Scan     DLL Analysis
        │               │               │
        └───────────────┼───────────────┘
                        ▼
              Risk Analysis Engine
                        │
                        ▼
            Interactive Dashboard
                        │
                        ▼
               PDF Investigation Report
```

---

## 🛠️ Technologies Used

- Python 3
- Volatility 3
- Tkinter / CustomTkinter
- Matplotlib
- JSON
- Git & GitHub

---

## 📂 Project Structure

```
RAM-Forensics/
│
├── app.py
├── backend/
│   └── volatility.py
├── pages/
├── widgets/
├── assets/
├── reports/
├── output/
├── sample dump/
├── requirements.txt
└── README.md
```

---

## ⚙️ Installation

Clone the repository

```bash
git clone https://github.com/ArohiPathak/RAM-Forensics.git
cd RAM-Forensics
```

Create a virtual environment

```bash
python -m venv .venv
```

Activate the environment

### Linux / Kali

```bash
source .venv/bin/activate
```

### Windows

```bash
.venv\Scripts\activate
```

Install dependencies

```bash
pip install -r requirements.txt
```

---

## 🚀 Running the Project

Launch the application

```bash
python app.py
```

Upload a supported Windows memory dump (`.mem`) and click **Analyze** to begin the forensic investigation.

---

## 🔍 Volatility Plugins Used

- `windows.info`
- `windows.pslist`
- `windows.pstree`
- `windows.netscan`
- `windows.cmdline`
- `windows.dlllist`

---

## 📊 Risk Analysis

The application assigns a rule-based risk score by correlating multiple forensic indicators, including:

- Suspicious processes
- External network connections
- Unusual DLL loading
- Suspicious command-line activity
- Hidden or anomalous processes

The calculated score is classified as:

- 🟢 Low
- 🟡 Medium
- 🟠 High
- 🔴 Critical

---

## 📷 Application Modules

- Dashboard
- Upload Memory
- Processes
- Network Analysis
- DLL Analysis
- Timeline
- Report Generation

---

## 📌 Future Enhancements

- Support for Linux memory dumps
- Malware signature integration
- VirusTotal API integration
- Advanced anomaly detection
- IOC extraction
- Automated PDF report customization

---

## 📄 License

This project was developed as part of an academic **Software Development Project (SDP)** for educational purposes.
