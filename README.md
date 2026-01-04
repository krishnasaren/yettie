# yettie
# 🛡️ Web-Based Application Security Testing Platform

A **web-based application security testing platform** that provides Burp Suite–like functionality directly in the browser.  
It enables interception, replaying, automated attacks, and vulnerability scanning of HTTP/HTTPS traffic without requiring a native desktop client.

This project is designed for **security researchers, penetration testers, and developers** who want deep protocol-level control with a modern web UI.

---

## ✨ Features

### 🔁 Proxy & Interception
- HTTP & HTTPS interception
- Modify requests and responses in real time
- Dynamic SSL/TLS certificate generation
- Full traffic logging and inspection

### 🔂 Repeater
- Manually craft and resend raw HTTP requests
- Full control over method, headers, body, and payloads
- Automatic handling of HTTP vs HTTPS
- Gzip / chunked response decoding
- Render responses directly in the browser

### ⚔️ Intruder
- Automated attack engine with support for:
  - Sniper
  - Battering Ram
  - Pitchfork
  - Cluster Bomb
- Multi-threaded request execution
- Real-time progress tracking
- Payload generators:
  - Wordlists
  - Bruteforce
  - Regex
  - Custom payloads
- Grep and extract match results

### 🧠 Scanner
- Passive and active scanning
- Security header analysis
- Information disclosure detection
- Authentication & session checks
- Structured findings with severity, confidence, CVSS, and remediation

### 📊 Job Management
- Persistent job storage
- Live status updates (`created`, `running`, `completed`, `failed`)
- Payload-level progress tracking
- Safe handling of raw request/response data

---

## 🏗 Architecture Overview

- **Backend:** Python (Flask-style API, multi-threaded execution)
- **Frontend:** Web UI (JavaScript, HTML, CSS)
- **Concurrency:** Thread pools for Intruder and scanning engines
- **Persistence:** Database-backed jobs, results, and scan history
- **Protocol Handling:** Raw HTTP parsing and execution (Burp-style)

The system is designed with **clear separation of concerns**:
- Parsing
- Execution
- Progress tracking
- Finalization

---

## 🚀 Getting Started

### ✅ Requirements
- Python **3.10+**
- A modern web browser
- Database (SQLite by default)

---

### 📦 Installation

```bash
git clone https://github.com/yourusername/web-security-platform.git
cd web-security-platform

python -m venv venv
source venv/bin/activate   # Linux/macOS
venv\Scripts\activate      # Windows
```

`pip install -r requirements.txt`

### Run
`python p.py`



