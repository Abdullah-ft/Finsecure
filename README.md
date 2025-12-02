## 🛡️ Finsecure – Cybersecurity Toolkit

**CY4053 Final Project – PayBuddy Security Assessment**  
Interactive cybersecurity toolkit with both **CLI** and **modern web UI** for safe, controlled security testing.

### ⚠️ Usage & Ethics

**THIS TOOLKIT IS FOR AUTHORIZED EDUCATIONAL USE ONLY.**

- 🔑 All operations require valid `identity.txt` and `consent.txt` files
- 🎯 Testing is restricted to **approved lab targets only**
- 🚫 Unauthorized or production testing is **strictly prohibited**
- 🧪 Designed for **controlled educational environments** and lab work

---

## 💡 Overview

Finsecure is a Python-based cybersecurity toolkit that provides a guided workflow for assessing the security posture of web applications and networks. It offers:

- 🔍 **Port Scanning** – TCP port scan with basic banner grabbing
- 🔐 **Password Assessment** – Offline password policy and strength checking
- 📈 **Load / Stress Testing** – Controlled HTTP load generation (max 200 clients)
- 🌐 **Web Discovery** – Directory and endpoint enumeration for web targets
- 📡 **Packet Capture** – Local network packet capture and summarization
- 📑 **Reporting** – Consolidated DOCX/PDF report generation from collected results

You can use Finsecure either via:

- A **command-line interface (CLI)** (`src/main.py`), or  
- A **Flask-based web UI** (`src/web_ui.py`) with authentication and modern dashboard.

---

## 🧱 Architecture & Project Structure

```text
Finsecure/
├── src/
│   ├── main.py               # CLI entry point
│   ├── web_ui.py             # Flask web UI (dashboard + modules)
│   ├── identity_checker.py   # identity.txt + consent.txt validation
│   ├── config.py             # Global configuration management
│   ├── logger.py             # Logging + SHA-256 integrity
│   ├── port_scanner.py       # Port scanning module
│   ├── password_tester.py    # Password assessment module
│   ├── stress_tester.py      # Load/stress testing module
│   ├── web_discovery.py      # Web discovery/footprinting module
│   ├── packet_capture.py     # Packet capture module
│   └── report_generator.py   # Report generation module
├── templates/                # Jinja2 HTML templates (web UI)
│   ├── base.html             # Shared layout, navbar, footer
│   ├── login.html            # Identity-based login page
│   ├── port_scanner.html     # Port scanner module page
│   ├── password_assessment.html
│   ├── load_testing.html
│   ├── web_discovery.html
│   ├── packet_capture.html
│   ├── report_generator.html
│   ├── results.html          # Results viewer
│   ├── status_header.html    # Identity / consent status banner
│   └── toast.html            # Toast notifications
├── static/
│   ├── css/style.css         # Modern, neon-themed UI styling
│   └── js/
│       ├── main.js           # Shared JS helpers
│       └── app.js            # Module form handling + API calls
├── output/                   # Scan results, metrics, reports (auto-created)
├── logs/                     # Append-only logs + SHA-256 hashes
├── uploads/                  # Uploaded password files (web UI)
├── identity.txt              # Team information (required)
├── consent.txt               # Approved targets (required)
├── config.json               # Configuration file (auto-created)
├── requirements.txt          # Python dependencies
├── run.py                    # Optional helper/entry (if used)
└── README.md                 # This documentation
```

---

## 👥 Identity & Consent Model

Before any module can run, Finsecure enforces:

- ✅ **Identity verification** via `identity.txt`
- ✅ **Target authorization** via `consent.txt`

### `identity.txt` (team identity)

Required format (example):

```text
Team Name: FinSecure
Members: Abdullah (22I-2264), Mohadis Khan (22I-2273), M.Usman (22I-7463)
```

The web UI login uses this file as its **source of credentials**:

- 👤 **Username** = full member name (e.g. `Abdullah`)
- 🔑 **Password** = registration number (e.g. `22I-2264`)

### `consent.txt` (approved targets)

Required structure (simplified):

```text
Approved Targets:
- localhost
- 127.0.0.1
- 192.168.1.100
- example.com
- testphp.vulnweb.com
...
```

Modules that interact with external systems (port scanning, stress testing, web discovery) will **refuse to run** against targets not listed in `consent.txt`.

---

## 🧩 Toolkit Modules (High-Level)

- 🔍 **Port Scanner**
  - TCP port scans with basic banner grabbing.
  - Honors `consent.txt` and thread/timeout limits from `config.json`.

- 🔐 **Password Assessment**
  - Offline analysis of password lists (no network calls).
  - Supports simulation mode for safe policy testing.

- 📈 **Load / Stress Testing**
  - HTTP load generation with client and duration limits.
  - Hard cap of **200 clients** for safety.

- 🌐 **Web Discovery / Footprinting**
  - Directory and endpoint enumeration for approved web targets.
  - Designed to test lab environments such as `testphp.vulnweb.com`.

- 📡 **Packet Capture**
  - Captures packets on local interfaces with optional BPF filters.
  - Produces JSON and summary text outputs for quick analysis.

- 📑 **Report Generator**
  - Aggregates JSON output from all modules.
  - Generates DOCX and/or PDF reports summarizing findings.

---

## 🔧 Prerequisites

- 🐍 Python **3.8+** (tested on modern 3.x)
- 📦 Dependencies from `requirements.txt`
- 📄 Valid `identity.txt` and `consent.txt` files in the project root

Install dependencies:

```bash
pip install -r requirements.txt
```

---

## 🖥️ Running the Web UI (Recommended)

The web UI provides a guided, visual way to run each module with validation and status feedback.

### 1️⃣ Prepare identity and consent

1. Create `identity.txt` with your team name and members (see example above).
2. Create or update `consent.txt` with approved lab targets only.
3. Ensure both files are placed in the project root next to `src/`.

### 2️⃣ Start the Flask web UI

From the project root:

```bash
python src/web_ui.py
```

You should see:

- Server listening at `http://127.0.0.1:5000`
- Validation messages if `identity.txt` / `consent.txt` are missing.

### 3️⃣ Log in

1. Open `http://127.0.0.1:5000` in your browser.
2. You’ll be redirected to the **Sign In** page.
3. Log in using:
   - **Username**: full name from `identity.txt` (e.g. `Abdullah`)
   - **Password**: registration number (e.g. `22I-2264`)

### 4️⃣ Use the module pages

After login you land on the **Port Scanner** page and can navigate via the top navbar:

- **Port Scanner** – Scan approved IPs/domains and view results.
- **Password Assessment** – Upload password lists and analyze strength.
- **Load Testing** – Generate HTTP load against allowed URLs (e.g. `http://localhost:8000`, `http://httpbin.org`).  
- **Web Discovery** – Enumerate paths on approved web targets (e.g. `http://testphp.vulnweb.com`).
- **Packet Capture** – Capture traffic on local interfaces with filters (e.g. `tcp port 80`).
- **Report Generator** – Consolidate all module outputs into DOCX/PDF reports.
- **Results** – Browse recent JSON results via the results dashboard.

Each module page:

- Shows **identity/consent status** in the top banner.
- Provides a **“Latest Activity & Examples”** card with sample targets from `consent.txt` and a 2–3 step mini flow.

To stop the UI, press **Ctrl+C** in the terminal running `python src/web_ui.py`.

---

## 🧮 Using the CLI

The CLI provides direct access to all modules and is useful for scripting or automation.

### Basic command pattern

```bash
python src/main.py [--dry-run] <command> [options]
```

### Commands & examples

- **Port Scanner**

  ```bash
  python src/main.py scan 192.168.1.100 -p 1-1000
  python src/main.py scan example.com -p 80,443,8080 -t 50
  ```

- **Password Assessment**

  ```bash
  python src/main.py auth_test passwords.txt --simulate
  ```

- **Load / Stress Testing**

  ```bash
  python src/main.py stress http://example.com -c 50 -d 60
  ```

- **Web Discovery**

  ```bash
  python src/main.py footprint example.com -t 10
  ```

- **Packet Capture**

  ```bash
  python src/main.py pcap -i eth0 -c 100
  ```

- **Report Generation**

  ```bash
  python src/main.py report -i output/ -f both
  ```

### Dry-run mode

To validate configuration without executing the actual operation:

```bash
python src/main.py --dry-run scan example.com
```

---

## 🔒 Safety Features

1. **Identity Verification** – Requires valid `identity.txt` before running modules.
2. **Consent Validation** – Only targets in `consent.txt` are allowed for network tests.
3. **Rate Limiting** – Built-in delays to avoid aggressive scanning.
4. **Thread Limits** – Maximum concurrent threads for safe operation.
5. **Client Limits** – Load testing capped at **200 clients**.
6. **Logging + Integrity** – All operations logged with SHA‑256 hashes for tamper detection.
7. **Dry Run Mode** – Safely validate commands and configuration.

---

## 📂 Output & Logging

- **Output files** (in `output/`):
  - `<module>_<target>_<timestamp>.json` – JSON results
  - `<module>_<target>_<timestamp>.html` – Port scan HTML reports
  - `<module>_<target>_<timestamp>.png` – Stress test plots
  - `report_<timestamp>.docx` – DOCX report
  - `report_<timestamp>.pdf` – PDF report

- **Logs** (in `logs/`):
  - Timestamped log files with SHA-256 sidecar hashes.
  - Useful for audit trails and verifying integrity.

---

## 🩺 Troubleshooting

### `"identity.txt not found"`

- Create `identity.txt` with the proper format.
- Ensure it lives in the project root (same level as `src/`).

### `"consent.txt not found"`

- Create `consent.txt` with **only approved** test targets.

### `"scapy not available"`

- Install: `pip install scapy`
- Note: may require admin/root privileges on some systems.

### `"Module not found"` or import errors

- Re-install dependencies:
  ```bash
  pip install -r requirements.txt
  ```
- Confirm you are running **Python 3.8+**.

---

## 📜 License & Responsibility

This project is for **educational purposes only**. Use it **responsibly**, only against systems and environments for which you have **explicit written permission**.

> **Remember:** Always test responsibly and only on systems you are authorized to assess.

