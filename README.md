# 🚀 Enterprise Security Monitoring & Threat Intelligence Platform

A production-grade, modular, high-performance security automation platform designed to monitor Windows system activity (metrics, processes, network sockets, SCM services), track directory modifications, analyze DNS records, query external threat intelligence APIs (VirusTotal, AbuseIPDB, AlienVault OTX, Shodan), evaluate host behavior via a User and Entity Behavior Analytics (UEBA) engine, and store normalized events as structured JSON logs.

---

## 🛠️ Key Features

- **Modular Clean Architecture:** Centralized orchestrator controller executing concurrent decoupled monitoring modules.
- **Multithreaded Execution:** Threads running continuous low-overhead checks, feeding a background thread pool for threat API lookups.
- **Unified Event Schema:** Normalizes all events into a standard SOC/SIEM JSON payload with severity categorizations.
- **Threat Intelligence Aggregator:** Checks IPs, domains, and hashes across VirusTotal, AbuseIPDB, AlienVault OTX, and Shodan in parallel, calculating composite reputation scores.
- **API Caching & Fail-safes:** Stores lookup histories locally with configurable TTLs to handle rate limit thresholds and internet outages.
- **Watchdog File Monitoring:** Event-driven directory checks.
- **UEBA Engine:** Tracks user baseline activity profiles, records session metrics, compares patterns against department peer groups, detects behavioral deviations, and dynamically increments host risk scores.
- **Corrupt-JSON Recovery & Log Rotation:** Automatically shifts large output logs and backups corrupted configurations to ensure database integrity.

---

## 📂 Folder Structure

```text
SOC/
│
├── main.py                          # Orchestrator Controller
│
├── requirements.txt                 # Platform Dependencies
│
├── config/
│   ├── settings.py                  # Settings Manager
│   └── constants.py                 # Platform Constants & Severity Levels
│
├── utils/
│   ├── logger.py                    # Thread-safe rotating logger
│   ├── json_manager.py              # Safe JSON reads/writes/rotations
│   ├── timestamp.py                 # UTC timestamp builder
│   ├── validators.py                # Regex validations
│   └── error_handler.py             # Global Exception Manager
│
├── modules/
│   ├── virustotal/                  # VirusTotal client
│   ├── windows/                     # OS usage, processes, sockets, services
│   ├── threat_intel/                # AbuseIPDB, OTX, Shodan API connectors
│   ├── file_monitor/                # Watchdog directory monitor & file hasher
│   ├── network_monitor/             # DNS Cache parser & IP classifier
│   └── ueba/                        # UEBA profiles & deviation evaluator
│
├── data/
│   ├── events/                      # Recorded event JSON streams
│   ├── logs/                        # Platform debug/info logs
│   ├── baselines/                   # Integrity hash baselines & API cache logs
│   └── reports/                     # Security overview summary logs
│
└── docs/                            # Research papers & design specifications
```

---

## 💻 Installation

### 1. Prerequisite Packages
Requires **Python 3.8+** on a Windows host. Install dependencies via pip:

```bash
pip install -r requirements.txt
```

---

## ⚙️ Configuration & API Setup

Configure API credentials and directory targets by creating a `config.json` file in the root workspace folder, or by exporting environment variables.

### Option A: `config.json` Setup (Recommended)
Create `config.json` in the root folder:

```json
{
  "api_keys": {
    "virustotal": "YOUR_VIRUSTOTAL_API_KEY",
    "abuseipdb": "YOUR_ABUSEIPDB_API_KEY",
    "alienvault": "YOUR_ALIENVAULT_OTX_KEY",
    "shodan": "YOUR_SHODAN_KEY"
  },
  "mock_mode": false,
  "monitoring": {
    "file_monitor_path": "./monitored_directory",
    "dns_polling_interval": 5,
    "system_usage_interval": 30,
    "process_polling_interval": 5,
    "service_polling_interval": 60,
    "connections_polling_interval": 10
  }
}
```

### Option B: Environment Variables Setup
Alternatively, set variables in PowerShell:
```powershell
$env:SOC_VIRUSTOTAL_API_KEY="key"
$env:SOC_ABUSEIPDB_API_KEY="key"
$env:SOC_ALIENVAULT_API_KEY="key"
$env:SOC_SHODAN_API_KEY="key"
$env:SOC_MOCK_MODE="False"
```

> [!NOTE]
> **Mock Mode Fallback:** If API keys are left blank, the platform automatically runs in `mock_mode = true`, simulating api reputation lookups and metric events so you can test alert pipelines without active API subscriptions.

---

## 🚀 Execution

Start the platform orchestrator:

```bash
python main.py
```

Press `Ctrl+C` to terminate the monitoring agents cleanly.

---

## 📋 JSON Event Standard

Every event generated conforms to the SIEM schema:

```json
{
  "event_id": "EVT-d0b490f2-ec58-45be-ac9e-32b04f323be0",
  "timestamp": "2026-06-06T11:24:15.004Z",
  "module": "network_connection",
  "event_type": "network_connection",
  "severity": "INFO",
  "status": "success",
  "data": {
    "src_ip": "192.168.1.50",
    "src_port": 50132,
    "dst_ip": "8.8.8.8",
    "dst_port": 53,
    "protocol": "UDP",
    "connection_state": "ESTABLISHED",
    "pid": 3204,
    "process_name": "chrome.exe",
    "resolved_domain": "google.com"
  }
}
```
