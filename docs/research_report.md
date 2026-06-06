# Enterprise Security Monitoring - Research Report

This research report documents the security APIs, endpoints, utilities, and engineering techniques used to build the monitoring and threat intelligence platform.

---

## 1. Windows Monitoring APIs

To achieve performant, cross-version Windows monitoring, we evaluated several APIs:

### A. System Usage Metrics
- **Mechanism:** Python `psutil` wraps C APIs (`GetSystemTimes`, `GlobalMemoryStatusEx`, `GetDiskFreeSpaceEx`, `GetIfTable2`).
- **Data Points Collected:**
  - **CPU:** `psutil.cpu_percent(interval=None)` (non-blocking).
  - **Memory:** `psutil.virtual_memory()` (total, available, percent, used).
  - **Disk:** `psutil.disk_usage('/')` (total, used, free, percent).
  - **Network:** `psutil.net_io_counters()` (bytes sent/received, packets sent/received).

### B. Process Monitoring
- **Mechanism:** Dual-layer process tracking.
  - **Snapshot Polling:** `psutil.process_iter(['pid', 'name', 'username', 'ppid', 'exe', 'create_time'])`.
  - **Real-Time Births (WMI Event Subscriptions):** WMI allows listening for process launch events asynchronously. In Python, this can be achieved natively without heavy modules by subscribing to `__InstanceCreationEvent` on the class `Win32_Process`.
  - **Command Fallback:** Standard process querying can fall back to running `tasklist /FO JSON` or `powershell Get-Process` inside `subprocess.Popen` if `psutil` encounters permission limits.

### C. Network Connections
- **Mechanism:** `psutil.net_connections(kind='inet')`.
  - Maps to Windows `GetExtendedTcpTable` and `GetExtendedUdpTable` APIs.
  - Obtains source IP (`laddr.ip`), source port (`laddr.port`), destination IP (`raddr.ip`), destination port (`raddr.port`), socket status, protocol (TCP/UDP), and PID.

### D. Windows Services
- **Mechanism:** `psutil.win_service_iter()` and `psutil.win_service_get(name)`.
  - Wraps the Service Control Manager (SCM) APIs (`EnumServicesStatusEx`).
  - Reports service status (e.g., `running`, `stopped`, `start_pending`) and configurations.

---

## 2. Threat Intelligence APIs

### A. VirusTotal API v3
- **Base URL:** `https://www.virustotal.com/api/v3`
- **Authentication:** `x-apikey: <api_key>` in header.
- **Endpoints:**
  - **Check IP:** `GET /ip_addresses/{ip}`
  - **Check Domain:** `GET /domains/{domain}`
  - **Check Hash:** `GET /files/{hash}`
  - **Upload File:** `POST /files` (Returns analysis ID, query `GET /analyses/{id}` to fetch result).

### B. AbuseIPDB API v2
- **Base URL:** `https://api.abuseipdb.com/api/v2`
- **Authentication:** `Key: <api_key>` and `Accept: application/json` in headers.
- **Endpoints:**
  - **Check IP:** `GET /check?ipAddress={ip}&maxAgeInDays=90&verbose`

### C. AlienVault OTX API v1
- **Base URL:** `https://otx.alienvault.com/api/v1`
- **Authentication:** `X-OTX-API-KEY: <api_key>` in header.
- **Endpoints:**
  - **Check IP:** `GET /indicators/IPv4/{ip}/general`
  - **Check Domain:** `GET /indicators/domain/{domain}/general`
  - **Check Hash:** `GET /indicators/file/{hash}/general`

### D. Shodan API
- **Base URL:** `https://api.shodan.io` & `https://internetdb.shodan.io`
- **Authentication:** Query parameter `key` (for main endpoints); no authentication needed for InternetDB.
- **Endpoints:**
  - **Host Lookup (Standard):** `GET /shodan/host/{ip}?key={api_key}`
  - **InternetDB (Fast check):** `GET /1.1.1.1` on `https://internetdb.shodan.io` (Provides open ports, hostnames, and vulnerabilities without keys).

---

## 3. File Monitoring & Integrity

### A. High-Performance Directory Monitoring
- **Mechanism:** Python `watchdog` library.
  - On Windows, `watchdog` invokes `ReadDirectoryChangesW` asynchronously in a background thread pool.
  - Generates events on:
    - `on_created`: File creation.
    - `on_deleted`: File deletion.
    - `on_modified`: File edit (triggered by metadata/write changes).
    - `on_moved`: File renaming or path change.

### B. Integrity Verification
- **Mechanism:** Python `hashlib`.
  - Calculates SHA256, SHA1, or MD5 of file content.
  - Implements chunk-based hashing to prevent high memory usage on large files:
    ```python
    sha256 = hashlib.sha256()
    with open(filepath, 'rb') as f:
        while chunk := f.read(8192):
            sha256.update(chunk)
    ```

---

## 4. DNS Monitoring on Windows

Windows does not write DNS queries to a simple text file. We researched three ways to capture DNS transactions in Python:

1. **DNS Client Cache Polling (Native & Low Overhead):**
   - Execute `ipconfig /displaydns` or the PowerShell cmdlet `Get-DnsClientCache`.
   - Parse the structured stdout.
   - Pros: Works immediately, requires no administrative rights.
   - Cons: Polling based (can miss transient requests).
2. **Sniffing Port 53 Traffic (Raw socket / Scapy):**
   - Uses `scapy` to sniff packets.
   - Pros: Catches raw DNS packets.
   - Cons: Requires installing `Npcap` driver on Windows, which is an external dependency and requires high permissions.
3. **ETW (Event Tracing for Windows) / Windows Event Logs:**
   - Querying the `Microsoft-Windows-DNS-Client/Operational` event log channel (Event ID 3008).
   - Read via `win32evtlog` or Python `subprocess` querying `wevtutil qe Microsoft-Windows-DNS-Client/Operational /q:"*[System[(EventID=3008)]]" /f:text`.
   - Pros: Clean, event-driven, native.
   - Cons: DNS Operational logging must be enabled in Windows Event Viewer first.

**Platform Decision:** We will implement **DNS Client Cache Polling** as the primary method, with an optional **Windows Event Log Reader** that checks if the DNS operational channel is active.

---

## 5. Engineering Challenges & Solutions

### A. Rate Limits & Caching
- Threat Intel free tiers are highly restricted (VirusTotal: 4 reqs/min).
- **Solution:** Implement an in-memory cache with disk-based persistence (`data/baselines/threat_intel_cache.json`). Cache entries expire after 24 hours.

### B. Performance & Multithreading
- Network queries are blocking operations.
- **Solution:** Implement a worker pool using Python's `concurrent.futures.ThreadPoolExecutor`. File monitoring and WMI event tracking run on dedicated background daemon threads.

### C. Large JSON File Rotation
- Accumulating events in a single JSON file can crash memory.
- **Solution:** Implement JSON rotation. If `events.json` exceeds a threshold (e.g., 10MB), rotate it to `events_YYYY-MM-DD_HHMMSST.json`.
