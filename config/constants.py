"""
Global constant definitions for the Security Monitoring Platform.
"""

# Severity levels conforming to enterprise SOC/SIEM standards
SEVERITY_INFO = "INFO"
SEVERITY_WARNING = "WARNING"
SEVERITY_ERROR = "ERROR"
SEVERITY_CRITICAL = "CRITICAL"

# Collection intervals in seconds
INTERVAL_5_SEC = 5
INTERVAL_30_SEC = 30
INTERVAL_1_MIN = 60
INTERVAL_5_MIN = 300
INTERVAL_15_MIN = 900

# Directory paths relative to project root
DIR_DATA = "data"
DIR_EVENTS = "data/events"
DIR_LOGS = "data/logs"
DIR_BASELINES = "data/baselines"
DIR_REPORTS = "data/reports"
DIR_DOCS = "docs"

# Standard Event Types
EVENT_SYSTEM_USAGE = "system_usage"
EVENT_PROCESS_CREATED = "process_created"
EVENT_PROCESS_TERMINATED = "process_terminated"
EVENT_NETWORK_CONNECTION = "network_connection"
EVENT_SERVICE_STATUS = "service_status"
EVENT_FILE_CREATED = "file_created"
EVENT_FILE_DELETED = "file_deleted"
EVENT_FILE_MODIFIED = "file_modified"
EVENT_FILE_RENAMED = "file_renamed"
EVENT_DNS_QUERY = "dns_query"
EVENT_THREAT_INTEL = "threat_intel_enrichment"
EVENT_UEBA_DEVIATION = "ueba_deviation"
EVENT_SYSTEM_ALERT = "system_alert"

# API Endpoints
VIRUSTOTAL_BASE_URL = "https://www.virustotal.com/api/v3"
ABUSEIPDB_BASE_URL = "https://api.abuseipdb.com/api/v2"
ALIENVAULT_BASE_URL = "https://otx.alienvault.com/api/v1"
SHODAN_BASE_URL = "https://api.shodan.io"
SHODAN_INTERNETDB_URL = "https://internetdb.shodan.io"
