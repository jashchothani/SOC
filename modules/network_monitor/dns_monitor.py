"""
DNS Query Monitor parsing Windows local DNS Client Cache.
"""
import subprocess
import json
import uuid
import re
import psutil
from typing import List, Set, Tuple
from utils.logger import logger
from utils.timestamp import get_utc_timestamp
from utils.error_handler import run_gracefully
from config.constants import EVENT_DNS_QUERY, SEVERITY_INFO

class DNSMonitor:
    def __init__(self):
        self.seen_resolutions: Set[Tuple[str, str]] = set()
        self.is_first_scan = True

    @run_gracefully(module_name="dns_monitor", default_return=[])
    def scan(self) -> List[dict]:
        """
        Scans DNS resolutions from the Windows DNS Cache.
        Returns newly detected queries.
        """
        resolutions = self._collect_dns_cache()
        events = []
        
        if self.is_first_scan:
            self.seen_resolutions = set(resolutions)
            self.is_first_scan = False
            logger.info(f"DNS baseline established with {len(self.seen_resolutions)} cached resolutions.")
            return []
            
        for query, ip in resolutions:
            if (query, ip) not in self.seen_resolutions:
                self.seen_resolutions.add((query, ip))
                
                # Standard DNS monitoring schema fields + SOC standard event schema
                event = {
                    "event_id": f"EVT-{uuid.uuid4()}",
                    "timestamp": get_utc_timestamp(),
                    "module": "network_dns",
                    "event_type": EVENT_DNS_QUERY,
                    "severity": SEVERITY_INFO,
                    "status": "success",
                    "query": query,
                    "resolved_ip": ip,
                    "data": {
                        "query": query,
                        "resolved_ip": ip
                    }
                }
                events.append(event)
                logger.info(f"DNS Resolution Detected: Query={query} -> IP={ip}")
                
        return events

    def _collect_dns_cache(self) -> List[Tuple[str, str]]:
        """Collect DNS entries using PowerShell Get-DnsClientCache or ipconfig backup."""
        if not psutil.WINDOWS:
            return []
            
        # Try PowerShell first (JSON output makes it extremely clean)
        try:
            cmd = ["powershell", "-NoProfile", "-Command", "Get-DnsClientCache | Select-Object Name, Data | ConvertTo-Json"]
            proc = subprocess.run(cmd, capture_output=True, text=True, timeout=10)
            if proc.returncode == 0 and proc.stdout.strip():
                data = json.loads(proc.stdout)
                entries = []
                # Handle single object vs list output from PowerShell
                if isinstance(data, dict):
                    data = [data]
                for item in data:
                    name = item.get("Name")
                    ip = item.get("Data")
                    if name and ip and not name.startswith("localhost") and not name.endswith(".local"):
                        # Ensure Data is an IP address
                        if re.match(r'^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$', str(ip)):
                            entries.append((name.lower(), str(ip)))
                return entries
        except Exception as e:
            logger.debug(f"PowerShell DNS query failed, attempting ipconfig displaydns fallback: {e}")
            
        # Fallback to ipconfig /displaydns
        return self._collect_ipconfig_displaydns()

    def _collect_ipconfig_displaydns(self) -> List[Tuple[str, str]]:
        """Fallback regex parser for ipconfig /displaydns."""
        entries = []
        try:
            proc = subprocess.run(["ipconfig", "/displaydns"], capture_output=True, text=True, timeout=10)
            if proc.returncode == 0:
                output = proc.stdout
                # Match records
                record_blocks = output.split("\n\n")
                for block in record_blocks:
                    name_match = re.search(r'Record Name\s+\.\s+\.\s+\.\s+\.\s+:\s+([^\s\r\n]+)', block)
                    ip_match = re.search(r'(?:A \(Host\) Record|IP Address)\s+\.\s+\.\s+\.\s+:\s+([0-9\.]+)', block)
                    if name_match and ip_match:
                        query = name_match.group(1).lower()
                        ip = ip_match.group(1)
                        if query and ip and not query.startswith("localhost"):
                            entries.append((query, ip))
        except Exception as e:
            logger.error(f"Failed to query local DNS cache using ipconfig fallback: {e}")
        return entries

# Globally accessible dns monitor object
dns_monitor = DNSMonitor()
