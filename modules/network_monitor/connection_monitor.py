"""
Network connection monitor identifying new external sockets and mapping resolved domains to target IPs.
"""
import uuid
from typing import List, Set, Dict, Tuple
from utils.logger import logger
from utils.timestamp import get_utc_timestamp
from utils.error_handler import run_gracefully
from modules.windows.network_connections import collect_network_connections
from modules.network_monitor.ip_monitor import is_external_ip
from config.constants import EVENT_NETWORK_CONNECTION, SEVERITY_INFO, SEVERITY_WARNING

class ConnectionMonitor:
    def __init__(self):
        # Cache active connections as: (src_ip, src_port, dst_ip, dst_port, protocol)
        self.seen_connections: Set[Tuple[str, int, str, int, str]] = set()
        self.is_first_scan = True

    @run_gracefully(module_name="connection_monitor", default_return=[])
    def scan(self, dns_cache_map: Dict[str, str]) -> List[dict]:
        """
        Scans current sockets, flags new public connections, and links them to domains.
        
        dns_cache_map: Map of IP address -> Resolved Domain Name
        """
        raw_conns = collect_network_connections()
        new_events: List[dict] = []
        current_active_keys: Set[Tuple[str, int, str, int, str]] = set()
        
        for conn in raw_conns:
            data = conn["data"]
            src_ip = data["src_ip"]
            src_port = data["src_port"]
            dst_ip = data["dst_ip"]
            dst_port = data["dst_port"]
            protocol = data["protocol"]
            
            # Key identifier for unique socket channel
            key = (src_ip, src_port, dst_ip, dst_port, protocol)
            current_active_keys.add(key)
            
            # Skip local or loopback checks on first baseline
            if self.is_first_scan:
                continue
                
            # If connection is newly spawned
            if key not in self.seen_connections:
                # We focus on public/external targets
                if dst_ip and is_external_ip(dst_ip):
                    resolved_domain = dns_cache_map.get(dst_ip, "")
                    
                    severity = SEVERITY_INFO
                    # Alert on common suspicious outbound ports (e.g. IRC, SSH, Telnet, SMB)
                    if dst_port in (21, 22, 23, 137, 138, 139, 445, 6667):
                        severity = SEVERITY_WARNING
                        
                    event = {
                        "event_id": f"EVT-{uuid.uuid4()}",
                        "timestamp": get_utc_timestamp(),
                        "module": "network_connection",
                        "event_type": EVENT_NETWORK_CONNECTION,
                        "severity": severity,
                        "status": "success",
                        "data": {
                            "src_ip": src_ip,
                            "src_port": src_port,
                            "dst_ip": dst_ip,
                            "dst_port": dst_port,
                            "protocol": protocol,
                            "connection_state": data["connection_state"],
                            "pid": data["pid"],
                            "process_name": data["process_name"],
                            "resolved_domain": resolved_domain
                        }
                    }
                    new_events.append(event)
                    logger.info(
                        f"New outbound connection: PID={data['pid']} ({data['process_name']}) -> "
                        f"{dst_ip}:{dst_port} ({resolved_domain or 'No DNS'})"
                    )
                    
        # Update connections cache
        self.seen_connections = current_active_keys
        
        if self.is_first_scan:
            self.is_first_scan = False
            logger.info(f"Connection monitor baseline established with {len(self.seen_connections)} active sockets.")
            
        return new_events

# Globally accessible connection monitor object
connection_monitor = ConnectionMonitor()
