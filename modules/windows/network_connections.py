"""
Windows active network connection tracker (TCP/UDP ports, IPs, protocols, and originating PID).
"""
import psutil
import uuid
from typing import List
from utils.logger import logger
from utils.timestamp import get_utc_timestamp
from utils.error_handler import run_gracefully
from config.constants import EVENT_NETWORK_CONNECTION, SEVERITY_INFO

@run_gracefully(module_name="network_connections", default_return=[])
def collect_network_connections() -> List[dict]:
    """Retrieves active TCP/UDP sockets and returns them as a list of SOC events."""
    events = []
    
    # Pre-cache PID to Process Name map to avoid slow lookups inside loop
    pid_name_cache = {}
    for proc in psutil.process_iter(['pid', 'name']):
        try:
            pid_name_cache[proc.info['pid']] = proc.info['name']
        except (psutil.NoSuchProcess, psutil.AccessDenied):
            continue
            
    # Fetch connection records
    connections = psutil.net_connections(kind='inet')
    
    for conn in connections:
        # We only care about connections with endpoints established
        # (e.g. bypass completely unbound listening UDP ports unless they have a status, or include TCP only)
        # However, to be thorough, let's process any connection with a remote address or listening state
        
        src_ip = conn.laddr.ip if conn.laddr else ""
        src_port = conn.laddr.port if conn.laddr else 0
        
        dst_ip = conn.raddr.ip if conn.raddr else ""
        dst_port = conn.raddr.port if conn.raddr else 0
        
        # Skip local loopback traffic if needed, or monitor everything. We monitor everything but label appropriately
        protocol = "TCP" if conn.type == 1 else "UDP" # type 1 is socket.SOCK_STREAM, type 2 is socket.SOCK_DGRAM
        status = conn.status
        pid = conn.pid or 0
        proc_name = pid_name_cache.get(pid, "unknown")
        
        event = {
            "event_id": f"EVT-{uuid.uuid4()}",
            "timestamp": get_utc_timestamp(),
            "module": "windows_network",
            "event_type": EVENT_NETWORK_CONNECTION,
            "severity": SEVERITY_INFO,
            "status": "success",
            "data": {
                "src_ip": src_ip,
                "src_port": src_port,
                "dst_ip": dst_ip,
                "dst_port": dst_port,
                "protocol": protocol,
                "connection_state": status,
                "pid": pid,
                "process_name": proc_name
            }
        }
        events.append(event)
        
    logger.debug(f"Collected {len(events)} network socket records.")
    return events
