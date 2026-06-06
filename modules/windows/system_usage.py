"""
Windows System Usage monitor (CPU, Memory, Disk, Network IO).
"""
import psutil
import uuid
from utils.logger import logger
from utils.timestamp import get_utc_timestamp
from utils.error_handler import run_gracefully
from config.constants import EVENT_SYSTEM_USAGE, SEVERITY_INFO, SEVERITY_WARNING

@run_gracefully(module_name="system_usage", default_return={})
def collect_system_usage() -> dict:
    """Collects CPU, RAM, Disk, and Network traffic usage metrics on Windows."""
    # CPU Percent (non-blocking call)
    cpu_percent = psutil.cpu_percent(interval=None)
    
    # RAM Usage
    virtual_mem = psutil.virtual_memory()
    ram_total_gb = round(virtual_mem.total / (1024 ** 3), 2)
    ram_used_gb = round(virtual_mem.used / (1024 ** 3), 2)
    ram_percent = virtual_mem.percent
    
    # Disk Usage (Primary C: drive on Windows or root '/')
    disk_path = "C:\\" if psutil.WINDOWS else "/"
    try:
        disk_info = psutil.disk_usage(disk_path)
        disk_total_gb = round(disk_info.total / (1024 ** 3), 2)
        disk_used_gb = round(disk_info.used / (1024 ** 3), 2)
        disk_percent = disk_info.percent
    except Exception as disk_err:
        logger.warning(f"Could not read disk usage for path '{disk_path}': {disk_err}. Defaulting to empty fields.")
        disk_total_gb = disk_used_gb = disk_percent = 0.0
        
    # Network IO
    net_io = psutil.net_io_counters()
    net_sent_mb = round(net_io.bytes_sent / (1024 * 1024), 2)
    net_recv_mb = round(net_io.bytes_recv / (1024 * 1024), 2)
    
    severity = SEVERITY_INFO
    if cpu_percent > 85.0 or ram_percent > 90.0 or disk_percent > 95.0:
        severity = SEVERITY_WARNING
        
    # Standard SOC Event layout
    event = {
        "event_id": f"EVT-{uuid.uuid4()}",
        "timestamp": get_utc_timestamp(),
        "module": "windows_usage",
        "event_type": EVENT_SYSTEM_USAGE,
        "severity": severity,
        "status": "success",
        "data": {
            "cpu": {
                "percent": cpu_percent
            },
            "ram": {
                "total_gb": ram_total_gb,
                "used_gb": ram_used_gb,
                "percent": ram_percent
            },
            "disk": {
                "drive": disk_path,
                "total_gb": disk_total_gb,
                "used_gb": disk_used_gb,
                "percent": disk_percent
            },
            "network": {
                "mb_sent": net_sent_mb,
                "mb_received": net_recv_mb
            }
        }
    }
    
    logger.debug(f"Collected system usage: CPU={cpu_percent}%, RAM={ram_percent}%, Disk={disk_percent}%")
    return event
