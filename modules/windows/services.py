"""
Windows services monitor querying service states (Running vs. Stopped).
"""
import psutil
import uuid
from typing import List
from utils.logger import logger
from utils.timestamp import get_utc_timestamp
from utils.error_handler import run_gracefully
from config.constants import EVENT_SERVICE_STATUS, SEVERITY_INFO

@run_gracefully(module_name="services_monitor", default_return=[])
def collect_services() -> List[dict]:
    """Retrieves status details for Windows Services and returns list of SOC events."""
    events = []
    
    # psutil win_service_iter is only supported on Windows
    if not psutil.WINDOWS:
        logger.warning("Service monitoring requested but system is not Windows. Skipping service checks.")
        return []
        
    for svc in psutil.win_service_iter():
        try:
            info = svc.as_dict()
            name = info.get('name', 'unknown')
            display_name = info.get('display_name', '')
            status = info.get('status', 'unknown')
            start_type = info.get('start_type', 'unknown')
            binpath = info.get('binpath', '')
            
            # Form standard SOC event
            event = {
                "event_id": f"EVT-{uuid.uuid4()}",
                "timestamp": get_utc_timestamp(),
                "module": "windows_services",
                "event_type": EVENT_SERVICE_STATUS,
                "severity": SEVERITY_INFO,
                "status": "success",
                "data": {
                    "service_name": name,
                    "display_name": display_name,
                    "status": status,
                    "start_type": start_type,
                    "binary_path": binpath
                }
            }
            events.append(event)
        except Exception as svc_err:
            # SCM permissions or transient states can cause individual service reads to fail
            continue
            
    logger.debug(f"Collected {len(events)} service status records.")
    return events
