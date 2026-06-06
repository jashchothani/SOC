"""
Windows process monitor tracking active running processes and process birth/death event triggers.
"""
import psutil
import uuid
from typing import Dict, List, Set, Any
from utils.logger import logger
from utils.timestamp import get_utc_timestamp
from utils.error_handler import run_gracefully
from config.constants import EVENT_PROCESS_CREATED, EVENT_PROCESS_TERMINATED, SEVERITY_INFO

# Class to keep track of process states between intervals
class ProcessMonitor:
    def __init__(self):
        self.known_processes: Dict[int, Dict[str, Any]] = {}
        self.is_first_scan = True

    @run_gracefully(module_name="process_monitor", default_return=[])
    def scan(self) -> List[dict]:
        """
        Scan running processes.
        Returns a list of birth and death events compared to the previous scan.
        """
        current_processes: Dict[int, Dict[str, Any]] = {}
        events: List[dict] = []
        
        # Collect currently running processes
        for proc in psutil.process_iter(['pid', 'ppid', 'name', 'username', 'exe', 'cmdline']):
            try:
                info = proc.info
                pid = info['pid']
                current_processes[pid] = {
                    "pid": pid,
                    "ppid": info['ppid'] or 0,
                    "name": info['name'] or "unknown",
                    "username": info['username'] or "SYSTEM",
                    "exe": info['exe'] or "",
                    "command_line": " ".join(info['cmdline']) if info['cmdline'] else ""
                }
            except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
                continue
                
        # On first run, establish baseline and generate no birth/death events
        if self.is_first_scan:
            self.known_processes = current_processes
            self.is_first_scan = False
            logger.info(f"Process monitor baseline established with {len(self.known_processes)} running processes.")
            return []
            
        # Detect Process Created (present in current_processes but not known_processes)
        new_pids = set(current_processes.keys()) - set(self.known_processes.keys())
        for pid in new_pids:
            proc_data = current_processes[pid]
            event = {
                "event_id": f"EVT-{uuid.uuid4()}",
                "timestamp": get_utc_timestamp(),
                "module": "windows_process",
                "event_type": EVENT_PROCESS_CREATED,
                "severity": SEVERITY_INFO,
                "status": "success",
                "data": proc_data
            }
            events.append(event)
            logger.info(f"Process Created: PID={pid}, Name={proc_data['name']}")
            
        # Detect Process Terminated (present in known_processes but not current_processes)
        dead_pids = set(self.known_processes.keys()) - set(current_processes.keys())
        for pid in dead_pids:
            proc_data = self.known_processes[pid]
            event = {
                "event_id": f"EVT-{uuid.uuid4()}",
                "timestamp": get_utc_timestamp(),
                "module": "windows_process",
                "event_type": EVENT_PROCESS_TERMINATED,
                "severity": SEVERITY_INFO,
                "status": "success",
                "data": proc_data
            }
            events.append(event)
            logger.info(f"Process Terminated: PID={pid}, Name={proc_data['name']}")
            
        # Update state cache
        self.known_processes = current_processes
        return events

# Globally accessible process monitor object
process_monitor = ProcessMonitor()
