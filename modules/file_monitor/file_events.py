"""
Asynchronous, event-driven file system monitor utilizing Watchdog API.
"""
import os
import uuid
from typing import Callable
from watchdog.observers import Observer
from watchdog.events import FileSystemEventHandler, FileSystemEvent
from utils.logger import logger
from utils.timestamp import get_utc_timestamp
from utils.error_handler import run_gracefully
from modules.file_monitor.file_hashing import calculate_sha256
from config.constants import (
    EVENT_FILE_CREATED, EVENT_FILE_DELETED, EVENT_FILE_MODIFIED, EVENT_FILE_RENAMED,
    SEVERITY_INFO, SEVERITY_WARNING
)

class FileMonitorHandler(FileSystemEventHandler):
    def __init__(self, event_callback: Callable[[dict], None]):
        super().__init__()
        self.event_callback = event_callback

    def _process_event(self, event_type: str, filepath: str, dest_filepath: str = None):
        """Build standard event objects and send to database callback."""
        if os.path.isdir(filepath) or (dest_filepath and os.path.isdir(dest_filepath)):
            # Skip directories, monitor files only
            return
            
        filename = os.path.basename(filepath)
        location = os.path.dirname(os.path.abspath(filepath))
        
        file_hash = ""
        # Do not calculate hash for deletions
        if event_type != EVENT_FILE_DELETED and os.path.exists(filepath):
            try:
                file_hash = calculate_sha256(filepath)
            except Exception as e:
                logger.warning(f"Could not hash file {filepath} (might be locked/temp): {e}")
                
        severity = SEVERITY_INFO
        # Alert if executable files are changed
        if filename.endswith(('.exe', '.dll', '.bat', '.ps1', '.vbs', '.cmd')):
            severity = SEVERITY_WARNING
            
        file_details = {
            "filename": filename,
            "location": location,
            "hash": file_hash
        }
        
        if event_type == EVENT_FILE_RENAMED and dest_filepath:
            file_details["dest_filename"] = os.path.basename(dest_filepath)
            file_details["dest_location"] = os.path.dirname(os.path.abspath(dest_filepath))
            
        # Conforms to BOTH standard event schema AND file event schema
        soc_event = {
            "event_id": f"EVT-{uuid.uuid4()}",
            "timestamp": get_utc_timestamp(),
            "module": "file_monitor",
            "event_type": event_type,
            "severity": severity,
            "status": "success",
            "data": file_details,
            "file_details": file_details
        }
        
        logger.info(f"File Event [{event_type.upper()}]: {filename} in {location}")
        self.event_callback(soc_event)
        
        # Trigger AI Secret Scanning asynchronously for creations and modifications
        if event_type in (EVENT_FILE_CREATED, EVENT_FILE_MODIFIED) and os.path.exists(filepath):
            import threading
            from modules.ai.credential_scanner import scan_file_for_secrets
            
            def run_scan():
                try:
                    alert = scan_file_for_secrets(filepath)
                    if alert:
                        self.event_callback(alert)
                except Exception as e:
                    logger.error(f"Error in background AI file scan: {e}")
                    
            threading.Thread(target=run_scan, name=f"AIScan-{filename}", daemon=True).start()

    def on_created(self, event: FileSystemEvent):
        self._process_event(EVENT_FILE_CREATED, event.src_path)

    def on_deleted(self, event: FileSystemEvent):
        self._process_event(EVENT_FILE_DELETED, event.src_path)

    def on_modified(self, event: FileSystemEvent):
        self._process_event(EVENT_FILE_MODIFIED, event.src_path)

    def on_moved(self, event: FileSystemEvent):
        self._process_event(EVENT_FILE_RENAMED, event.src_path, event.dest_path)


class FileMonitor:
    def __init__(self, monitor_path: str, event_callback: Callable[[dict], None]):
        self.monitor_path = monitor_path
        self.event_callback = event_callback
        self.observer = Observer()
        self.handler = FileMonitorHandler(self.event_callback)

    @run_gracefully(module_name="file_monitor")
    def start(self):
        """Starts directory observer in background daemon thread."""
        os.makedirs(self.monitor_path, exist_ok=True)
        self.observer.schedule(self.handler, self.monitor_path, recursive=True)
        self.observer.start()
        logger.info(f"Asynchronous file system observer started on path: {self.monitor_path}")

    def stop(self):
        """Stops background observer."""
        self.observer.stop()
        self.observer.join()
        logger.info("Asynchronous file system observer stopped.")
