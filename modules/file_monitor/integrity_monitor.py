"""
Integrity monitoring component checking files against a known hash baseline.
"""
import os
import uuid
from typing import Dict, List
from utils.logger import logger
from utils.timestamp import get_utc_timestamp
from utils.error_handler import run_gracefully
from utils.json_manager import read_json_file, write_json_file
from modules.file_monitor.file_hashing import calculate_sha256
from config.constants import DIR_BASELINES, SEVERITY_WARNING, SEVERITY_INFO

class IntegrityMonitor:
    def __init__(self, baseline_filename: str = "integrity_baseline.json"):
        self.baseline_path = os.path.join(DIR_BASELINES, baseline_filename)

    @run_gracefully(module_name="integrity_monitor", default_return=False)
    def generate_baseline(self, directory_to_baseline: str) -> bool:
        """Scan a directory and record hashes of all files to the baseline file."""
        if not os.path.exists(directory_to_baseline):
            logger.error(f"Cannot generate baseline: directory does not exist: {directory_to_baseline}")
            return False
            
        baseline: Dict[str, str] = {}
        for root, _, files in os.walk(directory_to_baseline):
            for file in files:
                filepath = os.path.join(root, file)
                normalized_path = os.path.abspath(filepath)
                file_hash = calculate_sha256(normalized_path)
                if file_hash:
                    baseline[normalized_path] = file_hash
                    
        os.makedirs(os.path.dirname(self.baseline_path), exist_ok=True)
        write_json_file(self.baseline_path, baseline)
        logger.info(f"Generated file integrity baseline at {self.baseline_path} with {len(baseline)} entries.")
        return True

    @run_gracefully(module_name="integrity_monitor", default_return=[])
    def check_integrity(self, directory_to_check: str) -> List[dict]:
        """
        Compare current files against the baseline.
        Returns a list of alerts for modified, missing, or added files.
        """
        baseline: Dict[str, str] = read_json_file(self.baseline_path)
        if baseline is None:
            logger.warning("Integrity baseline file not found. Generating baseline first.")
            self.generate_baseline(directory_to_check)
            return []
            
        alerts: List[dict] = []
        current_files: Dict[str, str] = {}
        
        # Scan target folder
        for root, _, files in os.walk(directory_to_check):
            for file in files:
                filepath = os.path.join(root, file)
                normalized_path = os.path.abspath(filepath)
                file_hash = calculate_sha256(normalized_path)
                if file_hash:
                    current_files[normalized_path] = file_hash
                    
        # Check for modifications & deleted files
        for baseline_path, baseline_hash in baseline.items():
            if baseline_path not in current_files:
                # File Deleted
                alert = self._create_integrity_alert(
                    filepath=baseline_path,
                    alert_type="integrity_file_deleted",
                    message=f"Critical file missing from baseline: {baseline_path}",
                    severity=SEVERITY_WARNING
                )
                alerts.append(alert)
                logger.warning(f"Integrity Alert [DELETED]: {baseline_path}")
            elif current_files[baseline_path] != baseline_hash:
                # File Modified
                alert = self._create_integrity_alert(
                    filepath=baseline_path,
                    alert_type="integrity_file_modified",
                    message=f"File hash changed from baseline: {baseline_path}",
                    severity=SEVERITY_WARNING
                )
                alerts.append(alert)
                logger.warning(f"Integrity Alert [MODIFIED]: {baseline_path}")
                
        # Check for new files not in baseline
        for current_path, current_hash in current_files.items():
            if current_path not in baseline:
                alert = self._create_integrity_alert(
                    filepath=current_path,
                    alert_type="integrity_file_added",
                    message=f"New file found not present in baseline: {current_path}",
                    severity=SEVERITY_INFO
                )
                alerts.append(alert)
                logger.info(f"Integrity Alert [ADDED]: {current_path}")
                
        return alerts

    def _create_integrity_alert(self, filepath: str, alert_type: str, message: str, severity: str) -> dict:
        filename = os.path.basename(filepath)
        location = os.path.dirname(os.path.abspath(filepath))
        
        # Conforms to event schema standard
        return {
            "event_id": f"EVT-{uuid.uuid4()}",
            "timestamp": get_utc_timestamp(),
            "module": "integrity_monitor",
            "event_type": alert_type,
            "severity": severity,
            "status": "detected",
            "data": {
                "message": message,
                "filename": filename,
                "location": location,
                "filepath": filepath
            }
        }
