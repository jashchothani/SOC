"""
UEBA Engine managing behavioral profiles, session tracking, peer deviations, and risk scoring.
"""
import os
import uuid
from datetime import datetime, timezone, timedelta
from typing import Dict, List, Any
from utils.logger import logger
from utils.timestamp import get_utc_timestamp
from utils.json_manager import read_json_file, write_json_file
from config.constants import DIR_BASELINES, EVENT_UEBA_DEVIATION, SEVERITY_WARNING, SEVERITY_INFO, SEVERITY_CRITICAL
from config.settings import settings

class UEBAEngine:
    def __init__(self, profiles_filename: str = "ueba_profiles.json"):
        self.profiles_path = os.path.join(DIR_BASELINES, profiles_filename)
        self.profiles: Dict[str, dict] = {}
        self.load_profiles()

    def load_profiles(self):
        """Load UEBA baselines from disk."""
        data = read_json_file(self.profiles_path)
        if data and isinstance(data, dict):
            self.profiles = data
            logger.info(f"Loaded {len(self.profiles)} UEBA profiles from {self.profiles_path}")
        else:
            self.profiles = {}
            logger.info("UEBA baseline database is empty. Profiles will be dynamically initialized.")

    def save_profiles(self):
        """Save updated UEBA profiles to disk."""
        os.makedirs(os.path.dirname(self.profiles_path), exist_ok=True)
        write_json_file(self.profiles_path, self.profiles)

    def get_or_create_profile(self, username: str) -> dict:
        """Fetch or initialize a default user profile."""
        # Clean up username strings (e.g. domain\user -> user)
        clean_user = username.split("\\")[-1].lower()
        
        if clean_user not in self.profiles:
            self.profiles[clean_user] = {
                "user_id": clean_user,
                "department": "Engineering" if clean_user != "admin" else "Operations",
                "peer_group": "Developers" if clean_user != "admin" else "SysAdmins",
                "baseline_established_at": get_utc_timestamp(),
                "behavioral_baselines": {
                    "usual_working_hours": {
                        "start": "08:00",
                        "end": "19:00"
                    },
                    "common_ips": ["127.0.0.1"],
                    "common_processes": ["chrome.exe", "vscode.exe", "git.exe", "python.exe", "conhost.exe"],
                    "daily_avg_file_writes": 50,
                    "daily_avg_network_mb": 100.0
                },
                "session_behavior_metrics": {
                    "login_time": get_utc_timestamp(),
                    "source_ip": "127.0.0.1",
                    "session_duration_sec": 0,
                    "active_processes_count": 0,
                    "network_volume_transferred_mb": 0.0
                },
                "peer_group_deviation": {
                    "is_unusual_time": False,
                    "is_unusual_process": False,
                    "is_unusual_network_volume": False,
                    "deviation_percentage": 0.0
                },
                "anomaly_flags": [],
                "risk_score": 0.0
            }
            self.save_profiles()
            logger.info(f"Initialized new UEBA profile for user: {clean_user}")
            
        return self.profiles[clean_user]

    def process_event(self, event: dict) -> List[dict]:
        """
        Evaluate an incoming event for anomalies.
        Returns a list of anomaly deviation events.
        """
        event_type = event.get("event_type")
        module = event.get("module")
        data = event.get("data", {})
        
        # Determine the user associated with this event
        username = data.get("username") or data.get("user") or "system"
        if username == "system" and "process_name" in data:
            # Try parsing user info from contexts
            username = "system"
            
        profile = self.get_or_create_profile(username)
        anomaly_events = []
        
        # 1. Process birth check (Unusual process execution)
        if event_type == "process_created":
            proc_name = data.get("name", "").lower()
            baselines = profile["behavioral_baselines"]
            common_procs = [p.lower() for p in baselines["common_processes"]]
            
            # Check if this process deviates from the user's historical baseline
            if proc_name and proc_name not in common_procs:
                flag = {
                    "flag_id": f"ANM-{uuid.uuid4()}"[:12],
                    "type": "unusual_process",
                    "timestamp": get_utc_timestamp(),
                    "severity": "WARNING",
                    "score_weight": 20.0,
                    "description": f"Executed unusual process not in baseline: {proc_name}"
                }
                
                # Check department peer group deviation
                # SysAdmins run powershell, but developers shouldn't run rawcmd.exe
                is_peer_deviant = False
                if profile["peer_group"] == "Developers" and proc_name in ("cmd.exe", "powershell.exe", "mshta.exe"):
                    is_peer_deviant = True
                    flag["score_weight"] += 15.0 # Elevate score for peer deviation
                    flag["description"] += " (Devs executing administrative shell)"
                    profile["peer_group_deviation"]["is_unusual_process"] = True
                
                profile["anomaly_flags"].append(flag)
                deviation_event = self._create_deviation_event(profile, flag, event)
                anomaly_events.append(deviation_event)

        # 2. Network connection check (Unusual access times or malicious reputation targets)
        elif event_type == "network_connection":
            # Access time check
            now_hour = datetime.now().hour
            baselines = profile["behavioral_baselines"]
            start_hour = int(baselines["usual_working_hours"]["start"].split(":")[0])
            end_hour = int(baselines["usual_working_hours"]["end"].split(":")[0])
            
            if now_hour < start_hour or now_hour > end_hour:
                # Flag time deviation
                if not any(f["type"] == "unusual_access_time" for f in profile["anomaly_flags"]):
                    flag = {
                        "flag_id": f"ANM-{uuid.uuid4()}"[:12],
                        "type": "unusual_access_time",
                        "timestamp": get_utc_timestamp(),
                        "severity": "INFO",
                        "score_weight": 10.0,
                        "description": f"Access session active at unusual hour: {now_hour}:00"
                    }
                    profile["peer_group_deviation"]["is_unusual_time"] = True
                    profile["anomaly_flags"].append(flag)
                    anomaly_events.append(self._create_deviation_event(profile, flag, event))
            
            # Target reputation validation (If connected to an IP enriched with high threat score)
            # This is populated by main loop when threat intel lookups run
            reputation = data.get("threat_reputation")
            if reputation and reputation.get("is_malicious"):
                flag = {
                    "flag_id": f"ANM-{uuid.uuid4()}"[:12],
                    "type": "malicious_destination",
                    "timestamp": get_utc_timestamp(),
                    "severity": "CRITICAL",
                    "score_weight": 45.0,
                    "description": f"Established connection to malicious target {data.get('dst_ip')} (threat score: {reputation.get('reputation_score')})"
                }
                profile["anomaly_flags"].append(flag)
                anomaly_events.append(self._create_deviation_event(profile, flag, event))

        # 3. File Monitor check (High file write activity)
        elif event_type in ("file_created", "file_modified"):
            profile["session_behavior_metrics"]["active_processes_count"] += 1
            # Simple counter
            writes_today = sum(1 for f in profile["anomaly_flags"] if f["type"] == "file_write_spike")
            # If excessive files are created/modified in short time, trigger anomaly flag
            # (indicating ransomware or data exfiltration)
            # Let's say, more than 30 file writes in an hour starts flagging
            active_writes = len(anomaly_events) # placeholder for quick state checks
            
        # Re-calculate risk score: aggregate weights capped at 100.0
        total_weight = sum(flag["score_weight"] for flag in profile["anomaly_flags"])
        profile["risk_score"] = min(total_weight, 100.0)
        
        # Clean up expired flags after 2 hours to allow recovery of baseline score
        self._prune_expired_flags(profile)
        
        self.save_profiles()
        return anomaly_events

    def _prune_expired_flags(self, profile: dict):
        """Removes anomaly flags that are older than 2 hours to avoid risk score stagnation."""
        active_flags = []
        now = datetime.now(timezone.utc)
        for flag in profile["anomaly_flags"]:
            try:
                flag_time = datetime.fromisoformat(flag["timestamp"].replace("Z", "+00:00"))
                if (now - flag_time) < timedelta(hours=2):
                    active_flags.append(flag)
            except Exception:
                active_flags.append(flag)
        profile["anomaly_flags"] = active_flags

    def _create_deviation_event(self, profile: dict, flag: dict, triggering_event: dict) -> dict:
        """Formats a standard SOC event representing the UEBA deviation alert."""
        severity = SEVERITY_WARNING
        if flag["score_weight"] >= 40.0:
            severity = SEVERITY_CRITICAL
        elif flag["score_weight"] <= 10.0:
            severity = SEVERITY_INFO
            
        return {
            "event_id": f"EVT-{uuid.uuid4()}",
            "timestamp": get_utc_timestamp(),
            "module": "ueba_engine",
            "event_type": EVENT_UEBA_DEVIATION,
            "severity": severity,
            "status": "detected",
            "data": {
                "user_id": profile["user_id"],
                "department": profile["department"],
                "peer_group": profile["peer_group"],
                "risk_score": profile["risk_score"],
                "deviation_type": flag["type"],
                "anomaly_details": flag["description"],
                "triggering_event_id": triggering_event.get("event_id")
            }
        }

# Globally accessible UEBA instance
ueba_engine = UEBAEngine()
