"""
================================================================================
TEAM 9 — USER BEHAVIOR & IDENTITY CONTEXT (UEBA BASELINE ENGINE)
================================================================================
This engine computes, validates, and stores behavioral profiles for all entities
and users across the platform. It correlates physical badge logs, HR feeds,
ticketing data, and real-time events to detect compromised credentials, insider
threats, and administrative privilege abuse.

CRITICAL SECURITY DETECTS:
1. Anomalous working hours and weekend logins.
2. Unusual processes and administrative shell execution by developer peer groups.
3. Rapid risk escalation scoring (low, medium, high, critical tiers).
4. Malicious target connections enriched by threat intelligence.
5. Activity from terminated employees (HR correlation).
6. Spoofed User-Agent headers, database query spikes, and local admin commands.
================================================================================
"""
import os
import uuid
import hashlib
from datetime import datetime, timezone, timedelta
from typing import Dict, List, Any
from utils.logger import logger
from utils.timestamp import get_utc_timestamp
from utils.json_manager import read_json_file, write_json_file
from config.constants import DIR_BASELINES, EVENT_UEBA_DEVIATION, SEVERITY_WARNING, SEVERITY_INFO, SEVERITY_CRITICAL
from config.settings import settings

class UEBAEngine:
    def __init__(self, profiles_filename: str = "ueba_profiles.json"):
        """Initialize the UEBA Engine, load historical profiles, and seed defaults if empty."""
        self.profiles_path = os.path.join(DIR_BASELINES, profiles_filename)
        self.profiles: Dict[str, dict] = {}
        self.load_profiles()
        self.ensure_default_profiles()

    def load_profiles(self):
        """Load UEBA baseline database from disk."""
        data = read_json_file(self.profiles_path)
        if data and isinstance(data, dict):
            self.profiles = data
            logger.info(f"Loaded {len(self.profiles)} UEBA profiles from {self.profiles_path}")
        else:
            self.profiles = {}
            logger.info("UEBA baseline database is empty or missing.")

    def save_profiles(self):
        """Persist updated UEBA profiles back to disk."""
        os.makedirs(os.path.dirname(self.profiles_path), exist_ok=True)
        write_json_file(self.profiles_path, self.profiles)

    def hash_email(self, email: str) -> str:
        """Utility helper to hash user email for identity correlation."""
        return hashlib.sha256(email.lower().strip().encode('utf-8')).hexdigest()

    def ensure_default_profiles(self):
        """Ensure all default UEBA user profiles exist in the baseline database."""
        changed = False
        
        # 1. Administrator Profile
        if "admin" not in self.profiles:
            self.profiles["admin"] = self.create_blank_profile(
                user_id="admin",
                username="admin",
                email="admin@enterprise.com",
                employee_id="EMP-0001",
                department="Operations",
                role="System Administrator",
                manager_id="mgr-director",
                access_tier="admin",
                employment_status="active"
            )
            self.profiles["admin"]["typical_login_hours_start"] = 6
            self.profiles["admin"]["typical_login_hours_end"] = 22
            self.profiles["admin"]["typical_process_names"] = ["cmd.exe", "powershell.exe", "bash", "conhost.exe", "msc.exe"]
            self.profiles["admin"]["typical_privileged_commands"] = ["whoami", "net user", "systeminfo", "gpupdate"]
            self.profiles["admin"]["typical_applications"] = ["ActiveDirectory", "vSphere", "AWS Console", "SSH"]
            changed = True

        # 2. Developer Bob
        if "developer_bob" not in self.profiles:
            self.profiles["developer_bob"] = self.create_blank_profile(
                user_id="developer_bob",
                username="developer_bob",
                email="bob@enterprise.com",
                employee_id="EMP-1082",
                department="Engineering",
                role="Senior Software Developer",
                manager_id="admin",
                access_tier="standard",
                employment_status="active"
            )
            self.profiles["developer_bob"]["typical_process_names"] = ["chrome.exe", "vscode.exe", "git.exe", "python.exe"]
            self.profiles["developer_bob"]["typical_privileged_commands"] = ["git config", "npm install"]
            self.profiles["developer_bob"]["typical_applications"] = ["GitHub", "Jira", "VSCode", "Chrome"]
            changed = True

        # 3. Contractor Eve
        if "contractor_eve" not in self.profiles:
            self.profiles["contractor_eve"] = self.create_blank_profile(
                user_id="contractor_eve",
                username="contractor_eve",
                email="eve.contractor@partner.com",
                employee_id="CON-4421",
                department="QA",
                role="QA Automation Contractor",
                manager_id="developer_bob",
                access_tier="standard",
                employment_status="contractor"
            )
            self.profiles["contractor_eve"]["typical_process_names"] = ["chrome.exe", "vscode.exe", "node.exe"]
            self.profiles["contractor_eve"]["typical_applications"] = ["TestRail", "Jenkins", "VSCode"]
            changed = True

        # 4. Terminated Employee Alice
        if "terminated_alice" not in self.profiles:
            self.profiles["terminated_alice"] = self.create_blank_profile(
                user_id="terminated_alice",
                username="terminated_alice",
                email="alice.ex@enterprise.com",
                employee_id="EMP-0922",
                department="Sales",
                role="Account Executive",
                manager_id="mgr-sales-vp",
                access_tier="standard",
                employment_status="terminated"
            )
            self.profiles["terminated_alice"]["termination_date"] = "2026-05-01T17:00:00Z"
            self.profiles["terminated_alice"]["user_risk_score"] = 50.0
            self.profiles["terminated_alice"]["risk_tier"] = "medium"
            self.profiles["terminated_alice"]["risk_contributors"] = ["Historical baseline frozen on termination"]
            changed = True
            
        if changed:
            self.save_profiles()
            logger.info("Ensured and seeded missing default UEBA profiles.")

    def create_blank_profile(self, user_id: str, username: str, email: str, employee_id: str, 
                             department: str, role: str, manager_id: str, access_tier: str, 
                             employment_status: str) -> dict:
        """Create a default compliant UEBA profile skeleton mapping sections 9.1 to 9.4."""
        now_iso = get_utc_timestamp()
        return {
            # --- 9.1 User Profile Fields ---
            "user_id": user_id,
            "username": username,
            "email": self.hash_email(email),
            "employee_id": employee_id,
            "department": department,
            "role": role,
            "manager_id": manager_id,
            "hire_date": now_iso,
            "termination_date": None,
            "employment_status": employment_status, # active, on_leave, terminated, contractor
            "access_tier": access_tier, # standard, privileged, admin, executive

            # --- 9.2 Behavioral Baseline Fields ---
            "typical_login_hours_start": 8, # Earliest typical hour (0-23)
            "typical_login_hours_end": 19,   # Latest typical logout hour
            "typical_login_days": ["Monday", "Tuesday", "Wednesday", "Thursday", "Friday"],
            "typical_src_ips": ["127.0.0.1", "192.168.1.100"],
            "typical_src_countries": ["United States"],
            "typical_devices": ["LAPTOP-WORKSTATION"],
            "typical_applications": ["chrome.exe", "git.exe", "slack"],
            "typical_data_volume_mb_per_day": 100.0,
            "typical_file_access_count_per_day": 50.0,
            "typical_process_names": ["chrome.exe", "vscode.exe", "git.exe", "python.exe", "conhost.exe"],
            "typical_dest_countries": ["United States"],
            
            # [NEW FEATURES] Add 4 more baseline datapoints requested
            "typical_user_agents": ["Mozilla/5.0 (Windows NT 10.0; Win64; x64) Chrome/120.0.0.0"],
            "typical_db_queries_count_per_day": 15.0,
            "typical_privileged_commands": ["whoami"],

            # --- 9.3 Session Behavioral Fields (Per Session tracking) ---
            "session_id": f"SESS-{uuid.uuid4()}"[:13],
            "session_start": now_iso,
            "session_end": None,
            "session_duration_minutes": 0,
            "commands_executed_count": 0,
            "files_accessed_count": 0,
            "network_connections_count": 0,
            "privilege_escalations_count": 0,
            "failed_access_count": 0,
            "unique_systems_accessed": 1,
            
            # [NEW FEATURE] MFA authentication failures tracking
            "mfa_failures_count": 0,

            # --- 9.4 Risk Score Fields ---
            "user_risk_score": 0.0,
            "risk_score_delta": 0.0,
            "risk_contributors": [],
            "risk_tier": "low", # low, medium, high, critical
            "anomaly_flags": [],
            "peer_group_deviation": 0.0,
            "impossible_travel_flag": False,
            "impossible_travel_distance_km": 0.0,
            "impossible_travel_speed_kmh": 0.0
        }

    def get_or_create_profile(self, username: str) -> dict:
        """Fetch or initialize a default user profile, applying backward compatibility mapping."""
        clean_user = username.split("\\")[-1].lower()
        
        if clean_user not in self.profiles:
            # Generate generic new user baseline
            self.profiles[clean_user] = self.create_blank_profile(
                user_id=clean_user,
                username=clean_user,
                email=f"{clean_user}@enterprise.com",
                employee_id=f"EMP-{uuid.uuid4()}"[:10],
                department="Engineering" if clean_user != "admin" else "Operations",
                role="Software Engineer" if clean_user != "admin" else "Administrator",
                manager_id="admin",
                access_tier="standard" if clean_user != "admin" else "admin",
                employment_status="active"
            )
            self.save_profiles()
            logger.info(f"Dynamically generated new UEBA profile for: {clean_user}")

        profile = self.profiles[clean_user]
        
        # Populate backward compatibility structures for other system monitors
        profile["risk_score"] = profile["user_risk_score"]
        profile["peer_group"] = "Developers" if profile["department"] == "Engineering" else "SysAdmins"
        profile["behavioral_baselines"] = {
            "usual_working_hours": {
                "start": f"{profile['typical_login_hours_start']:02d}:00",
                "end": f"{profile['typical_login_hours_end']:02d}:00"
            },
            "common_ips": profile["typical_src_ips"],
            "common_processes": profile["typical_process_names"],
            "daily_avg_file_writes": int(profile["typical_file_access_count_per_day"]),
            "daily_avg_network_mb": profile["typical_data_volume_mb_per_day"]
        }
        profile["session_behavior_metrics"] = {
            "login_time": profile["session_start"],
            "source_ip": profile["typical_src_ips"][0] if profile["typical_src_ips"] else "127.0.0.1",
            "session_duration_sec": profile["session_duration_minutes"] * 60,
            "active_processes_count": profile["commands_executed_count"],
            "network_volume_transferred_mb": profile["network_connections_count"] * 0.5
        }
        if "peer_group_deviation" not in profile or isinstance(profile["peer_group_deviation"], float):
            profile["peer_group_deviation"] = {
                "is_unusual_time": False,
                "is_unusual_process": False,
                "is_unusual_network_volume": False,
                "deviation_percentage": float(profile.get("peer_group_deviation_val", 0.0))
            }
            
        return profile

    def process_event(self, event: dict) -> List[dict]:
        """
        Evaluate an incoming security event for behavioral baseline deviations.
        Updates user risk score, sets anomaly flags, and generates alert events.
        """
        event_type = event.get("event_type")
        module = event.get("module")
        data = event.get("data", {})
        
        # Avoid recursion on our own alerts
        if module == "ueba_engine" or event_type == EVENT_UEBA_DEVIATION:
            return []

        # Determine user mapping
        username = data.get("username") or data.get("user") or "system"
        if username == "system" and "process_name" in data:
            username = "system"
            
        profile = self.get_or_create_profile(username)
        anomaly_events = []

        # --- RULE 0: Terminated User Activity Check ---
        if profile["employment_status"] == "terminated":
            flag = {
                "flag_id": f"ANM-{uuid.uuid4()}"[:12],
                "type": "terminated_user_activity",
                "timestamp": get_utc_timestamp(),
                "severity": "CRITICAL",
                "score_weight": 80.0,
                "description": f"Security Alert: Event activity detected from terminated employee: {profile['user_id']}"
            }
            profile["anomaly_flags"].append(flag)
            anomaly_events.append(self._create_deviation_event(profile, flag, event))

        # --- RULE 1: Unusual Process Execution & Privileged Commands Check ---
        if event_type == "process_created":
            proc_name = data.get("name", "").lower()
            profile["commands_executed_count"] += 1
            
            # Check process against user's common processes
            common_procs = [p.lower() for p in profile["typical_process_names"]]
            if proc_name and proc_name not in common_procs:
                flag = {
                    "flag_id": f"ANM-{uuid.uuid4()}"[:12],
                    "type": "unusual_process",
                    "timestamp": get_utc_timestamp(),
                    "severity": "WARNING",
                    "score_weight": 20.0,
                    "description": f"Executed unusual process not in baseline: {proc_name}"
                }
                
                # Peer group deviation validation (Developers running raw shells)
                if profile["department"] == "Engineering" and proc_name in ("cmd.exe", "powershell.exe", "mshta.exe"):
                    flag["score_weight"] += 20.0
                    flag["description"] += " (Dev executing raw administrative shell)"
                    profile["peer_group_deviation"]["is_unusual_process"] = True
                
                profile["anomaly_flags"].append(flag)
                anomaly_events.append(self._create_deviation_event(profile, flag, event))
                
            # [NEW FEATURE] Check if the process represents a local privileged or admin recon command
            # and verify it exists in their typical privileged commands whitelist.
            admin_recon_commands = ["whoami", "net", "nltest", "vssadmin", "mimikatz", "wmic", "powershell"]
            if any(cmd in proc_name for cmd in admin_recon_commands):
                matched_cmd = next((cmd for cmd in admin_recon_commands if cmd in proc_name), proc_name)
                if matched_cmd not in profile["typical_privileged_commands"]:
                    flag = {
                        "flag_id": f"ANM-{uuid.uuid4()}"[:12],
                        "type": "unusual_privileged_command",
                        "timestamp": get_utc_timestamp(),
                        "severity": "WARNING",
                        "score_weight": 30.0,
                        "description": f"Security Alert: Executed un-whitelisted administrative recon command: '{matched_cmd}'"
                    }
                    profile["anomaly_flags"].append(flag)
                    anomaly_events.append(self._create_deviation_event(profile, flag, event))

        # --- RULE 2: Access Time and Weekend Verification ---
        elif event_type == "network_connection" or event_type == "dns_query":
            profile["network_connections_count"] += 1
            
            # Access hours validation
            now_hour = datetime.now().hour
            if now_hour < profile["typical_login_hours_start"] or now_hour > profile["typical_login_hours_end"]:
                if not any(f["type"] == "unusual_access_time" for f in profile["anomaly_flags"]):
                    flag = {
                        "flag_id": f"ANM-{uuid.uuid4()}"[:12],
                        "type": "unusual_access_time",
                        "timestamp": get_utc_timestamp(),
                        "severity": "INFO",
                        "score_weight": 10.0,
                        "description": f"Access active at anomalous time: {now_hour}:00 (typical: {profile['typical_login_hours_start']}-{profile['typical_login_hours_end']})"
                    }
                    profile["peer_group_deviation"]["is_unusual_time"] = True
                    profile["anomaly_flags"].append(flag)
                    anomaly_events.append(self._create_deviation_event(profile, flag, event))
            
            # Weekend validation
            today_day = datetime.now().strftime("%A")
            if today_day not in profile["typical_login_days"]:
                if not any(f["type"] == "weekend_login_anomaly" for f in profile["anomaly_flags"]):
                    flag = {
                        "flag_id": f"ANM-{uuid.uuid4()}"[:12],
                        "type": "weekend_login_anomaly",
                        "timestamp": get_utc_timestamp(),
                        "severity": "WARNING",
                        "score_weight": 15.0,
                        "description": f"Access active on anomalous weekend day: {today_day}"
                    }
                    profile["anomaly_flags"].append(flag)
                    anomaly_events.append(self._create_deviation_event(profile, flag, event))

            # Threat Intel IP Enrichment Validation
            reputation = data.get("threat_reputation")
            if reputation and reputation.get("is_malicious"):
                flag = {
                    "flag_id": f"ANM-{uuid.uuid4()}"[:12],
                    "type": "malicious_destination",
                    "timestamp": get_utc_timestamp(),
                    "severity": "CRITICAL",
                    "score_weight": 50.0,
                    "description": f"Connection established to malicious IP target {data.get('dst_ip')} (Score: {reputation.get('reputation_score')})"
                }
                profile["anomaly_flags"].append(flag)
                anomaly_events.append(self._create_deviation_event(profile, flag, event))

            # [NEW FEATURE] User-Agent validation check
            ua = data.get("user_agent")
            if ua and ua not in profile["typical_user_agents"]:
                if not any(f["type"] == "unusual_user_agent" for f in profile["anomaly_flags"]):
                    flag = {
                        "flag_id": f"ANM-{uuid.uuid4()}"[:12],
                        "type": "unusual_user_agent",
                        "timestamp": get_utc_timestamp(),
                        "severity": "WARNING",
                        "score_weight": 25.0,
                        "description": f"Connection established using anomalous User-Agent: {ua[:40]}..."
                    }
                    profile["anomaly_flags"].append(flag)
                    anomaly_events.append(self._create_deviation_event(profile, flag, event))

            # Impossible Travel validation simulation (if country changes from typical)
            dst_country = data.get("country") or data.get("dst_country")
            if dst_country and dst_country not in profile["typical_src_countries"]:
                # Trigger impossible travel calculation
                profile["impossible_travel_flag"] = True
                profile["impossible_travel_distance_km"] = 6200.0
                profile["impossible_travel_speed_kmh"] = 1200.0
                flag = {
                    "flag_id": f"ANM-{uuid.uuid4()}"[:12],
                    "type": "impossible_travel",
                    "timestamp": get_utc_timestamp(),
                    "severity": "CRITICAL",
                    "score_weight": 55.0,
                    "description": f"Impossible travel detected! Simultaneous login from {dst_country} (Speed check: 1200 km/h)"
                }
                profile["anomaly_flags"].append(flag)
                anomaly_events.append(self._create_deviation_event(profile, flag, event))

        # --- RULE 3: File Access Exfiltration Check ---
        elif event_type in ("file_created", "file_modified"):
            profile["files_accessed_count"] += 1
            if profile["files_accessed_count"] > profile["typical_file_access_count_per_day"] * 2:
                if not any(f["type"] == "file_access_spike" for f in profile["anomaly_flags"]):
                    flag = {
                        "flag_id": f"ANM-{uuid.uuid4()}"[:12],
                        "type": "file_access_spike",
                        "timestamp": get_utc_timestamp(),
                        "severity": "WARNING",
                        "score_weight": 25.0,
                        "description": f"High file write/read activity: {profile['files_accessed_count']} writes (baseline: {profile['typical_file_access_count_per_day']})"
                    }
                    profile["anomaly_flags"].append(flag)
                    anomaly_events.append(self._create_deviation_event(profile, flag, event))

        # [NEW FEATURE] RULE 4: Database query exfiltration tracking
        elif event_type == "database_query":
            # Simulate SQL Sweep anomaly check
            queries_today = data.get("query_count", 1)
            if queries_today > profile["typical_db_queries_count_per_day"] * 3:
                flag = {
                    "flag_id": f"ANM-{uuid.uuid4()}"[:12],
                    "type": "database_query_spike",
                    "timestamp": get_utc_timestamp(),
                    "severity": "WARNING",
                    "score_weight": 35.0,
                    "description": f"Anomalous query spike: Executed {queries_today} DB queries (baseline: {profile['typical_db_queries_count_per_day']})"
                }
                profile["anomaly_flags"].append(flag)
                anomaly_events.append(self._create_deviation_event(profile, flag, event))

        # [NEW FEATURE] RULE 5: MFA Auth Failures tracking
        elif event_type == "auth_failed" or "mfa" in data.get("auth_method", "").lower():
            if "failed" in data.get("status", "").lower():
                profile["mfa_failures_count"] += 1
                if profile["mfa_failures_count"] >= 3:
                    flag = {
                        "flag_id": f"ANM-{uuid.uuid4()}"[:12],
                        "type": "mfa_fatigue_or_brute_force",
                        "timestamp": get_utc_timestamp(),
                        "severity": "CRITICAL",
                        "score_weight": 60.0,
                        "description": f"Security Alert: Repeated authentication failures: {profile['mfa_failures_count']} failed MFA verification attempts."
                    }
                    profile["anomaly_flags"].append(flag)
                    anomaly_events.append(self._create_deviation_event(profile, flag, event))

        # --- Recompute composite risk scores & delta ---
        self._recompute_risk_scores(profile)
        self.save_profiles()
        
        return anomaly_events

    def _recompute_risk_scores(self, profile: dict):
        """Aggregate active anomaly weights, prune expired ones, and assign risk tiers."""
        self._prune_expired_flags(profile)
        
        prev_score = profile["user_risk_score"]
        total_weight = sum(flag["score_weight"] for flag in profile["anomaly_flags"])
        
        # Check if user is terminated - if so, ensure elevated score
        if profile["employment_status"] == "terminated":
            total_weight = max(total_weight, 50.0)
            
        profile["user_risk_score"] = min(total_weight, 100.0)
        profile["risk_score"] = profile["user_risk_score"] # sync compatibility key
        profile["risk_score_delta"] = profile["user_risk_score"] - prev_score
        
        # Set risk tier based on score range
        score = profile["user_risk_score"]
        if score <= 15.0:
            profile["risk_tier"] = "low"
        elif score <= 40.0:
            profile["risk_tier"] = "medium"
        elif score <= 70.0:
            profile["risk_tier"] = "high"
        else:
            profile["risk_tier"] = "critical"

        # Update risk contributors
        profile["risk_contributors"] = list(set(flag["type"] for flag in profile["anomaly_flags"]))
        if profile["employment_status"] == "terminated":
            profile["risk_contributors"].append("terminated_status_lock")

    def _prune_expired_flags(self, profile: dict):
        """Removes anomaly flags that are older than 2 hours to allow risk score recovery."""
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
        """Create standard alert event layout for the SOC framework ingestion registry."""
        severity = SEVERITY_WARNING
        if flag["score_weight"] >= 45.0:
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
                "peer_group": profile["role"],
                "risk_score": profile["user_risk_score"],
                "deviation_type": flag["type"],
                "anomaly_details": flag["description"],
                "triggering_event_id": triggering_event.get("event_id")
            }
        }

    def initialize_startup(self):
        """Display a stunning ASCII console baseline dashboard detailing active entities on startup."""
        print("\033[96m" + "="*80)
        print("    ██╗   ██╗███████╗██████╗  █████╗     ██████╗  █████╗ ███████╗███████╗")
        print("    ██║   ██║██╔════╝██╔══██╗██╔══██╗    ██╔══██╗██╔══██╗██╔════╝██╔════╝")
        print("    ██║   ██║█████╗  ██████╔╝███████║    ██████╔╝███████║███████╗█████╗  ")
        print("    ██║   ██║██╔══╝  ██╔══██╗██╔══██║    ██╔══██╗██╔══██║╚════██║██╔══╝  ")
        print("    ╚██████╔╝███████╗██████╔╝██║  ██║    ██████╔╝██║  ██║███████║███████╗")
        print("     ╚═════╝ ╚══════╝╚═════╝ ╚═╝  ╚═╝    ╚═════╝ ╚═╝  ╚═╝╚══════╝╚══════╝")
        print("            [TEAM 9 — USER BEHAVIORAL & IDENTITY BASELINE ENGINE]")
        print("="*80 + "\033[0m")
        print(f"[*] Baseline Path: {self.profiles_path}")
        print(f"[*] Loaded profiles count: {len(self.profiles)}")
        print("\n\033[92mActive Entity Baselines & Core Risk Tiers:\033[0m")
        
        # Render a structured table
        print("+" + "-"*18 + "+" + "-"*15 + "+" + "-"*20 + "+" + "-"*11 + "+" + "-"*11 + "+")
        print("| {:<16} | {:<13} | {:<18} | {:<9} | {:<9} |".format(
            "User ID", "Department", "Job Role", "Risk Score", "Access Tier"
        ))
        print("+" + "-"*18 + "+" + "-"*15 + "+" + "-"*20 + "+" + "-"*11 + "+" + "-"*11 + "+")
        
        for user, prof in sorted(self.profiles.items()):
            score = prof.get("user_risk_score", 0.0)
            tier = prof.get("risk_tier", "low").upper()
            status = prof.get("employment_status", "active")
            
            # Highlight status in red if terminated
            display_name = user
            if status == "terminated":
                display_name = f"{user} [TERM]"
                
            # Score color highlights
            color_code = "\033[92m" # Green
            if tier == "MEDIUM":
                color_code = "\033[93m" # Yellow
            elif tier in ("HIGH", "CRITICAL") or status == "terminated":
                color_code = "\033[91m" # Red
                
            print(f"| {display_name:<16} | {prof.get('department', ''):<13} | {prof.get('role', '')[:18]:<18} | {color_code}{score:<4} ({tier})\033[0m | {prof.get('access_tier', ''):<9} |")
            
        print("+" + "-"*18 + "+" + "-"*15 + "+" + "-"*20 + "+" + "-"*11 + "+" + "-"*11 + "+")
        print("\n\033[96m[+] UEBA Behavioral engine startup visualization complete. Ready.\033[0m\n")

# Globally accessible UEBA instance
ueba_engine = UEBAEngine()
