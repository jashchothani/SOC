"""
================================================================================
THREAT INTELLIGENCE AGGREGATOR ENGINE
================================================================================
This engine orchestrates querying threat feeds in parallel (VirusTotal,
AbuseIPDB, AlienVault OTX), normalizes threat score outcomes, scales metrics,
and caches reports to minimize API query rates.

CRITICAL LOGIC & ENRICHMENTS:
- ThreadPoolExecutor parallel indicator fetches.
- Composite risk calculation (VT=50%, AbuseIPDB=30%, AlienVault=20%).
- Persistent JSON threat database caching.
- Dynamic normalization of metadata schema.
================================================================================
"""
import os
import uuid
from datetime import datetime, timedelta, timezone
from concurrent.futures import ThreadPoolExecutor, as_completed
from utils.logger import logger
from utils.timestamp import get_utc_timestamp, parse_utc_timestamp
from utils.json_manager import read_json_file, write_json_file
from config.settings import settings
from config.constants import DIR_BASELINES, EVENT_THREAT_INTEL, SEVERITY_WARNING, SEVERITY_CRITICAL, SEVERITY_INFO

# API Lookups
from modules.virustotal.virustotal import VirusTotalClient
from modules.threat_intel.abuseipdb import check_ip_abuse
from modules.threat_intel.alienvault import check_indicator_otx

class ThreatIntelAggregator:
    def __init__(self, cache_filename: str = "threat_intel_cache.json"):
        self.cache_path = os.path.join(DIR_BASELINES, cache_filename)
        self.cache = {}
        self.load_cache()

    def load_cache(self):
        """Loads cached results from disk."""
        data = read_json_file(self.cache_path)
        if data and isinstance(data, dict):
            self.cache = data
            logger.info(f"Loaded threat intelligence cache from {self.cache_path} ({len(self.cache)} entries).")
        else:
            self.cache = {}
            logger.info("Threat intelligence cache is empty or missing. Starting fresh.")

    def save_cache(self):
        """Writes current cache back to disk."""
        os.makedirs(os.path.dirname(self.cache_path), exist_ok=True)
        write_json_file(self.cache_path, self.cache)
        logger.debug("Threat intelligence cache saved to disk.")

    def _is_cache_valid(self, entry: dict) -> bool:
        """Checks if a cache entry is within the expiration window."""
        cached_time_str = entry.get("cached_at")
        if not cached_time_str:
            return False
            
        try:
            cached_time = parse_utc_timestamp(cached_time_str)
            now = datetime.now(timezone.utc)
            expiry = timedelta(hours=settings.cache_expiry_hours)
            return (now - cached_time) < expiry
        except Exception as e:
            logger.error(f"Error checking cache validation: {e}")
            return False

    def lookup(self, indicator: str, indicator_type: str) -> dict:
        """
        Query all intelligence feeds for an indicator.
        Resolves cache hits or issues parallel lookup requests.
        """
        # Check cache
        cache_key = f"{indicator_type}:{indicator}"
        if cache_key in self.cache:
            cached_entry = self.cache[cache_key]
            if self._is_cache_valid(cached_entry):
                logger.debug(f"Cache hit for threat indicator {indicator}.")
                return cached_entry

        # Query APIs in parallel
        logger.info(f"Cache miss or expired. Fetching fresh threat intelligence for {indicator_type}: {indicator}...")
        raw_results = self._fetch_all(indicator, indicator_type)
        
        # Normalize response
        normalized = self._normalize(indicator, indicator_type, raw_results)
        
        # Save to cache
        self.cache[cache_key] = normalized
        self.save_cache()
        
        return normalized

    def _fetch_all(self, indicator: str, indicator_type: str) -> dict:
        """Execute checks in parallel using a ThreadPoolExecutor."""
        results = {}
        
        # Define tasks based on indicator type
        tasks = {}
        with ThreadPoolExecutor(max_workers=settings.max_worker_threads) as executor:
            if indicator_type == "ip":
                tasks["virustotal"] = executor.submit(VirusTotalClient.check_ip, indicator)
                tasks["abuseipdb"] = executor.submit(check_ip_abuse, indicator)
                tasks["alienvault"] = executor.submit(check_indicator_otx, indicator, "ip")
            elif indicator_type == "domain":
                tasks["virustotal"] = executor.submit(VirusTotalClient.check_domain, indicator)
                tasks["alienvault"] = executor.submit(check_indicator_otx, indicator, "domain")
            elif indicator_type == "hash":
                tasks["virustotal"] = executor.submit(VirusTotalClient.check_hash, indicator)
                tasks["alienvault"] = executor.submit(check_indicator_otx, indicator, "hash")

            for source, future in tasks.items():
                try:
                    results[source] = future.result()
                except Exception as e:
                    logger.error(f"Thread lookup failed for {source} checking {indicator}: {e}")
                    results[source] = {"error": f"Task execution failed: {e}"}
                    
        return results

    def _normalize(self, indicator: str, indicator_type: str, raw: dict) -> dict:
        """Normalizes multiple API outputs into a single SOC schema and calculates risk score."""
        is_malicious = False
        reputation_score = 0.0
        positives = 0
        total_scans = 0
        
        # VirusTotal details parsing
        vt = raw.get("virustotal") or {}
        vt_stats = {}
        if vt and "data" in vt:
            attributes = vt["data"].get("attributes", {})
            vt_stats = attributes.get("last_analysis_stats", {})
            positives = vt_stats.get("malicious", 0)
            total_scans = sum(vt_stats.values())
            if positives > 0:
                is_malicious = True
                
        # AbuseIPDB details parsing
        abuse = raw.get("abuseipdb") or {}
        abuse_score = 0
        if abuse and "data" in abuse:
            abuse_score = abuse["data"].get("abuseConfidenceScore", 0)
            if abuse_score > 10:
                is_malicious = True
                
        # AlienVault details parsing
        otx = raw.get("alienvault") or {}
        pulse_count = 0
        if otx and "general" in otx:
            pulse_info = otx["general"].get("pulse_info", {})
            pulse_count = pulse_info.get("count", 0)
            if pulse_count > 0:
                is_malicious = True
                
        # Calculate composite reputation score (0 to 100)
        # Weighting: VT = 50%, AbuseIPDB = 30%, AlienVault = 20% (Shodan removed)
        score_components = []
        
        if vt_stats:
            vt_ratio = (positives / total_scans) if total_scans > 0 else 0
            score_components.append(vt_ratio * 100 * 0.50)
            
        if indicator_type == "ip" and abuse:
            score_components.append(abuse_score * 0.30)
            
        if otx:
            # Scale OTX by count of pulses (capped at 5 pulses for 100%)
            otx_score = min((pulse_count / 5.0) * 100, 100)
            score_components.append(otx_score * 0.20)
            
        if score_components:
            # Sum up weights relative to components queried
            reputation_score = sum(score_components)
            
        # Standardize event layout
        severity = SEVERITY_INFO
        if is_malicious:
            severity = SEVERITY_WARNING
        if reputation_score > 70.0:
            severity = SEVERITY_CRITICAL

        event = {
            "event_id": f"EVT-{uuid.uuid4()}",
            "timestamp": get_utc_timestamp(),
            "module": "threat_intelligence",
            "event_type": EVENT_THREAT_INTEL,
            "severity": severity,
            "status": "success",
            "indicator": indicator,
            "type": indicator_type,
            "is_malicious": is_malicious,
            "reputation_score": int(reputation_score),
            "positives": positives,
            "total_scans": total_scans,
            "cached_at": get_utc_timestamp(),
            "data": {
                "indicator": indicator,
                "type": indicator_type,
                "is_malicious": is_malicious,
                "reputation_score": int(reputation_score)
            },
            "sources": {
                "virustotal": {
                    "status": "success" if vt and "error" not in vt else "failed",
                    "positives": positives,
                    "total": total_scans,
                    "raw_stats": vt_stats
                },
                "abuseipdb": {
                    "status": "success" if abuse and "error" not in abuse else "failed",
                    "abuse_score": abuse_score
                },
                "alienvault": {
                    "status": "success" if otx and "error" not in otx else "failed",
                    "pulse_count": pulse_count
                }
            }
        }
        
        return event

# Globally accessible aggregator instance
threat_intel_aggregator = ThreatIntelAggregator()
