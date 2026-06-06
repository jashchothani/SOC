"""
AbuseIPDB v2 IP address reputation lookup client.
"""
import requests
from config.settings import settings
from config.constants import ABUSEIPDB_BASE_URL
from utils.logger import logger
from utils.validators import is_valid_ip
from utils.error_handler import retry_on_exception, run_gracefully

@run_gracefully(module_name="abuseipdb", default_return=None)
@retry_on_exception(retries=3, backoff_factor=2.0, exceptions=(requests.RequestException,))
def check_ip_abuse(ip: str) -> dict:
    """Query reputation of an IP address from AbuseIPDB v2."""
    if not is_valid_ip(ip):
        logger.warning(f"Invalid IP passed to AbuseIPDB check: {ip}")
        return {"error": "Invalid IP address"}
        
    if settings.mock_mode:
        # Mock responses
        is_malicious = ip.endswith(".66") or ip == "192.168.1.66"
        abuse_score = 85 if is_malicious else 0
        total_reports = 154 if is_malicious else 0
        return {
            "data": {
                "ipAddress": ip,
                "isPublic": True,
                "ipVersion": 4,
                "isWhitelisted": False,
                "abuseConfidenceScore": abuse_score,
                "countryCode": "US",
                "countryName": "United States",
                "usageType": "Data Center/Web Hosting/Transit",
                "isp": "Mock Cloud Services",
                "domain": "mockcloud.com",
                "totalReports": total_reports,
                "lastReportedAt": "2026-06-05T10:00:00Z"
            }
        }
        
    api_key = settings.api_keys.get("abuseipdb")
    if not api_key:
        logger.warning("AbuseIPDB API Key is missing. Skipping lookup.")
        return {"error": "API Key missing"}
        
    url = f"{ABUSEIPDB_BASE_URL}/check"
    headers = {
        "Key": api_key,
        "Accept": "application/json"
    }
    params = {
        "ipAddress": ip,
        "maxAgeInDays": 90,
        "verbose": True
    }
    
    response = requests.get(url, headers=headers, params=params, timeout=10)
    
    if response.status_code == 429:
        logger.error("AbuseIPDB API rate limit reached.")
        return {"error": "Rate limit exceeded"}
    elif response.status_code == 401 or response.status_code == 403:
        logger.error("AbuseIPDB Authentication failed.")
        return {"error": "Authentication failed"}
        
    response.raise_for_status()
    return response.json()
