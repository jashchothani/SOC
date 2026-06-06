"""
VirusTotal IP Address reputation checker.
"""
import requests
from config.settings import settings
from config.constants import VIRUSTOTAL_BASE_URL
from utils.logger import logger
from utils.validators import is_valid_ip
from utils.error_handler import retry_on_exception, run_gracefully

@run_gracefully(module_name="virustotal_check_ip", default_return=None)
@retry_on_exception(retries=3, backoff_factor=2.0, exceptions=(requests.RequestException,))
def check_ip(ip: str) -> dict:
    """Check IP reputation on VirusTotal."""
    if not is_valid_ip(ip):
        logger.warning(f"Invalid IP passed to VirusTotal lookup: {ip}")
        return {"error": "Invalid IP address"}
        
    if settings.mock_mode:
        # Mock analysis stats
        is_malicious = ip.endswith(".66") or ip == "192.168.1.66"
        malicious_count = 14 if is_malicious else 0
        return {
            "data": {
                "id": ip,
                "type": "ip_address",
                "attributes": {
                    "last_analysis_stats": {
                        "harmless": 70 if not is_malicious else 50,
                        "malicious": malicious_count,
                        "suspicious": 1 if is_malicious else 0,
                        "undetected": 10
                    },
                    "as_owner": "Mock Network Provider",
                    "country": "US"
                }
            }
        }
        
    api_key = settings.api_keys.get("virustotal")
    if not api_key:
        logger.warning("VirusTotal API Key is missing. Falling back to empty response.")
        return {"error": "API Key missing"}
        
    url = f"{VIRUSTOTAL_BASE_URL}/ip_addresses/{ip}"
    headers = {
        "x-apikey": api_key,
        "accept": "application/json"
    }
    
    response = requests.get(url, headers=headers, timeout=10)
    
    if response.status_code == 429:
        logger.error("VirusTotal API rate limit (Quota Exhausted) encountered.")
        return {"error": "Rate limit exceeded"}
    elif response.status_code == 403:
        logger.error("VirusTotal API Forbidden. Invalid API key.")
        return {"error": "Authentication failed"}
        
    response.raise_for_status()
    return response.json()
