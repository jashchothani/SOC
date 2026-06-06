"""
VirusTotal Domain reputation checker.
"""
import requests
from config.settings import settings
from config.constants import VIRUSTOTAL_BASE_URL
from utils.logger import logger
from utils.validators import is_valid_domain
from utils.error_handler import retry_on_exception, run_gracefully

@run_gracefully(module_name="virustotal_check_domain", default_return=None)
@retry_on_exception(retries=3, backoff_factor=2.0, exceptions=(requests.RequestException,))
def check_domain(domain: str) -> dict:
    """Check domain reputation on VirusTotal."""
    if not is_valid_domain(domain):
        logger.warning(f"Invalid domain passed to VirusTotal lookup: {domain}")
        return {"error": "Invalid domain name"}
        
    if settings.mock_mode:
        # Mock analysis stats
        is_malicious = "malicious" in domain or domain == "badsite.com"
        malicious_count = 18 if is_malicious else 0
        return {
            "data": {
                "id": domain,
                "type": "domain",
                "attributes": {
                    "last_analysis_stats": {
                        "harmless": 80 if not is_malicious else 40,
                        "malicious": malicious_count,
                        "suspicious": 2 if is_malicious else 0,
                        "undetected": 8
                    }
                }
            }
        }
        
    api_key = settings.api_keys.get("virustotal")
    if not api_key:
        logger.warning("VirusTotal API Key is missing. Falling back to empty response.")
        return {"error": "API Key missing"}
        
    url = f"{VIRUSTOTAL_BASE_URL}/domains/{domain}"
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
