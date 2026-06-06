"""
AlienVault OTX REST API threat intelligence indicator checker.
"""
import requests
from config.settings import settings
from config.constants import ALIENVAULT_BASE_URL
from utils.logger import logger
from utils.validators import is_valid_ip, is_valid_domain, is_valid_hash, get_hash_type
from utils.error_handler import retry_on_exception, run_gracefully

@run_gracefully(module_name="alienvault_otx", default_return=None)
@retry_on_exception(retries=3, backoff_factor=2.0, exceptions=(requests.RequestException,))
def check_indicator_otx(indicator: str, indicator_type: str) -> dict:
    """Query threat intelligence metadata for an indicator (ip, domain, file hash) from AlienVault OTX."""
    if settings.mock_mode:
        # Mock responses
        is_malicious = (
            indicator.endswith(".66") or 
            indicator == "192.168.1.66" or 
            "malicious" in indicator or 
            indicator == "badsite.com" or 
            indicator.startswith("66") or 
            "bad" in indicator.lower()
        )
        pulse_count = 12 if is_malicious else 0
        malware_count = 5 if is_malicious else 0
        return {
            "indicator": indicator,
            "sections": ["general"],
            "general": {
                "indicator": indicator,
                "type": indicator_type,
                "pulse_info": {
                    "count": pulse_count,
                    "pulses": [
                        {
                            "name": "Simulated Malicious Traffic Campaign" if is_malicious else "Clean Traffic IP",
                            "description": "Mock threat feed indicator classification.",
                            "adversary": "Mock Actor Group"
                        }
                    ] if is_malicious else []
                },
                "base_indicator": {
                    "content": indicator,
                    "id": 999999
                },
                "validation": [],
                "false_positive": []
            }
        }
        
    api_key = settings.api_keys.get("alienvault")
    # OTX allows unauthenticated requests but with limited rate limits (1000/hour)
    # We will log warnings if key is missing but proceed
    headers = {}
    if api_key:
        headers["X-OTX-API-KEY"] = api_key
    else:
        logger.debug("AlienVault API Key is missing. Continuing lookup unauthenticated.")
        
    # Translate types to OTX formats
    otx_type_path = ""
    if indicator_type == "ip":
        if not is_valid_ip(indicator):
            return {"error": "Invalid IP address"}
        otx_type_path = f"IPv4/{indicator}"
    elif indicator_type == "domain":
        if not is_valid_domain(indicator):
            return {"error": "Invalid domain name"}
        otx_type_path = f"domain/{indicator}"
    elif indicator_type == "hash":
        if not is_valid_hash(indicator):
            return {"error": "Invalid hash"}
        hash_type = get_hash_type(indicator)
        if hash_type == "unknown":
            return {"error": "Unsupported hash type"}
        otx_type_path = f"file/{indicator}"
    else:
        return {"error": f"Unsupported indicator type: {indicator_type}"}
        
    url = f"{ALIENVAULT_BASE_URL}/indicators/{otx_type_path}/general"
    
    response = requests.get(url, headers=headers, timeout=10)
    
    if response.status_code == 403:
        logger.error("AlienVault OTX Forbidden. Invalid API Key.")
        return {"error": "Authentication failed"}
    elif response.status_code == 429:
        logger.error("AlienVault OTX rate limit reached.")
        return {"error": "Rate limit exceeded"}
        
    response.raise_for_status()
    return response.json()
