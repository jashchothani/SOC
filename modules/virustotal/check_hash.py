"""
VirusTotal Hash reputation checker.
"""
import requests
from config.settings import settings
from config.constants import VIRUSTOTAL_BASE_URL
from utils.logger import logger
from utils.validators import is_valid_hash
from utils.error_handler import retry_on_exception, run_gracefully

@run_gracefully(module_name="virustotal_check_hash", default_return=None)
@retry_on_exception(retries=3, backoff_factor=2.0, exceptions=(requests.RequestException,))
def check_hash(file_hash: str) -> dict:
    """Check hash reputation on VirusTotal."""
    if not is_valid_hash(file_hash):
        logger.warning(f"Invalid hash passed to VirusTotal lookup: {file_hash}")
        return {"error": "Invalid file hash"}
        
    if settings.mock_mode:
        # Mock analysis stats
        # EICAR test string hash or hash starting with '66' or containing 'bad'
        is_malicious = (
            file_hash.startswith("66") or 
            "bad" in file_hash.lower() or 
            file_hash.lower() == "44d88612fea8a8f36de82e1278abb02f" or
            file_hash.lower() == "275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f"
        )
        malicious_count = 55 if is_malicious else 0
        return {
            "data": {
                "id": file_hash,
                "type": "file",
                "attributes": {
                    "last_analysis_stats": {
                        "harmless": 72 if not is_malicious else 12,
                        "malicious": malicious_count,
                        "suspicious": 3 if is_malicious else 0,
                        "undetected": 5
                    },
                    "meaningful_name": "malicious_payload.exe" if is_malicious else "clean_utility.dll",
                    "size": 1048576
                }
            }
        }
        
    api_key = settings.api_keys.get("virustotal")
    if not api_key:
        logger.warning("VirusTotal API Key is missing. Falling back to empty response.")
        return {"error": "API Key missing"}
        
    url = f"{VIRUSTOTAL_BASE_URL}/files/{file_hash}"
    headers = {
        "x-apikey": api_key,
        "accept": "application/json"
    }
    
    response = requests.get(url, headers=headers, timeout=10)
    
    if response.status_code == 429:
        logger.error("VirusTotal API rate limit (Quota Exhausted) encountered.")
        return {"error": "Rate limit exceeded"}
    elif response.status_code == 404:
        logger.info(f"Hash {file_hash} not found in VirusTotal database.")
        return {"status": "not_found", "message": "Hash not found in VT"}
    elif response.status_code == 403:
        logger.error("VirusTotal API Forbidden. Invalid API key.")
        return {"error": "Authentication failed"}
        
    response.raise_for_status()
    return response.json()
