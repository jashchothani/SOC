"""
Shodan host port and vulnerability lookup client (supports keyless InternetDB lookup).
"""
import requests
from config.settings import settings
from config.constants import SHODAN_BASE_URL, SHODAN_INTERNETDB_URL
from utils.logger import logger
from utils.validators import is_valid_ip
from utils.error_handler import retry_on_exception, run_gracefully

@run_gracefully(module_name="shodan_lookup", default_return=None)
@retry_on_exception(retries=3, backoff_factor=2.0, exceptions=(requests.RequestException,))
def check_ip_shodan(ip: str) -> dict:
    """Query Shodan for open ports and vulnerabilities."""
    if not is_valid_ip(ip):
        logger.warning(f"Invalid IP passed to Shodan lookup: {ip}")
        return {"error": "Invalid IP address"}
        
    if settings.mock_mode:
        # Mock responses
        is_malicious = ip.endswith(".66") or ip == "192.168.1.66"
        ports = [22, 80, 443, 445, 6667] if is_malicious else [80, 443]
        vulns = ["CVE-2017-0144"] if is_malicious else []
        return {
            "ip": ip,
            "ports": ports,
            "vulns": vulns,
            "hostnames": ["mock-server.net"] if is_malicious else ["clean-host.org"],
            "isp": "Mock Hosting Provider",
            "country_name": "United States"
        }
        
    api_key = settings.api_keys.get("shodan")
    if not api_key:
        # If API key is missing, fall back to InternetDB (which is completely free and keyless)
        logger.debug(f"Shodan API Key is missing. Falling back to keyless InternetDB lookup for IP {ip}.")
        return check_ip_internetdb(ip)
        
    url = f"{SHODAN_BASE_URL}/shodan/host/{ip}"
    params = {
        "key": api_key
    }
    
    response = requests.get(url, params=params, timeout=10)
    
    if response.status_code == 429:
        logger.error("Shodan API rate limit reached.")
        return {"error": "Rate limit exceeded"}
    elif response.status_code == 401:
        logger.error("Shodan API unauthorized. Check your API key.")
        return {"error": "Authentication failed"}
    elif response.status_code == 404:
        logger.debug(f"IP {ip} not found in Shodan database.")
        return {"status": "not_found", "ports": [], "vulns": []}
        
    response.raise_for_status()
    return response.json()

def check_ip_internetdb(ip: str) -> dict:
    """Keyless fallback lookup using Shodan InternetDB API."""
    try:
        url = f"{SHODAN_INTERNETDB_URL}/{ip}"
        response = requests.get(url, timeout=5)
        if response.status_code == 404:
            return {"status": "not_found", "ports": [], "vulns": []}
        response.raise_for_status()
        return response.json()
    except Exception as e:
        logger.warning(f"Keyless InternetDB lookup failed for IP {ip}: {e}")
        return {"error": "InternetDB lookup failed"}
