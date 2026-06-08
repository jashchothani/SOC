"""
================================================================================
SHODAN LOOKUP CONNECTOR - DEPRECATED
================================================================================
[!] NOTICE: The Shodan API integration has been fully deprecated and removed from
the platform based on SOC requirements.

This file serves as a retired legacy placeholder. Any calls to Shodan lookups
are disabled and will return empty/safe default profiles.
================================================================================
"""
from utils.logger import logger

def check_ip_shodan(ip: str) -> dict:
    """Deprecated lookup function. Returns empty placeholder."""
    logger.warning(f"Attempted to call deprecated Shodan lookup function for IP: {ip}")
    return {
        "status": "deprecated",
        "ports": [],
        "vulns": []
    }

def check_ip_internetdb(ip: str) -> dict:
    """Deprecated InternetDB lookup function. Returns empty placeholder."""
    logger.warning(f"Attempted to call deprecated Shodan InternetDB lookup function for IP: {ip}")
    return {
        "status": "deprecated",
        "ports": [],
        "vulns": []
    }
