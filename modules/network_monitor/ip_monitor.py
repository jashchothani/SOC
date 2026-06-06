"""
IP Monitor identifying external/global IP addresses for Threat Intelligence evaluation.
"""
import ipaddress
from typing import Dict
from utils.logger import logger
from utils.validators import is_valid_ip
from utils.error_handler import run_gracefully

# Cache local validation results to speed up checking
_ip_classification_cache: Dict[str, bool] = {}

@run_gracefully(module_name="ip_monitor", default_return=False)
def is_external_ip(ip_str: str) -> bool:
    """Check if an IP address is a public/external IP (not private, loopback, or multicast)."""
    if not is_valid_ip(ip_str):
        return False
        
    if ip_str in _ip_classification_cache:
        return _ip_classification_cache[ip_str]
        
    try:
        ip = ipaddress.ip_address(ip_str)
        # We classify as external if it is a global public address
        # Exclude: loopback, private, link-local, multicast, unspecified
        is_ext = ip.is_global and not ip.is_private and not ip.is_loopback and not ip.is_link_local
        _ip_classification_cache[ip_str] = is_ext
        return is_ext
    except Exception as e:
        logger.debug(f"Error classifying IP {ip_str}: {e}")
        return False
