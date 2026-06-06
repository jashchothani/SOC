"""
Input validation utilities for IPs, domains, hashes, and files.
"""
import re
import ipaddress
import os

# Regular Expressions
DOMAIN_REGEX = re.compile(
    r'^([a-zA-Z0-9]|[a-zA-Z0-9][a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])'
    r'(\.([a-zA-Z0-9]|[a-zA-Z0-9][a-zA-Z0-9\-]{0,61}[a-zA-Z0-9]))*$'
)

MD5_REGEX = re.compile(r'^[a-fA-F0-9]{32}$')
SHA1_REGEX = re.compile(r'^[a-fA-F0-9]{40}$')
SHA256_REGEX = re.compile(r'^[a-fA-F0-9]{64}$')

def is_valid_ip(ip_str: str) -> bool:
    """Validate if string is a valid IPv4 or IPv6 address."""
    if not ip_str:
        return False
    try:
        ipaddress.ip_address(ip_str)
        return True
    except ValueError:
        return False

def is_valid_domain(domain_str: str) -> bool:
    """Validate if string is a valid domain name."""
    if not domain_str or len(domain_str) > 255:
        return False
    # Exclude numeric IP strings that bypass standard domain regex
    if is_valid_ip(domain_str):
        return False
    return bool(DOMAIN_REGEX.match(domain_str))

def is_valid_hash(hash_str: str) -> bool:
    """Validate if string is a valid MD5, SHA1, or SHA256 hash."""
    if not hash_str:
        return False
    return bool(MD5_REGEX.match(hash_str) or SHA1_REGEX.match(hash_str) or SHA256_REGEX.match(hash_str))

def is_valid_filepath(path_str: str) -> bool:
    """Check if filepath points to an existing file."""
    if not path_str:
        return False
    return os.path.isfile(path_str)

def get_hash_type(hash_str: str) -> str:
    """Return the type of hash (md5, sha1, sha256) or 'unknown'."""
    if not hash_str:
        return "unknown"
    if MD5_REGEX.match(hash_str):
        return "md5"
    if SHA1_REGEX.match(hash_str):
        return "sha1"
    if SHA256_REGEX.match(hash_str):
        return "sha256"
    return "unknown"
