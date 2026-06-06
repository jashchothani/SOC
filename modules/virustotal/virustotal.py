"""
VirusTotal Module orchestrator wrapping check methods.
"""
from modules.virustotal.check_ip import check_ip
from modules.virustotal.check_domain import check_domain
from modules.virustotal.check_file import check_file
from modules.virustotal.check_hash import check_hash

class VirusTotalClient:
    """Consolidated client wrapper for VirusTotal v3 operations."""
    
    @staticmethod
    def check_ip(ip: str) -> dict:
        """Query reputation for an IP address."""
        return check_ip(ip)
        
    @staticmethod
    def check_domain(domain: str) -> dict:
        """Query reputation for a domain name."""
        return check_domain(domain)
        
    @staticmethod
    def check_file(filepath: str) -> dict:
        """Scan a file or check its SHA256 reputation."""
        return check_file(filepath)
        
    @staticmethod
    def check_hash(file_hash: str) -> dict:
        """Query reputation for a file hash."""
        return check_hash(file_hash)
