"""
AI Password and Credential Exposure Scanner module.
Scans files in monitored directories for plaintext secrets, credentials, and keys using Gemini.
"""
import os
import uuid
from typing import Optional
from utils.logger import logger
from utils.timestamp import get_utc_timestamp
from modules.ai.gemini_client import gemini_client
from config.constants import SEVERITY_WARNING, SEVERITY_CRITICAL

# Ignore list for common binary or large format extensions
EXCLUDED_EXTENSIONS = (
    '.exe', '.dll', '.zip', '.tar', '.gz', '.png', '.jpg', '.jpeg',
    '.gif', '.pdf', '.docx', '.xlsx', '.pptx', '.mp3', '.mp4', '.avi',
    '.db', '.sqlite', '.pcap', '.bin', '.dat'
)

def scan_file_for_secrets(filepath: str) -> Optional[dict]:
    """
    Read file content (if text, and size < 50KB) and query Gemini to check for hardcoded credentials.
    Returns a standard SOC alert event if leak is detected, else None.
    """
    if not os.path.isfile(filepath):
        return None
        
    # Skip excluded extensions
    _, ext = os.path.splitext(filepath.lower())
    if ext in EXCLUDED_EXTENSIONS:
        return None
        
    try:
        # Check size to avoid massive files (token limits)
        size = os.path.getsize(filepath)
        if size > 50 * 1024:  # 50 KB limit
            logger.debug(f"Skipping AI secret scan for {filepath}: File too large ({size} bytes)")
            return None
            
        # Read file contents as text
        with open(filepath, 'r', encoding='utf-8', errors='ignore') as f:
            content = f.read(5000) # Read first 5000 characters to cover common header/config patterns
            
        if not content.strip():
            return None
            
        # Analyze content with Gemini client
        result = gemini_client.scan_file_for_secrets(filepath, content)
        
        if result and result.get("leak_detected"):
            risk = result.get("risk_level", "WARNING")
            severity = SEVERITY_CRITICAL if risk == "CRITICAL" else SEVERITY_WARNING
            
            alert = {
                "event_id": f"EVT-{uuid.uuid4()}",
                "timestamp": get_utc_timestamp(),
                "module": "ai_credential_scanner",
                "event_type": "secret_leak_detected",
                "severity": severity,
                "status": "detected",
                "data": {
                    "file_path": filepath,
                    "filename": os.path.basename(filepath),
                    "secret_type": result.get("secret_type", "password"),
                    "risk_level": risk,
                    "lines": result.get("lines", []),
                    "explanation": result.get("explanation", "Potential plaintext secret found.")
                }
            }
            logger.warning(f"AI Credentials Leak Warning: Hardcoded {result.get('secret_type')} found in {filepath}!")
            return alert
            
    except Exception as e:
        logger.error(f"Failed to scan file {filepath} for secrets: {e}")
        
    return None
