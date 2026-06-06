"""
VirusTotal File scanner.
Checks file hash first, and uploads file for scanning if not found.
"""
import os
import requests
from config.settings import settings
from config.constants import VIRUSTOTAL_BASE_URL
from utils.logger import logger
from utils.validators import is_valid_filepath
from utils.error_handler import retry_on_exception, run_gracefully
from modules.virustotal.check_hash import check_hash
from modules.file_monitor.file_hashing import calculate_sha256

@run_gracefully(module_name="virustotal_check_file", default_return=None)
def check_file(filepath: str) -> dict:
    """Scan a local file on VirusTotal."""
    if not is_valid_filepath(filepath):
        logger.warning(f"File path does not exist or is invalid: {filepath}")
        return {"error": "Invalid file path"}
        
    # Step 1: Calculate SHA256 of file
    file_hash = calculate_sha256(filepath)
    if not file_hash:
        return {"error": "Failed to calculate file hash"}
        
    logger.info(f"Checking reputation for hash {file_hash} first (File: {filepath})")
    
    # Step 2: Check hash reputation (to save bandwidth and quota)
    hash_result = check_hash(file_hash)
    if hash_result and "error" not in hash_result and hash_result.get("status") != "not_found":
        return hash_result
        
    # If in mock mode, return mock scan upload result
    if settings.mock_mode:
        logger.info(f"[Mock Mode] Simulating upload for file: {filepath}")
        return {
            "status": "queued",
            "message": "File scan successfully simulated",
            "data": {
                "id": f"scan-{file_hash}",
                "type": "analysis"
            }
        }
        
    api_key = settings.api_keys.get("virustotal")
    if not api_key:
        logger.warning("VirusTotal API Key is missing. Cannot upload file.")
        return {"error": "API Key missing"}
        
    # Step 3: Upload file if not found
    file_size = os.path.getsize(filepath)
    if file_size > 32 * 1024 * 1024:  # 32MB upload limit for standard endpoint
        logger.warning(f"File size {file_size} exceeds VirusTotal standard upload limit of 32MB.")
        return {"error": "File too large for standard upload"}
        
    logger.info(f"Uploading file {filepath} to VirusTotal...")
    return upload_file_to_virustotal(filepath, api_key)

@retry_on_exception(retries=2, backoff_factor=3.0, exceptions=(requests.RequestException,))
def upload_file_to_virustotal(filepath: str, api_key: str) -> dict:
    """Uploads file to VT /files endpoint."""
    url = f"{VIRUSTOTAL_BASE_URL}/files"
    headers = {
        "x-apikey": api_key
    }
    with open(filepath, 'rb') as f:
        files = {
            'file': (os.path.basename(filepath), f)
        }
        response = requests.post(url, headers=headers, files=files, timeout=30)
        
    if response.status_code == 429:
        logger.error("VirusTotal API rate limit (Quota Exhausted) encountered on file upload.")
        return {"error": "Rate limit exceeded"}
        
    response.raise_for_status()
    return response.json()
