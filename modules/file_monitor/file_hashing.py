"""
Chunk-based hashing utility for MD5, SHA1, and SHA256 file hashes.
"""
import hashlib
from utils.logger import logger
from utils.error_handler import run_gracefully

@run_gracefully(module_name="file_hashing", default_return="")
def calculate_sha256(filepath: str) -> str:
    """Calculate the SHA256 hash of a file in a memory-safe, chunked manner."""
    sha256 = hashlib.sha256()
    with open(filepath, 'rb') as f:
        while chunk := f.read(8192):
            sha256.update(chunk)
    return sha256.hexdigest()

@run_gracefully(module_name="file_hashing", default_return="")
def calculate_md5(filepath: str) -> str:
    """Calculate the MD5 hash of a file in a memory-safe, chunked manner."""
    md5 = hashlib.md5()
    with open(filepath, 'rb') as f:
        while chunk := f.read(8192):
            md5.update(chunk)
    return md5.hexdigest()

@run_gracefully(module_name="file_hashing", default_return="")
def calculate_sha1(filepath: str) -> str:
    """Calculate the SHA1 hash of a file in a memory-safe, chunked manner."""
    sha1 = hashlib.sha1()
    with open(filepath, 'rb') as f:
        while chunk := f.read(8192):
            sha1.update(chunk)
    return sha1.hexdigest()

def get_all_hashes(filepath: str) -> dict:
    """Calculate MD5, SHA1, and SHA256 for a given file."""
    try:
        md5 = hashlib.md5()
        sha1 = hashlib.sha1()
        sha256 = hashlib.sha256()
        
        with open(filepath, 'rb') as f:
            while chunk := f.read(8192):
                md5.update(chunk)
                sha1.update(chunk)
                sha256.update(chunk)
                
        return {
            "md5": md5.hexdigest(),
            "sha1": sha1.hexdigest(),
            "sha256": sha256.hexdigest()
        }
    except Exception as e:
        logger.error(f"Failed to generate hashes for file {filepath}: {e}")
        return {"md5": "", "sha1": "", "sha256": ""}
