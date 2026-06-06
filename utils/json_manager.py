"""
Thread-safe JSON read/write operations, validation, and auto-rotation for large logs.
"""
import os
import json
import shutil
import threading
from typing import Any, List, Optional
from utils.logger import logger
from utils.timestamp import get_utc_timestamp
from config.settings import settings

# Thread lock to guarantee thread-safe writes across all monitoring modules
_file_lock = threading.Lock()

def read_json_file(filepath: str) -> Optional[Any]:
    """Read and parse a JSON file with lock safety."""
    if not os.path.exists(filepath):
        return None
        
    with _file_lock:
        try:
            with open(filepath, 'r', encoding='utf-8') as f:
                return json.load(f)
        except json.JSONDecodeError as jde:
            logger.error(f"Corrupt JSON detected in {filepath}: {jde}. Creating backup.")
            # Backup corrupt file and return None socaller can reset
            backup_corrupt_file(filepath)
            return None
        except Exception as e:
            logger.error(f"Failed to read JSON from {filepath}: {e}")
            return None

def write_json_file(filepath: str, data: Any) -> bool:
    """Write data to a JSON file with lock safety."""
    with _file_lock:
        try:
            dir_name = os.path.dirname(filepath)
            if dir_name:
                os.makedirs(dir_name, exist_ok=True)
            with open(filepath, 'w', encoding='utf-8') as f:
                json.dump(data, f, indent=2, ensure_ascii=False)
            return True
        except Exception as e:
            logger.error(f"Failed to write JSON to {filepath}: {e}")
            return False

def append_to_json_array(filepath: str, item: Any) -> bool:
    """
    Append an item to a JSON array saved in a file.
    Rotates the file if it exceeds settings.json_rotation_size_bytes.
    """
    with _file_lock:
        try:
            dir_name = os.path.dirname(filepath)
            if dir_name:
                os.makedirs(dir_name, exist_ok=True)
                
            # Check for rotation if file exists
            if os.path.exists(filepath):
                file_size = os.path.getsize(filepath)
                if file_size >= settings.json_rotation_size_bytes:
                    rotate_json_file(filepath)
            
            # Read existing list
            items: List[Any] = []
            if os.path.exists(filepath):
                try:
                    with open(filepath, 'r', encoding='utf-8') as f:
                        items = json.load(f)
                        if not isinstance(items, list):
                            logger.warning(f"File {filepath} was not a list. Resetting to list.")
                            items = []
                except json.JSONDecodeError:
                    logger.warning(f"Corrupt JSON in {filepath} while appending. Backing up.")
                    backup_corrupt_file(filepath)
                    items = []
            
            items.append(item)
            
            # Write back
            with open(filepath, 'w', encoding='utf-8') as f:
                json.dump(items, f, indent=2, ensure_ascii=False)
            return True
            
        except Exception as e:
            logger.error(f"Error appending to JSON file {filepath}: {e}")
            return False

def rotate_json_file(filepath: str):
    """Rename current file by appending timestamp and reset standard path."""
    try:
        timestamp = get_utc_timestamp().replace(":", "-").replace(".", "-")
        base, ext = os.path.splitext(filepath)
        rotated_path = f"{base}_{timestamp}{ext}"
        shutil.move(filepath, rotated_path)
        logger.info(f"Rotated large JSON log file: {filepath} -> {rotated_path}")
    except Exception as e:
        logger.error(f"Failed to rotate file {filepath}: {e}")

def backup_corrupt_file(filepath: str):
    """Backs up corrupt JSON file to allow code initialization without hanging."""
    try:
        timestamp = get_utc_timestamp().replace(":", "-").replace(".", "-")
        base, ext = os.path.splitext(filepath)
        corrupt_backup = f"{base}_corrupt_{timestamp}{ext}"
        shutil.move(filepath, corrupt_backup)
        logger.warning(f"Corrupt JSON backed up to {corrupt_backup}")
    except Exception as e:
        logger.error(f"Failed to backup corrupt file {filepath}: {e}")
