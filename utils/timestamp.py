"""
Utility for generating normalized ISO 8601 UTC timestamps.
"""
from datetime import datetime, timezone

def get_utc_timestamp() -> str:
    """Generate ISO 8601 formatted UTC timestamp with milliseconds and Z suffix."""
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.%f")[:-3] + "Z"

def parse_utc_timestamp(ts_str: str) -> datetime:
    """Parse a UTC timestamp string back into a datetime object."""
    # Strip the trailing Z if present and replace with UTC timezone
    if ts_str.endswith("Z"):
        ts_str = ts_str[:-1]
    
    # Try parsing with microsecond or millisecond representation
    try:
        return datetime.fromisoformat(ts_str).replace(tzinfo=timezone.utc)
    except ValueError:
        # Fallback format if string has exact seconds without decimals
        return datetime.strptime(ts_str, "%Y-%m-%dT%H:%M:%S").replace(tzinfo=timezone.utc)
