"""
================================================================================
SETTINGS MANAGEMENT ENGINE - SOC AUTOMATION PLATFORM
================================================================================
This file is responsible for parsing config files, applying environment
variable overrides, and validating default platform behaviors.

CRITICAL IMPLEMENTATIONS:
- Default settings dict (API keys, monitoring intervals, thread limits).
- Deep dictionary merging for layered config validation.
- Auto-triggering mock mode when client APIs are not present.
================================================================================
"""
import os
import json
from typing import Dict, Any

# Default settings dict
DEFAULTS: Dict[str, Any] = {
    "api_keys": {
        "virustotal": "",
        "abuseipdb": "",
        "alienvault": "",
        "gemini": ""
    },
    "mock_mode": True,  # Defaults to True if api_keys are empty
    "monitoring": {
        "file_monitor_path": "./monitored_directory",
        "dns_polling_interval": 5,      # seconds
        "system_usage_interval": 30,    # seconds
        "process_polling_interval": 5,   # seconds
        "service_polling_interval": 60,  # seconds
        "connections_polling_interval": 10 # seconds
    },
    "performance": {
        "max_worker_threads": 8,
        "cache_expiry_hours": 24,
        "json_rotation_size_mb": 10
    }
}

def _load_dotenv(dotenv_path: str = None):
    """
    Reads a .env file and updates os.environ with the key-value pairs if the file exists.
    Ignores comments, empty lines, and strips quotes.
    """
    if dotenv_path is None:
        # Check relative to settings.py parent (which is root of SOC project since settings.py is in config/)
        base_dir = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
        dotenv_path = os.path.join(base_dir, ".env")
        
    if os.path.exists(dotenv_path):
        try:
            with open(dotenv_path, "r", encoding="utf-8") as f:
                for line in f:
                    line = line.strip()
                    if not line or line.startswith("#"):
                        continue
                    if "=" in line:
                        key, val = line.split("=", 1)
                        key = key.strip()
                        val = val.strip()
                        # Strip single or double quotes
                        if (val.startswith('"') and val.endswith('"')) or (val.startswith("'") and val.endswith("'")):
                            val = val[1:-1]
                        os.environ[key] = val
        except Exception as e:
            print(f"Error loading .env file from {dotenv_path}: {e}")

class Settings:
    def __init__(self, config_path: str = "config.json"):
        _load_dotenv()
        self.config_path = config_path
        self.config = DEFAULTS.copy()
        self.load_config()
        self.override_from_env()
        self.check_mock_mode()
        
    def load_config(self):
        """Load configuration from JSON file if it exists."""
        if os.path.exists(self.config_path):
            try:
                with open(self.config_path, 'r', encoding='utf-8') as f:
                    file_config = json.load(f)
                    self.deep_update(self.config, file_config)
            except Exception as e:
                # Fallback to defaults if json is corrupt (handled by error handler later)
                print(f"Error loading configuration from {self.config_path}: {e}")

    def deep_update(self, base: dict, updates: dict):
        """Recursively updates nested dictionaries."""
        for key, value in updates.items():
            if isinstance(value, dict) and key in base and isinstance(base[key], dict):
                self.deep_update(base[key], value)
            else:
                base[key] = value

    def override_from_env(self):
        """Override configuration with environment variables if present."""
        # API Keys override
        for key in ["virustotal", "abuseipdb", "alienvault", "gemini"]:
            env_val = os.getenv(f"SOC_{key.upper()}_API_KEY")
            if env_val:
                self.config["api_keys"][key] = env_val
                
        # Mock mode override
        env_mock = os.getenv("SOC_MOCK_MODE")
        if env_mock is not None:
            self.config["mock_mode"] = env_mock.lower() in ("true", "1", "yes")
            
        # File monitor path override
        env_file_path = os.getenv("SOC_FILE_MONITOR_PATH")
        if env_file_path:
            self.config["monitoring"]["file_monitor_path"] = env_file_path

    def check_mock_mode(self):
        """Auto-enable mock mode if no valid API keys are supplied and not explicitly disabled."""
        keys = self.config["api_keys"]
        has_keys = any(keys.values())
        if not has_keys:
            self.config["mock_mode"] = True

    @property
    def api_keys(self) -> Dict[str, str]:
        return self.config["api_keys"]

    @property
    def gemini_api_key(self) -> str:
        return self.config["api_keys"].get("gemini", "")

    @property
    def mock_mode(self) -> bool:
        return self.config["mock_mode"]

    @property
    def file_monitor_path(self) -> str:
        path = self.config["monitoring"]["file_monitor_path"]
        return os.path.abspath(path)

    @property
    def dns_polling_interval(self) -> int:
        return int(self.config["monitoring"]["dns_polling_interval"])

    @property
    def system_usage_interval(self) -> int:
        return int(self.config["monitoring"]["system_usage_interval"])

    @property
    def process_polling_interval(self) -> int:
        return int(self.config["monitoring"]["process_polling_interval"])

    @property
    def service_polling_interval(self) -> int:
        return int(self.config["monitoring"]["service_polling_interval"])

    @property
    def connections_polling_interval(self) -> int:
        return int(self.config["monitoring"]["connections_polling_interval"])

    @property
    def max_worker_threads(self) -> int:
        return int(self.config["performance"]["max_worker_threads"])

    @property
    def cache_expiry_hours(self) -> int:
        return int(self.config["performance"]["cache_expiry_hours"])

    @property
    def json_rotation_size_bytes(self) -> int:
        mb = self.config["performance"]["json_rotation_size_mb"]
        return mb * 1024 * 1024

# Instantiate a global settings object
settings = Settings()
