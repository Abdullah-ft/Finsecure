"""
Configuration Module

Centralized configuration management for the Finsecure toolkit.
"""

import json
from pathlib import Path
from typing import Dict, Any, Optional


class Config:
    """Manages configuration settings for the toolkit."""
    
    # Default configuration values
    DEFAULT_CONFIG = {
        'max_threads': 50,
        'max_clients': 200,
        'timeout': 5,
        'rate_limit_delay': 0.1,
        'output_dir': 'output',
        'log_dir': 'logs',
        'default_wordlist': 'wordlists/common.txt',
        'banner_timeout': 3,
        'packet_count_limit': 1000,
        'scan_timeout': 10
    }
    
    def __init__(self, config_file: Optional[str] = None):
        """
        Initialize configuration.
        
        Args:
            config_file: Optional path to JSON configuration file
        """
        self.config_file = Path(config_file) if config_file else Path('config.json')
        self._config = self.DEFAULT_CONFIG.copy()
        
        if self.config_file.exists():
            self._load_config()
        else:
            self._create_default_config()
    
    def _load_config(self) -> None:
        """Load configuration from file."""
        try:
            with open(self.config_file, 'r', encoding='utf-8') as f:
                file_config = json.load(f)
                self._config.update(file_config)
        except Exception as e:
            print(f"⚠️  Warning: Failed to load config file: {e}")
            print("   Using default configuration")
    
    def _create_default_config(self) -> None:
        """Create a default configuration file."""
        try:
            with open(self.config_file, 'w', encoding='utf-8') as f:
                json.dump(self.DEFAULT_CONFIG, f, indent=4)
            print(f"📝 Created default configuration file: {self.config_file}")
        except Exception as e:
            print(f"⚠️  Warning: Could not create config file: {e}")
    
    def get(self, key: str, default: Any = None) -> Any:
        """
        Get a configuration value.
        
        Args:
            key: Configuration key
            default: Default value if key not found
            
        Returns:
            Configuration value or default
        """
        return self._config.get(key, default)
    
    def set(self, key: str, value: Any) -> None:
        """
        Set a configuration value.
        
        Args:
            key: Configuration key
            value: Value to set
        """
        self._config[key] = value
    
    def get_output_dir(self) -> Path:
        """Get the output directory path."""
        return Path(self.get('output_dir', 'output'))
    
    def get_log_dir(self) -> Path:
        """Get the log directory path."""
        return Path(self.get('log_dir', 'logs'))
    
    def get_max_threads(self) -> int:
        """Get maximum thread limit."""
        return self.get('max_threads', 50)
    
    def get_max_clients(self) -> int:
        """Get maximum client limit."""
        return min(self.get('max_clients', 200), 200)  # Hard limit at 200
    
    def get_timeout(self) -> int:
        """Get default timeout value."""
        return self.get('timeout', 5)
    
    def get_rate_limit_delay(self) -> float:
        """Get rate limiting delay in seconds."""
        return self.get('rate_limit_delay', 0.1)

