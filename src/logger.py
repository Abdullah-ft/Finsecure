"""
Logging Module

Centralized logging with SHA-256 integrity checking.
All logs are append-only and include timestamps and team information.
"""

import hashlib
import json
import logging
from datetime import datetime
from pathlib import Path
from typing import Optional, Dict, Any


class Logger:
    """Centralized logger with integrity checking."""
    
    def __init__(self, log_dir: str = 'logs'):
        """
        Initialize the logger.
        
        Args:
            log_dir: Directory for log files
        """
        self.log_dir = Path(log_dir)
        self.log_dir.mkdir(parents=True, exist_ok=True)
        
        # Create log file with timestamp
        timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
        self.log_file = self.log_dir / f"finsecure_{timestamp}.log"
        self.integrity_file = self.log_dir / f"finsecure_{timestamp}.sha256"
        
        # Setup Python logging
        self.logger = logging.getLogger('Finsecure')
        self.logger.setLevel(logging.DEBUG)
        
        # File handler
        file_handler = logging.FileHandler(self.log_file, mode='a', encoding='utf-8')
        file_handler.setLevel(logging.DEBUG)
        
        # Console handler
        console_handler = logging.StreamHandler()
        console_handler.setLevel(logging.INFO)
        
        # Formatter
        formatter = logging.Formatter(
            '%(asctime)s - %(name)s - %(levelname)s - %(message)s',
            datefmt='%Y-%m-%d %H:%M:%S'
        )
        file_handler.setFormatter(formatter)
        console_handler.setFormatter(formatter)
        
        self.logger.addHandler(file_handler)
        self.logger.addHandler(console_handler)
        
        # Initialize integrity tracking
        self._log_hashes = []
        self._update_integrity()
    
    def _update_integrity(self) -> None:
        """Update SHA-256 hash of log file."""
        try:
            if self.log_file.exists():
                with open(self.log_file, 'rb') as f:
                    content = f.read()
                    hash_value = hashlib.sha256(content).hexdigest()
                    
                    # Store hash with metadata
                    integrity_data = {
                        'timestamp': datetime.now().isoformat(),
                        'log_file': str(self.log_file),
                        'sha256': hash_value,
                        'size': len(content)
                    }
                    
                    with open(self.integrity_file, 'w', encoding='utf-8') as f:
                        json.dump(integrity_data, f, indent=2)
                    
                    self._log_hashes.append(hash_value)
        except Exception as e:
            self.logger.warning(f"Failed to update integrity hash: {e}")
    
    def info(self, message: str, **kwargs) -> None:
        """Log an info message."""
        self.logger.info(message, **kwargs)
        self._update_integrity()
    
    def warning(self, message: str, **kwargs) -> None:
        """Log a warning message."""
        self.logger.warning(message, **kwargs)
        self._update_integrity()
    
    def error(self, message: str, exc_info: bool = False, **kwargs) -> None:
        """Log an error message."""
        self.logger.error(message, exc_info=exc_info, **kwargs)
        self._update_integrity()
    
    def debug(self, message: str, **kwargs) -> None:
        """Log a debug message."""
        self.logger.debug(message, **kwargs)
        self._update_integrity()
    
    def log_operation(self, module: str, operation: str, details: Dict[str, Any]) -> None:
        """
        Log a structured operation.
        
        Args:
            module: Module name
            operation: Operation name
            details: Operation details
        """
        log_entry = {
            'timestamp': datetime.now().isoformat(),
            'module': module,
            'operation': operation,
            'details': details
        }
        
        self.logger.info(f"Operation: {module}.{operation} - {json.dumps(details)}")
        self._update_integrity()
    
    def verify_integrity(self) -> bool:
        """
        Verify the integrity of log files.
        
        Returns:
            True if integrity is valid, False otherwise
        """
        try:
            if not self.log_file.exists() or not self.integrity_file.exists():
                return False
            
            # Read stored hash
            with open(self.integrity_file, 'r', encoding='utf-8') as f:
                stored_data = json.load(f)
                stored_hash = stored_data.get('sha256')
            
            # Calculate current hash
            with open(self.log_file, 'rb') as f:
                content = f.read()
                current_hash = hashlib.sha256(content).hexdigest()
            
            return current_hash == stored_hash
            
        except Exception as e:
            self.logger.error(f"Integrity verification failed: {e}")
            return False
    
    def get_log_file(self) -> Path:
        """Get the current log file path."""
        return self.log_file
    
    def get_integrity_file(self) -> Path:
        """Get the integrity file path."""
        return self.integrity_file

