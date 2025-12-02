"""
Password Assessment Module

Offline password policy checker with entropy calculation.
NO online brute-forcing capabilities - simulation mode only.
"""

import json
import math
import re
from datetime import datetime
from pathlib import Path
from typing import List, Dict, Optional

from logger import Logger
from config import Config


class PasswordTester:
    """Password policy and strength assessment tool."""
    
    # Common weak passwords
    COMMON_PASSWORDS = [
        'password', '123456', '12345678', 'qwerty', 'abc123',
        'password1', 'admin', 'letmein', 'welcome', 'monkey',
        '1234567', '1234567890', '1234', 'dragon', 'sunshine',
        'princess', 'football', 'master', 'hello', 'freedom'
    ]
    
    def __init__(self, logger: Logger, config: Config):
        """
        Initialize the password tester.
        
        Args:
            logger: Logger instance
            config: Configuration instance
        """
        self.logger = logger
        self.config = config
    
    def calculate_entropy(self, password: str) -> float:
        """
        Calculate password entropy (bits of entropy).
        
        Args:
            password: Password string
            
        Returns:
            Entropy value in bits
        """
        if not password:
            return 0.0
        
        # Determine character set size
        has_lower = bool(re.search(r'[a-z]', password))
        has_upper = bool(re.search(r'[A-Z]', password))
        has_digit = bool(re.search(r'\d', password))
        has_special = bool(re.search(r'[^a-zA-Z0-9]', password))
        
        charset_size = 0
        if has_lower:
            charset_size += 26
        if has_upper:
            charset_size += 26
        if has_digit:
            charset_size += 10
        if has_special:
            charset_size += 33  # Common special characters
        
        if charset_size == 0:
            return 0.0
        
        # Entropy = log2(charset_size^length)
        entropy = len(password) * math.log2(charset_size)
        return round(entropy, 2)
    
    def check_password_policy(self, password: str) -> Dict:
        """
        Check password against common policy requirements.
        
        Args:
            password: Password to check
            
        Returns:
            Dictionary with policy check results
        """
        checks = {
            'length': len(password),
            'min_length_8': len(password) >= 8,
            'min_length_12': len(password) >= 12,
            'has_lowercase': bool(re.search(r'[a-z]', password)),
            'has_uppercase': bool(re.search(r'[A-Z]', password)),
            'has_digit': bool(re.search(r'\d', password)),
            'has_special': bool(re.search(r'[^a-zA-Z0-9]', password)),
            'entropy': self.calculate_entropy(password),
            'is_common': password.lower() in [p.lower() for p in self.COMMON_PASSWORDS],
            'has_sequence': self._has_sequence(password),
            'has_repetition': self._has_repetition(password)
        }
        
        # Overall strength assessment
        score = 0
        if checks['min_length_12']:
            score += 2
        elif checks['min_length_8']:
            score += 1
        
        if checks['has_lowercase']:
            score += 1
        if checks['has_uppercase']:
            score += 1
        if checks['has_digit']:
            score += 1
        if checks['has_special']:
            score += 1
        
        if checks['entropy'] >= 60:
            score += 2
        elif checks['entropy'] >= 40:
            score += 1
        
        if checks['is_common']:
            score -= 3
        if checks['has_sequence']:
            score -= 1
        if checks['has_repetition']:
            score -= 1
        
        if score >= 7:
            checks['strength'] = 'Strong'
        elif score >= 4:
            checks['strength'] = 'Moderate'
        else:
            checks['strength'] = 'Weak'
        
        checks['score'] = max(0, min(10, score))
        
        return checks
    
    def _has_sequence(self, password: str) -> bool:
        """Check for obvious sequences (123, abc, etc.)."""
        sequences = ['123', 'abc', 'qwe', 'asd', 'zxc']
        password_lower = password.lower()
        return any(seq in password_lower for seq in sequences)
    
    def _has_repetition(self, password: str) -> bool:
        """Check for character repetition (aaa, 111, etc.)."""
        return bool(re.search(r'(.)\1{2,}', password))
    
    def test_passwords(self, password_file: str, simulate: bool = True,
                      output_dir: Optional[str] = None) -> int:
        """
        Test passwords from a file.
        
        Args:
            password_file: Path to file containing passwords (one per line)
            simulate: Simulation mode (always True - offline only)
            output_dir: Output directory for results
            
        Returns:
            Exit code (0 for success)
        """
        if not simulate:
            print("⚠️  WARNING: Online password testing is disabled for safety.")
            print("   Running in simulation mode (offline only).")
            simulate = True
        
        self.logger.info(f"Starting password assessment (simulation mode)")
        self.logger.log_operation('password_tester', 'test_start', {
            'password_file': password_file,
            'simulate': True
        })
        
        # Read passwords from file
        password_path = Path(password_file)
        if not password_path.exists():
            print(f"❌ ERROR: Password file not found: {password_file}")
            self.logger.error(f"Password file not found: {password_file}")
            return 1
        
        passwords = []
        with open(password_path, 'r', encoding='utf-8', errors='ignore') as f:
            for line in f:
                password = line.strip()
                if password and not password.startswith('#'):
                    passwords.append(password)
        
        self.logger.info(f"Testing {len(passwords)} passwords")
        
        # Test each password
        results = []
        for password in passwords:
            # Don't store actual passwords in results for security
            policy_check = self.check_password_policy(password)
            results.append({
                'length': policy_check['length'],
                'strength': policy_check['strength'],
                'score': policy_check['score'],
                'entropy': policy_check['entropy'],
                'policy_compliance': {
                    'min_length_8': policy_check['min_length_8'],
                    'min_length_12': policy_check['min_length_12'],
                    'has_lowercase': policy_check['has_lowercase'],
                    'has_uppercase': policy_check['has_uppercase'],
                    'has_digit': policy_check['has_digit'],
                    'has_special': policy_check['has_special']
                },
                'weakness_flags': {
                    'is_common': policy_check['is_common'],
                    'has_sequence': policy_check['has_sequence'],
                    'has_repetition': policy_check['has_repetition']
                }
            })
        
        # Generate summary
        summary = {
            'timestamp': datetime.now().isoformat(),
            'total_passwords': len(passwords),
            'strong_count': sum(1 for r in results if r['strength'] == 'Strong'),
            'moderate_count': sum(1 for r in results if r['strength'] == 'Moderate'),
            'weak_count': sum(1 for r in results if r['strength'] == 'Weak'),
            'average_entropy': sum(r['entropy'] for r in results) / len(results) if results else 0,
            'common_password_count': sum(1 for r in results if r['weakness_flags']['is_common']),
            'results': results
        }
        
        # Display summary
        print(f"\n📊 Password Assessment Summary:")
        print(f"   Total Passwords: {summary['total_passwords']}")
        print(f"   Strong: {summary['strong_count']}")
        print(f"   Moderate: {summary['moderate_count']}")
        print(f"   Weak: {summary['weak_count']}")
        print(f"   Average Entropy: {summary['average_entropy']:.2f} bits")
        print(f"   Common Passwords: {summary['common_password_count']}")
        
        self.logger.info(f"Assessment complete: {summary['weak_count']} weak passwords found")
        
        # Export results
        if output_dir:
            self._export_results(output_dir, summary)
        else:
            self._export_results(self.config.get_output_dir(), summary)
        
        return 0
    
    def _export_results(self, output_dir: str, summary: Dict) -> None:
        """
        Export assessment results to JSON.
        
        Args:
            output_dir: Output directory
            summary: Assessment summary dictionary
        """
        output_path = Path(output_dir)
        output_path.mkdir(parents=True, exist_ok=True)
        
        timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
        json_file = output_path / f"auth_test_{timestamp}.json"
        
        with open(json_file, 'w', encoding='utf-8') as f:
            json.dump(summary, f, indent=2)
        
        self.logger.info(f"Results exported to {json_file}")

