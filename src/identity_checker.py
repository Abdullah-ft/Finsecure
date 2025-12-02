"""
Identity and Consent Verification Module

This module ensures that all operations are authorized by verifying:
1. identity.txt - Contains team information and member details
2. consent.txt - Contains approved test targets

CRITICAL: No operations should proceed without valid verification.
"""

import json
from pathlib import Path
from typing import Dict, List, Optional
from datetime import datetime


class IdentityChecker:
    """Handles identity and consent verification for authorized operations."""
    
    def __init__(self, identity_file: str = 'identity.txt', consent_file: str = 'consent.txt'):
        """
        Initialize the identity checker.
        
        Args:
            identity_file: Path to identity.txt file
            consent_file: Path to consent.txt file
        """
        self.identity_file = Path(identity_file)
        self.consent_file = Path(consent_file)
        self._team_info: Optional[Dict] = None
    
    def verify_identity(self) -> bool:
        """
        Verify that identity.txt exists and contains valid information.
        
        Returns:
            True if identity file is valid, False otherwise
        """
        if not self.identity_file.exists():
            print(f"❌ ERROR: {self.identity_file} not found!")
            print("   Please create identity.txt with the following format:")
            print("   Team Name: Your Team Name")
            print("   Members: Name1 (Reg123), Name2 (Reg456)")
            return False
        
        try:
            team_info = self._parse_identity_file()
            if not team_info:
                return False
            
            # Validate required fields
            required_fields = ['team_name', 'members']
            for field in required_fields:
                if field not in team_info or not team_info[field]:
                    print(f"❌ ERROR: Missing or empty '{field}' in identity.txt")
                    return False
            
            self._team_info = team_info
            return True
            
        except Exception as e:
            print(f"❌ ERROR: Failed to parse identity.txt: {str(e)}")
            return False
    
    def verify_consent(self) -> bool:
        """
        Verify that consent.txt exists and contains approved targets.
        
        Returns:
            True if consent file is valid, False otherwise
        """
        if not self.consent_file.exists():
            print(f"❌ ERROR: {self.consent_file} not found!")
            print("   Please create consent.txt with approved test targets:")
            print("   Approved Targets:")
            print("   - example.com")
            print("   - 192.168.1.100")
            return False
        
        try:
            approved_targets = self._parse_consent_file()
            if not approved_targets:
                print("❌ ERROR: No approved targets found in consent.txt")
                return False
            
            if self._team_info:
                self._team_info['approved_targets'] = approved_targets
            
            return True
            
        except Exception as e:
            print(f"❌ ERROR: Failed to parse consent.txt: {str(e)}")
            return False
    
    def _parse_identity_file(self) -> Optional[Dict]:
        """
        Parse the identity.txt file.
        
        Returns:
            Dictionary containing team information or None if parsing fails
        """
        team_info = {
            'team_name': '',
            'members': [],
            'registration_numbers': []
        }
        
        with open(self.identity_file, 'r', encoding='utf-8') as f:
            lines = f.readlines()
        
        for line in lines:
            line = line.strip()
            if not line or line.startswith('#'):
                continue
            
            if ':' in line:
                key, value = line.split(':', 1)
                key = key.strip().lower()
                value = value.strip()
                
                if 'team' in key and 'name' in key:
                    team_info['team_name'] = value
                elif 'member' in key:
                    # Parse members: "Name1 (Reg123), Name2 (Reg456)"
                    members = [m.strip() for m in value.split(',')]
                    for member in members:
                        if '(' in member and ')' in member:
                            name = member[:member.index('(')].strip()
                            reg = member[member.index('(')+1:member.index(')')].strip()
                            team_info['members'].append(f"{name} ({reg})")
                            team_info['registration_numbers'].append(reg)
                        else:
                            team_info['members'].append(member)
        
        return team_info if team_info['team_name'] else None
    
    def _parse_consent_file(self) -> List[str]:
        """
        Parse the consent.txt file to extract approved targets.
        
        Returns:
            List of approved target addresses/domains
        """
        approved_targets = []
        
        with open(self.consent_file, 'r', encoding='utf-8') as f:
            lines = f.readlines()
        
        in_targets_section = False
        
        for line in lines:
            line = line.strip()
            if not line or line.startswith('#'):
                continue
            
            if 'approved' in line.lower() and 'target' in line.lower():
                in_targets_section = True
                continue
            
            if in_targets_section:
                # Remove list markers (-, *, numbers)
                target = line.lstrip('- *0123456789. ').strip()
                if target:
                    approved_targets.append(target)
        
        return approved_targets
    
    def get_team_info(self) -> Dict:
        """
        Get the parsed team information.
        
        Returns:
            Dictionary containing team information
        """
        if not self._team_info:
            raise ValueError("Team info not loaded. Call verify_identity() first.")
        return self._team_info
    
    def is_target_approved(self, target: str) -> bool:
        """
        Check if a target is in the approved list.
        
        Args:
            target: Target address/domain to check
            
        Returns:
            True if target is approved, False otherwise
        """
        if not self._team_info or 'approved_targets' not in self._team_info:
            return False
        
        approved = self._team_info['approved_targets']
        
        # Check exact match
        if target in approved:
            return True
        
        # Check if target is a subdomain or path of approved target
        for approved_target in approved:
            if target.startswith(approved_target) or approved_target in target:
                return True
        
        return False
    
    def get_registration_numbers(self) -> List[str]:
        """
        Get list of registration numbers from identity file.
        
        Returns:
            List of registration numbers
        """
        if not self._team_info:
            return []
        return self._team_info.get('registration_numbers', [])

