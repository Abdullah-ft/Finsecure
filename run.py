#!/usr/bin/env python3
"""
Quick launcher for Finsecure Toolkit
Run this from the project root directory
"""

import sys
from pathlib import Path

# Add src directory to Python path
src_path = Path(__file__).parent / 'src'
sys.path.insert(0, str(src_path))

# Import and run main
from main import main

if __name__ == '__main__':
    sys.exit(main())