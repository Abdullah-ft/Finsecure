#!/bin/bash

echo "========================================"
echo "Finsecure Toolkit - Web UI Launcher"
echo "========================================"
echo ""

# Check if Python is available
if ! command -v python3 &> /dev/null; then
    echo "ERROR: Python 3 is not installed or not in PATH"
    exit 1
fi

# Check if identity.txt exists
if [ ! -f "identity.txt" ]; then
    echo "ERROR: identity.txt not found!"
    echo "Please create identity.txt before starting the web UI"
    exit 1
fi

# Check if consent.txt exists
if [ ! -f "consent.txt" ]; then
    echo "ERROR: consent.txt not found!"
    echo "Please create consent.txt before starting the web UI"
    exit 1
fi

echo "Starting Finsecure Web UI..."
echo ""
echo "Access the UI at: http://127.0.0.1:5000"
echo "Press Ctrl+C to stop the server"
echo ""
echo "========================================"
echo ""

python3 src/web_ui.py

