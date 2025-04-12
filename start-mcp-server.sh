#!/bin/bash

# Exit on error
set -e

# Script directory
SCRIPT_DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" && pwd )"

# Check if the virtual environment exists
if [ ! -d "$SCRIPT_DIR/venv" ]; then
    echo "Virtual environment not found in $SCRIPT_DIR/venv"
    echo "Please run the setup script first to create the virtual environment."
    exit 1
fi

# Activate the virtual environment
echo "Activating virtual environment..."
source "$SCRIPT_DIR/venv/bin/activate"

# Start the server
echo "Starting mcp server..."
python "$SCRIPT_DIR/kali-mcp-server.py"

# This line will only be reached if the server exits
echo "Server has stopped."

# Deactivate the virtual environment
deactivate