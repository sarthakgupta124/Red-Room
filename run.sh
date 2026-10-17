#!/bin/bash
# Simple runner for The Red Room CLI

# Add src to Python path
export PYTHONPATH="$(pwd)/src:$PYTHONPATH"

# Run the CLI
python3 src/redroom/cli.py "$@"
