#!/bin/bash

echo "========================================"
echo "The Red Room - Quick Install"
echo "========================================"
echo ""

# Check Python
if ! command -v python3 &> /dev/null; then
    echo "[ERROR] Python not found!"
    echo "Please install Python 3.10+ from https://www.python.org/"
    exit 1
fi

echo "[1/3] Installing Python dependencies..."
pip3 install -e .

if [ $? -ne 0 ]; then
    echo "[ERROR] Failed to install dependencies"
    exit 1
fi

echo ""
echo "[2/3] Checking Docker..."
if ! command -v docker &> /dev/null; then
    echo "[WARNING] Docker not found!"
    echo "Docker is required for the fullscan command."
    echo "Install: curl -fsSL https://get.docker.com | sh"
    echo ""
    echo "You can still run: python3 -m redroom.cli version"
else
    echo "Docker found!"
fi

echo ""
echo "[3/3] Verifying installation..."
python3 -m redroom.cli version

echo ""
echo "========================================"
echo "Installation Complete!"
echo "========================================"
echo ""
echo "Quick Start:"
echo "  Scan demo app:"
echo "     python3 -m redroom.cli fullscan src/demo/fintech_app"
echo "     (or: ./run.sh fullscan src/demo/fintech_app)"
echo ""
echo "  Show version:"
echo "     python3 -m redroom.cli version"
echo "     (or: ./run.sh version)"
echo ""
