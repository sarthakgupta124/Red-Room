#!/bin/bash
set -e

echo "Deploying The Red Room demo fintech app..."

echo "Building demo Fintech application..."
docker build -t fintech-demo:latest src/demo/fintech_app/

echo "Starting demo container..."
docker rm -f demo-fintech >/dev/null 2>&1 || true
docker run -d --name demo-fintech -p 8080:8080 \
  -e ENABLE_VULNERABILITY=true \
  fintech-demo:latest

echo "Demo deployed successfully."
echo "Demo Fintech App: http://localhost:8080"
echo ""
echo "To run the full pipeline:"
echo "  python -m redroom.cli fullscan src/demo/fintech_app"
