#!/bin/bash
set -e

echo "🔴 Setting up The Red Room development environment..."

# Check Python version
python_version=$(python3 --version | cut -d' ' -f2 | cut -d'.' -f1,2)
if (( $(echo "$python_version < 3.10" | bc -l) )); then
    echo "❌ Python 3.10+ required. Current: $python_version"
    exit 1
fi

# Install Poetry if not present
if ! command -v poetry &> /dev/null; then
    echo "📦 Installing Poetry..."
    curl -sSL https://install.python-poetry.org | python3 -
fi

# Install dependencies
echo "📦 Installing dependencies..."
poetry install --with dev,docs

# Setup pre-commit hooks
echo "🪝 Setting up pre-commit hooks..."
poetry run pre-commit install

# Create necessary directories
echo "📁 Creating directories..."
mkdir -p models data logs evidence artifacts

# Copy environment file
if [ ! -f .env ]; then
    echo "📝 Creating .env file..."
    cp .env.example .env
    echo "⚠️  Please edit .env with your configuration"
fi

# Check Docker
if ! command -v docker &> /dev/null; then
    echo "⚠️  Docker not found. Please install Docker."
else
    echo "✅ Docker found"
fi

echo "✅ Development environment setup complete!"
echo ""
echo "Next steps:"
echo "  1. Edit .env with your configuration"
echo "  2. Run: ./scripts/setup-amd-hardware.sh"
echo "  3. Run: make test"
