.PHONY: help install dev-install setup test lint format clean docker-build docker-up demo

help:
	@echo "Red Room - The Infinite Adversary"
	@echo ""
	@echo "Available targets:"
	@echo "  install       - Install production dependencies"
	@echo "  dev-install   - Install development dependencies"
	@echo "  setup         - Setup development environment"
	@echo "  test          - Run tests"
	@echo "  lint          - Run linting"
	@echo "  format        - Format code"
	@echo "  docker-build  - Build Docker images"
	@echo "  docker-up     - Start Docker services"
	@echo "  demo          - Run demo scenario"
	@echo "  clean         - Clean temporary files"

install:
	poetry install --only main

dev-install:
	poetry install --with dev,docs
	poetry run pre-commit install

setup: dev-install
	./scripts/setup-dev-env.sh
	./scripts/setup-amd-hardware.sh

test:
	poetry run pytest -v --cov=redroom --cov-report=html

lint:
	poetry run ruff check src/ tests/
	poetry run mypy src/

format:
	poetry run black src/ tests/
	poetry run ruff check --fix src/ tests/

docker-build:
	docker-compose build

docker-up:
	docker-compose up -d

demo:
	./scripts/deploy-demo.sh
	poetry run redroom start --mode demo

clean:
	find . -type d -name "__pycache__" -exec rm -rf {} +
	find . -type f -name "*.pyc" -delete
	rm -rf .pytest_cache .coverage htmlcov .mypy_cache
