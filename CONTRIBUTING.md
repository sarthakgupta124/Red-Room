# Contributing to The Red Room

Thank you for your interest in contributing to The Red Room! This document provides guidelines and instructions for contributing.

## Code of Conduct

Be respectful, inclusive, and professional in all interactions.

## Getting Started

1. Fork the repository
2. Clone your fork: `git clone https://github.com/your-username/red-room.git`
3. Create a branch: `git checkout -b feature/your-feature-name`
4. Make your changes
5. Run tests: `make test`
6. Commit: `git commit -m "Add your feature"`
7. Push: `git push origin feature/your-feature-name`
8. Create a Pull Request

## Development Setup

```bash
make dev-install
make setup
```

## Code Style

- Follow PEP 8
- Use Black for formatting
- Use Ruff for linting
- Add type hints
- Write docstrings

## Testing

- Write tests for new features
- Maintain >80% code coverage
- Run `make test` before submitting PR

## Pull Request Process

1. Update documentation
2. Add tests
3. Ensure CI passes
4. Request review from maintainers
