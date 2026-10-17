# The Red Room

**An autonomous AI security scanning pipeline that finds vulnerabilities, proves exploitability, and proposes fixes.**

---

## Overview

The Red Room is a three-agent pipeline that continuously monitors application code for security vulnerabilities, autonomously proves that found issues are exploitable (in an isolated Docker environment), and generates production-ready patches with tests — all without human intervention in the inner loop.

```
Git Diff / Code Change
        │
        ▼
  ┌─────────────┐      ┌──────────────┐      ┌──────────────┐
  │  Saboteur   │ ───► │  Exploit Lab │ ───► │   Surgeon    │
  │  (Scanner + │      │  (Exploit    │      │  (Patch +    │
  │  Hypothesis │      │   Execution) │      │   PR)        │
  └─────────────┘      └──────────────┘      └──────────────┘
        │                     │                     │
   Hypothesis            ExploitResult          PatchResult
   (vuln type,           (confirmed?,           (diff, tests,
    confidence,           evidence,              explanation,
    affected endpoints)   reproducibility)       PR URL)
```

The agents are wired as a **LangGraph state machine**. The `fullscan` CLI command runs the complete path: scan → sandboxed exploit proof → patch generation → PDF report → optional GitHub PR.

---

## What It Does

### Agent I — Scanner / Saboteur
Analyzes git diffs and running applications for security vulnerabilities. Parses code changes, identifies suspicious patterns (race conditions, injection vectors, broken authentication), and generates a structured *attack hypothesis* with confidence score and affected endpoints.

### Agent II — Exploit Lab
Takes the hypothesis and generates a targeted exploit script. Executes the script against an isolated **shadow container** (Docker, with 512Mi RAM / 0.5 CPU limits) to confirm exploitability, collecting HTTP responses, database state changes, and timing evidence.

### Agent III — Surgeon
Uses a configured LLM (Google Gemini by default, or OpenAI / Anthropic / local Ollama) to analyze the confirmed exploit and generate a minimal, safe patch. Produces:
- A unified diff patch
- Regression test cases
- Complexity analysis (before / after)
- A fully formatted GitHub pull request
- A PDF security report covering findings, evidence, and remediations

---

## Tech Stack

| Layer | Technology |
|---|---|
| Orchestration | LangGraph, LangChain |
| LLM Backend | Single configured provider (Gemini by default) |
| API Server | FastAPI, Uvicorn |
| CLI | Typer, Rich |
| Database | SQLAlchemy, Alembic, PostgreSQL |
| Caching / State | Redis |
| Container Infra | Docker (shadow-container isolation) |
| GitHub Integration | PyGitHub |
| Web Scanning | Playwright, httpx |
| Reports | ReportLab PDF generation |
| Logging | structlog |
| Packaging | Poetry |

---

## Installation

### Prerequisites
- Python 3.10+
- Docker (for shadow namespace isolation)
- An LLM API key (Gemini by default)

### Using the install script (recommended)

**Linux / macOS:**
```bash
chmod +x install.sh
./install.sh
```

**Windows:**
```cmd
install.bat
```

### Manual install with pip / Poetry

```bash
# Clone the repo
git clone https://github.com/your-org/red-room.git
cd red-room

# Install with Poetry
poetry install

# Or with pip
pip install -e .
```

### Environment setup

Copy `.env.example` to `.env` and fill in your credentials:

```bash
cp .env.example .env
```

Key variables:

```env
GEMINI_API_KEY=your_gemini_api_key_here
GITHUB_TOKEN=your_github_token_here
DATABASE_URL=sqlite:///./redroom_scans.db
REDIS_URL=redis://localhost:6379/0
```

---

## Usage

### Full pipeline (the only operational command)

Deploys the target, scans it, proves exploits in Docker, generates patches, writes a PDF report, and optionally opens a PR:

```bash
redroom fullscan /path/to/your/project --port 8080 --output reports/scan.pdf

# Against the bundled fintech demo (deliberate race condition)
redroom fullscan src/demo/fintech_app --port 8080

# Also open a GitHub pull request for the generated patch
redroom fullscan src/demo/fintech_app --create-pr --repo owner/repo
```

### Show version

```bash
redroom version
```

The LangGraph orchestrator remains available as a FastAPI service (`redroom.orchestrator.main:app`) for CI and programmatic triggers:

```bash
uvicorn redroom.orchestrator.main:app --host 0.0.0.0 --port 8000
# Then: POST /scan with {"git_diff": "...", "commit_sha": "..."}
```

---

## Project Structure

```
src/redroom/
├── agents/
│   ├── scanner/          # Web vulnerability scanner
│   ├── saboteur/         # Hypothesis generation from diffs
│   ├── exploit_lab/      # Exploit script generation & execution
│   └── surgeon/          # Patch generation & PR creation
├── orchestrator/         # LangGraph engine + FastAPI server
├── workflows/            # End-to-end full scan workflow
├── infrastructure/       # Shadow container lifecycle (Docker)
├── database/             # SQLAlchemy scan history
├── reports/              # PDF report generation
├── models/               # Pydantic schemas
├── utils/                # Logging, AST validation
├── ui/                   # Rich terminal UI
└── cli.py                # Typer CLI: fullscan, version
```

---

## Docker Compose

Start the stack (orchestrator + Redis + PostgreSQL + demo fintech app):

```bash
docker-compose up -d
```

Services:
- **Orchestrator** — `http://localhost:8000`
- **Demo Fintech App** — `http://localhost:8080`
- **Jaeger** — `http://localhost:16686`

---

## Contributing

See [CONTRIBUTING.md](CONTRIBUTING.md) for development setup, coding standards, and how to submit pull requests.

---

## License

MIT License — see [LICENSE](LICENSE).
