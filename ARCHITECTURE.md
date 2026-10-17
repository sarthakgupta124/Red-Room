# Architecture — The Red Room

## Overview

The Red Room is structured as a **linear three-agent pipeline** orchestrated by LangGraph. Each agent produces a typed artifact that is passed as input to the next, creating a clear data flow from code change to merged pull request. The `fullscan` command is the operator-facing path through that same pipeline, ending in a PDF report and an optional GitHub PR.

---

## High-Level Pipeline

```
┌─────────────────────────────────────────────────────────────────┐
│                        Input Layer                              │
│        Git Diff  /  Web Application URL  /  API Trigger        │
└──────────────────────────┬──────────────────────────────────────┘
                           │
                           ▼
┌─────────────────────────────────────────────────────────────────┐
│                    Agent I: Saboteur                            │
│  src/redroom/agents/saboteur/                                   │
│                                                                 │
│  DiffAnalyzer → pattern recognition → ContractParser           │
│       └─────────────────► HypothesisGenerator                  │
│                                 │                               │
│                        Hypothesis (typed)                       │
│         { vulnerability_type, confidence_score,                 │
│           affected_endpoints, attack_hypothesis }               │
└──────────────────────────┬──────────────────────────────────────┘
                           │
                           ▼
┌─────────────────────────────────────────────────────────────────┐
│                    Agent II: Exploit Lab                        │
│  src/redroom/agents/exploit_lab/                                │
│                                                                 │
│  ExploitGenerator → generates Python exploit script            │
│  Shadow container created (Docker, 512Mi / 0.5 CPU)             │
│  Script executed against isolated target                        │
│  EvidenceCollector → collects HTTP + DB state evidence         │
│                                 │                               │
│                        ExploitResult (typed)                    │
│         { exploit_successful, evidence,                         │
│           reproducibility_score, execution_time_ms }            │
└──────────────────────────┬──────────────────────────────────────┘
                           │
                           ▼
┌─────────────────────────────────────────────────────────────────┐
│                    Agent III: Surgeon                           │
│  src/redroom/agents/surgeon/                                    │
│                                                                 │
│  PatchGenerator (single LLM client) → unified diff patch       │
│  PRCreator → opens GitHub PR with evidence + patch             │
│  PDFReportGenerator → writes a security scan PDF               │
│                                 │                               │
│                        PatchResult (typed)                      │
│         { patch, explanation, regression_tests,                 │
│           complexity_analysis, pr_url }                         │
└─────────────────────────────────────────────────────────────────┘
```

---

## Module Responsibilities

### `src/redroom/agents/scanner/`
- **`web_scanner.py`** — Crawls HTTP endpoints, probes for 17+ vulnerability classes (SQLi, XSS, CSRF, SSRF, path traversal, etc.), generates a structured vulnerability report.

### `src/redroom/agents/saboteur/`
- **`hypothesis_generator.py`** — Orchestrates diff analysis, pattern identification, and inference. Produces a `Hypothesis` object.
- **`diff_analyzer.py`** — Parses unified diffs into added/removed/context lines; identifies security-relevant patterns.
- **`contract_parser.py`** — Parses YAML security contracts (e.g., "balance must never go negative").
- **`diff_parser.py`** — Low-level diff tokenizer.

### `src/redroom/agents/exploit_lab/`
- **`exploit_generator.py`** — Generates targeted Python exploit scripts from a `Hypothesis`. Executes them in a shadow container using `asyncio.gather` for concurrent requests.
- **`evidence_collector.py`** — Aggregates HTTP response evidence, database state changes, and timing data into a structured `evidence` dict.

### `src/redroom/agents/surgeon/`
- **`patch_generator.py`** — Calls a single configured LLM (Gemini by default) with the vulnerable code + exploit evidence, returns a structured `PatchResult` with diff + tests.
- **`pr_creator.py`** — Creates a GitHub branch and pull request, formats a detailed PR body including evidence summary.

### `src/redroom/reports/`
- **`pdf_generator.py`** — Renders the scan into a PDF (severity breakdown, endpoints, evidence). Invoked by the fullscan workflow; the generator itself is a standalone ReportLab module.

### `src/redroom/orchestrator/`
- **`langgraph_engine.py`** — Defines the LangGraph `StateGraph`: nodes are the three agents, edges encode the pipeline flow, state is typed via Pydantic schemas.
- **`main.py`** — FastAPI application exposing `/scan`, `/status/{id}`, and `/results/{id}` endpoints.

### `src/redroom/workflows/`
- **`full_scan.py`** — Deploys a project into Docker, runs the web scanner, feeds findings through the agent pipeline, writes a PDF report, and returns a complete results dict.

### `src/redroom/infrastructure/`
- **`namespace_lifecycle.py`** — Creates and destroys isolated Docker shadow containers used for safe exploit execution. Enforces memory/CPU limits; containers are ephemeral and cleaned up after each run.

### `src/redroom/database/`
- **`scan_history.py`** — SQLAlchemy models for persisting scan results, hypotheses, and patches across runs.

### `src/redroom/utils/`
- **`logger.py`** — Structured logging with structlog.
- **`ast_validator.py`** — AST-based Python syntax validation for generated exploit scripts.

---

## Data Flow

```
                        ┌───────────────┐
                        │  Pydantic     │
                        │  Schemas      │
                        │  (schemas.py) │
                        └──────┬────────┘
                               │  typed throughout
      ┌────────────────────────┼────────────────────────┐
      │                        │                        │
  Hypothesis              ExploitResult            PatchResult
      │                        │                        │
  saboteur/               exploit_lab/             surgeon/
  hypothesis_generator    exploit_generator        patch_generator
      │                        │                        │
      └────────────────────────┴────────────────────────┘
                               │
                    LangGraph StateGraph
                    (orchestrator/langgraph_engine.py)
                               │
                    Persisted via SQLAlchemy
                    (database/scan_history.py)
                    PDF report via reports/pdf_generator.py
```

---

## Deployment

### Local (Docker Compose)

```bash
docker-compose up -d
```

Starts: Orchestrator, Redis, PostgreSQL, Demo Fintech App, Jaeger.

### Shadow isolation

`NamespaceLifecycle` launches an ephemeral Docker container per scan:

- Named `shadow-<app>-<id>`
- Resource limits: 512Mi RAM, 0.5 CPU
- Destroyed after exploit execution (and after 1 hour if leaked)
- Exploit execution is limited to network-level HTTP requests

### CI Integration

The orchestrator exposes a REST API and can be triggered from any CI/CD system:

```bash
curl -X POST http://orchestrator:8000/scan \
  -H "Content-Type: application/json" \
  -d '{"git_diff": "...", "commit_sha": "abc123", "repo": "org/repo"}'
```

---

## Observability

| Signal | Tool | Endpoint |
|--------|------|----------|
| Distributed traces | Jaeger | `:16686` |
| Structured logs | structlog → stdout | — |
