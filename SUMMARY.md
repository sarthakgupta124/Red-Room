# Project Summary — The Red Room

## Problem Statement

Security vulnerabilities in production applications are often discovered too late — after deployment, during incident response, or in bug bounty reports. Existing static analysis tools produce high false-positive rates and require manual triage. There is no automated system that can take a code change, confirm whether it is actually exploitable, and produce a ready-to-merge fix, all without developer intervention.

## Approach

The Red Room is a **fully autonomous, three-agent AI pipeline** that closes the loop between vulnerability detection and remediation:

1. **Scanner/Saboteur** — Analyzes git diffs and live HTTP endpoints for security issues. Uses pattern recognition and structural code analysis to generate a typed attack hypothesis with vulnerability type, confidence score, and targeted attack payload.

2. **Exploit Lab** — Generates a purpose-built exploit script from the hypothesis and executes it against an isolated, ephemeral Docker shadow container. Collects hard evidence: HTTP response data, database state before/after, and timing measurements. Confirms actual exploitability rather than just static potential.

3. **Surgeon** — Feeds the confirmed exploit and evidence into a large language model (Google Gemini by default) to generate a minimal, safe patch. Produces a unified diff, regression test suite, complexity analysis, a PDF security report, and opens a GitHub pull request with complete evidence attached for human review.

The three agents are wired together as a **LangGraph state machine**, enabling structured type-safe state passing and straightforward extension. The operator-facing surface is two CLI commands: `fullscan` (the entire pipeline) and `version`.

## Key Technical Decisions

- **LangGraph for orchestration** — chosen over a linear script because graph-based state machines cleanly express conditional flows (e.g., skip Surgeon if exploit fails) and make agent boundaries explicit.
- **Ephemeral Docker shadow containers** — exploit execution happens in isolated Docker containers, not against production. Resource limits (512Mi RAM, 0.5 CPU) are enforced; containers are destroyed after each run.
- **Pattern-based inference first** — the Saboteur uses structural code pattern matching for fast, dependency-free hypothesis generation, with the design allowing future substitution of a fine-tuned LLM.
- **LLM only for patch generation** — a single configured provider is called only in the Surgeon step, where reasoning over code structure benefits most from a large language model and where determinism matters less than quality.
- **Structured evidence** — every scan result is a typed Pydantic object persisted to PostgreSQL via SQLAlchemy, enabling historical querying and audit trails.
- **PDF as a first-class artifact** — every fullscan run writes a ReportLab PDF covering findings, severity, and endpoints so the proof is portable outside the CLI.

## What Was Built

- Full three-agent pipeline (Scanner, Saboteur, Exploit Lab, Surgeon) with typed inter-agent contracts
- LangGraph orchestration engine with FastAPI REST interface
- Shadow container lifecycle manager (Docker, with memory/CPU limits and automatic cleanup)
- Web vulnerability scanner covering 17+ vulnerability classes (SQLi, XSS, CSRF, SSRF, path traversal, race conditions, etc.)
- Exploit generator for race condition, SQL injection, and authentication bypass scenarios
- LLM-assisted patch generator producing unified diffs, test cases, and complexity analysis
- GitHub PR creator with structured evidence summary in the PR body
- PDF security report generation as part of the fullscan pipeline
- Rich terminal UI with real-time progress display
- Docker Compose stack with PostgreSQL, Redis, and the deliberate-race-condition fintech demo

## Outcome

The pipeline successfully demonstrates end-to-end autonomous security remediation: given a code change introducing a race condition in a fintech transfer endpoint, the system detects the issue, generates 10 concurrent requests that confirm the negative balance invariant is violated, produces a patch implementing proper database locking, and writes a PDF report — all within a single `redroom fullscan src/demo/fintech_app` invocation.
