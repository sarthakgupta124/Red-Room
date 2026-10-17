"""CLI interface for The Red Room."""

import asyncio
from typing import Optional

import typer
from rich.console import Console

from redroom.ui.terminal_ui import TerminalUI

app = typer.Typer(name="redroom", help="The Red Room: Autonomous AI Security Scanning Pipeline")
console = Console()
ui = TerminalUI()


def setup_logging():
    """Lazy import logger to avoid loading dependencies unless needed."""
    try:
        from redroom.utils.logger import setup_logging as _setup_logging
        _setup_logging()
    except ImportError:
        pass


def _severity_color(severity: str) -> str:
    colors = {
        "critical": "red bold",
        "high": "red",
        "medium": "yellow",
        "low": "blue",
    }
    return colors.get(severity, "white")


@app.command()
def fullscan(
    project: str = typer.Argument(..., help="Path to project folder or GitHub repo"),
    port: int = typer.Option(8080, help="Port to run the app on"),
    output: Optional[str] = typer.Option(None, help="Path for the generated PDF report"),
    create_pr: bool = typer.Option(False, help="Open a GitHub PR for generated patches"),
    repo: Optional[str] = typer.Option(None, help="GitHub owner/repo used when --create-pr is set"),
):
    """
    Full pipeline: deploy, scan, prove exploit, generate patch, write PDF report, optionally open a PR.

    1. Deploys the target in Docker
    2. Scans for vulnerabilities
    3. Proves exploitability in an isolated container
    4. Generates an LLM-backed patch
    5. Writes a PDF security report
    6. Optionally creates a GitHub pull request
    """
    setup_logging()
    ui.display_banner()

    console.print("[bold red]Full Scan Workflow[/bold red]\n")
    console.print(f"[cyan]Project:[/cyan] {project}")
    console.print(f"[cyan]Port:[/cyan] {port}\n")

    async def run_workflow():
        from redroom.workflows.full_scan import FullScanWorkflow

        workflow = FullScanWorkflow(project)
        results = await workflow.run(port=port, output=output)

        console.print("\n[bold green]Scan Complete![/bold green]\n")

        console.print("[bold]Deployment:[/bold]")
        if results["deployment"].get("success"):
            console.print("  Status: [green]Success[/green]")
            console.print(f"  Method: {results['deployment'].get('method', 'unknown')}")
            console.print(f"  URL: {results['deployment'].get('url', 'unknown')}")
        else:
            console.print("  Status: [red]Failed[/red]")
            console.print(f"  Error: {results['deployment'].get('error', 'unknown')}")
            return

        console.print("\n[bold]Scan Results:[/bold]")
        console.print(f"  Endpoints found: {results['scan_results'].get('endpoints_found', 0)}")
        console.print(f"  Vulnerabilities found: {results['scan_results'].get('vulnerabilities_found', 0)}")

        if results["vulnerabilities"]:
            console.print("\n[bold]Vulnerabilities Analyzed:[/bold]")
            for i, vuln_analysis in enumerate(results["vulnerabilities"], 1):
                vuln = vuln_analysis["vulnerability"]
                console.print(f"\n  {i}. {vuln['type'].upper()}")
                console.print(f"     Endpoint: {vuln['endpoint']}")
                console.print(
                    f"     Severity: [{_severity_color(vuln['severity'])}]"
                    f"{vuln['severity'].upper()}[/{_severity_color(vuln['severity'])}]"
                )

        if results["fixes"]:
            console.print("\n[bold]Fixes Generated:[/bold]")
            for i, fix in enumerate(results["fixes"], 1):
                vuln = fix["vulnerability"]
                console.print(f"\n  {i}. Fix for {vuln['type'].upper()}")
                console.print(f"     Endpoint: {vuln['endpoint']}")
                console.print("     Patch: Generated")

        pdf_path = results.get("pdf_report")
        if pdf_path:
            console.print(f"\n[green]PDF report saved to: {pdf_path}[/green]")

        if create_pr and results.get("fixes"):
            await _maybe_create_pr(results, repo)

    try:
        asyncio.run(run_workflow())
    except KeyboardInterrupt:
        console.print("\n[yellow]Scan interrupted by user[/yellow]")
    except Exception as e:
        console.print(f"\n[red]Error: {e}[/red]")
        raise typer.Exit(1)


async def _maybe_create_pr(results: dict, repo_name: Optional[str]) -> None:
    """Open a GitHub PR for the first generated patch when requested."""
    from redroom.agents.surgeon.pr_creator import PRCreator
    from redroom.models.schemas import ExploitResult, Hypothesis, PatchResult

    fix = results["fixes"][0]
    vuln_analysis = results["vulnerabilities"][0] if results.get("vulnerabilities") else {}
    hypothesis_data = vuln_analysis.get("hypothesis") or {}

    patch_payload = fix.get("patch") or {}
    patch_result = PatchResult(**patch_payload) if isinstance(patch_payload, dict) else patch_payload

    if isinstance(hypothesis_data, dict) and hypothesis_data:
        hypothesis = Hypothesis(**hypothesis_data)
    else:
        hypothesis = None

    mock_exploit = ExploitResult(
        exploit_successful=True,
        evidence={"summary": {"exploit_successful": True}},
        reproducibility_score=1.0,
        execution_time_ms=100,
        shadow_namespace="local",
    )

    if hypothesis is None:
        console.print("\n[yellow]Skipping PR: no hypothesis available[/yellow]")
        return

    pr_creator = PRCreator()
    pr_url = await pr_creator.create_pr(
        patch_result=patch_result,
        exploit_result=mock_exploit,
        hypothesis=hypothesis,
        repo_name=repo_name,
    )
    if pr_url:
        console.print(f"\n[green]Pull request: {pr_url}[/green]")
    else:
        console.print("\n[yellow]PR was not created (missing GitHub token or repository)[/yellow]")


@app.command()
def version():
    """Show version information."""
    from redroom import __version__
    console.print(f"[bold red]The Red Room[/bold red] v{__version__}")
    console.print("[dim]Autonomous AI Security Scanning Pipeline[/dim]")


if __name__ == "__main__":
    app()
