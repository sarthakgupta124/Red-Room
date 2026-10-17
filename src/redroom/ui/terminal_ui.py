"""Terminal UI for The Red Room."""

from rich.console import Console
from rich.live import Live
from rich.table import Table
from rich.panel import Panel
from rich.progress import Progress, SpinnerColumn, TextColumn
from rich.layout import Layout
from rich.text import Text
from typing import Dict, Any
import asyncio

from redroom.models.schemas import AgentStatus


class TerminalUI:
    """Rich terminal UI for displaying agent status."""
    
    def __init__(self):
        """Initialize terminal UI."""
        self.console = Console()
    
    def display_banner(self):
        """Display The Red Room banner."""
        banner = """
╔═══════════════════════════════════════════════════════════╗
║                                                           ║
║              🔴 THE RED ROOM 🔴                          ║
║        Autonomous AI Security Pipeline                   ║
║                                                           ║
║     Scanner · Saboteur · Surgeon                         ║
║                                                           ║
╚═══════════════════════════════════════════════════════════╝
        """
        self.console.print(banner, style="bold red")
    
    def display_agent_status(self, state: Dict[str, Any]):
        """Display real-time agent status."""
        table = Table(title="Agent Status", show_header=True, header_style="bold magenta")

        table.add_column("Agent", style="cyan", width=20)
        table.add_column("Role", style="yellow", width=20)
        table.add_column("Status", style="green", width=15)
        table.add_column("Progress", style="blue", width=30)

        # Agent I: Saboteur
        saboteur_status = state.get("saboteur_status", "idle")
        saboteur_progress = state.get("saboteur_progress", 0)
        table.add_row(
            "🔍 Saboteur",
            "Hypothesis Generation",
            self._format_status(saboteur_status),
            self._progress_bar(saboteur_progress)
        )

        # Agent II: Exploit Lab
        exploit_status = state.get("exploit_status", "idle")
        exploit_progress = state.get("exploit_progress", 0)
        table.add_row(
            "💣 Exploit Lab",
            "Exploit Execution",
            self._format_status(exploit_status),
            self._progress_bar(exploit_progress)
        )

        # Agent III: Surgeon
        surgeon_status = state.get("surgeon_status", "idle")
        surgeon_progress = state.get("surgeon_progress", 0)
        table.add_row(
            "🔧 Surgeon",
            "Patch Generation",
            self._format_status(surgeon_status),
            self._progress_bar(surgeon_progress)
        )

        self.console.print(table)
    
    def display_hypothesis(self, hypothesis: Dict[str, Any]):
        """Display vulnerability hypothesis."""
        panel = Panel(
            f"""
[bold yellow]Vulnerability Detected![/bold yellow]

[cyan]Type:[/cyan] {hypothesis.get('vulnerability_type', 'Unknown')}
[cyan]Confidence:[/cyan] {hypothesis.get('confidence_score', 0):.1%}
[cyan]Endpoints:[/cyan] {', '.join(hypothesis.get('affected_endpoints', []))}

[bold]Invariant Break:[/bold]
{hypothesis.get('invariant_break', {}).get('expected_behavior', 'N/A')}

[bold red]Attack Hypothesis:[/bold red]
{hypothesis.get('attack_hypothesis', {}).get('method', 'N/A')}
            """,
            title="🔍 Agent I: Hypothesis Generated",
            border_style="yellow"
        )
        self.console.print(panel)
    
    def display_exploit_result(self, result: Dict[str, Any]):
        """Display exploit execution result."""
        success = result.get('exploit_successful', False)
        style = "green" if success else "red"
        title = "✅ Exploit Successful" if success else "❌ Exploit Failed"
        
        panel = Panel(
            f"""
[bold]Reproducibility:[/bold] {result.get('reproducibility_score', 0):.1%}
[bold]Execution Time:[/bold] {result.get('execution_time_ms', 0)}ms
[bold]Shadow Namespace:[/bold] {result.get('shadow_namespace', 'N/A')}

[bold]Evidence:[/bold]
- HTTP Responses: {len(result.get('evidence', {}).get('http_responses', []))}
- DB State Captured: {'Yes' if result.get('evidence', {}).get('db_state_before') else 'No'}
            """,
            title=f"💣 Agent II: {title}",
            border_style=style
        )
        self.console.print(panel)
    
    def display_patch_result(self, result: Dict[str, Any]):
        """Display patch generation result."""
        panel = Panel(
            f"""
[bold green]Patch Generated Successfully![/bold green]

[cyan]Explanation:[/cyan]
{result.get('explanation', 'N/A')}

[cyan]Complexity Analysis:[/cyan]
Before: {result.get('complexity_analysis', {}).get('before', 'N/A')}
After: {result.get('complexity_analysis', {}).get('after', 'N/A')}

[cyan]Performance Impact:[/cyan]
P95 Latency: {result.get('performance_delta', {}).get('p95_latency_delta_ms', 0):.1f}ms
Throughput: {result.get('performance_delta', {}).get('throughput_delta_rps', 0):.1f} rps

[bold]PR URL:[/bold] {result.get('pr_url', 'Not created')}
            """,
            title="🔧 Agent III: Patch Created",
            border_style="green"
        )
        self.console.print(panel)
    
    def _format_status(self, status: str) -> str:
        """Format status with color."""
        status_colors = {
            "idle": "dim",
            "analyzing": "yellow",
            "exploiting": "red",
            "patching": "blue",
            "completed": "green",
            "failed": "red bold"
        }
        color = status_colors.get(status, "white")
        return f"[{color}]{status.upper()}[/{color}]"
    
    def _progress_bar(self, progress: float) -> str:
        """Create a simple progress bar."""
        filled = int(progress * 20)
        bar = "█" * filled + "░" * (20 - filled)
        return f"{bar} {progress:.0%}"
    
    async def run_live_demo(self):
        """Run a live demo with animated progress."""
        self.display_banner()
        
        with Progress(
            SpinnerColumn(),
            TextColumn("[progress.description]{task.description}"),
            console=self.console
        ) as progress:
            
            # Agent I
            task1 = progress.add_task("[cyan]Agent I: Analyzing code...", total=100)
            for i in range(100):
                await asyncio.sleep(0.02)
                progress.update(task1, advance=1)
            
            self.console.print("✅ [green]Hypothesis generated: Race condition detected[/green]")
            
            # Agent II
            task2 = progress.add_task("[red]Agent II: Exploiting vulnerability...", total=100)
            for i in range(100):
                await asyncio.sleep(0.03)
                progress.update(task2, advance=1)
            
            self.console.print("✅ [green]Exploit successful: Balance went negative[/green]")
            
            # Agent III
            task3 = progress.add_task("[blue]Agent III: Generating patch...", total=100)
            for i in range(100):
                await asyncio.sleep(0.02)
                progress.update(task3, advance=1)
            
            self.console.print("✅ [green]Patch created: PR #123 opened[/green]")
        
        self.console.print("\n[bold green]🎉 Red Room execution completed successfully![/bold green]")


if __name__ == "__main__":
    ui = TerminalUI()
    asyncio.run(ui.run_live_demo())
