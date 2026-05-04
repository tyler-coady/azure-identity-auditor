"""Rich console reporter."""

from __future__ import annotations

from collections import Counter
from pathlib import Path

from rich import box
from rich.console import Console
from rich.panel import Panel
from rich.table import Table
from rich.text import Text

from ..models import Finding, ScanResult, Severity

_SEVERITY_STYLE: dict[Severity, str] = {
    Severity.CRITICAL: "bold red",
    Severity.HIGH: "red",
    Severity.MEDIUM: "yellow",
    Severity.LOW: "blue",
    Severity.INFO: "dim",
}

_SEVERITY_ICON: dict[Severity, str] = {
    Severity.CRITICAL: "●",
    Severity.HIGH: "◆",
    Severity.MEDIUM: "▲",
    Severity.LOW: "▸",
    Severity.INFO: "·",
}


class ConsoleReporter:
    def __init__(self, console: Console | None = None) -> None:
        self._console = console or Console()

    def write(self, result: ScanResult, output_dir: Path | None = None) -> None:
        findings = sorted(result.findings, key=lambda f: f.severity.weight, reverse=True)

        self._render_summary(result, findings)

        if not findings:
            self._console.print("[bold green]✓ No findings — all checks passed.[/bold green]")
        else:
            self._render_table(findings)
            self._render_details(findings)

        if result.errors:
            self._console.print("\n[yellow]Scan errors:[/yellow]")
            for err in result.errors:
                self._console.print(f"  [dim]{err}[/dim]")

        if output_dir:
            txt_path = output_dir / "report.txt"
            with open(txt_path, "w") as fh:
                file_console = Console(file=fh, highlight=False)
                ConsoleReporter(file_console).write(result)

    def _render_summary(self, result: ScanResult, findings: list[Finding]) -> None:
        counts = Counter(f.severity for f in findings)
        parts: list[str] = []
        for sev in [Severity.CRITICAL, Severity.HIGH, Severity.MEDIUM, Severity.LOW, Severity.INFO]:
            n = counts[sev]
            if n:
                style = _SEVERITY_STYLE[sev]
                parts.append(f"[{style}]{n} {sev.value}[/{style}]")

        body = "  ".join(parts) if parts else "[green]0 findings[/green]"
        subtitle = ""
        if result.subscription_id:
            subtitle = f"Subscription: {result.subscription_id}"
        if result.scan_duration_seconds:
            subtitle += f"  ({result.scan_duration_seconds:.1f}s)"

        self._console.print(
            Panel(
                body + (f"\n[dim]{subtitle}[/dim]" if subtitle else ""),
                title="[bold]Azure Managed Identity Audit[/bold]",
                border_style="blue",
            )
        )
        self._console.print()

    def _render_table(self, findings: list[Finding]) -> None:
        table = Table(box=box.ROUNDED, show_lines=False, expand=True)
        table.add_column("ID", style="dim", width=8, no_wrap=True)
        table.add_column("Sev", width=10, no_wrap=True)
        table.add_column("Rule", width=9, no_wrap=True)
        table.add_column("Resource", width=28, no_wrap=True)
        table.add_column("Title", ratio=1)

        for f in findings:
            style = _SEVERITY_STYLE[f.severity]
            icon = _SEVERITY_ICON[f.severity]
            sev_cell = Text(f"{icon} {f.severity.value}", style=style)
            table.add_row(f.id, sev_cell, f.rule_id, f.resource_id.split("/")[-1] or f.resource_id, f.title)

        self._console.print(table)
        self._console.print()

    def _render_details(self, findings: list[Finding]) -> None:
        self._console.print("[bold underline]Finding Details[/bold underline]\n")
        for f in findings:
            style = _SEVERITY_STYLE[f.severity]
            self._console.print(f"[{style}][{f.rule_id}] {f.title}[/{style}]  [dim]({f.id})[/dim]")
            if f.resource_id:
                self._console.print(f"  Resource:     {f.resource_id}")
            if f.resource_group:
                self._console.print(f"  Group:        {f.resource_group}")
            if f.subscription_id:
                self._console.print(f"  Subscription: {f.subscription_id}")
            self._console.print(f"  Description:  {f.description}")
            self._console.print(f"  [bold]Fix:[/bold] {f.remediation}")
            if f.details:
                for k, v in f.details.items():
                    self._console.print(f"  {k}: [dim]{v}[/dim]")
            self._console.print()
