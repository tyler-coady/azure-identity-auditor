"""CLI entry point for azure-identity-auditor."""

from __future__ import annotations

import sys
import time
from pathlib import Path

import click
from rich.console import Console

from . import __version__
from .models import ScanResult, Severity

_console = Console()

_FAIL_ON_CHOICES = ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO", "never"]
_FORMAT_CHOICES = ["console", "json", "html", "all"]


@click.group()
@click.version_option(version=__version__, prog_name="aia")
def main() -> None:
    """Azure Managed Identity Auditor — ensure AI services use managed identities."""


# ---------------------------------------------------------------------------
# scan azure
# ---------------------------------------------------------------------------


@main.command("scan-azure")
@click.option(
    "--subscription", "-s", "subscriptions", multiple=True, metavar="ID",
    help="Subscription ID(s). Defaults to all accessible subscriptions.",
)
@click.option("--resource-group", "-g", metavar="NAME", help="Limit to a specific resource group.")
@click.option(
    "--format", "output_format", default="console", show_default=True,
    type=click.Choice(_FORMAT_CHOICES), help="Output format.",
)
@click.option("--output-dir", "-o", type=click.Path(path_type=Path), help="Directory to write reports.")
@click.option(
    "--min-severity", default="LOW", show_default=True,
    type=click.Choice([s.value for s in Severity]), help="Minimum severity to include.",
)
@click.option(
    "--fail-on", default="CRITICAL", show_default=True,
    type=click.Choice(_FAIL_ON_CHOICES), help="Exit 1 if findings at or above this severity exist.",
)
def scan_azure(
    subscriptions: tuple[str, ...],
    resource_group: str | None,
    output_format: str,
    output_dir: Path | None,
    min_severity: str,
    fail_on: str,
) -> None:
    """Scan live Azure subscriptions for managed identity issues."""
    from azure.identity import DefaultAzureCredential, CredentialUnavailableError
    from azure.mgmt.resource import SubscriptionClient

    from .scanners import AIFoundryScanner, AIServicesScanner, AppServicesScanner, RBACScanner

    try:
        credential = DefaultAzureCredential()
    except Exception as exc:
        _console.print(f"[red]Failed to initialize Azure credential: {exc}[/red]")
        _console.print("Run [bold]az login[/bold] or set AZURE_CLIENT_ID / AZURE_CLIENT_SECRET / AZURE_TENANT_ID.")
        sys.exit(1)

    sub_ids: list[str]
    if subscriptions:
        sub_ids = list(subscriptions)
    else:
        try:
            sub_client = SubscriptionClient(credential)
            sub_ids = [s.subscription_id for s in sub_client.subscriptions.list() if s.state == "Enabled"]
        except CredentialUnavailableError:
            _console.print("[red]No Azure credentials available.[/red]")
            _console.print("Run [bold]az login[/bold] or configure a service principal.")
            sys.exit(1)
        except Exception as exc:
            _console.print(f"[red]Failed to list subscriptions: {exc}[/red]")
            sys.exit(1)

    if not sub_ids:
        _console.print("[yellow]No accessible subscriptions found.[/yellow]")
        sys.exit(0)

    merged = ScanResult()
    start = time.monotonic()

    for sub_id in sub_ids:
        _console.print(f"[dim]Scanning subscription {sub_id}…[/dim]")
        for ScannerClass in (AIServicesScanner, AppServicesScanner, RBACScanner, AIFoundryScanner):
            scanner = ScannerClass(credential, sub_id)
            result = scanner.scan()
            merged.merge(result)

    merged.scan_duration_seconds = time.monotonic() - start
    _emit(merged, output_format, output_dir, min_severity, fail_on)


# ---------------------------------------------------------------------------
# scan iac
# ---------------------------------------------------------------------------


@main.command("scan-iac")
@click.argument("paths", nargs=-1, required=True, type=click.Path(exists=True, path_type=Path))
@click.option(
    "--format", "output_format", default="console", show_default=True,
    type=click.Choice(_FORMAT_CHOICES),
)
@click.option("--output-dir", "-o", type=click.Path(path_type=Path))
@click.option(
    "--min-severity", default="LOW", show_default=True,
    type=click.Choice([s.value for s in Severity]),
)
@click.option("--fail-on", default="CRITICAL", show_default=True, type=click.Choice(_FAIL_ON_CHOICES))
def scan_iac(
    paths: tuple[Path, ...],
    output_format: str,
    output_dir: Path | None,
    min_severity: str,
    fail_on: str,
) -> None:
    """Scan IaC files for hardcoded credentials. No Azure login required."""
    from .scanners import IaCScanner

    start = time.monotonic()
    scanner = IaCScanner(list(paths))
    result = scanner.scan()
    result.scan_duration_seconds = time.monotonic() - start
    _emit(result, output_format, output_dir, min_severity, fail_on)


# ---------------------------------------------------------------------------
# scan all (combined)
# ---------------------------------------------------------------------------


@main.command("scan")
@click.option("--subscription", "-s", "subscriptions", multiple=True, metavar="ID")
@click.option("--iac-path", "-p", "iac_paths", multiple=True, type=click.Path(exists=True, path_type=Path), help="IaC directory/file to scan.")
@click.option("--skip-azure", is_flag=True)
@click.option("--skip-iac", is_flag=True)
@click.option("--format", "output_format", default="console", show_default=True, type=click.Choice(_FORMAT_CHOICES))
@click.option("--output-dir", "-o", type=click.Path(path_type=Path))
@click.option("--min-severity", default="LOW", show_default=True, type=click.Choice([s.value for s in Severity]))
@click.option("--fail-on", default="CRITICAL", show_default=True, type=click.Choice(_FAIL_ON_CHOICES))
def scan(
    subscriptions: tuple[str, ...],
    iac_paths: tuple[Path, ...],
    skip_azure: bool,
    skip_iac: bool,
    output_format: str,
    output_dir: Path | None,
    min_severity: str,
    fail_on: str,
) -> None:
    """Run a full audit — live Azure resources and/or IaC files."""
    from .scanners import AIFoundryScanner, AIServicesScanner, AppServicesScanner, IaCScanner, RBACScanner

    merged = ScanResult()
    start = time.monotonic()

    if not skip_azure:
        try:
            from azure.identity import DefaultAzureCredential, CredentialUnavailableError
            from azure.mgmt.resource import SubscriptionClient

            credential = DefaultAzureCredential()
            sub_ids: list[str]
            if subscriptions:
                sub_ids = list(subscriptions)
            else:
                sub_client = SubscriptionClient(credential)
                sub_ids = [
                    s.subscription_id
                    for s in sub_client.subscriptions.list()
                    if s.state == "Enabled"
                ]

            for sub_id in sub_ids:
                _console.print(f"[dim]Scanning subscription {sub_id}…[/dim]")
                for ScannerClass in (AIServicesScanner, AppServicesScanner, RBACScanner, AIFoundryScanner):
                    merged.merge(ScannerClass(credential, sub_id).scan())

        except Exception as exc:
            if not skip_iac:
                _console.print(f"[yellow]Azure scan skipped: {exc}[/yellow]")
            else:
                _console.print(f"[red]Azure scan failed: {exc}[/red]")
                sys.exit(1)

    if not skip_iac and iac_paths:
        _console.print(f"[dim]Scanning {len(iac_paths)} IaC path(s)…[/dim]")
        merged.merge(IaCScanner(list(iac_paths)).scan())

    merged.scan_duration_seconds = time.monotonic() - start
    _emit(merged, output_format, output_dir, min_severity, fail_on)


# ---------------------------------------------------------------------------
# Shared output helper
# ---------------------------------------------------------------------------


def _emit(
    result: ScanResult,
    output_format: str,
    output_dir: Path | None,
    min_severity: str,
    fail_on: str,
) -> None:
    from .reporters import ConsoleReporter, HtmlReporter, JsonReporter

    min_weight = Severity(min_severity).weight
    result.findings = [f for f in result.findings if f.severity.weight >= min_weight]

    if output_dir:
        output_dir.mkdir(parents=True, exist_ok=True)

    if output_format in ("console", "all"):
        ConsoleReporter(_console).write(result, output_dir if output_format == "all" else None)

    if output_format in ("json", "all"):
        out = JsonReporter().write(result, output_dir)
        if output_format == "json" and not output_dir:
            print(out)

    if output_format in ("html", "all"):
        out_dir = output_dir or Path(".")
        HtmlReporter().write(result, out_dir)
        if output_format == "html":
            _console.print(f"[green]HTML report written to {out_dir / 'report.html'}[/green]")

    if fail_on != "never":
        if result.has_severity_at_or_above(Severity(fail_on)):
            sys.exit(1)
