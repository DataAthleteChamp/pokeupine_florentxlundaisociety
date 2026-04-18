"""Rich terminal report — colored output for scan findings."""

from __future__ import annotations

from rich.console import Console
from rich.panel import Panel
from rich.text import Text

from pokeupine.schemas import Finding, Pack

console = Console()

SEVERITY_COLORS = {
    "critical": "red",
    "high": "yellow",
    "medium": "cyan",
    "low": "green",
}

STATUS_MARKS = {
    "fail": ("✗", "red"),
    "uncertain": ("?", "yellow"),
    "pass": ("✓", "green"),
}


def print_report(findings: list[Finding], pack: Pack) -> None:
    """Print a colored terminal report of scan findings."""
    if not findings:
        console.print("[green]  ✓ No findings — all checks passed.[/green]\n")
        return

    # Build a lookup from control_id → Control
    controls = {c.id: c for c in pack.controls}

    # Sort by severity (critical first)
    severity_order = {"critical": 0, "high": 1, "medium": 2, "low": 3}
    findings_sorted = sorted(
        findings,
        key=lambda f: severity_order.get(
            controls.get(f.control_id, None) and controls[f.control_id].severity or "low", 3
        ),
    )

    for finding in findings_sorted:
        control = controls.get(finding.control_id)
        severity = control.severity if control else "medium"
        title = control.title if control else finding.control_id
        color = SEVERITY_COLORS.get(severity, "white")

        mark_char, mark_color = STATUS_MARKS.get(finding.status, ("?", "yellow"))

        # Status line
        confidence_note = ""
        if finding.confidence < 1.0:
            confidence_note = f"  (LLM-judge, {finding.confidence:.0%} confidence)"

        console.print(
            f"  [{mark_color}]{mark_char}[/{mark_color}] "
            f"{finding.control_id} [{color}][{severity}][/{color}]   "
            f"{title}{confidence_note}"
        )

        # Evidence line
        if finding.file:
            location = f"{finding.file}:{finding.line}" if finding.line else finding.file
            console.print(f"      {location}   {finding.evidence}")
        else:
            console.print(f"      {finding.evidence}")

    console.print()

    # Summary
    fail_count = sum(1 for f in findings if f.status == "fail")
    uncertain_count = sum(1 for f in findings if f.status == "uncertain")
    total = len(findings)

    parts = []
    if fail_count:
        parts.append(f"[red]{fail_count} failed[/red]")
    if uncertain_count:
        parts.append(f"[yellow]{uncertain_count} uncertain[/yellow]")
    summary = ", ".join(parts)

    console.print(f"  {total} findings ({summary})")
    console.print("  Run [bold]pokeupine explain <id>[/bold] for proof-backed evidence.\n")
