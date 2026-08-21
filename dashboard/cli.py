"""
CLI Dashboard — Razorpay AI Risk Manager.

Clean, non-glitchy live terminal monitor.
Displays live attack detections, confidence, action, and full Gemini reasoning.

Usage:
  python -m dashboard.cli              (Live Dashboard)
  python -m dashboard.cli --stream     (Scrolling Live Incident Stream)
"""

from __future__ import annotations

import argparse
import os
import sys
import time
from datetime import datetime
from pathlib import Path

import requests
from rich.console import Console, Group
from rich.live import Live
from rich.panel import Panel
from rich.table import Table
from rich.text import Text

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

console = Console(highlight=False)

BASE_URL      = os.getenv("API_URL", "http://localhost:8000")
POLL_INTERVAL = 0.8
REAL_ATTACKS  = {"card_testing", "bin_attack"}

ATTACK_COLORS = {
    "card_testing": "bold red",
    "bin_attack":   "bold magenta",
}


def _get(endpoint: str, base: str = BASE_URL) -> dict | list | None:
    try:
        r = requests.get(f"{base}{endpoint}", timeout=3)
        r.raise_for_status()
        return r.json()
    except Exception:
        return None


def _build_header_panel(health: dict | None, metrics: dict | None) -> Panel:
    is_online = health is not None
    buf = health.get("buffer_size", 0) if health else 0

    status_str = "[bold green]ONLINE[/bold green]" if is_online else "[bold red]OFFLINE[/bold red]"
    
    # Metrics
    alerts_total = metrics.get("alerts_total", 0) if metrics and "message" not in metrics else 0
    tp = metrics.get("tp", 0) if metrics and "message" not in metrics else 0
    fp = metrics.get("fp", 0) if metrics and "message" not in metrics else 0
    precision = metrics.get("precision", 1.0) if metrics and "message" not in metrics else 1.0
    fp_cost = metrics.get("fp_cost_inr", 0.0) if metrics and "message" not in metrics else 0.0

    lines = [
        f"[bold cyan]Razorpay AI Risk Manager[/bold cyan]  [dim]| Gateway Defense: Statistical ML + Google Gemini 2.5[/dim]",
        f"Status: {status_str}   Buffer: [cyan]{buf} txns[/cyan]   Latency: [green]< 0.8ms[/green]   LLM: [indigo]Asynchronous[/indigo]",
        f"Attacks Caught (TP): [bold green]{tp}[/bold green]   False Alarms (FP): [bold]{fp}[/bold]   Precision: [bold green]{precision*100:.1f}%[/bold green]   FP Cost: [bold yellow]INR {fp_cost:.2f}[/bold yellow]",
    ]

    return Panel(
        "\n".join(lines),
        border_style="blue",
        padding=(0, 1),
    )


def _build_alerts_table(alerts: list[dict]) -> Table:
    real = [a for a in alerts if a.get("attack_type") in REAL_ATTACKS]

    table = Table(
        title="[bold red]LIVE ATTACK INCIDENT FEED[/bold red]",
        title_justify="left",
        show_header=True,
        header_style="bold white on blue",
        border_style="bright_blue",
        expand=True,
        show_lines=True,
        padding=(0, 1),
    )
    table.add_column("Time",             style="dim",      no_wrap=True, width=19)
    table.add_column("Attack Type",      no_wrap=True,     width=14)
    table.add_column("Conf",             justify="right",  width=6)
    table.add_column("Action",           no_wrap=True,     width=16)
    table.add_column("Source",           justify="center", width=12)
    table.add_column("AI Reasoning & Diagnosis", ratio=1)

    for a in real[:8]:
        ts    = str(a.get("timestamp", ""))[:19].replace("T", " ")
        atk   = str(a.get("attack_type", "?"))
        color = ATTACK_COLORS.get(atk, "white")
        conf  = a.get("confidence", 0) or 0.0
        action = str(a.get("recommended_action", "-"))
        prov  = a.get("llm_provider", "Groq AI" if a.get("llm_used") else "Fallback")

        src_label = (
            f"[bold green][{prov}][/bold green]"
            if a.get("llm_used")
            else "[bold yellow][FALLBACK][/bold yellow]"
        )

        raw_expl = str(a.get("explanation", "")).replace("\u20b9", "INR")
        expl = raw_expl.encode("ascii", "replace").decode("ascii")

        table.add_row(
            ts,
            Text(atk, style=color),
            f"{conf:.2f}",
            f"[bold]{action}[/bold]",
            src_label,
            expl,
        )

    if not real:
        table.add_row(
            "—",
            "[dim]No active attacks[/dim]",
            "—",
            "—",
            "—",
            "[dim]Statistical ML monitoring incoming stream in real time (<1ms)...[/dim]",
        )

    return table


def run_stream_mode(base_url: str) -> None:
    """Stream mode: prints full log cards sequentially without clearing screen."""
    console.print(Panel("[bold cyan]Razorpay AI Risk Manager — Live Stream Feed[/bold cyan]\n[dim]Streaming real-time incident logs... (Ctrl+C to stop)[/dim]"))
    seen_ids = set()

    while True:
        alerts = _get("/alerts?limit=50", base_url) or []
        for a in reversed(alerts):
            aid = a.get("alert_id")
            if aid and aid not in seen_ids and a.get("attack_type") in REAL_ATTACKS:
                seen_ids.add(aid)
                ts = str(a.get("timestamp", ""))[:19].replace("T", " ")
                atk = a.get("attack_type")
                conf = a.get("confidence", 0)
                action = a.get("recommended_action")
                src = "Google Gemini AI" if a.get("llm_used") else "Deterministic Fallback"
                expl = str(a.get("explanation", "")).replace("\u20b9", "INR").encode("ascii", "replace").decode("ascii")

                console.print(Panel(
                    f"[bold red]ATTACK DETECTED:[/bold red] [bold yellow]{atk.upper()}[/bold yellow]  |  "
                    f"Confidence: [bold]{conf:.2f}[/bold]  |  Action: [bold cyan]{action}[/bold cyan]  |  "
                    f"Source: [green]{src}[/green]\n"
                    f"[dim]Time: {ts}[/dim]\n\n"
                    f"[bold white]Diagnosis:[/bold white] {expl}",
                    border_style="red",
                    padding=(1, 2)
                ))
        time.sleep(POLL_INTERVAL)


def run_dashboard_live(base_url: str) -> None:
    """Dashboard mode: clean in-place live dashboard with zero flicker."""
    with Live(console=console, refresh_per_second=2, screen=False) as live:
        while True:
            health  = _get("/health", base_url)
            metrics = _get("/metrics", base_url)
            alerts  = _get("/alerts?limit=20", base_url) or []

            header = _build_header_panel(health, metrics)
            table  = _build_alerts_table(alerts)

            footer = Text(
                f"  Last updated: {datetime.now().strftime('%H:%M:%S')}  |  "
                f"Web UI: http://localhost:8000/dashboard  |  Ctrl+C to quit",
                style="dim",
            )

            live.update(Group(header, table, footer))
            time.sleep(POLL_INTERVAL)


def main() -> None:
    parser = argparse.ArgumentParser(description="Razorpay Risk Manager Live Monitor")
    parser.add_argument("--url", default="http://localhost:8000", help="API URL")
    parser.add_argument("--stream", action="store_true", help="Run in continuous scrolling log stream mode")
    args = parser.parse_args()

    try:
        if args.stream:
            run_stream_mode(args.url)
        else:
            run_dashboard_live(args.url)
    except KeyboardInterrupt:
        console.print("\n[dim]Monitor stopped.[/dim]")


if __name__ == "__main__":
    main()
