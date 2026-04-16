"""
Terminal and JSON renderer for ttl-watch results.
Rich terminal output with fallback to plain text when Rich is unavailable.
"""

import json
from datetime import datetime
from .engine import DomainCandidate


CONFIDENCE_COLORS = {
    "CRITICAL":      "bold red",
    "HIGH":          "red",
    "MEDIUM":        "yellow",
    "LOW":           "cyan",
    "INFORMATIONAL": "dim white",
}

SIGNAL_BAR_WIDTH = 20


def _score_bar(score: float, width: int = SIGNAL_BAR_WIDTH) -> str:
    filled = int(score * width)
    return "█" * filled + "░" * (width - filled)


def _ts_to_human(ts_str: str) -> str:
    try:
        ts = float(ts_str)
        if ts <= 0:
            return "unknown"
        return datetime.utcfromtimestamp(ts).strftime("%Y-%m-%d %H:%M:%S")
    except Exception:
        return ts_str or "unknown"


BANNER = r"""
  _____  _____  _                        _          _
 |_   _||_   _|| |      __      __  __ _| |_   ___ | |__
   | |    | |  | |______\ \ /\ / / / _` | __| / __|| '_ \
   | |    | |  | |_______\ V  V / | (_| | |_ | (__ | | | |
   |_|    |_|  |_|        \_/\_/   \__,_|\__| \___||_| |_|

  Multi-signal DNS anomaly detector  •  NorthQuinn Inc.
"""


def render_summary_table(candidates: list[DomainCandidate], console=None):
    try:
        from rich.console import Console
        from rich.table import Table
        from rich import box
        from rich.text import Text
    except ImportError:
        _fallback_summary(candidates)
        return

    if console is None:
        console = Console()

    console.print(f"[bold cyan]{BANNER}[/bold cyan]")

    table = Table(
        title="[bold]ttl-watch[/bold] — DNS Anomaly Candidates",
        box=box.MINIMAL_DOUBLE_HEAD,
        show_lines=False,
        title_style="bold white",
        header_style="bold cyan",
        border_style="dim white",
    )

    table.add_column("#",           style="dim",        width=4,  justify="right")
    table.add_column("Domain",      style="white",      min_width=24)
    table.add_column("Score",       style="white",      width=8,  justify="right")
    table.add_column("Confidence",  style="white",      width=14)
    table.add_column("Queries",     style="dim white",  width=9,  justify="right")
    table.add_column("Subdomains",  style="dim white",  width=11, justify="right")
    table.add_column("NXDOMAINs",  style="dim white",  width=11, justify="right")
    table.add_column("ATT&CK",      style="dim cyan",   min_width=18)
    table.add_column("First Seen",  style="dim",        width=20)

    for i, c in enumerate(candidates, 1):
        color = CONFIDENCE_COLORS.get(c.confidence, "white")
        attack_str = " ".join(t["id"] for t in c.attack_techniques[:3])
        table.add_row(
            str(i),
            c.domain,
            f"[{color}]{c.total_score:.4f}[/{color}]",
            f"[{color}]{c.confidence}[/{color}]",
            str(c.query_count),
            str(c.unique_subdomains),
            str(c.nxdomain_count),
            attack_str,
            _ts_to_human(c.first_seen),
        )

    console.print()
    console.print(table)
    console.print()


def render_candidate_detail(candidate: DomainCandidate, console=None):
    try:
        from rich.console import Console
        from rich.panel import Panel
        from rich.table import Table
        from rich import box
    except ImportError:
        _fallback_detail(candidate)
        return

    if console is None:
        console = Console()

    color = CONFIDENCE_COLORS.get(candidate.confidence, "white")

    header = (
        f"[bold white]{candidate.domain}[/bold white]  "
        f"[{color}]{candidate.confidence}[/{color}]  "
        f"score=[{color}]{candidate.total_score:.4f}[/{color}]  "
        f"queries=[dim]{candidate.query_count}[/dim]  "
        f"subdomains=[dim]{candidate.unique_subdomains}[/dim]  "
        f"nxdomain=[dim]{candidate.nxdomain_count}[/dim]"
    )

    sig_table = Table(box=box.SIMPLE, show_header=True, header_style="bold dim")
    sig_table.add_column("Signal",   style="white",     min_width=22)
    sig_table.add_column("Score",    style="white",     width=8,  justify="right")
    sig_table.add_column("Weight",   style="dim white", width=8,  justify="right")
    sig_table.add_column("Weighted", style="white",     width=10, justify="right")
    sig_table.add_column("Bar",      style="cyan",      width=SIGNAL_BAR_WIDTH + 2)
    sig_table.add_column("ATT&CK",   style="dim cyan",  width=12)
    sig_table.add_column("Evidence", style="dim white", min_width=36)

    for s in sorted(candidate.signals, key=lambda x: x.weighted, reverse=True):
        bar = _score_bar(s.score)
        attack_id = s.attack["id"] if s.attack else ""
        row_style = "bold" if s.fired else "dim"
        sig_table.add_row(
            f"[{row_style}]{s.name}[/{row_style}]",
            f"{s.score:.3f}",
            f"{s.weight:.2f}",
            f"{s.weighted:.4f}",
            bar,
            attack_id,
            s.evidence,
        )

    attack_lines = "\n".join(
        f"  [{color}]{t['id']}[/{color}]  {t['name']}"
        for t in candidate.attack_techniques
    ) or "  none"

    top_subs = ", ".join(candidate.top_subdomains[:8]) or "none"
    unique_ans = ", ".join(candidate.unique_answers[:6]) or "none"
    time_range = f"{_ts_to_human(candidate.first_seen)} → {_ts_to_human(candidate.last_seen)}"

    panel_content = (
        f"{header}\n"
        f"[dim]time_range:[/dim]      {time_range}\n"
        f"[dim]top_subdomains:[/dim]  {top_subs}\n"
        f"[dim]unique_answers:[/dim]  {unique_ans}\n"
        f"\n[dim bold]ATT&CK Techniques:[/dim bold]\n{attack_lines}\n\n"
    )

    console.print(Panel(panel_content, border_style="dim white", expand=False))
    console.print(sig_table)
    console.print()


def render_json_output(candidates: list[DomainCandidate]) -> str:
    out = []
    for c in candidates:
        signals_out = [
            {
                "name":     s.name,
                "score":    s.score,
                "weight":   s.weight,
                "weighted": s.weighted,
                "fired":    s.fired,
                "evidence": s.evidence,
                "attack":   s.attack,
            }
            for s in c.signals
        ]
        out.append({
            "domain":            c.domain,
            "total_score":       c.total_score,
            "confidence":        c.confidence,
            "query_count":       c.query_count,
            "unique_subdomains": c.unique_subdomains,
            "nxdomain_count":    c.nxdomain_count,
            "first_seen":        _ts_to_human(c.first_seen),
            "last_seen":         _ts_to_human(c.last_seen),
            "top_subdomains":    c.top_subdomains,
            "unique_answers":    c.unique_answers,
            "attack_techniques": c.attack_techniques,
            "signals":           signals_out,
            "ttl_sample":        c.all_ttls[:20],
        })
    return json.dumps({"dns_anomaly_candidates": out}, indent=2)


def _fallback_summary(candidates: list[DomainCandidate]):
    print(BANNER)
    print(f"\n{'#':<4} {'Domain':<28} {'Score':<8} {'Confidence':<14} {'Queries':<9} {'NXD':<6} {'ATT&CK'}")
    print("-" * 90)
    for i, c in enumerate(candidates, 1):
        attacks = " ".join(t["id"] for t in c.attack_techniques[:3])
        print(f"{i:<4} {c.domain:<28} {c.total_score:<8.4f} {c.confidence:<14} {c.query_count:<9} {c.nxdomain_count:<6} {attacks}")
    print()


def _fallback_detail(candidate: DomainCandidate):
    print(f"\n--- {candidate.domain} | {candidate.confidence} | score={candidate.total_score:.4f} ---")
    for s in candidate.signals:
        print(f"  {s.name:<25} score={s.score:.3f}  weighted={s.weighted:.4f}  {s.evidence}")
    print()
