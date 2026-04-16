#!/usr/bin/env python3
"""
ttl-watch: Multi-signal DNS anomaly detector.

Usage:
  ttl-watch --dns dns.log
  ttl-watch --pcap capture.pcap
  ttl-watch --dns dns.log --out report.json --detail
  ttl-watch --dns dns.log --config weights.yaml --top 10
  ttl-watch --generate-config weights.yaml
"""

import argparse
import os
import sys


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="ttl-watch",
        description=(
            "Multi-signal DNS anomaly detector. Scores domain families from Zeek dns.log "
            "for TTL manipulation, DGA patterns, fast-flux, and DNS tunneling indicators."
        ),
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
examples:
  ttl-watch --dns dns.log
  ttl-watch --pcap capture.pcap --out report.json --detail
  ttl-watch --dns dns.log --config weights.yaml --top 10 --min-queries 5
  ttl-watch --generate-config my_weights.yaml
        """
    )

    # Input
    input_group = parser.add_argument_group("input (choose one)")
    mx = input_group.add_mutually_exclusive_group()
    mx.add_argument(
        "--dns", metavar="FILE",
        help="Zeek dns.log path (TSV or JSON, optionally gzipped)."
    )
    mx.add_argument(
        "--pcap", metavar="FILE",
        help="Raw PCAP file. Zeek is invoked automatically to generate dns.log."
    )

    # Output
    output_group = parser.add_argument_group("output")
    output_group.add_argument(
        "--out", "-o", metavar="FILE", default=None,
        help="Write JSON report to this file."
    )
    output_group.add_argument(
        "--json-only", action="store_true",
        help="Suppress terminal table, print raw JSON to stdout."
    )
    output_group.add_argument(
        "--detail", "-d", action="store_true",
        help="Show per-signal breakdown for each candidate."
    )
    output_group.add_argument(
        "--top", "-n", metavar="N", type=int, default=20,
        help="Number of top candidates to show (default: 20)."
    )

    # Scoring
    score_group = parser.add_argument_group("scoring")
    score_group.add_argument(
        "--config", metavar="FILE", default=None,
        help="YAML or TOML file with custom signal weights."
    )
    score_group.add_argument(
        "--min-queries", metavar="N", type=int, default=3,
        help="Minimum query count per domain to score (default: 3)."
    )
    score_group.add_argument(
        "--include-common", action="store_true",
        help="Include common high-volume domains like google.com, microsoft.com."
    )
    score_group.add_argument(
        "--threshold", metavar="FLOAT", type=float, default=0.0,
        help="Only output candidates with total_score >= threshold."
    )

    # Utility
    util_group = parser.add_argument_group("utility")
    util_group.add_argument(
        "--generate-config", metavar="FILE", default=None,
        help="Write a default weights config file and exit."
    )
    util_group.add_argument(
        "--version", action="version", version="ttl-watch 1.0.0"
    )

    return parser


def main():
    parser = build_parser()
    args = parser.parse_args()

    # -- Generate config and exit
    if args.generate_config:
        from ttl_watch.config import generate_default_config
        fmt = "toml" if args.generate_config.endswith(".toml") else "yaml"
        generate_default_config(args.generate_config, fmt=fmt)
        print(f"Default config written to: {args.generate_config}")
        sys.exit(0)

    # -- Validate input
    if not args.dns and not args.pcap:
        parser.error("Provide either --dns or --pcap.")

    # -- Load weights
    from ttl_watch.config import load_weights
    try:
        weights = load_weights(args.config)
    except (FileNotFoundError, ValueError, ImportError) as e:
        print(f"[ERROR] Config: {e}", file=sys.stderr)
        sys.exit(1)

    # -- Resolve dns.log path
    tmpdir = None
    dns_path = args.dns or ""

    if args.pcap:
        from ttl_watch.pcap import generate_dns_log_from_pcap, cleanup_tmpdir, zeek_available
        if not zeek_available():
            print("[ERROR] Zeek not found. Install Zeek or use --dns directly.", file=sys.stderr)
            sys.exit(1)
        try:
            result = generate_dns_log_from_pcap(args.pcap)
            tmpdir = result["tmpdir"]
            dns_path = result["dns"]
        except Exception as e:
            print(f"[ERROR] PCAP processing failed: {e}", file=sys.stderr)
            sys.exit(1)

    if not os.path.exists(dns_path):
        print(f"[ERROR] dns.log not found: {dns_path}", file=sys.stderr)
        sys.exit(1)

    # -- Correlate and score
    from ttl_watch.correlator import correlate_and_score
    try:
        candidates = correlate_and_score(
            dns_path=dns_path,
            weights=weights,
            min_queries=args.min_queries,
            exclude_common=not args.include_common,
            top_n=args.top,
        )
    except Exception as e:
        print(f"[ERROR] Scoring failed: {e}", file=sys.stderr)
        if tmpdir:
            from ttl_watch.pcap import cleanup_tmpdir
            cleanup_tmpdir(tmpdir)
        sys.exit(1)

    # -- Apply threshold
    if args.threshold > 0.0:
        candidates = [c for c in candidates if c.total_score >= args.threshold]

    # -- Render
    from ttl_watch.renderer import render_summary_table, render_candidate_detail, render_json_output

    json_str = render_json_output(candidates)

    if args.json_only:
        print(json_str)
    else:
        try:
            from rich.console import Console
            console = Console()
        except ImportError:
            console = None

        render_summary_table(candidates, console=console)

        if args.detail:
            for c in candidates:
                render_candidate_detail(c, console=console)

        if not candidates:
            msg = (
                "No candidates found above threshold. "
                f"Try --min-queries {max(1, args.min_queries - 1)} or --include-common."
            )
            if console:
                console.print(f"[dim]{msg}[/dim]")
            else:
                print(msg)

    if args.out:
        with open(args.out, "w") as f:
            f.write(json_str)
        msg = f"JSON report written to {args.out}"
        if not args.json_only:
            try:
                from rich.console import Console
                Console().print(f"[dim]{msg}[/dim]")
            except ImportError:
                print(msg)

    if tmpdir:
        from ttl_watch.pcap import cleanup_tmpdir
        cleanup_tmpdir(tmpdir)


if __name__ == "__main__":
    main()
