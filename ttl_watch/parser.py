"""
Zeek dns.log parser for ttl-watch.
Handles both TSV (#fields/#types) and JSON-per-line formats.
Auto-detects format. Supports gzipped logs.
"""

import gzip
import json
import os
from pathlib import Path
from typing import Iterator


def _open_log(path: str):
    p = Path(path)
    if p.suffix == ".gz":
        return gzip.open(path, "rt", encoding="utf-8", errors="replace")
    return open(path, "r", encoding="utf-8", errors="replace")


def _is_json_log(path: str) -> bool:
    with _open_log(path) as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            return line.startswith("{")
    return False


def _parse_tsv_log(path: str) -> Iterator[dict]:
    fields = []
    types = []
    with _open_log(path) as f:
        for line in f:
            line = line.rstrip("\r\n")
            if line.startswith("#fields"):
                fields = line.split("\t")[1:]
            elif line.startswith("#types"):
                types = line.split("\t")[1:]
            elif line.startswith("#"):
                continue
            elif fields:
                parts = line.split("\t")
                row = {}
                for i, field in enumerate(fields):
                    val = parts[i] if i < len(parts) else "-"
                    if val == "-" or val == "(empty)":
                        row[field] = None
                    else:
                        t = types[i] if i < len(types) else "string"
                        try:
                            if t in ("double", "interval", "time"):
                                row[field] = float(val)
                            elif t in ("count", "int", "port"):
                                row[field] = int(val)
                            elif t == "bool":
                                row[field] = val == "T"
                            else:
                                row[field] = val
                        except (TypeError, ValueError):
                            row[field] = val
                yield row


def _parse_json_log(path: str) -> Iterator[dict]:
    with _open_log(path) as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            try:
                yield json.loads(line)
            except json.JSONDecodeError:
                continue


def parse_dns_log(path: str) -> Iterator[dict]:
    if not os.path.exists(path):
        return
    if _is_json_log(path):
        yield from _parse_json_log(path)
    else:
        yield from _parse_tsv_log(path)


def load_dns_records(path: str) -> list[dict]:
    """
    Load and normalize all dns.log records.
    Returns list of normalized dicts.
    """
    records = []
    for row in parse_dns_log(path):
        query = row.get("query", "") or ""
        rcode = row.get("rcode_name", row.get("rcode", "")) or ""
        answers = row.get("answers", []) or []
        ttls = row.get("TTLs", []) or []

        # Normalize answers: TSV delivers comma-separated string
        if isinstance(answers, str):
            answers = [a.strip() for a in answers.split(",") if a.strip()] if answers else []

        # Normalize TTLs: TSV delivers comma-separated string
        if isinstance(ttls, str):
            parsed = []
            for t in ttls.split(","):
                t = t.strip()
                if t:
                    try:
                        parsed.append(float(t))
                    except ValueError:
                        pass
            ttls = parsed

        ts = row.get("ts", 0)
        try:
            ts = float(ts) if ts else 0.0
        except (TypeError, ValueError):
            ts = 0.0

        records.append({
            "ts":       ts,
            "uid":      row.get("uid", "") or "",
            "orig_h":   row.get("id.orig_h", "") or "",
            "resp_h":   row.get("id.resp_h", "") or "",
            "query":    query.rstrip(".").lower(),
            "qtype":    row.get("qtype_name", row.get("qtype", "")) or "",
            "answers":  answers,
            "TTLs":     ttls,
            "rcode":    rcode,
        })
    return records
