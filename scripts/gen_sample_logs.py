#!/usr/bin/env python3
"""
Generate synthetic Zeek dns.log samples for testing ttl-watch.
Produces a dns.log with:
  - DGA domain family (high entropy subdomains, NXDOMAIN hits)
  - Fast-flux domain (rotating answers, low TTL, low variance)
  - DNS tunneling domain (long uniform query lengths)
  - TTL pivot domain (sudden TTL drop mid-window)
  - Normal browsing traffic (noise)
"""

import json
import random
import time
import os

random.seed(42)
BASE_TS = time.time() - 3600 * 6


def uid():
    return "D" + "".join(random.choices("abcdefghijklmnopqrstuvwxyz0123456789", k=17))


def write_json_log(path: str, records: list):
    os.makedirs(os.path.dirname(path) if os.path.dirname(path) else ".", exist_ok=True)
    with open(path, "w") as f:
        for r in records:
            f.write(json.dumps(r) + "\n")
    print(f"  wrote {len(records):>5} records → {path}")


# ── Traffic profiles ──────────────────────────────────────────────────────────

def gen_dga_traffic(base_domain: str, count: int = 80):
    """High-entropy subdomains, ~40% NXDOMAIN rate."""
    records = []
    ts = BASE_TS
    alpha = "abcdefghijklmnopqrstuvwxyz0123456789"
    for i in range(count):
        ts += random.uniform(3, 45)
        sub_len = random.randint(12, 24)
        subdomain = "".join(random.choices(alpha, k=sub_len))
        fqdn = f"{subdomain}.{base_domain}"
        nxdomain = random.random() < 0.40
        records.append({
            "ts": round(ts, 6),
            "uid": uid(),
            "id.orig_h": "10.0.0.50",
            "id.resp_h": "8.8.8.8",
            "query": fqdn,
            "qtype_name": "A",
            "answers": [] if nxdomain else [f"45.{random.randint(1,254)}.{random.randint(1,254)}.{random.randint(1,254)}"],
            "TTLs": [] if nxdomain else [random.uniform(28, 32)],
            "rcode_name": "NXDOMAIN" if nxdomain else "NOERROR",
        })
    return records


def gen_fast_flux(base_domain: str, count: int = 60):
    """Rotating A record answers, very low uniform TTL (30s), low variance."""
    records = []
    ts = BASE_TS
    ip_pool = [f"185.{random.randint(1,254)}.{random.randint(1,254)}.{random.randint(1,254)}" for _ in range(20)]
    for i in range(count):
        ts += random.uniform(10, 120)
        # Rotate through different IPs per query
        answer_ips = random.sample(ip_pool, k=random.randint(2, 4))
        records.append({
            "ts": round(ts, 6),
            "uid": uid(),
            "id.orig_h": "10.0.0.51",
            "id.resp_h": "8.8.8.8",
            "query": f"cdn.{base_domain}",
            "qtype_name": "A",
            "answers": answer_ips,
            "TTLs": [30.0] * len(answer_ips),
            "rcode_name": "NOERROR",
        })
    return records


def gen_dns_tunnel(base_domain: str, count: int = 50):
    """Long, uniform query lengths encoding data payloads."""
    records = []
    ts = BASE_TS
    alpha = "abcdefghijklmnopqrstuvwxyz0123456789"
    for i in range(count):
        ts += random.uniform(1, 15)
        # Encoded payload in subdomain - long, near-uniform length
        payload_len = random.randint(48, 56)
        payload = "".join(random.choices(alpha, k=payload_len))
        fqdn = f"{payload}.{base_domain}"
        records.append({
            "ts": round(ts, 6),
            "uid": uid(),
            "id.orig_h": "10.0.0.52",
            "id.resp_h": "8.8.8.8",
            "query": fqdn,
            "qtype_name": "TXT",
            "answers": [f"data={random.randint(1000,9999)}"],
            "TTLs": [60.0],
            "rcode_name": "NOERROR",
        })
    return records


def gen_ttl_pivot(base_domain: str, count: int = 60):
    """TTL starts high (3600s), drops sharply halfway through window."""
    records = []
    ts = BASE_TS
    for i in range(count):
        ts += random.uniform(60, 180)
        # First half: normal TTL; second half: sudden drop to 30s
        ttl = 3600.0 if i < count // 2 else random.uniform(28, 35)
        records.append({
            "ts": round(ts, 6),
            "uid": uid(),
            "id.orig_h": "10.0.0.53",
            "id.resp_h": "8.8.8.8",
            "query": f"api.{base_domain}",
            "qtype_name": "A",
            "answers": [f"194.{random.randint(1,254)}.{random.randint(1,254)}.{random.randint(1,254)}"],
            "TTLs": [ttl],
            "rcode_name": "NOERROR",
        })
    return records


def gen_normal_traffic(count: int = 300):
    """Normal browsing — varied domains, normal TTLs, low query rates."""
    records = []
    ts = BASE_TS
    normal_domains = [
        "docs.python.org", "stackoverflow.com", "github.com",
        "npmjs.com", "pypi.org", "developer.mozilla.org",
        "api.example.com", "cdn.example.net", "static.example.org",
    ]
    for _ in range(count):
        ts += random.uniform(2, 240)
        domain = random.choice(normal_domains)
        records.append({
            "ts": round(ts, 6),
            "uid": uid(),
            "id.orig_h": "10.0.0.100",
            "id.resp_h": "1.1.1.1",
            "query": domain,
            "qtype_name": "A",
            "answers": [f"104.{random.randint(1,254)}.{random.randint(1,254)}.{random.randint(1,254)}"],
            "TTLs": [random.uniform(60, 3600)],
            "rcode_name": "NOERROR",
        })
    return records


# ── Assemble and write ────────────────────────────────────────────────────────

def generate(output_dir: str = "sample_logs"):
    print(f"\nGenerating synthetic Zeek dns.log → {output_dir}/\n")

    all_records = []

    c = gen_dga_traffic("dyndns-beacon.net", count=80)
    all_records += c
    print("  [DGA]       dyndns-beacon.net       high-entropy subdomains, ~40% NXDOMAIN, 80 queries")

    c = gen_fast_flux("fastflux-cdn.com", count=60)
    all_records += c
    print("  [FAST-FLUX] fastflux-cdn.com         rotating IPs, 30s TTL, 60 queries")

    c = gen_dns_tunnel("tunnel-exfil.io", count=50)
    all_records += c
    print("  [TUNNEL]    tunnel-exfil.io           long uniform queries (TXT), 50 queries")

    c = gen_ttl_pivot("pivot-c2.org", count=60)
    all_records += c
    print("  [TTL PIVOT] pivot-c2.org              TTL drops from 3600s to 30s mid-window, 60 queries")

    c = gen_normal_traffic(count=300)
    all_records += c
    print("  [NOISE]     various                   normal browsing traffic, 300 queries\n")

    random.shuffle(all_records)

    os.makedirs(output_dir, exist_ok=True)
    write_json_log(f"{output_dir}/dns.log", all_records)

    print(f"\nRun: ttl-watch --dns {output_dir}/dns.log --detail\n")


if __name__ == "__main__":
    import sys
    out = sys.argv[1] if len(sys.argv) > 1 else "sample_logs"
    generate(out)
