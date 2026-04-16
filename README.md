# ttl-watch

**Multi-signal DNS anomaly detector for TTL manipulation, DGA, fast-flux, and DNS tunneling.**

ttl-watch scores domain families from Zeek `dns.log` using eight signals: TTL behavioral modeling, subdomain entropy, query length distribution, NXDOMAIN ratio, resolver inconsistency, and sudden TTL pivot detection. Drop in a PCAP and it handles Zeek invocation automatically.

```
$ ttl-watch --dns dns.log --detail

 #   Domain                  Score    Confidence    Queries  NXD   ATT&CK
 ─────────────────────────────────────────────────────────────────────────────
 1   tunnel-exfil.io         0.7514   HIGH          50       0     T1568.002 T1568.001
 2   dyndns-beacon.net       0.7430   HIGH          80       31    T1568.002 T1568.001
 3   fastflux-cdn.com        0.5604   MEDIUM        60       0     T1568.001 T1568
 4   pivot-c2.org            0.3402   LOW           60       0     T1568 T1071.004
```

---

## Why ttl-watch

DNS is one of the most reliable C2 channels precisely because it is rarely inspected at depth. Most tooling flags individual domains against blocklists. ttl-watch goes further: it builds a behavioral model of how each domain family behaves over the observation window and scores it across multiple independent signals.

All records belonging to the same registered domain are rolled up into a single scored finding. You get one actionable result per domain family — not hundreds of rows per subdomain — with the full evidence chain underneath it.

---

## Signals

| Signal | ATT&CK | Description |
|---|---|---|
| `ttl_low_mean` | T1071.004 | Low mean TTL — short-lived attacker-controlled infrastructure |
| `ttl_variance_low` | T1568 | Low TTL coefficient of variation — uniform manipulation or fast-flux staging |
| `subdomain_entropy` | T1568.002 | High Shannon entropy on subdomain labels — DGA or DNS tunnel payload |
| `query_length_anomaly` | T1071.004 | Long, uniform query lengths — DNS tunneling data encoding |
| `nxdomain_ratio` | T1568.002 | High NXDOMAIN rate — DGA miss pattern |
| `resolver_inconsistency` | T1568.001 | Rotating answer sets per query — fast-flux IP churn |
| `ttl_sudden_drop` | T1568 | TTL drops sharply mid-window — infrastructure pivot or C2 rotation |
| `query_frequency` | T1071.004 | High query rate to single domain — automated DNS beaconing |

Confidence bands:

| Score | Confidence |
|---|---|
| ≥ 0.80 | CRITICAL |
| ≥ 0.60 | HIGH |
| ≥ 0.40 | MEDIUM |
| ≥ 0.20 | LOW |
| < 0.20 | INFORMATIONAL |

---

## Installation

Requires Python 3.10+.

```bash
git clone https://github.com/0xPersist/ttl-watch
cd ttl-watch
pip install .
```

With Rich terminal output (recommended):

```bash
pip install ".[rich]"
```

---

## Usage

### From Zeek dns.log

```bash
ttl-watch --dns dns.log
```

### From PCAP

Zeek must be installed and in PATH.

```bash
ttl-watch --pcap capture.pcap
```

### Output

```bash
# Terminal table + JSON report
ttl-watch --dns dns.log --out report.json

# Per-signal breakdown for each candidate
ttl-watch --dns dns.log --detail

# JSON only — pipe-friendly
ttl-watch --dns dns.log --json-only | jq '.dns_anomaly_candidates[0]'

# Filter by threshold, increase minimum query count
ttl-watch --dns dns.log --threshold 0.40 --min-queries 10

# Include common domains (google.com, microsoft.com, etc.)
ttl-watch --dns dns.log --include-common
```

### Custom weights

```bash
ttl-watch --generate-config weights.yaml
# edit weights
ttl-watch --dns dns.log --config weights.yaml
```

---

## JSON report format

```json
{
  "dns_anomaly_candidates": [
    {
      "domain": "dyndns-beacon.net",
      "total_score": 0.7430,
      "confidence": "HIGH",
      "query_count": 80,
      "unique_subdomains": 80,
      "nxdomain_count": 31,
      "first_seen": "2024-11-14 12:00:00",
      "last_seen": "2024-11-14 17:59:00",
      "top_subdomains": ["xk3j9mf2b1abc", "a8f2k1pmqrstu"],
      "unique_answers": ["45.12.34.56", "45.78.90.12"],
      "attack_techniques": [
        {"id": "T1568.002", "name": "Domain Generation Algorithms"},
        {"id": "T1568.001", "name": "Fast Flux DNS"}
      ],
      "signals": [
        {
          "name": "subdomain_entropy",
          "score": 0.827,
          "weight": 0.20,
          "weighted": 0.1654,
          "fired": true,
          "evidence": "mean_entropy=3.720, max=4.278 over 80 subdomains",
          "attack": {"id": "T1568.002", "name": "Domain Generation Algorithms"}
        }
      ]
    }
  ]
}
```

---

## Domain rollup

All records sharing a registered base domain are scored together. `a.evil.com`, `b.evil.com`, and `xk3j9mf.evil.com` all contribute to one `evil.com` score. Multi-part TLDs are handled correctly: `sub.evil.co.uk` rolls up to `evil.co.uk`.

Common high-volume legitimate domains (Google, Microsoft, Apple, Cloudflare, Akamai, etc.) are excluded from results by default. Use `--include-common` to override.

---

## Testing

Generate synthetic logs and validate:

```bash
python scripts/gen_sample_logs.py
ttl-watch --dns sample_logs/dns.log --detail
```

The generator produces four labeled threat profiles:
- DGA domain family with high-entropy subdomains and ~40% NXDOMAIN rate
- Fast-flux domain with rotating IPs and uniform 30s TTL
- DNS tunneling domain with long, near-uniform TXT query payloads
- TTL pivot domain where TTL drops from 3600s to 30s mid-window

Run tests:

```bash
pip install pytest
pytest tests/ -v
```

---

## Flags

```
input:
  --dns  FILE           Zeek dns.log (TSV or JSON, optionally gzipped)
  --pcap FILE           Raw PCAP. Zeek invoked automatically.

output:
  --out FILE            Write JSON report to file
  --json-only           Suppress terminal output, print JSON to stdout
  --detail              Show per-signal breakdown for each candidate
  --top N               Number of candidates to show (default: 20)

scoring:
  --config FILE         YAML or TOML weights config
  --min-queries N       Minimum query count per domain (default: 3)
  --include-common      Include common high-volume domains
  --threshold FLOAT     Only output candidates >= this score

utility:
  --generate-config FILE  Write default weights config and exit
  --version
```

---

## Related

- [beacon-score](https://github.com/0xPersist/beacon-score) — multi-signal C2 beacon detection from Zeek conn/dns/ssl logs
- [Zeek](https://zeek.org) — network analysis framework
- [ATT&CK Navigator](https://mitre-attack.github.io/attack-navigator/) — technique visualization

---

## License

MIT
