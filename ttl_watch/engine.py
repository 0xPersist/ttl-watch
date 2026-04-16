"""
ttl-watch: Multi-signal DNS anomaly detection engine.
Scores domains by TTL manipulation, DGA patterns, fast-flux behavior,
and DNS tunneling indicators from Zeek dns.log.
"""

import math
import statistics
from collections import defaultdict
from dataclasses import dataclass, field
from datetime import datetime
from typing import Optional


# ATT&CK technique mappings per signal
ATTACK_MAP = {
    "ttl_low_mean":             {"id": "T1071.004", "name": "DNS"},
    "ttl_variance_low":         {"id": "T1568",     "name": "Dynamic Resolution"},
    "subdomain_entropy":        {"id": "T1568.002", "name": "Domain Generation Algorithms"},
    "query_length_anomaly":     {"id": "T1071.004", "name": "DNS"},
    "nxdomain_ratio":           {"id": "T1568.002", "name": "Domain Generation Algorithms"},
    "resolver_inconsistency":   {"id": "T1568.001", "name": "Fast Flux DNS"},
    "ttl_sudden_drop":          {"id": "T1568",     "name": "Dynamic Resolution"},
    "query_frequency":          {"id": "T1071.004", "name": "DNS"},
}

DEFAULT_WEIGHTS = {
    "ttl_low_mean":           0.15,
    "ttl_variance_low":       0.15,
    "subdomain_entropy":      0.20,
    "query_length_anomaly":   0.15,
    "nxdomain_ratio":         0.12,
    "resolver_inconsistency": 0.10,
    "ttl_sudden_drop":        0.08,
    "query_frequency":        0.05,
}


@dataclass
class SignalResult:
    name: str
    score: float
    weight: float
    weighted: float
    evidence: str
    attack: Optional[dict] = None
    fired: bool = False


@dataclass
class DomainCandidate:
    domain: str
    total_score: float
    confidence: str
    signals: list[SignalResult] = field(default_factory=list)
    query_count: int = 0
    unique_subdomains: int = 0
    top_subdomains: list[str] = field(default_factory=list)
    unique_answers: list[str] = field(default_factory=list)
    nxdomain_count: int = 0
    first_seen: str = ""
    last_seen: str = ""
    attack_techniques: list[dict] = field(default_factory=list)
    all_ttls: list[float] = field(default_factory=list)


def _entropy(s: str) -> float:
    if not s:
        return 0.0
    freq = defaultdict(int)
    for c in s:
        freq[c] += 1
    n = len(s)
    return -sum((v / n) * math.log2(v / n) for v in freq.values())


def _coefficient_of_variation(values: list[float]) -> float:
    if len(values) < 2:
        return 0.0
    mean = statistics.mean(values)
    if mean == 0:
        return 0.0
    return statistics.stdev(values) / mean


def _confidence_label(score: float) -> str:
    if score >= 0.80:
        return "CRITICAL"
    if score >= 0.60:
        return "HIGH"
    if score >= 0.40:
        return "MEDIUM"
    if score >= 0.20:
        return "LOW"
    return "INFORMATIONAL"


# ── Signal functions ──────────────────────────────────────────────────────────

def _ttl_low_mean_score(ttls: list[float]) -> tuple[float, str]:
    """
    Low mean TTL = short-lived attacker-controlled infrastructure.
    Normal CDN TTLs: 30-300s. Attacker C2: often < 60s.
    """
    if not ttls:
        return 0.0, "no TTL data"
    mean_ttl = statistics.mean(ttls)
    # Score peaks at TTL=0, approaches 0 at TTL >= 300s
    score = max(0.0, 1.0 - (mean_ttl / 300.0))
    return round(score, 3), f"mean_ttl={mean_ttl:.1f}s over {len(ttls)} records"


def _ttl_variance_low_score(ttls: list[float]) -> tuple[float, str]:
    """
    Low TTL variance = uniform manipulation, fast-flux staging or scripted rotation.
    Legitimate domains have natural TTL variance as records age.
    """
    if len(ttls) < 3:
        return 0.0, "insufficient TTL samples"
    cov = _coefficient_of_variation(ttls)
    # Very low CoV combined with low mean = suspicious uniformity
    score = max(0.0, 1.0 - (cov / 0.5))
    mean_ttl = statistics.mean(ttls)
    return round(score, 3), f"TTL CoV={cov:.3f}, mean={mean_ttl:.1f}s over {len(ttls)} samples"


def _subdomain_entropy_score(subdomains: list[str]) -> tuple[float, str]:
    """
    High Shannon entropy on subdomain labels = DGA or DNS tunneling payload.
    """
    if not subdomains:
        return 0.0, "no subdomains observed"
    entropies = [_entropy(s) for s in subdomains if s]
    if not entropies:
        return 0.0, "no subdomain entropy data"
    mean_entropy = statistics.mean(entropies)
    max_entropy = max(entropies)
    # Threshold: entropy > 3.5 is suspicious on subdomain labels
    score = min(1.0, mean_entropy / 4.5)
    return (
        round(score, 3),
        f"mean_entropy={mean_entropy:.3f}, max={max_entropy:.3f} over {len(subdomains)} subdomains"
    )


def _query_length_anomaly_score(query_lengths: list[int]) -> tuple[float, str]:
    """
    Abnormal query length distribution = DNS tunneling data encoding.
    Tunneling tools encode data in query labels, producing long, uniform-length queries.
    Normal queries: short, variable. Tunnel queries: long, uniform.
    """
    if len(query_lengths) < 3:
        return 0.0, "insufficient query samples"
    mean_len = statistics.mean(query_lengths)
    cov = _coefficient_of_variation(query_lengths)
    # Long queries (mean > 40 chars) with low variance = encoded payload
    length_score = min(1.0, mean_len / 80.0)
    uniformity_score = max(0.0, 1.0 - (cov / 0.5))
    score = (length_score * 0.6) + (uniformity_score * 0.4)
    return (
        round(score, 3),
        f"mean_query_len={mean_len:.1f}, CoV={cov:.3f} over {len(query_lengths)} queries"
    )


def _nxdomain_ratio_score(nxdomain_count: int, total_count: int) -> tuple[float, str]:
    """
    High NXDOMAIN ratio = DGA miss pattern — algorithm generating domains
    faster than they are registered/activated.
    """
    if total_count == 0:
        return 0.0, "no queries"
    ratio = nxdomain_count / total_count
    # > 30% NXDOMAIN is suspicious; > 70% is very suspicious
    score = min(1.0, ratio / 0.7)
    return (
        round(score, 3),
        f"{nxdomain_count}/{total_count} queries returned NXDOMAIN ({ratio*100:.1f}%)"
    )


def _resolver_inconsistency_score(answer_sets: list[frozenset]) -> tuple[float, str]:
    """
    Multiple different answer sets for the same domain across queries = fast-flux.
    Legitimate domains return consistent A records. Fast-flux rotates IPs rapidly.
    """
    if len(answer_sets) < 2:
        return 0.0, "insufficient answer samples"
    unique_sets = len(set(answer_sets))
    total = len(answer_sets)
    churn_ratio = unique_sets / total
    # > 50% unique answer sets = high churn
    score = min(1.0, churn_ratio / 0.5)
    return (
        round(score, 3),
        f"{unique_sets} unique answer sets across {total} queries (churn={churn_ratio*100:.1f}%)"
    )


def _ttl_sudden_drop_score(ttl_series: list[tuple[float, float]]) -> tuple[float, str]:
    """
    Sudden TTL drop mid-window = infrastructure pivot or C2 rotation.
    Takes list of (timestamp, ttl) pairs sorted by time.
    Detects step-change drops of > 50% within the observation window.
    """
    if len(ttl_series) < 4:
        return 0.0, "insufficient time-series data"
    ttl_series_sorted = sorted(ttl_series, key=lambda x: x[0])
    ttls = [t[1] for t in ttl_series_sorted]
    # Split into halves and compare means
    mid = len(ttls) // 2
    first_half_mean = statistics.mean(ttls[:mid])
    second_half_mean = statistics.mean(ttls[mid:])
    if first_half_mean == 0:
        return 0.0, "zero TTL in first window"
    drop_ratio = (first_half_mean - second_half_mean) / first_half_mean
    # > 50% drop = significant pivot
    score = max(0.0, min(1.0, drop_ratio / 0.5)) if drop_ratio > 0 else 0.0
    return (
        round(score, 3),
        f"TTL dropped from mean={first_half_mean:.1f}s to {second_half_mean:.1f}s "
        f"(drop={drop_ratio*100:.1f}%)"
    )


def _query_frequency_score(query_count: int, duration_hours: float) -> tuple[float, str]:
    """
    High query rate to a single domain = automated DNS beaconing.
    """
    if duration_hours <= 0:
        return 0.0, "no duration"
    rate = query_count / duration_hours
    # > 120 queries/hr to single domain is suspicious
    score = min(1.0, rate / 120.0)
    return (
        round(score, 3),
        f"{query_count} queries over {duration_hours:.1f}h = {rate:.1f} queries/hr"
    )


# ── Core scorer ───────────────────────────────────────────────────────────────

def score_domain(
    domain: str,
    records: list[dict],
    weights: dict,
) -> DomainCandidate:
    """
    Score a base domain using all DNS records attributed to it.
    records: list of normalized dns.log rows for this domain family.
    """
    signals = []

    # -- Build data structures from records
    all_ttls = []
    subdomains = []
    query_lengths = []
    nxdomain_count = 0
    answer_sets = []
    all_answers_flat = []
    ttl_series = []  # (timestamp, ttl) pairs
    timestamps = []

    for r in records:
        ts = r.get("ts", 0)
        if ts and ts > 0:
            timestamps.append(ts)

        query = r.get("query", "") or ""
        rcode = r.get("rcode", "") or ""
        ttls = r.get("TTLs", []) or []
        answers = r.get("answers", []) or []

        # Query length (full FQDN)
        if query:
            query_lengths.append(len(query))

        # Extract subdomain label (everything before base domain)
        parts = query.rstrip(".").split(".")
        if len(parts) > 2:
            sub = parts[0]
            if sub:
                subdomains.append(sub)

        # TTL collection
        for t in ttls:
            try:
                val = float(t)
                if val >= 0:
                    all_ttls.append(val)
                    if ts and ts > 0:
                        ttl_series.append((ts, val))
            except (TypeError, ValueError):
                continue

        # NXDOMAIN tracking
        if "NXDOMAIN" in rcode.upper():
            nxdomain_count += 1

        # Answer set for resolver inconsistency
        if isinstance(answers, list) and answers:
            ans_set = frozenset(str(a) for a in answers if a)
            if ans_set:
                answer_sets.append(ans_set)
                all_answers_flat.extend(str(a) for a in answers if a)

    duration_hours = (
        (max(timestamps) - min(timestamps)) / 3600.0
        if len(timestamps) > 1 else 0.0
    )
    first_seen = str(int(min(timestamps))) if timestamps else ""
    last_seen = str(int(max(timestamps))) if timestamps else ""
    total_queries = len(records)

    # -- Score each signal

    sc, ev = _ttl_low_mean_score(all_ttls)
    signals.append(SignalResult(
        name="ttl_low_mean", score=sc,
        weight=weights.get("ttl_low_mean", 0),
        weighted=round(sc * weights.get("ttl_low_mean", 0), 4),
        evidence=ev, attack=ATTACK_MAP.get("ttl_low_mean"),
        fired=sc > 0.3
    ))

    sc, ev = _ttl_variance_low_score(all_ttls)
    signals.append(SignalResult(
        name="ttl_variance_low", score=sc,
        weight=weights.get("ttl_variance_low", 0),
        weighted=round(sc * weights.get("ttl_variance_low", 0), 4),
        evidence=ev, attack=ATTACK_MAP.get("ttl_variance_low"),
        fired=sc > 0.3
    ))

    sc, ev = _subdomain_entropy_score(subdomains)
    signals.append(SignalResult(
        name="subdomain_entropy", score=sc,
        weight=weights.get("subdomain_entropy", 0),
        weighted=round(sc * weights.get("subdomain_entropy", 0), 4),
        evidence=ev, attack=ATTACK_MAP.get("subdomain_entropy"),
        fired=sc > 0.4
    ))

    sc, ev = _query_length_anomaly_score(query_lengths)
    signals.append(SignalResult(
        name="query_length_anomaly", score=sc,
        weight=weights.get("query_length_anomaly", 0),
        weighted=round(sc * weights.get("query_length_anomaly", 0), 4),
        evidence=ev, attack=ATTACK_MAP.get("query_length_anomaly"),
        fired=sc > 0.3
    ))

    sc, ev = _nxdomain_ratio_score(nxdomain_count, total_queries)
    signals.append(SignalResult(
        name="nxdomain_ratio", score=sc,
        weight=weights.get("nxdomain_ratio", 0),
        weighted=round(sc * weights.get("nxdomain_ratio", 0), 4),
        evidence=ev, attack=ATTACK_MAP.get("nxdomain_ratio"),
        fired=sc > 0.3
    ))

    sc, ev = _resolver_inconsistency_score(answer_sets)
    signals.append(SignalResult(
        name="resolver_inconsistency", score=sc,
        weight=weights.get("resolver_inconsistency", 0),
        weighted=round(sc * weights.get("resolver_inconsistency", 0), 4),
        evidence=ev, attack=ATTACK_MAP.get("resolver_inconsistency"),
        fired=sc > 0.4
    ))

    sc, ev = _ttl_sudden_drop_score(ttl_series)
    signals.append(SignalResult(
        name="ttl_sudden_drop", score=sc,
        weight=weights.get("ttl_sudden_drop", 0),
        weighted=round(sc * weights.get("ttl_sudden_drop", 0), 4),
        evidence=ev, attack=ATTACK_MAP.get("ttl_sudden_drop"),
        fired=sc > 0.4
    ))

    sc, ev = _query_frequency_score(total_queries, duration_hours)
    signals.append(SignalResult(
        name="query_frequency", score=sc,
        weight=weights.get("query_frequency", 0),
        weighted=round(sc * weights.get("query_frequency", 0), 4),
        evidence=ev, attack=ATTACK_MAP.get("query_frequency"),
        fired=sc > 0.3
    ))

    total_score = round(sum(s.weighted for s in signals), 4)
    confidence = _confidence_label(total_score)

    attack_techniques = list({
        (s.attack["id"], s.attack["name"])
        for s in signals if s.fired and s.attack
    })
    attack_techniques = [{"id": t[0], "name": t[1]} for t in attack_techniques]

    # Top subdomains by frequency for evidence
    sub_freq: dict[str, int] = defaultdict(int)
    for r in records:
        q = r.get("query", "") or ""
        parts = q.rstrip(".").split(".")
        if len(parts) > 2:
            sub_freq[parts[0]] += 1
    top_subdomains = sorted(sub_freq, key=lambda x: sub_freq[x], reverse=True)[:10]

    unique_answers = sorted(set(all_answers_flat))[:20]

    return DomainCandidate(
        domain=domain,
        total_score=total_score,
        confidence=confidence,
        signals=signals,
        query_count=total_queries,
        unique_subdomains=len(set(subdomains)),
        top_subdomains=top_subdomains,
        unique_answers=unique_answers,
        nxdomain_count=nxdomain_count,
        first_seen=first_seen,
        last_seen=last_seen,
        attack_techniques=attack_techniques,
        all_ttls=all_ttls[:30],
    )
