"""
Groups DNS records by registered base domain and scores each domain family.
"""

from collections import defaultdict
from .engine import DomainCandidate, DEFAULT_WEIGHTS, score_domain
from .parser import load_dns_records
from .domains import extract_base_domain, is_excluded


# Internal/infrastructure domains to skip
EXCLUDE_TLDS = {"arpa", "local", "localhost", "internal", "corp", "lan"}

# Well-known high-volume legitimate domains to suppress from results by default
# (analysts can override with --include-common)
COMMON_DOMAINS = {
    "google.com", "googleapis.com", "gstatic.com", "googlevideo.com",
    "youtube.com", "ytimg.com", "doubleclick.net",
    "microsoft.com", "windows.com", "windowsupdate.com", "live.com",
    "office.com", "office365.com", "microsoftonline.com", "azure.com",
    "akamai.net", "akamaiedge.net", "akamaitechnologies.com",
    "cloudfront.net", "amazonaws.com", "awsstatic.com",
    "fastly.net", "fastlylb.net",
    "apple.com", "icloud.com", "mzstatic.com",
    "facebook.com", "fbcdn.net", "instagram.com",
    "twitter.com", "x.com", "twimg.com",
    "cloudflare.com", "cloudflare-dns.com",
    "digicert.com", "letsencrypt.org", "ocsp.sectigo.com",
}


def _is_excluded_tld(domain: str) -> bool:
    parts = domain.split(".")
    return parts[-1] in EXCLUDE_TLDS if parts else False


def correlate_and_score(
    dns_path: str,
    weights: dict = None,
    min_queries: int = 3,
    exclude_common: bool = True,
    top_n: int = 20,
) -> list[DomainCandidate]:
    """
    Load dns.log, group records by base domain, score each domain family.
    Returns list sorted by total_score descending.
    """
    if weights is None:
        weights = DEFAULT_WEIGHTS

    records = load_dns_records(dns_path) if dns_path else []

    # Group by base domain
    by_domain: dict[str, list] = defaultdict(list)
    for r in records:
        query = r.get("query", "")
        if not query:
            continue
        base = extract_base_domain(query)
        if not base or is_excluded(base):
            continue
        if _is_excluded_tld(base):
            continue
        if exclude_common and base in COMMON_DOMAINS:
            continue
        by_domain[base].append(r)

    candidates = []
    for domain, domain_records in by_domain.items():
        if len(domain_records) < min_queries:
            continue
        candidate = score_domain(
            domain=domain,
            records=domain_records,
            weights=weights,
        )
        candidates.append(candidate)

    candidates.sort(key=lambda c: c.total_score, reverse=True)
    return candidates[:top_n]
