"""
Domain utilities for ttl-watch.
Extracts registered base domain from FQDNs for rollup scoring.
Handles common TLDs and multi-part TLDs (co.uk, com.au, etc.).
"""

# Common multi-part TLDs that need two levels preserved
MULTI_PART_TLDS = {
    "co.uk", "co.nz", "co.za", "co.jp", "co.in", "co.kr",
    "com.au", "com.br", "com.mx", "com.ar", "com.sg", "com.hk",
    "org.uk", "org.au", "net.au", "net.uk",
    "gov.uk", "gov.au", "gov.in",
    "ac.uk", "ac.nz", "ac.za",
    "edu.au",
}

# Domains to always exclude from analysis
EXCLUDE_DOMAINS = {
    "localhost",
    "local",
    "",
    ".",
    "in-addr.arpa",
    "ip6.arpa",
}


def extract_base_domain(fqdn: str) -> str:
    """
    Extract the registered base domain from a FQDN.

    Examples:
        sub.evil.com         -> evil.com
        a.b.c.evil.co.uk     -> evil.co.uk
        evil.com             -> evil.com
        com                  -> (empty — TLD only)
    """
    if not fqdn:
        return ""

    # Strip trailing dot (fully qualified)
    fqdn = fqdn.rstrip(".").lower()

    if fqdn in EXCLUDE_DOMAINS:
        return ""

    parts = fqdn.split(".")
    if len(parts) < 2:
        return ""

    # Check for multi-part TLD (e.g. co.uk, com.au)
    possible_multi = f"{parts[-2]}.{parts[-1]}"
    if possible_multi in MULTI_PART_TLDS:
        # Need at least 3 parts to have a registered domain on top of the multi-part TLD
        # e.g. 'evil.co.uk' = ['evil','co','uk'] -> 'evil.co.uk'
        # but 'co.uk' alone = ['co','uk'] -> empty (TLD only)
        if len(parts) >= 3:
            return f"{parts[-3]}.{possible_multi}"
        return ""

    # Standard: return last two parts
    return f"{parts[-2]}.{parts[-1]}"


def is_excluded(domain: str) -> bool:
    return not domain or domain in EXCLUDE_DOMAINS or "." not in domain


def normalize_query(query: str) -> str:
    return query.rstrip(".").lower() if query else ""
