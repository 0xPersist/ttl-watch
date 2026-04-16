"""
Tests for ttl-watch engine, parser, correlator, domains, config, and renderer.
"""

import json
import os
import tempfile
import pytest

from ttl_watch.engine import (
    _entropy,
    _coefficient_of_variation,
    _ttl_low_mean_score,
    _ttl_variance_low_score,
    _subdomain_entropy_score,
    _query_length_anomaly_score,
    _nxdomain_ratio_score,
    _resolver_inconsistency_score,
    _ttl_sudden_drop_score,
    _query_frequency_score,
    _confidence_label,
    score_domain,
    DEFAULT_WEIGHTS,
)
from ttl_watch.domains import extract_base_domain, is_excluded
from ttl_watch.parser import load_dns_records
from ttl_watch.correlator import correlate_and_score
from ttl_watch.config import load_weights, generate_default_config
from ttl_watch.renderer import render_json_output


# ── Engine unit tests ─────────────────────────────────────────────────────────

class TestEntropy:
    def test_empty(self):
        assert _entropy("") == 0.0

    def test_uniform(self):
        assert _entropy("aaaa") == 0.0

    def test_high_entropy(self):
        assert _entropy("a1b2c3d4e5f6g7") > 3.0

    def test_binary(self):
        assert abs(_entropy("ab") - 1.0) < 0.001


class TestCoV:
    def test_zero_mean(self):
        assert _coefficient_of_variation([0, 0, 0]) == 0.0

    def test_single(self):
        assert _coefficient_of_variation([5.0]) == 0.0

    def test_uniform(self):
        assert _coefficient_of_variation([10, 10, 10]) == 0.0

    def test_varied(self):
        assert _coefficient_of_variation([1, 10, 100]) > 1.0


class TestTtlLowMean:
    def test_very_low_ttl(self):
        score, ev = _ttl_low_mean_score([30.0] * 10)
        assert score > 0.8

    def test_normal_ttl(self):
        score, _ = _ttl_low_mean_score([3600.0] * 10)
        assert score == 0.0

    def test_empty(self):
        score, ev = _ttl_low_mean_score([])
        assert score == 0.0
        assert "no TTL" in ev

    def test_boundary_300(self):
        score, _ = _ttl_low_mean_score([300.0] * 10)
        assert score == 0.0


class TestTtlVarianceLow:
    def test_perfectly_uniform(self):
        score, _ = _ttl_variance_low_score([30.0] * 20)
        assert score > 0.9

    def test_high_variance(self):
        import random
        random.seed(1)
        ttls = [random.uniform(30, 3600) for _ in range(20)]
        score, _ = _ttl_variance_low_score(ttls)
        assert score < 0.7

    def test_insufficient(self):
        score, ev = _ttl_variance_low_score([30.0, 30.0])
        assert score == 0.0
        assert "insufficient" in ev


class TestSubdomainEntropy:
    def test_high_entropy(self):
        import random
        random.seed(2)
        alpha = "abcdefghijklmnopqrstuvwxyz0123456789"
        subs = ["".join(random.choices(alpha, k=18)) for _ in range(30)]
        score, _ = _subdomain_entropy_score(subs)
        assert score > 0.7

    def test_normal_subdomains(self):
        subs = ["www", "mail", "api", "cdn", "static", "dev"]
        score, _ = _subdomain_entropy_score(subs)
        assert score < 0.5

    def test_empty(self):
        score, ev = _subdomain_entropy_score([])
        assert score == 0.0


class TestQueryLengthAnomaly:
    def test_long_uniform(self):
        # Tunnel-like: long, very uniform
        lengths = [52, 53, 51, 54, 52, 53, 51, 52, 53, 51]
        score, _ = _query_length_anomaly_score(lengths)
        assert score > 0.5

    def test_short_varied(self):
        lengths = [8, 15, 22, 6, 30, 12, 9, 18]
        score, _ = _query_length_anomaly_score(lengths)
        assert score < 0.5

    def test_insufficient(self):
        score, ev = _query_length_anomaly_score([50, 51])
        assert score == 0.0


class TestNxdomainRatio:
    def test_high_nxdomain(self):
        score, ev = _nxdomain_ratio_score(70, 100)
        assert score >= 1.0

    def test_low_nxdomain(self):
        score, _ = _nxdomain_ratio_score(2, 100)
        assert score < 0.1

    def test_zero_queries(self):
        score, _ = _nxdomain_ratio_score(0, 0)
        assert score == 0.0

    def test_all_nxdomain(self):
        score, ev = _nxdomain_ratio_score(10, 10)
        assert score >= 1.0
        assert "100.0%" in ev


class TestResolverInconsistency:
    def test_high_churn(self):
        # Every query returns different IPs = fast-flux
        answer_sets = [frozenset([f"1.2.3.{i}"]) for i in range(20)]
        score, ev = _resolver_inconsistency_score(answer_sets)
        assert score >= 1.0

    def test_consistent(self):
        # Same answer every time = legitimate
        answer_sets = [frozenset(["1.2.3.4"])] * 20
        score, _ = _resolver_inconsistency_score(answer_sets)
        assert score == 0.0

    def test_insufficient(self):
        score, _ = _resolver_inconsistency_score([frozenset(["1.2.3.4"])])
        assert score == 0.0


class TestTtlSuddenDrop:
    def test_large_drop(self):
        # First half: 3600s TTL, second half: 30s TTL
        ts = 1700000000.0
        series = []
        for i in range(40):
            ts += 60.0
            ttl = 3600.0 if i < 20 else 30.0
            series.append((ts, ttl))
        score, ev = _ttl_sudden_drop_score(series)
        assert score > 0.8
        assert "dropped" in ev

    def test_no_drop(self):
        ts = 1700000000.0
        series = [(ts + i * 60, 300.0) for i in range(20)]
        score, _ = _ttl_sudden_drop_score(series)
        assert score == 0.0

    def test_insufficient(self):
        score, _ = _ttl_sudden_drop_score([(1700000000.0, 300.0)] * 3)
        assert score == 0.0

    def test_ttl_increase_not_flagged(self):
        # TTL going UP should not score high
        ts = 1700000000.0
        series = []
        for i in range(20):
            ts += 60.0
            ttl = 30.0 if i < 10 else 3600.0
            series.append((ts, ttl))
        score, _ = _ttl_sudden_drop_score(series)
        assert score == 0.0


class TestQueryFrequency:
    def test_high_rate(self):
        score, ev = _query_frequency_score(360, 1.0)
        assert score >= 1.0

    def test_low_rate(self):
        score, _ = _query_frequency_score(5, 6.0)
        assert score < 0.1

    def test_zero_duration(self):
        score, _ = _query_frequency_score(100, 0.0)
        assert score == 0.0


class TestConfidenceLabel:
    def test_all_bands(self):
        assert _confidence_label(0.85) == "CRITICAL"
        assert _confidence_label(0.70) == "HIGH"
        assert _confidence_label(0.50) == "MEDIUM"
        assert _confidence_label(0.30) == "LOW"
        assert _confidence_label(0.10) == "INFORMATIONAL"

    def test_boundaries(self):
        assert _confidence_label(0.80) == "CRITICAL"
        assert _confidence_label(0.60) == "HIGH"
        assert _confidence_label(0.40) == "MEDIUM"
        assert _confidence_label(0.20) == "LOW"


# ── Domain extraction ─────────────────────────────────────────────────────────

class TestExtractBaseDomain:
    def test_simple(self):
        assert extract_base_domain("www.evil.com") == "evil.com"

    def test_deep_subdomain(self):
        assert extract_base_domain("a.b.c.evil.com") == "evil.com"

    def test_no_subdomain(self):
        assert extract_base_domain("evil.com") == "evil.com"

    def test_multi_part_tld(self):
        assert extract_base_domain("sub.evil.co.uk") == "evil.co.uk"

    def test_trailing_dot(self):
        assert extract_base_domain("www.evil.com.") == "evil.com"

    def test_tld_only(self):
        assert extract_base_domain("com") == ""

    def test_empty(self):
        assert extract_base_domain("") == ""

    def test_uppercase_normalized(self):
        assert extract_base_domain("WWW.Evil.COM") == "evil.com"

    def test_com_au(self):
        assert extract_base_domain("sub.evil.com.au") == "evil.com.au"


class TestIsExcluded:
    def test_excluded(self):
        assert is_excluded("")
        assert is_excluded("localhost")

    def test_not_excluded(self):
        assert not is_excluded("evil.com")
        assert not is_excluded("c2.net")


class TestExtractBaseDomainEdgeCases:
    def test_tld_only_multi_part(self):
        """co.uk alone is a TLD, not a registered domain — must return empty."""
        assert extract_base_domain("co.uk") == ""

    def test_com_au_tld_only(self):
        """com.au alone is a TLD — must return empty."""
        assert extract_base_domain("com.au") == ""

    def test_registered_on_multi_part_tld(self):
        """evil.co.uk has a registered domain on top of the multi-part TLD."""
        assert extract_base_domain("evil.co.uk") == "evil.co.uk"

    def test_sub_on_multi_part_tld(self):
        """sub.evil.co.uk should roll up to evil.co.uk."""
        assert extract_base_domain("sub.evil.co.uk") == "evil.co.uk"


# ── Parser tests ──────────────────────────────────────────────────────────────

class TestParser:
    def test_json_format(self):
        with tempfile.NamedTemporaryFile(mode="w", suffix=".log", delete=False) as f:
            record = {
                "ts": 1700000000.0, "uid": "D1",
                "id.orig_h": "10.0.0.1", "id.resp_h": "8.8.8.8",
                "query": "evil.com", "qtype_name": "A",
                "answers": ["1.2.3.4"], "TTLs": [30.0],
                "rcode_name": "NOERROR",
            }
            f.write(json.dumps(record) + "\n")
            path = f.name
        try:
            records = load_dns_records(path)
            assert len(records) == 1
            assert records[0]["query"] == "evil.com"
            assert isinstance(records[0]["answers"], list)
            assert isinstance(records[0]["TTLs"], list)
            assert records[0]["TTLs"][0] == 30.0
        finally:
            os.unlink(path)

    def test_tsv_answers_normalized(self):
        lines = [
            "#separator \\x09",
            "#set_separator ,",
            "#empty_field (empty)",
            "#unset_field -",
            "#fields\tts\tuid\tid.orig_h\tid.resp_h\tquery\tqtype_name\tanswers\tTTLs\trcode_name",
            "#types\ttime\tstring\taddr\taddr\tstring\tstring\tvector[string]\tvector[interval]\tstring",
            "1700000000.0\tD2\t10.0.0.1\t8.8.8.8\tevil.com\tA\t1.2.3.4,5.6.7.8\t30.0,30.0\tNOERROR",
        ]
        with tempfile.NamedTemporaryFile(mode="w", suffix=".log", delete=False) as f:
            f.write("\n".join(lines))
            path = f.name
        try:
            records = load_dns_records(path)
            assert len(records) == 1
            assert isinstance(records[0]["answers"], list)
            assert "1.2.3.4" in records[0]["answers"]
            assert isinstance(records[0]["TTLs"], list)
        finally:
            os.unlink(path)

    def test_crlf_line_endings(self):
        with tempfile.NamedTemporaryFile(mode="wb", suffix=".log", delete=False) as f:
            lines = [
                b'{"ts": 1700000000.0, "uid": "D1", "id.orig_h": "10.0.0.1", '
                b'"id.resp_h": "8.8.8.8", "query": "evil.com", "qtype_name": "A", '
                b'"answers": ["1.2.3.4"], "TTLs": [30.0], "rcode_name": "NOERROR"}\r\n',
            ]
            f.writelines(lines)
            path = f.name
        try:
            records = load_dns_records(path)
            assert len(records) == 1
        finally:
            os.unlink(path)

    def test_missing_file(self):
        records = load_dns_records("/nonexistent/dns.log")
        assert records == []

    def test_empty_file(self):
        with tempfile.NamedTemporaryFile(mode="w", suffix=".log", delete=False) as f:
            path = f.name
        try:
            records = load_dns_records(path)
            assert records == []
        finally:
            os.unlink(path)

    def test_zero_ts_handled(self):
        with tempfile.NamedTemporaryFile(mode="w", suffix=".log", delete=False) as f:
            record = {
                "ts": 0, "uid": "D1", "id.orig_h": "10.0.0.1",
                "id.resp_h": "8.8.8.8", "query": "evil.com",
                "qtype_name": "A", "answers": [], "TTLs": [], "rcode_name": "NOERROR",
            }
            f.write(json.dumps(record) + "\n")
            path = f.name
        try:
            records = load_dns_records(path)
            assert records[0]["ts"] == 0.0
        finally:
            os.unlink(path)


# ── score_domain integration ──────────────────────────────────────────────────

class TestScoreDomain:
    def _make_dga_records(self, count=50):
        import random
        random.seed(5)
        ts = 1700000000.0
        records = []
        alpha = "abcdefghijklmnopqrstuvwxyz0123456789"
        for i in range(count):
            ts += random.uniform(5, 30)
            sub = "".join(random.choices(alpha, k=18))
            nxd = random.random() < 0.4
            records.append({
                "ts": ts,
                "query": f"{sub}.evil-dga.net",
                "qtype": "A",
                "answers": [] if nxd else [f"1.2.3.{random.randint(1,254)}"],
                "TTLs": [] if nxd else [30.0],
                "rcode": "NXDOMAIN" if nxd else "NOERROR",
            })
        return records

    def test_dga_scores_high(self):
        records = self._make_dga_records(50)
        candidate = score_domain("evil-dga.net", records, DEFAULT_WEIGHTS)
        assert candidate.total_score > 0.3
        assert candidate.domain == "evil-dga.net"

    def test_all_signals_present(self):
        records = self._make_dga_records(20)
        candidate = score_domain("evil-dga.net", records, DEFAULT_WEIGHTS)
        signal_names = {s.name for s in candidate.signals}
        expected = {
            "ttl_low_mean", "ttl_variance_low", "subdomain_entropy",
            "query_length_anomaly", "nxdomain_ratio", "resolver_inconsistency",
            "ttl_sudden_drop", "query_frequency",
        }
        assert expected == signal_names

    def test_normal_traffic_scores_low(self):
        import random
        random.seed(6)
        ts = 1700000000.0
        records = []
        for _ in range(20):
            ts += random.uniform(60, 600)
            records.append({
                "ts": ts,
                "query": "docs.python.org",
                "qtype": "A",
                "answers": ["151.101.1.164"],
                "TTLs": [random.uniform(60, 3600)],
                "rcode": "NOERROR",
            })
        candidate = score_domain("python.org", records, DEFAULT_WEIGHTS)
        assert candidate.total_score < 0.4

    def test_query_count_correct(self):
        records = self._make_dga_records(30)
        candidate = score_domain("evil-dga.net", records, DEFAULT_WEIGHTS)
        assert candidate.query_count == 30


# ── Correlator tests ──────────────────────────────────────────────────────────

class TestCorrelator:
    def _write_dns_log(self, path, records):
        with open(path, "w") as f:
            for r in records:
                f.write(json.dumps(r) + "\n")

    def test_base_domain_rollup(self, tmp_path):
        """Subdomains of same base domain should roll up to one candidate."""
        import random
        random.seed(7)
        ts = 1700000000.0
        records = []
        alpha = "abcdefghijklmnopqrstuvwxyz0123456789"
        for i in range(20):
            ts += 30.0
            sub = "".join(random.choices(alpha, k=16))
            records.append({
                "ts": ts, "uid": f"D{i}",
                "id.orig_h": "10.0.0.1", "id.resp_h": "8.8.8.8",
                "query": f"{sub}.evil-rollup.net",
                "qtype_name": "A",
                "answers": [f"1.2.3.{i % 254}"],
                "TTLs": [30.0],
                "rcode_name": "NOERROR",
            })
        dns_path = tmp_path / "dns.log"
        self._write_dns_log(str(dns_path), records)
        candidates = correlate_and_score(
            str(dns_path), min_queries=3, exclude_common=True
        )
        domains = [c.domain for c in candidates]
        assert "evil-rollup.net" in domains
        # Should be one entry, not 20
        assert domains.count("evil-rollup.net") == 1

    def test_min_queries_filter(self, tmp_path):
        records = []
        ts = 1700000000.0
        for i in range(2):
            ts += 60.0
            records.append({
                "ts": ts, "uid": f"D{i}",
                "id.orig_h": "10.0.0.1", "id.resp_h": "8.8.8.8",
                "query": "rare-domain.net",
                "qtype_name": "A", "answers": ["1.2.3.4"],
                "TTLs": [30.0], "rcode_name": "NOERROR",
            })
        dns_path = tmp_path / "dns.log"
        self._write_dns_log(str(dns_path), records)
        candidates = correlate_and_score(
            str(dns_path), min_queries=3, exclude_common=False
        )
        domains = [c.domain for c in candidates]
        assert "rare-domain.net" not in domains

    def test_common_domains_excluded_by_default(self, tmp_path):
        records = []
        ts = 1700000000.0
        for i in range(20):
            ts += 30.0
            records.append({
                "ts": ts, "uid": f"D{i}",
                "id.orig_h": "10.0.0.1", "id.resp_h": "8.8.8.8",
                "query": f"www.google.com",
                "qtype_name": "A", "answers": ["142.250.80.46"],
                "TTLs": [300.0], "rcode_name": "NOERROR",
            })
        dns_path = tmp_path / "dns.log"
        self._write_dns_log(str(dns_path), records)
        candidates = correlate_and_score(
            str(dns_path), min_queries=3, exclude_common=True
        )
        domains = [c.domain for c in candidates]
        assert "google.com" not in domains

    def test_common_domains_included_when_flag_set(self, tmp_path):
        records = []
        ts = 1700000000.0
        for i in range(10):
            ts += 30.0
            records.append({
                "ts": ts, "uid": f"D{i}",
                "id.orig_h": "10.0.0.1", "id.resp_h": "8.8.8.8",
                "query": "www.google.com",
                "qtype_name": "A", "answers": ["142.250.80.46"],
                "TTLs": [300.0], "rcode_name": "NOERROR",
            })
        dns_path = tmp_path / "dns.log"
        self._write_dns_log(str(dns_path), records)
        candidates = correlate_and_score(
            str(dns_path), min_queries=3, exclude_common=False
        )
        domains = [c.domain for c in candidates]
        assert "google.com" in domains


# ── Config tests ──────────────────────────────────────────────────────────────

class TestConfig:
    def test_default_weights(self):
        weights = load_weights(None)
        assert set(weights.keys()) == set(DEFAULT_WEIGHTS.keys())
        assert weights == DEFAULT_WEIGHTS

    def test_yaml_override(self, tmp_path):
        config_path = tmp_path / "w.yaml"
        with open(config_path, "w") as f:
            f.write("weights:\n  subdomain_entropy: 0.50\n")
        weights = load_weights(str(config_path))
        assert weights["subdomain_entropy"] == 0.50
        assert weights["ttl_low_mean"] == DEFAULT_WEIGHTS["ttl_low_mean"]

    def test_invalid_range(self, tmp_path):
        config_path = tmp_path / "bad.yaml"
        with open(config_path, "w") as f:
            f.write("weights:\n  subdomain_entropy: 2.0\n")
        with pytest.raises(ValueError):
            load_weights(str(config_path))

    def test_zero_weight_valid(self, tmp_path):
        config_path = tmp_path / "zero.yaml"
        with open(config_path, "w") as f:
            f.write("weights:\n  subdomain_entropy: 0.0\n")
        weights = load_weights(str(config_path))
        assert weights["subdomain_entropy"] == 0.0

    def test_missing_file(self):
        with pytest.raises(FileNotFoundError):
            load_weights("/nonexistent/weights.yaml")

    def test_generate_yaml(self, tmp_path):
        out = tmp_path / "out.yaml"
        generate_default_config(str(out), fmt="yaml")
        assert out.exists()
        weights = load_weights(str(out))
        assert weights == DEFAULT_WEIGHTS

    def test_generate_toml(self, tmp_path):
        out = tmp_path / "out.toml"
        generate_default_config(str(out), fmt="toml")
        assert out.exists()
        content = out.read_text()
        assert "[weights]" in content
        assert "subdomain_entropy" in content


# ── Renderer tests ────────────────────────────────────────────────────────────

class TestRenderer:
    def _make_candidate(self):
        import random
        random.seed(8)
        ts = 1700000000.0
        records = []
        alpha = "abcdefghijklmnopqrstuvwxyz0123456789"
        for i in range(30):
            ts += random.uniform(5, 30)
            sub = "".join(random.choices(alpha, k=16))
            nxd = random.random() < 0.35
            records.append({
                "ts": ts,
                "query": f"{sub}.test-domain.net",
                "qtype": "A",
                "answers": [] if nxd else [f"1.2.3.{i % 254}"],
                "TTLs": [] if nxd else [30.0],
                "rcode": "NXDOMAIN" if nxd else "NOERROR",
            })
        return score_domain("test-domain.net", records, DEFAULT_WEIGHTS)

    def test_json_structure(self):
        candidate = self._make_candidate()
        output = render_json_output([candidate])
        data = json.loads(output)
        assert "dns_anomaly_candidates" in data
        assert len(data["dns_anomaly_candidates"]) == 1
        c = data["dns_anomaly_candidates"][0]
        for field in ("domain", "total_score", "confidence", "query_count",
                      "unique_subdomains", "nxdomain_count", "signals",
                      "attack_techniques", "first_seen", "last_seen"):
            assert field in c

    def test_json_signals_complete(self):
        candidate = self._make_candidate()
        output = render_json_output([candidate])
        data = json.loads(output)
        signals = data["dns_anomaly_candidates"][0]["signals"]
        assert len(signals) == 8
        signal_names = {s["name"] for s in signals}
        assert "subdomain_entropy" in signal_names
        assert "nxdomain_ratio" in signal_names
        assert "ttl_sudden_drop" in signal_names

    def test_json_empty(self):
        output = render_json_output([])
        data = json.loads(output)
        assert data["dns_anomaly_candidates"] == []

    def test_fallback_summary(self, capsys):
        from ttl_watch.renderer import _fallback_summary
        _fallback_summary([])
        captured = capsys.readouterr()
        assert "ttl-watch" in captured.out.lower() or "TTL" in captured.out or "Domain" in captured.out

    def test_fallback_detail(self, capsys):
        from ttl_watch.renderer import _fallback_detail
        candidate = self._make_candidate()
        _fallback_detail(candidate)
        captured = capsys.readouterr()
        assert candidate.domain in captured.out
