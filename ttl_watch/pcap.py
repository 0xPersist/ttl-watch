"""
PCAP ingestion for ttl-watch.
Auto-invokes Zeek to extract dns.log from a raw PCAP.
"""

import os
import shutil
import subprocess
import tempfile


def zeek_available() -> bool:
    return shutil.which("zeek") is not None or shutil.which("bro") is not None


def _zeek_bin() -> str:
    return shutil.which("zeek") or shutil.which("bro") or "zeek"


def generate_dns_log_from_pcap(pcap_path: str, output_dir: str = None) -> dict:
    """
    Run Zeek against a PCAP and return path to generated dns.log.
    Returns dict with keys: dns, tmpdir.
    Caller is responsible for cleanup via cleanup_tmpdir().
    """
    if not os.path.exists(pcap_path):
        raise FileNotFoundError(f"PCAP not found: {pcap_path}")

    if not zeek_available():
        raise RuntimeError(
            "Zeek is not installed or not in PATH. "
            "Install Zeek or provide a dns.log directly with --dns."
        )

    tmpdir = output_dir or tempfile.mkdtemp(prefix="ttlwatch_zeek_")

    cmd = [
        _zeek_bin(),
        "-r", os.path.abspath(pcap_path),
        "LogAscii::use_json=T",
        "base/protocols/dns",
    ]

    result = subprocess.run(
        cmd,
        cwd=tmpdir,
        capture_output=True,
        text=True,
        timeout=300,
    )

    if result.returncode != 0:
        stderr = result.stderr[:500] if result.stderr else "(no stderr)"
        raise RuntimeError(f"Zeek exited with code {result.returncode}: {stderr}")

    def find_log(name: str) -> str:
        for candidate in [
            os.path.join(tmpdir, f"{name}.log"),
            os.path.join(tmpdir, f"{name}.log.gz"),
        ]:
            if os.path.exists(candidate):
                return candidate
        return ""

    dns_path = find_log("dns")
    if not dns_path:
        raise RuntimeError("Zeek did not produce a dns.log. Check PCAP validity.")

    return {
        "dns":    dns_path,
        "tmpdir": tmpdir,
        "zeek_stdout": result.stdout,
        "zeek_stderr": result.stderr,
    }


def cleanup_tmpdir(tmpdir: str):
    if tmpdir and os.path.exists(tmpdir):
        shutil.rmtree(tmpdir, ignore_errors=True)
