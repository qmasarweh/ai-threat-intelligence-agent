"""Local security log parsing and suspicious event detection.

Reads SSH `auth.log` and Nginx `access.log` files and extracts suspicious
events (failed logins, brute-force campaigns, scanners, web attacks, ...)
as structured :class:`LogEntry` records. All parsing is fully local — no
data leaves the machine at this stage.
"""

from __future__ import annotations

import re
from collections import Counter
from dataclasses import dataclass
from pathlib import Path
from typing import Optional

# --------------------------------------------------------------------------
# Tunables
# --------------------------------------------------------------------------

BRUTE_FORCE_THRESHOLD = 5      # failed password attempts per source IP
WEB_BRUTE_FORCE_THRESHOLD = 3  # login-endpoint hits per source IP

# --------------------------------------------------------------------------
# Data model
# --------------------------------------------------------------------------


@dataclass(frozen=True)
class LogEntry:
    """A single suspicious event extracted from a log file."""

    source: str            # "ssh" | "nginx"
    timestamp: Optional[str]
    src_ip: Optional[str]
    category: str
    severity: str          # critical | high | medium | low
    message: str
    line: int              # source line number (0 for derived aggregates)
    file: str

    def as_dict(self) -> dict:
        return {
            "source": self.source,
            "timestamp": self.timestamp,
            "src_ip": self.src_ip,
            "category": self.category,
            "severity": self.severity,
            "message": self.message,
            "line": self.line,
            "file": self.file,
        }


SEVERITY = {
    # ssh
    "brute_force": "critical",
    "breakin_attempt": "critical",
    "max_auth_attempts": "critical",
    "auth_failure": "high",
    "sudo_failure": "high",
    "invalid_user": "medium",
    "aborted_auth": "medium",
    # nginx
    "sql_injection": "critical",
    "web_bruteforce": "critical",
    "directory_traversal": "high",
    "sensitive_file": "high",
    "user_enumeration": "high",
    "web_login": "medium",
    "scan_ua": "medium",
    "server_error": "medium",
    "forbidden": "medium",
    "probe_404": "low",
}

# --------------------------------------------------------------------------
# SSH auth.log parsing
# --------------------------------------------------------------------------

SSH_TIMESTAMP_RE = re.compile(r"^([A-Z][a-z]{2}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2})")
IP_RE = re.compile(r"(\d{1,3}(?:\.\d{1,3}){3})")


def _categorize_ssh(line: str) -> Optional[str]:
    """Return the suspicious category for an auth.log line, or None if benign.

    Order matters: "Failed password" also appears in "Failed password for
    invalid user ..." lines, which we classify as authentication failures.
    """
    if "Failed password" in line:
        return "auth_failure"
    if "POSSIBLE BREAK-IN" in line.upper():
        return "breakin_attempt"
    if "maximum authentication attempts exceeded" in line:
        return "max_auth_attempts"
    if "pam_unix(sudo:auth): authentication failure" in line:
        return "sudo_failure"
    if "Invalid user " in line:
        return "invalid_user"
    if "Connection closed by authenticating user" in line or \
       "Disconnected from authenticating user" in line:
        return "aborted_auth"
    return None


def parse_ssh(path: Path | str) -> list[LogEntry]:
    """Parse an SSH auth.log, returning suspicious events plus derived
    brute-force aggregates grouped by source IP."""
    raw = Path(path)
    failed_by_ip: Counter[str] = Counter()
    entries: list[LogEntry] = []

    for lineno, line in enumerate(
        raw.read_text(encoding="utf-8", errors="replace").splitlines(), start=1
    ):
        category = _categorize_ssh(line)
        if category is None:
            continue
        ts_match = SSH_TIMESTAMP_RE.match(line)
        ip_match = IP_RE.search(line)
        entries.append(
            LogEntry(
                source="ssh",
                timestamp=ts_match.group(1) if ts_match else None,
                src_ip=ip_match.group(1) if ip_match else None,
                category=category,
                severity=SEVERITY[category],
                message=line,
                line=lineno,
                file=str(raw),
            )
        )
        if category == "auth_failure" and ip_match:
            failed_by_ip[ip_match.group(1)] += 1

    for ip, count in failed_by_ip.items():
        if count >= BRUTE_FORCE_THRESHOLD:
            entries.append(
                LogEntry(
                    source="ssh",
                    timestamp=None,
                    src_ip=ip,
                    category="brute_force",
                    severity=SEVERITY["brute_force"],
                    message=(
                        f"{count} failed password attempts from {ip} "
                        f"(threshold >= {BRUTE_FORCE_THRESHOLD})"
                    ),
                    line=0,
                    file=str(raw),
                )
            )
    return entries


# --------------------------------------------------------------------------
# Nginx access.log parsing
# --------------------------------------------------------------------------

NGINX_LOG_RE = re.compile(
    r'^(\S+) - - \[([^\]]+)\] "([^"]*)" (\d{3}) (\S+) "([^"]*)" "([^"]*)"'
)

# User agents of known scanning/attack tooling.
SCANNER_UAS = (
    "sqlmap", "nikto", "nessus", "masscan", "zgrab",
    "wpscan", "acunetix", "dirbuster", "gobuster", "ffuf", "wfuzz", "nuclei",
)


def _is_scanner_ua(ua: str) -> bool:
    ua_lower = ua.lower()
    return any(tool in ua_lower for tool in SCANNER_UAS)


def _url_signals(url: str) -> list[str]:
    """Return attack signals detected in a request URL (in priority order)."""
    u = url.lower()
    signals: list[str] = []
    if ".." in u:
        signals.append("directory_traversal")
    if ".env" in u or ".git/config" in u:
        signals.append("sensitive_file")
    if "/wp-json/wp/v2/users" in u:
        signals.append("user_enumeration")
    if (
        ("union" in u and "select" in u)
        or "information_schema" in u
        or "sleep(" in u
        or "1%3d1" in u
        or "1%3d2" in u
        or "1=1" in u
        or "1=2" in u
    ):
        signals.append("sql_injection")
    if "wp-login.php" in u:
        signals.append("web_login")
    return signals


def parse_nginx(path: Path | str) -> list[LogEntry]:
    """Parse an Nginx combined-format access log into suspicious events."""
    raw = Path(path)
    login_hits: Counter[str] = Counter()
    entries: list[LogEntry] = []

    for lineno, line in enumerate(
        raw.read_text(encoding="utf-8", errors="replace").splitlines(), start=1
    ):
        match = NGINX_LOG_RE.match(line)
        if not match:
            continue
        ip, ts, request, status_str, _size, _referer, ua = match.groups()
        status = int(status_str)
        parts = request.split()
        url = parts[1] if len(parts) > 1 else request

        url_sig = _url_signals(url)
        if url_sig:
            category = url_sig[0]
        elif _is_scanner_ua(ua):
            category = "scan_ua"
        elif status >= 500:
            category = "server_error"
        elif status == 403:
            category = "forbidden"
        elif status == 404:
            category = "probe_404"
        else:
            continue

        entries.append(
            LogEntry(
                source="nginx",
                timestamp=ts,
                src_ip=ip,
                category=category,
                severity=SEVERITY[category],
                message=f"{status} {request} (UA: {ua})",
                line=lineno,
                file=str(raw),
            )
        )
        if category == "web_login" and ip:
            login_hits[ip] += 1

    for ip, count in login_hits.items():
        if count >= WEB_BRUTE_FORCE_THRESHOLD:
            entries.append(
                LogEntry(
                    source="nginx",
                    timestamp=None,
                    src_ip=ip,
                    category="web_bruteforce",
                    severity=SEVERITY["web_bruteforce"],
                    message=(
                        f"{count} attempts against login endpoint from {ip} "
                        f"(threshold >= {WEB_BRUTE_FORCE_THRESHOLD})"
                    ),
                    line=0,
                    file=str(raw),
                )
            )
    return entries


# --------------------------------------------------------------------------
# Dispatch
# --------------------------------------------------------------------------


def parse_log_file(path: Path | str) -> list[LogEntry]:
    """Parse a log file, dispatching on the filename.

    SSH auth logs contain "auth"/"ssh" in the name; Nginx access logs
    contain "access"/"nginx".
    """
    raw = Path(path)
    if not raw.exists():
        raise FileNotFoundError(f"Log file not found: {raw}")
    name = raw.name.lower()
    if "auth" in name or "ssh" in name:
        return parse_ssh(raw)
    if "access" in name or "nginx" in name:
        return parse_nginx(raw)
    raise ValueError(
        f"Cannot infer log type from filename '{raw.name}' "
        "(expected an SSH auth.log or Nginx access.log)"
    )