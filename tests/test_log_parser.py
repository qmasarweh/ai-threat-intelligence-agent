"""Tests for src.log_parser: suspicious log detection from SSH auth.log and Nginx access logs."""

from pathlib import Path

import pytest

from src.log_parser import LogEntry, parse_log_file

SAMPLES = Path(__file__).resolve().parent.parent / "data" / "samples"
SSH_LOG = SAMPLES / "ssh_auth.log"
NGINX_LOG = SAMPLES / "nginx_access.log"


@pytest.fixture(scope="module")
def ssh_entries():
    return parse_log_file(SSH_LOG)


@pytest.fixture(scope="module")
def nginx_entries():
    return parse_log_file(NGINX_LOG)


def _by_category(entries, category):
    return [e for e in entries if e.category == category]


# ---------------------------------------------------------------- dispatch --

def test_dispatch_detects_ssh_source():
    entries = parse_log_file(SSH_LOG)
    assert entries
    assert all(e.source == "ssh" for e in entries)


def test_dispatch_detects_nginx_source():
    entries = parse_log_file(NGINX_LOG)
    assert entries
    assert all(e.source == "nginx" for e in entries)


def test_dispatch_missing_file_raises():
    with pytest.raises(FileNotFoundError):
        parse_log_file(Path("does/not/exist.log"))


def test_dispatch_unknown_filename_raises(tmp_path):
    unknown = tmp_path / "unknown_source.log"
    unknown.write_text("some log content\n", encoding="utf-8")
    with pytest.raises(ValueError):
        parse_log_file(unknown)


# ---------------------------------------------------------------------- ssh --

def test_ssh_counts_failed_passwords(ssh_entries):
    assert len(_by_category(ssh_entries, "auth_failure")) == 21


def test_ssh_detects_standalone_invalid_user(ssh_entries):
    invalid = _by_category(ssh_entries, "invalid_user")
    assert len(invalid) == 1
    assert invalid[0].src_ip == "198.51.100.23"


def test_ssh_detects_breakin_attempt(ssh_entries):
    breakin = _by_category(ssh_entries, "breakin_attempt")
    assert len(breakin) == 1
    assert breakin[0].src_ip == "45.155.205.233"


def test_ssh_detects_sudo_auth_failure(ssh_entries):
    assert len(_by_category(ssh_entries, "sudo_failure")) == 1


def test_ssh_flags_brute_force_ips(ssh_entries):
    brute = _by_category(ssh_entries, "brute_force")
    flagged = {e.src_ip for e in brute}
    assert "203.0.113.7" in flagged   # 8 failed attempts
    assert "185.220.101.4" in flagged  # 8 failed attempts
    assert "198.51.100.23" not in flagged  # only 3 failed attempts
    assert "45.155.205.233" not in flagged  # only 2 failed attempts


def test_ssh_brute_force_entries_carry_count():
    from src.log_parser import parse_ssh
    brute = [e for e in parse_ssh(SSH_LOG) if e.category == "brute_force" and e.src_ip == "203.0.113.7"]
    assert len(brute) == 1
    assert "8 failed password" in brute[0].message


def test_ssh_ignores_successful_logins(ssh_entries):
    messages = " ".join(e.message for e in ssh_entries)
    assert "Accepted publickey for qusai" not in messages
    assert "Accepted publickey for deploy" not in messages


def test_ssh_logentry_fields_populated(ssh_entries):
    entry = _by_category(ssh_entries, "breakin_attempt")[0]
    assert entry.source == "ssh"
    assert entry.src_ip == "45.155.205.233"
    assert entry.severity == "critical"
    assert entry.line > 0
    assert "POSSIBLE BREAK-IN" in entry.message


# -------------------------------------------------------------------- nginx --

def test_nginx_counts_sql_injection(nginx_entries):
    assert len(_by_category(nginx_entries, "sql_injection")) == 3


def test_nginx_counts_directory_traversal(nginx_entries):
    traversal = _by_category(nginx_entries, "directory_traversal")
    assert len(traversal) == 2
    assert all(e.src_ip == "185.220.101.4" for e in traversal)


def test_nginx_detects_sensitive_file_probes(nginx_entries):
    assert len(_by_category(nginx_entries, "sensitive_file")) == 2


def test_nginx_detects_user_enumeration(nginx_entries):
    enum = _by_category(nginx_entries, "user_enumeration")
    assert len(enum) == 1
    assert enum[0].src_ip == "45.155.205.233"


def test_nginx_flags_server_error(nginx_entries):
    assert len(_by_category(nginx_entries, "server_error")) == 1


def test_nginx_detects_scanner_ua(nginx_entries):
    scan = _by_category(nginx_entries, "scan_ua")
    assert len(scan) == 1  # sqlmap UA hitting /admin/config.php without SQL payload
    assert scan[0].src_ip == "198.51.100.23"


def test_nginx_detects_wordpress_bruteforce(nginx_entries):
    brute = _by_category(nginx_entries, "web_bruteforce")
    assert brute
    assert any(e.src_ip == "203.0.113.7" for e in brute)


def test_nginx_ignores_healthy_requests(nginx_entries):
    messages = " ".join(e.message for e in nginx_entries)
    assert "/healthz" not in messages
    assert "/api/v1/health" not in messages


def test_nginx_probe_404_detected(nginx_entries):
    probes = _by_category(nginx_entries, "probe_404")
    assert any("/cgi-bin/test.cgi" in e.message for e in probes)


def test_nginx_logentry_fields_populated(nginx_entries):
    entry = _by_category(nginx_entries, "sql_injection")[0]
    assert entry.source == "nginx"
    assert entry.src_ip == "198.51.100.23"
    assert entry.severity == "critical"