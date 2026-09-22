"""Tests for src.report_generator: Markdown incident report formatting."""

from src.report_generator import generate_report, save_report

META = {
    "source_file": "data/samples/ssh_auth.log",
    "model": "llama3",
    "generated_at": "2026-09-22T10:00:00Z",
}

SAMPLE_ENTRY = {
    "source": "ssh",
    "timestamp": "Sep 20 03:14:52",
    "src_ip": "203.0.113.7",
    "category": "auth_failure",
    "severity": "high",
    "message": "Failed password for invalid user admin from 203.0.113.7",
    "line": 1,
    "file": "data/samples/ssh_auth.log",
}

SAMPLE_STATS = {"auth_failure": 18, "brute_force": 2}


def test_report_contains_expected_sections():
    md = generate_report(META, [SAMPLE_ENTRY], SAMPLE_STATS, "Some analysis text.")
    assert "# Incident Report" in md
    assert "## Executive Summary" in md
    assert "## Suspicious Events" in md
    assert "## AI Analysis" in md
    assert "## Indicators" in md
    assert "## Recommended Actions" in md


def test_report_includes_meta_and_stats():
    md = generate_report(META, [SAMPLE_ENTRY], SAMPLE_STATS, "Analysis.")
    assert META["source_file"] in md
    assert META["model"] in md
    assert "18" in md  # auth failure total
    assert "203.0.113.7" in md


def test_report_embeds_ai_analysis():
    md = generate_report(META, [SAMPLE_ENTRY], SAMPLE_STATS, "Brute force campaign from 203.0.113.7.")
    assert "Brute force campaign from 203.0.113.7." in md


def test_report_notes_offline_when_no_analysis():
    md = generate_report(META, [SAMPLE_ENTRY], SAMPLE_STATS, None)
    assert "unavailable" in md.lower()


def test_save_report_creates_file(tmp_path):
    target = tmp_path / "nested" / "dir" / "report.md"
    save_report("# Incident Report", target)
    assert target.exists()
    assert target.read_text(encoding="utf-8").startswith("# Incident Report")