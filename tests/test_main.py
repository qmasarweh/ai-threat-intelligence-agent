"""Tests for main.py CLI behavior: graceful degradation when Ollama fails."""

from pathlib import Path

import main

SAMPLES = Path(__file__).resolve().parent.parent / "data" / "samples"
SSH_LOG = SAMPLES / "ssh_auth.log"


def test_main_continues_offline_on_ollama_http_error(tmp_path, monkeypatch, capsys):
    """A model-not-found (HTTP 404) must not crash the CLI: exit 0 + report."""
    def boom(*args, **kwargs):
        raise RuntimeError("Ollama API error 404: model 'llama3' not found")

    monkeypatch.setattr(main, "analyze", boom)
    out_path = tmp_path / "report.md"

    rc = main.main(["--log-file", str(SSH_LOG), "--output", str(out_path)])

    assert rc == 0
    captured = capsys.readouterr()
    assert "404" in captured.out
    assert "unavailable" in out_path.read_text(encoding="utf-8").lower()


def test_main_continues_offline_on_connection_error(tmp_path, monkeypatch):
    from src.ai_analyzer import OllamaConnectionError

    def boom(*args, **kwargs):
        raise OllamaConnectionError("Ollama unreachable")

    monkeypatch.setattr(main, "analyze", boom)
    out_path = tmp_path / "report.md"

    rc = main.main(["--log-file", str(SSH_LOG), "--output", str(out_path)])

    assert rc == 0
    assert "unavailable" in out_path.read_text(encoding="utf-8").lower()


def test_main_missing_log_file_exits_nonzero(capsys):
    rc = main.main(["--log-file", "does/not/exist.log"])
    assert rc == 1


def test_main_writes_report_with_analysis(tmp_path, monkeypatch):
    def fake_analyze(*args, **kwargs):
        return "Attack narrative: brute force campaign observed."

    monkeypatch.setattr(main, "analyze", fake_analyze)
    out_path = tmp_path / "report.md"

    rc = main.main(["--log-file", str(SSH_LOG), "--output", str(out_path)])

    assert rc == 0
    content = out_path.read_text(encoding="utf-8")
    assert "Attack narrative: brute force campaign observed." in content
    assert "unavailable" not in content.lower()