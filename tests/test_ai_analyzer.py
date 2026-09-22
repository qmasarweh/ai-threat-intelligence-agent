"""Tests for src.ai_analyzer: local Ollama integration with a SOC Analyst persona."""

import pytest
import requests

from src.ai_analyzer import OllamaConnectionError, analyze, build_prompt


class _FakeResponse:
    def __init__(self, payload, status_code=200):
        self._payload = payload
        self.status_code = status_code
        self.text = str(payload)

    def json(self):
        if self.status_code >= 400:
            return {"error": "model 'llama3' not found"}
        return self._payload

    def raise_for_status(self):
        if self.status_code >= 400:
            raise requests.HTTPError(f"{self.status_code} error")


ENTRIES = [
    {"source": "ssh", "timestamp": "Sep 20 03:14:52", "src_ip": "203.0.113.7",
     "category": "auth_failure", "severity": "high",
     "message": "Failed password for invalid user admin from 203.0.113.7",
     "line": 1, "file": "ssh_auth.log"},
]


def test_build_prompt_contains_soc_context_and_entries():
    prompt = build_prompt(ENTRIES, {"auth_failure": 1})
    assert "SOC" in prompt
    assert "203.0.113.7" in prompt
    assert "auth_failure" in prompt


def test_analyze_returns_generated_text(monkeypatch):
    captured = {}

    def fake_post(url, **kwargs):
        captured["url"] = url
        captured["payload"] = kwargs.get("json", {})
        return _FakeResponse({"response": "Suspicious activity detected.", "done": True})

    monkeypatch.setattr(requests, "post", fake_post)
    result = analyze(ENTRIES, {"auth_failure": 1}, model="llama3")
    assert result == "Suspicious activity detected."
    assert captured["url"].endswith("/api/generate")
    assert captured["payload"]["model"] == "llama3"
    assert captured["payload"]["stream"] is False
    assert "SOC Analyst" in captured["payload"]["system"]


def test_analyze_raises_on_connection_error(monkeypatch):
    def fake_post(url, **kwargs):
        raise requests.exceptions.ConnectionError("Connection refused")

    monkeypatch.setattr(requests, "post", fake_post)
    with pytest.raises(OllamaConnectionError):
        analyze(ENTRIES, {"auth_failure": 1}, model="llama3")


def test_analyze_raises_on_ollama_http_error(monkeypatch):
    monkeypatch.setattr(
        requests, "post",
        lambda url, **kwargs: _FakeResponse({}, status_code=404),
    )
    with pytest.raises(Exception) as excinfo:
        analyze(ENTRIES, {"auth_failure": 1}, model="llama3")
    assert "404" in str(excinfo.value)