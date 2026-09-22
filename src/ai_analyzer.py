"""Local Ollama integration: asks a locally hosted LLM to analyze threats.

Connects to the Ollama HTTP API (default http://localhost:11434) with a
SOC Analyst system prompt. Every request stays on the local machine; no log
content is ever sent to a third party.
"""

from __future__ import annotations

import requests

DEFAULT_OLLAMA_URL = "http://localhost:11434"

# SOC Analyst persona that frames every analysis.
SOC_ANALYST_SYSTEM_PROMPT = (
    "You are a Senior SOC Analyst (Security Operations Center) with 15 years "
    "of experience in incident response, threat hunting, and log analysis. "
    "You are reviewing suspicious events extracted from local server logs.\n"
    "Analyze the bundled events rigorously:\n"
    "1. Assess overall severity (critical / high / medium / low) with "
    "   justification.\n"
    "2. Summarize the attack narrative: what appears to have happened, in "
    "   what order, and whether multiple sources/techniques line up.\n"
    "3. List concrete indicators of compromise (source IPs, usernames, "
    "   paths, endpoints, tools observed).\n"
    "4. State the most likely hypothesis (e.g. brute force, scanner "
    "   reconnaissance, SQL injection attempt) and any alternative "
    "   hypotheses.\n"
    "5. Give prioritized, actionable recommendations a defender should "
    "   take now.\n"
    "6. Note what additional evidence or log sources would sharpen the "
    "   assessment.\n"
    "Be specific, concise, and evidence-driven. Do not invent indicators "
    "that are not present in the provided events."
)

_ENTRY_SAMPLE_LIMIT = 40


class OllamaConnectionError(RuntimeError):
    """Raised when the local Ollama server cannot be reached."""


def build_prompt(entries: list[dict] | list, stats: dict) -> str:
    """Build the analysis prompt from parsed events and category counts."""
    lines: list[str] = []
    lines.append("SUSPICIOUS EVENT SUMMARY")
    lines.append("------------------------")
    lines.append(f"Total suspicious events: {len(entries)}")
    lines.append("")
    lines.append("Event counts by category:")
    for category, count in sorted(stats.items(), key=lambda kv: -kv[1]):
        lines.append(f"  - {category}: {count}")
    lines.append("")
    lines.append("Individual events (most recent first, capped):")
    for entry in list(entries)[-_ENTRY_SAMPLE_LIMIT:][::-1]:
        if isinstance(entry, dict):
            lines.append(
                f"  [{entry.get('source')}] {entry.get('timestamp')} "
                f"ip={entry.get('src_ip')} severity={entry.get('severity')} "
                f"category={entry.get('category')} :: {entry.get('message')}"
            )
        else:
            lines.append(
                f"  [{entry.source}] {entry.timestamp} ip={entry.src_ip} "
                f"severity={entry.severity} category={entry.category} "
                f":: {entry.message}"
            )
    lines.append("")
    lines.append(
        "Provide your structured SOC analysis of the above events now."
    )
    return "\n".join(lines)


def analyze(
    entries: list[dict] | list,
    stats: dict,
    *,
    model: str = "llama3",
    base_url: str = DEFAULT_OLLAMA_URL,
    timeout: int = 120,
) -> str:
    """Send the events to Ollama for analysis and return the model's text.

    Raises :class:`OllamaConnectionError` if the local Ollama server is
    unreachable, so callers can degrade gracefully.
    """
    prompt = build_prompt(entries, stats)
    payload = {
        "model": model,
        "prompt": prompt,
        "system": SOC_ANALYST_SYSTEM_PROMPT,
        "stream": False,
        "options": {"temperature": 0.2},
    }
    endpoint = f"{base_url.rstrip('/')}/api/generate"
    try:
        response = requests.post(endpoint, json=payload, timeout=timeout)
    except requests.exceptions.ConnectionError as exc:
        raise OllamaConnectionError(
            f"Ollama unreachable at {base_url} - is `ollama serve` running "
            f"and is the model pulled? ({exc})"
        ) from exc
    except requests.exceptions.Timeout as exc:
        raise OllamaConnectionError(
            f"Ollama request timed out after {timeout}s at {base_url} ({exc})"
        ) from exc

    if response.status_code >= 400:
        raise RuntimeError(
            f"Ollama API error {response.status_code}: {response.text[:300]}"
        )
    data = response.json()
    return data.get("response", "").strip()