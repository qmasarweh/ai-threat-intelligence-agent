"""Markdown incident report generation."""

from __future__ import annotations

from collections import Counter
from dataclasses import asdict, is_dataclass
from pathlib import Path
from typing import Optional


def _entries_as_dicts(entries: list) -> list[dict]:
    out: list[dict] = []
    for entry in entries:
        if is_dataclass(entry):
            out.append(asdict(entry))
        else:
            out.append(dict(entry))
    return out


def generate_report(
    meta: dict,
    entries: list,
    stats: dict,
    analysis: Optional[str],
) -> str:
    """Format a complete Markdown incident report.

    ``meta`` should contain ``source_file``, ``model`` and ``generated_at``.
    ``analysis`` is the Ollama output; ``None`` produces an explicit offline
    notice so the report is still useful when the local model is unavailable.
    """
    entries = _entries_as_dicts(entries)
    counts: Counter[str] = Counter(stats)
    ips = sorted({e["src_ip"] for e in entries if e.get("src_ip")})
    by_severity: Counter[str] = Counter(e.get("severity") for e in entries)

    lines: list[str] = []
    lines.append("# Incident Report")
    lines.append("")
    lines.append("| Field | Value |")
    lines.append("|---|---|")
    lines.append(f"| Source log | `{meta.get('source_file', 'unknown')}` |")
    lines.append(f"| Analysis model | `{meta.get('model', 'unknown')}` (local Ollama) |")
    lines.append(f"| Generated | {meta.get('generated_at', 'unknown')} |")
    lines.append(f"| Suspicious events | {len(entries)} |")
    lines.append("")

    # Executive summary ---------------------------------------------------
    lines.append("## Executive Summary")
    lines.append("")
    if entries:
        lines.append(
            f"This report covers **{len(entries)}** suspicious event(s) extracted "
            f"locally from `{meta.get('source_file', '')}`."
        )
        top = ", ".join(
            f"{sev} ({n})" for sev, n in by_severity.most_common()
        )
        lines.append(f"Severity breakdown: {top}.")
        hot_categories = ", ".join(
            f"{c} ({n})" for c, n in counts.most_common(5)
        )
        lines.append(f"Dominant categories: {hot_categories or 'n/a'}.")
        if ips:
            lines.append(
                f"Watchlist of source IPs ({len(ips)} total): `{', '.join(ips)}`."
            )
    else:
        lines.append("No suspicious events were detected in the provided log.")
    lines.append("")

    # Suspicious events ----------------------------------------------------
    lines.append("## Suspicious Events")
    lines.append("")
    if entries:
        lines.append("| # | Source | Timestamp | IP | Severity | Category | Message |")
        lines.append("|---|---|---|---|---|---|---|")
        for idx, e in enumerate(entries, start=1):
            message = e.get("message", "").replace("|", "\\|").replace("\n", " ")
            lines.append(
                f"| {idx} | {e.get('source')} | {e.get('timestamp') or '-'} "
                f"| {e.get('src_ip') or '-'} | {e.get('severity')} "
                f"| {e.get('category')} | {message} |"
            )
    else:
        lines.append("_Nothing suspicious detected._")
    lines.append("")

    # AI analysis ----------------------------------------------------------
    lines.append("## AI Analysis")
    lines.append("")
    if analysis:
        lines.append(analysis)
    else:
        lines.append(
            "> **AI analysis unavailable.** The local Ollama server could not be "
            "reached, so no model-based assessment was produced. The event data "
            "above remains available for manual review. Ensure `ollama serve` is "
            "running and the model is pulled, then re-run the analysis."
        )
    lines.append("")

    # Indicators -------------------------------------------------------------
    lines.append("## Indicators")
    lines.append("")
    if ips:
        lines.append("| Type | Value |")
        lines.append("|---|---|")
        for ip in ips:
            lines.append(f"| Source IP | `{ip}` |")
    else:
        lines.append("_No IP indicators._")
    lines.append("")

    # Recommended actions -----------------------------------------------------
    lines.append("## Recommended Actions")
    lines.append("")
    lines.append("- Block or rate-limit the listed source IPs at the firewall/WAF level.")
    lines.append("- Rotate credentials for any accounts targeted by failed logins.")
    lines.append("- Review SSH config for root login / password auth policy hardening.")
    lines.append("- Correlate the same IPs across other logs (firewall, IDS, mail).")
    lines.append("- Check for post-exploitation activity: new users, cron jobs, outbound connections.")
    lines.append("- Patch and harden exposed web endpoints implicated in the events.")
    lines.append("")
    lines.append("---")
    lines.append(
        f"_Generated locally by the AI Threat Intelligence Agent. "
        f"All processing occurred on the host running this tool._"
    )
    lines.append("")
    return "\n".join(lines)


def save_report(markdown: str, output_path: Path | str) -> Path:
    """Write the report to disk, creating parent directories as needed."""
    target = Path(output_path)
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_text(markdown, encoding="utf-8")
    return target