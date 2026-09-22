# AI Threat Intelligence Agent

Analyze **local security logs** (SSH `auth.log`, Nginx `access.log`) with a **local Ollama LLM** acting as a SOC analyst — and get a structured Markdown **incident report**.

Everything runs on your machine: log parsing, LLM inference, and report generation. **No log data ever leaves your host.**

## Architecture

```
                          LOCAL MACHINE — nothing leaves this box
┌──────────────────────────────────────────────────────────────────────────┐
│                                                                          │
│  SSH auth.log ──┐                                                       │
│                 ├──► src/log_parser.py ──► suspicious events (LogEntry)  │
│  Nginx access   │        pattern-based,   │                              │
│  access.log  ───┘        offline          │                              │
│                                          ▼                              │
│                              ┌─────────────────────┐                    │
│                              │   src/ai_analyzer   │                    │
│                              │  SOC Analyst prompt │                    │
│                              └─────────┬───────────┘                    │
│                                        │ HTTP POST /api/generate         │
│                                        ▼                                │
│                              ┌─────────────────────┐                    │
│                              │   Ollama (local)    │◄─── llama3 etc.    │
│                              │ localhost:11434     │    pulled locally  │
│                              └─────────┬───────────┘                    │
│                                        │                                │
│                                        ▼                                │
│   main.py ──► src/report_generator.py ──► reports/incident_report_*.md  │
│                                                                          │
└──────────────────────────────────────────────────────────────────────────┘
```

## Features

- **Local-first threat parsing** — regex/pattern detection for both SSH and Nginx logs, fully offline:
  - SSH: failed passwords, invalid users, sudo auth failures, `POSSIBLE BREAK-IN` signals, max-auth-attempt errors, and **brute-force aggregation** per source IP (≥ 5 failures)
  - Nginx: SQL injection payloads, directory traversal, sensitive-file probes (`.env`, `.git/config`), user enumeration (`wp-json`), scanner user agents (sqlmap, nikto, ...), server errors, 404 probes, and **login-endpoint brute-force aggregation** (≥ 3 hits)
- **Local AI analysis** — prompts a locally hosted Ollama model with a Senior SOC Analyst system prompt for severity assessment, attack narrative, IoCs, hypotheses, and prioritized actions.
- **Structured Markdown reports** — executive summary, event table, AI analysis, indicators, and recommended actions.
- **Graceful offline operation** — if Ollama is unreachable or the model is missing, the tool still produces a report with an explicit "AI analysis unavailable" notice.

## Requirements

- Python 3.10+
- [Ollama](https://ollama.com) running locally (`ollama serve`), with a model pulled (default: `llama3`)

## Setup

```bash
# 1. Python environment
python -m venv .venv
source .venv/bin/activate        # Windows: .venv\Scripts\activate
pip install -r requirements.txt

# 2. Local LLM via Ollama
ollama pull llama3               # or any model, e.g. llama3.2:3b, qwen2.5:7b
```

## Usage

```bash
# Analyze an SSH auth.log (network auth failures, brute force)
python main.py --log-file data/samples/ssh_auth.log

# Analyze an Nginx access.log with a specific local model
python main.py --log-file data/samples/nginx_access.log --model llama3.2:3b

# Custom report path
python main.py --log-file data/samples/ssh_auth.log --output reports/ssh_incident.md
```

### CLI options

| Option | Description | Default |
|---|---|---|
| `--log-file` | Path to an SSH `auth.log` or Nginx `access.log` (required) | — |
| `--model` | Ollama model to use for analysis | `llama3` |
| `--output` | Markdown report output path | `reports/incident_report_<timestamp>.md` |

### Example run

```text
$ python main.py --log-file data/samples/nginx_access.log --model llama3.2:3b

[*] Parsed data/samples/nginx_access.log: 15 suspicious event(s)
    - web_login: 3
    - sql_injection: 3
    - directory_traversal: 2
    - sensitive_file: 2
    - scan_ua: 1
    - probe_404: 1
    - user_enumeration: 1
    - server_error: 1
    - web_bruteforce: 1
[*] Asking local Ollama model 'llama3.2:3b' to analyze...
[*] AI analysis received.
[+] Report written to reports/incident_report_20260922_191121.md
```

The report contains an executive summary, a full suspicious-event table, the model's SOC analysis (severity, attack narrative, indicators of compromise, hypotheses, recommended actions), an indicators watchlist, and prioritized defensive actions.

## Privacy

This tool is designed for **private, on-host threat analysis**:

- Log files are parsed **locally**; nothing is shipped to a cloud service.
- LLM inference runs in **your local Ollama server** (`http://localhost:11434`); prompts are generated from your logs on the fly and never transmitted off-machine.
- Reports are written **to your local disk** only.
- The only network connection used is the loopback call to Ollama.

Bring your own logs, keep your data yours.

## Project Structure

```
ai-threat-intelligence-agent/
├── main.py                  # CLI entry point
├── requirements.txt         # Runtime dependencies
├── requirements-dev.txt     # Test dependencies
├── pytest.ini
├── src/
│   ├── log_parser.py        # Suspicious event extraction (SSH + Nginx)
│   ├── ai_analyzer.py       # Local Ollama integration (SOC Analyst prompt)
│   └── report_generator.py  # Markdown incident report formatting
├── data/samples/            # Realistic sample logs for testing/demo
│   ├── ssh_auth.log
│   └── nginx_access.log
├── reports/                 # Generated incident reports (gitignored)
└── tests/                   # pytest suite (35 tests: parser, analyzer, report, CLI)
```

## Development

```bash
pip install -r requirements-dev.txt
python -m pytest        # full suite
```

Detection thresholds are tunable constants in `src/log_parser.py`:
`BRUTE_FORCE_THRESHOLD` (default 5) and `WEB_BRUTE_FORCE_THRESHOLD` (default 3).