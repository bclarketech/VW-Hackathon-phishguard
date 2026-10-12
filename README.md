# 🛡️ PhishGuard

A lightweight, explainable **phishing email analyzer**. Paste a suspicious email and get a
0–100 risk score with a plain-English list of exactly *why* it looks phishy.

Built as a classroom / hackathon project to demonstrate how phishing signals can be detected
with transparent heuristics instead of a black-box model.

## What it detects

| Category | Examples |
|---|---|
| **Sender tricks** | Brand in display name but unrelated sender domain, free-mail senders, lookalike domains (`paypa1-login.com`) |
| **URL tricks** | Raw IP hosts, punycode/IDN domains, deep subdomains, misleading `@`, `http://` links |
| **Link text mismatch** | `<a href="http://evil.com">https://paypal.com</a>` |
| **Language** | Urgency, threats of suspension, credential/SSN requests, fake security alerts, prize/advance-fee bait |
| **Other** | Generic greetings, suspicious attachment types |

Each finding is weighted (high/medium/low), summed into a **0–100 score**, and mapped to a
verdict: `likely_safe` · `suspicious` · `likely_phishing`.

## Quick start (run locally)

```bash
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt

# Development (debug OFF):
python app.py            # serves on http://127.0.0.1:8000

# Production-style:
gunicorn -w 2 -b 127.0.0.1:8000 app:app
```

Open <http://127.0.0.1:8000> and click **"Load a phishing sample"** to see it in action.

## Run the tests

```bash
python -m unittest discover -s tests -v
```

## Design & security notes

- **No storage.** Pasted emails are analyzed in memory only — nothing is written to disk,
  logged, or transmitted.
- **Debug mode stays off.** `app.py` runs `debug=False`, and the intended production command is
  `gunicorn`. The interactive Werkzeug debugger is a remote-code-execution risk if exposed.
- **Bounded input.** Pastes are capped at 50,000 characters to keep memory use predictable.
- **Deterministic & offline.** No external API calls during analysis; the same input always
  yields the same report.

> ⚠️ PhishGuard is a **teaching tool**, not a production mail gateway. It should complement —
> not replace — real email authentication (SPF/DKIM/DMARC) and gateway filtering.

## Project layout

```
phishguard/
├── app.py              # Flask routes (no debug, no storage)
├── analyzer.py         # Heuristic detection engine
├── templates/
│   └── index.html      # UI
├── static/
│   ├── style.css
│   └── app.js          # Score-ring animation + demo sample
├── tests/
│   └── test_analyzer.py
├── requirements.txt
└── README.md
```

## Future improvements

- Parse real email headers (SPF/DKIM/DMARC results) from raw `.eml` input
- URL reputation lookup (with caching) for live domain checks
- Containerized deployment (Docker + Kubernetes) behind a Cloudflare Tunnel
- Machine-learning classifier trained on a public phishing corpus
