# EMLYTICS

**EMLYTICS** is a local-first security triage workbench. It summarizes readable email bodies, classifies phishing-like and bulk/spam-like signals with supporting evidence, and provides offline inspection of submitted URLs, hostnames, HTML source, and PDF text/link annotations.

> This is a portfolio and learning project—not a malware sandbox, email gateway, or substitute for your organization’s security controls. A low score does not mean a message is safe.

## Features

- Analyze a local `.eml` file or paste raw email source.
- Review SPF, DKIM, and DMARC values when present in `Authentication-Results`.
- Inspect To, Cc, date, Return-Path, Message-ID, and a bounded Received-header trace.
- Add optional report source, case priority, impacted account/team, and analyst notes to the on-page triage summary. These values remain in the browser and do not affect scoring.
- Flag a differing `From` and `Reply-To` domain.
- Add low-confidence review cues for mismatched `From`/`Return-Path` domains, a display name that explicitly claims a different domain, and repeated `Received` relay hosts. These are not proof of spoofing; legitimate forwarding and routing can produce mismatches.
- Inventory HTTP/HTTPS links and highlight plaintext HTTP, IP-address hosts, punycode hostnames, and common URL shorteners.
- List attachment names and MIME types; flag a set of commonly abused extensions without opening or extracting any attachment.
- Get a short extractive brief of the message body.
- See phishing-like, bulk/spam-like, suspicious, or no-strong-indicators assessments with supporting email signals and separate heuristic scores.
- Inspect a submitted HTTP/HTTPS URL without visiting it, or review a hostname locally for basic syntax, direct-IP input, and punycode labels.
- Parse HTML visibly rendered text and links without executing scripts or visiting destinations.
- Optionally extract text, document metadata, and HTTP/HTTPS link annotations from PDFs using `pypdf`; scanned PDFs are not OCR-processed.
- See a simple, explainable risk score and finding details.
- In local mode, the server binds to `127.0.0.1`. Analysis does not save submissions or contact DNS, WHOIS, URLscan.io, VirusTotal, or other external services.
- Email, URL, domain, and HTML checks use the Python standard library. PDF text extraction requires the optional `pypdf` dependency.

## Requirements

- Python 3.10 or newer
- A modern web browser

## Run locally

From this project directory:

```powershell
python app.py
```

Open <http://127.0.0.1:8000> in your browser. Stop the server with `Ctrl+C`. If port 8000 is already in use, choose another loopback port in PowerShell, for example `$env:EMLYTICS_PORT = 8001; python app.py`, and open <http://127.0.0.1:8001>. Email source and text/HTML inputs are limited to 1 MB. PDF support is optional; to enable it, install the declared dependency before starting the app:

```powershell
python -m pip install -r requirements.txt
```

PDFs are limited to 5 MB and 100 pages. Use a sample or sanitized content; do not paste sensitive production material into a demo environment.

## Run tests

```powershell
python -m unittest discover -s tests -v
```

The tests exercise email summaries and assessments, URL and HTML parsing, offline hostname checks, PDF extraction flow/validation, and input limits. They do not require network access. Without the optional `pypdf` dependency, a test also verifies that PDF input receives a clear setup error.

## How the score works

EMLYTICS adds fixed points for selected warning signals and caps the result at 100. The current labels are **low** (0–19), **medium** (20–49), and **high** (50–100). The score is a triage aid, not a probability or verdict. Authentication values may be absent, and legitimate messages can trigger heuristics.

## Public sample demo deployment

The included `render.yaml` can be used to deploy a public sample-only demo to Render:

1. Push this project to a GitHub repository. Keep `.venv` out of the repository; the included `.gitignore` excludes it.
2. In Render, choose **New → Blueprint**, connect the repository, and deploy the `render.yaml` blueprint.
3. Render will provide the public URL after the service finishes building. Free services may sleep when idle and take a little time to wake up.

The public demo processes submissions on the hosting provider's server. The app does not intentionally save email submissions, but hosting providers may process connection and service logs. The interface displays a warning; submit only synthetic or sanitized samples. Do not use the public demo for personal, work, or confidential email. A public URL lets anyone access the analyzer and is intended for demonstration, not production or private case handling.

## Safety and limitations

- Only inspect email files that you are authorized to handle. Use sanitized samples in public demos.
- The tool does not execute, extract, or upload attachments; it only reads MIME metadata and filenames.
- Links are displayed as text and are never visited by the analyzer.
- Local mode is bound to loopback. The public sample demo uses Waitress behind the hosting provider's HTTPS proxy and enforces the request-size limit; it has no user accounts or private access controls.
- Heuristics can produce false positives and false negatives. Confirm suspicious messages using your organization’s established incident-response process.

## Suggested resume entry

**EMLYTICS — Local Email Threat-Triage Tool** | Python, HTTP, HTML/CSS/JavaScript

- Built a local-first email and indicator triage workbench that summarizes email, HTML, and PDF text and explains suspicious signals.
- Surfaced SPF/DKIM/DMARC results, sender mismatches, URL patterns, hostname syntax cues, and attachment extensions.
- Implemented bounded offline URL/domain/HTML/PDF analysis, visible evidence, and size/page limits; external reputation services are not contacted.
- Created a responsive browser interface and unit tests for core triage indicators.

Keep the bullets accurate to your own contribution and adjust them to match what you can confidently explain in an interview.

## Ideas for future work

- Add configurable rule weights and analyst feedback.
- Add safe, offline sample `.eml` fixtures and more parser edge-case tests.
- Add optional export of a redacted JSON report.
- Consider optional threat-intelligence integrations only with explicit per-query consent, clear disclosure of what data leaves the device, and secure API-key handling.

## Repository presentation

Suggested GitHub description: **EMLYTICS — local-first email threat triage with explainable phishing/spam signals, body summaries, and `.eml` analysis.**

Suggested topics: `email-security`, `phishing-analysis`, `cybersecurity`, `python`, `threat-triage`, `blue-team`
