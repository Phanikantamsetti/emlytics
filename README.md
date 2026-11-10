# EMLYTICS

**EMLYTICS** is a security analysis workbench for public-domain posture checks, email triage, and indicator review. It summarizes readable email bodies, explains phishing-like and bulk/spam-like signals, and provides URL, HTML, PDF, and domain-comparison workflows.

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
- Run an explicit, read-only public-domain posture check covering DNS A/AAAA/MX/NS/TXT/CAA and DMARC records, DNSSEC validation status, RDAP registration data, verified TLS certificates, and common HTTP security headers. Public-domain checks do not follow redirects or access private/reserved IP addresses.
- Compare two public domains using the same posture checks and inspect URLs for common brand lookalikes without visiting them.
- Optionally check up to five extracted URLs/domains with VirusTotal and URLScan.io after explicitly opting in. URLScan.io can also submit URLs for new public scans after a second confirmation.
- Optionally save a minimal scan summary to browser-local history. History is off by default and never stores email contents.
- Optionally create an account to save minimized reports, manage a personal domain watchlist, and manually refresh its checks.
- Optionally ask scan-grounded AI questions after explicit consent. Raw email bodies and headers are excluded from the evidence sent to the configured AI provider.
- Export the current structured findings and report as JSON.
- In local mode, the server binds to `127.0.0.1`. Reputation lookups are opt-in. The domain posture check separately contacts public DNS/RDAP services and makes a read-only HTTPS HEAD request after explicit consent.
- Email, URL, domain, and HTML checks use the Python standard library. PDF text extraction requires the optional `pypdf` dependency.

## Optional reputation lookups

External lookups are disabled unless at least one provider key is configured on the server:

- `EMLYTICS_VIRUSTOTAL_API_KEY`
- `EMLYTICS_URLSCAN_API_KEY`

The app owner sets these as environment variables for a local run, or as secret environment variables in the hosting provider dashboard. End users do not enter provider keys. Never put API keys in browser code or commit them. Either provider can be configured independently, and the interface reports which providers are available.

The first checkbox sends only up to five extracted URLs/domains—not the email body, headers, HTML/PDF contents, or attachments—to configured providers for existing reports. Either provider can be configured independently. The separate URLScan checkbox and browser confirmation submit extracted URLs for new **public** scans; URLScan's scanner visits the destinations and makes them visible in public search. Use only indicators you are authorized to share. Provider quotas and terms apply. Lookups can fail or be incomplete and do not establish that an indicator is safe.

The domain posture check is a separate, explicit opt-in. It sends the entered domain to Cloudflare's public DNS-over-HTTPS service and RDAP registration service, and makes a single HTTPS `HEAD /` request to the domain's public IP. DNS checks include A/AAAA/MX/NS/TXT/CAA and DMARC records, with the resolver's DNSSEC validation flag; the report explains SPF and DMARC policies when present. It does not download the page body, follow redirects, or scan for vulnerabilities. DNS/registration information may be incomplete, and service operators can receive request metadata. The configuration score is explainable and is not an AI verdict, reputation score, or proof of trustworthiness.

## Optional accounts and AI Q&A

Accounts and AI Q&A are disabled until configured by the site owner. Visitors do not need to provide their own API keys. The site owner is responsible for provider credentials, quotas, billing, and terms.

1. Create a Supabase project and run [`supabase_schema.sql`](./supabase_schema.sql) in its SQL editor. The schema grants table access only to authenticated users and uses row-level security so each user can access only their own saved reports and watchlist entries.
2. Set `EMLYTICS_SUPABASE_URL` and `EMLYTICS_SUPABASE_ANON_KEY` from the Supabase project settings. Use the public anon/publishable key—not a service-role key. Authentication, report storage, and watchlists are unavailable when either setting is missing.
3. To enable AI Q&A, set `EMLYTICS_AI_API_KEY` for the server. The default OpenAI-compatible endpoint and model target Gemini (`EMLYTICS_AI_BASE_URL` and `EMLYTICS_AI_MODEL` can override them). The AI receives the user's question plus a limited allowlist of report findings; raw message bodies, full headers, and attachments are excluded. The provider may process the submitted evidence and question.
4. Configure the Supabase project's allowed site URL and email confirmation/password recovery settings for the deployed app. No Supabase credentials are needed in browser code.

For a local PowerShell run, set the values in the same terminal before starting the server:

```powershell
$env:EMLYTICS_SUPABASE_URL = "https://your-project.supabase.co"
$env:EMLYTICS_SUPABASE_ANON_KEY = "your-public-anon-key"
$env:EMLYTICS_AI_API_KEY = "your-provider-key"
python app.py
```

Saving is explicit: the app stores a minimized report only when the signed-in user chooses **Save to account**. Email bodies, raw headers, and attachments are not retained in saved email reports. Watchlist checks are manual and limited to 10 domains; they are not background monitoring. Users can delete saved reports and watchlist entries from the app.

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

The tests exercise email summaries and assessments, URL and HTML parsing, offline hostname checks, opt-in domain posture scoring and API behavior, provider response handling, PDF extraction flow/validation, and input limits. They do not require network access. Without the optional `pypdf` dependency, a test also verifies that PDF input receives a clear setup error.

## How the score works

EMLYTICS adds fixed points for selected warning signals and caps the result at 100. The current labels are **low** (0–19), **medium** (20–49), and **high** (50–100). The score is a triage aid, not a probability or verdict. Authentication values may be absent, and legitimate messages can trigger heuristics.

## Free-tier deployment options

The included `render.yaml` configures a Render Free web service:

1. Push this project to a GitHub repository. Keep `.venv` out of the repository; the included `.gitignore` excludes it.
2. In Render, choose **New → Blueprint**, connect the repository, and deploy the `render.yaml` blueprint.
3. Render will provide the public URL after the service finishes building. Free services may spin down after inactivity and take time to wake up; check the current plan limits before relying on a public service.
4. Set any desired VirusTotal/URLScan.io provider keys, Supabase settings, and AI provider key as secret environment variables in the Render service settings. Accounts and AI Q&A remain unavailable until their respective server settings are configured.

### Publish on Vercel (selected option)

The local address `http://127.0.0.1:8000` is reachable only from the computer running the app. A Vercel deployment gives the app a public HTTPS address that can be opened from other devices and locations.

1. Push the project to the GitHub repository. Vercel deploys committed changes; uncommitted local edits are not included.
2. Sign in to Vercel, select **Add New → Project**, import `Phanikantamsetti/emlytics`, and keep the repository root as the project root. Vercel detects the Flask app from `requirements.txt` and `app.py`; keep the default Python build settings.
3. Before deploying, add any optional server-side variables under the project's **Settings → Environment Variables**. Use only the variables documented above; never add a Supabase service-role key or put provider secrets in frontend code. Features whose credentials are omitted stay disabled.
4. Deploy. Vercel assigns a public `*.vercel.app` address; use the project's production domain for a stable link across subsequent production deployments. You can connect a custom domain you own in **Settings → Domains**.
5. Test the public URL on a separate device/network. Verify `/api/config`, email analysis, and one domain scan. If enabling Supabase, add the deployed address to Supabase's allowed site and redirect URLs.

Vercel Hobby is a free option subject to its current eligibility, usage quotas, and terms. It is serverless, not a continuously running machine: after idle periods a request may take longer to start, and plan/function limits apply. A free deployment provides a public address, but cannot promise uninterrupted or always-warm availability. For a service that must stay responsive continuously, use hosting with an appropriate paid uptime commitment. Review current Vercel limits and terms before relying on the demo.

The included `vercel.json` configures the Flask function and bundles the app's HTML, CSS, and JavaScript assets. The Render blueprint remains available as an alternative; Render Free may spin down after inactivity.

On either host, submissions are processed by the hosting provider's server. The analyzer does not automatically retain email submissions, but hosting providers may process connection and service logs. Submit only synthetic or sanitized samples; do not use a public demo for personal, work, or confidential email. If provider keys are configured, anyone can trigger lookups using the server's provider quota; URLScan submissions are public and visit the targets. Domain posture and comparison checks contact public DNS/RDAP services and the specified hosts. When accounts are enabled, only reports explicitly saved by the user and watchlist data are stored in Supabase; the AI provider may process scan evidence and questions only after the user opts in. A public URL lets anyone access the analyzer and is intended for demonstration, not production or private case handling.

## Safety and limitations

- Only inspect email files that you are authorized to handle. Use sanitized samples in public demos.
- The tool does not execute, extract, or upload attachments; it only reads MIME metadata and filenames.
- Links are displayed as text and are never visited by offline analysis. Opting into new URLScan scans is different: its remote scanner visits submitted URLs and public submissions are searchable. Opting into a domain posture check makes a single HTTPS HEAD request to the supplied public host.
- Reputation lookups share selected URL/domain indicators with external providers only after opt-in. The email message and attachment contents are not sent to those providers by this feature.
- Domain posture scores cover only the displayed DNS, email-domain policy, certificate, and security-header checks. They do not measure site legitimacy, exploitability, or malicious content.
- Local mode is bound to loopback. The public sample demo uses Waitress behind the hosting provider's HTTPS proxy and enforces the request-size limit; it has no user accounts or private access controls.
- Heuristics can produce false positives and false negatives. Confirm suspicious messages using your organization’s established incident-response process.

## Suggested resume entry

**EMLYTICS — Local Email Threat-Triage Tool** | Python, HTTP, HTML/CSS/JavaScript

- Built a local-first email and indicator triage workbench that summarizes email, HTML, and PDF text and explains suspicious signals.
- Surfaced SPF/DKIM/DMARC results, sender mismatches, URL patterns, hostname syntax cues, and attachment extensions.
- Implemented bounded email/URL/HTML/PDF analysis, explicit opt-in domain posture checks, and optional consent-based VirusTotal/URLScan.io intelligence.
- Created a responsive browser interface and unit tests for core triage indicators.

Keep the bullets accurate to your own contribution and adjust them to match what you can confidently explain in an interview.

## Ideas for future work

- Add configurable rule weights and analyst feedback.
- Add safe, offline sample `.eml` fixtures and more parser edge-case tests.
- Add optional export of a redacted JSON report.

## Repository presentation

Suggested GitHub description: **EMLYTICS — local-first email threat triage with explainable phishing/spam signals, body summaries, and `.eml` analysis.**

Suggested topics: `email-security`, `phishing-analysis`, `cybersecurity`, `python`, `threat-triage`, `blue-team`
