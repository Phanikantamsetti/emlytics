from __future__ import annotations

import base64
import binascii
import ipaddress
import json
import os
import re
from collections import Counter
from email import policy
from email.parser import BytesParser
from email.utils import parseaddr
from html.parser import HTMLParser
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from io import BytesIO
from pathlib import Path
from urllib.parse import urlsplit

from flask import Flask, jsonify, request, send_from_directory
from werkzeug.exceptions import BadRequest, RequestEntityTooLarge

try:
    from pypdf import PdfReader
except ImportError:
    PdfReader = None

ROOT = Path(__file__).resolve().parent
MAX_EMAIL_BYTES = 1_000_000
MAX_PDF_BYTES = 5_000_000
MAX_PDF_PAGES = 100
MAX_TOOL_REQUEST_BYTES = 7_000_000
RISKY_EXTENSIONS = {
    ".ade", ".adp", ".bat", ".chm", ".cmd", ".com", ".cpl", ".dll", ".exe",
    ".hta", ".img", ".iso", ".js", ".jse", ".lnk", ".msi", ".ps1", ".scr",
    ".sct", ".vbe", ".vbs", ".wsf", ".wsh", ".docm", ".xlsm", ".pptm",
}
SHORTENERS = {"bit.ly", "t.co", "tinyurl.com", "goo.gl", "ow.ly", "is.gd", "buff.ly"}
URL_RE = re.compile(r"https?://[^\s<>\"')\]]+", re.IGNORECASE)
EMAIL_RE = re.compile(r"[A-Z0-9.!#$%&'*+/=?^_`{|}~-]+@[A-Z0-9](?:[A-Z0-9.-]*[A-Z0-9])?", re.IGNORECASE)
web_app = Flask(__name__)
web_app.config["MAX_CONTENT_LENGTH"] = MAX_TOOL_REQUEST_BYTES


def _processing_location() -> str:
    return "the hosted server" if os.environ.get("EMLYTICS_PUBLIC_DEMO") == "1" else "this device"


@web_app.after_request
def add_security_headers(response):
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["X-Frame-Options"] = "DENY"
    response.headers["Referrer-Policy"] = "no-referrer"
    response.headers["Content-Security-Policy"] = "default-src 'self'; script-src 'self'; style-src 'self'; base-uri 'none'; frame-ancestors 'none'; form-action 'self'"
    response.headers["Cache-Control"] = "no-store"
    return response


@web_app.get("/")
def home_page():
    return send_from_directory(ROOT, "index.html")


@web_app.get("/styles.css")
def styles_asset():
    return send_from_directory(ROOT, "styles.css")


@web_app.get("/app.js")
def script_asset():
    return send_from_directory(ROOT, "app.js")


@web_app.get("/api/config")
def public_config():
    return jsonify({"public_demo": os.environ.get("EMLYTICS_PUBLIC_DEMO") == "1"})


@web_app.post("/api/analyze")
@web_app.post("/api/analyze-input")
def analyze_api():
    if request.content_length is None or request.content_length <= 0:
        return jsonify({"error": "Request is empty or exceeds the 7 MB request limit."}), 413
    try:
        payload = request.get_json()
        result = _analyze_request(request.path, payload)
    except BadRequest:
        return jsonify({"error": "Invalid JSON request."}), 400
    except binascii.Error:
        return jsonify({"error": "Invalid JSON or base64 request."}), 400
    except ValueError as error:
        return jsonify({"error": str(error)}), 400
    return jsonify(result)


@web_app.errorhandler(RequestEntityTooLarge)
def request_too_large(_error):
    return jsonify({"error": "Request is empty or exceeds the 7 MB request limit."}), 413


class LinkParser(HTMLParser):
    def __init__(self) -> None:
        super().__init__(convert_charrefs=True)
        self.links: list[tuple[str, str]] = []
        self._anchor_text: list[str] | None = None
        self._anchor_url: str | None = None
        self.visible_text: list[str] = []
        self._hidden_depth = 0

    def handle_starttag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
        if tag.lower() in {"script", "style"}:
            self._hidden_depth += 1
            return
        if tag.lower() == "a" and self._hidden_depth == 0:
            self._anchor_url = dict(attrs).get("href")
            self._anchor_text = []

    def handle_data(self, data: str) -> None:
        if self._hidden_depth:
            return
        self.visible_text.append(data)
        if self._anchor_text is not None:
            self._anchor_text.append(data)

    def handle_endtag(self, tag: str) -> None:
        if tag.lower() in {"script", "style"} and self._hidden_depth:
            self._hidden_depth -= 1
        if tag.lower() == "a" and self._anchor_text is not None:
            if self._anchor_url:
                self.links.append((self._anchor_url.strip(), " ".join(self._anchor_text).strip()))
            self._anchor_text = None
            self._anchor_url = None


def _extract_body(message) -> tuple[str, list[tuple[str, str]]]:
    text_parts: list[str] = []
    html_parts: list[str] = []
    for part in message.walk():
        if part.is_multipart() or part.get_content_disposition() == "attachment":
            continue
        content_type = part.get_content_type()
        if content_type not in {"text/plain", "text/html"}:
            continue
        try:
            content = part.get_content()
        except (LookupError, UnicodeError, KeyError):
            payload = part.get_payload(decode=True) or b""
            content = payload.decode(part.get_content_charset() or "utf-8", errors="replace")
        if not isinstance(content, str):
            continue
        if content_type == "text/html":
            html_parts.append(content)
        else:
            text_parts.append(content)

    links: list[tuple[str, str]] = []
    html_text_parts: list[str] = []
    for content in html_parts:
        parser = LinkParser()
        try:
            parser.feed(content)
        except Exception:
            pass
        links.extend(parser.links)
        html_text_parts.append(" ".join(parser.visible_text))
    combined = "\n".join(text_parts + html_text_parts)
    links.extend((match.group(0).rstrip(".,;:"), "") for match in URL_RE.finditer(combined))
    unique: dict[str, tuple[str, str]] = {}
    for url, label in links:
        if url.lower().startswith(("http://", "https://")):
            unique.setdefault(url, (url, label))
    return combined, list(unique.values())


def _domain(address: str) -> str:
    return address.rsplit("@", 1)[-1].strip().strip("<>").lower() if "@" in address else ""


def _addresses(value: str | None) -> list[str]:
    return [match.lower() for match in EMAIL_RE.findall(value or "")]


def _display_name_domain(display_name: str) -> str:
    email_domains = [_domain(address) for address in _addresses(display_name)]
    if email_domains:
        return email_domains[0]
    matches = re.findall(r"(?<![\w.-])(?:[a-z0-9](?:[a-z0-9-]*[a-z0-9])?\.)+[a-z]{2,}(?![\w.-])", display_name, re.IGNORECASE)
    return matches[0].lower().rstrip(".") if matches else ""


def _repeated_received_by(received_headers: list[str]) -> str:
    seen: set[str] = set()
    for header in received_headers:
        match = re.search(r"\bby\s+([a-z0-9](?:[a-z0-9.-]*[a-z0-9])?)", header, re.IGNORECASE)
        if not match:
            continue
        host = match.group(1).lower().rstrip(".")
        if host in seen:
            return host
        seen.add(host)
    return ""


def _summarize_body(body: str) -> str:
    normalized = re.sub(r"\s+", " ", body).strip()
    if not normalized:
        return "No readable message body was found."

    sentences = [sentence.strip() for sentence in re.split(r"(?<=[.!?])\s+", normalized) if sentence.strip()]
    if len(sentences) <= 3:
        selected = sentences
    else:
        stop_words = {"the", "and", "for", "are", "you", "your", "this", "that", "with", "from", "have", "has", "was", "were", "will", "would", "can", "could", "our", "their", "they", "them", "then", "than", "into", "about", "there", "here", "what", "when", "where", "which", "while", "been", "being", "but", "not", "all", "any", "one", "who", "how", "its", "it", "a", "an", "to", "of", "in", "on", "at", "by", "as", "is", "be", "or", "if", "we", "i", "he", "she", "do", "does", "did", "so", "no", "up", "out"}
        tokens_by_sentence = [re.findall(r"[a-z0-9']+", sentence.lower()) for sentence in sentences]
        frequencies = Counter(token for tokens in tokens_by_sentence for token in set(tokens) if len(token) > 2 and token not in stop_words)
        important = {"account", "payment", "invoice", "password", "security", "delivery", "meeting", "action", "verify", "confirm", "deadline", "transfer", "click", "attachment", "subscription", "order", "refund", "review"}
        scored = []
        for index, (sentence, tokens) in enumerate(zip(sentences, tokens_by_sentence)):
            meaningful = [token for token in set(tokens) if len(token) > 2 and token not in stop_words]
            score = sum(1 + min(frequencies[token], 4) for token in meaningful) / max(len(tokens), 1) ** 0.5
            score += 1.5 * sum(1 for token in set(tokens) if token in important)
            if index == 0:
                score += 0.75
            scored.append((score, index, sentence))
        selected = [sentence for _, _, sentence in sorted(sorted(scored, reverse=True)[:3], key=lambda item: item[1])]

    brief = " ".join(selected)
    if len(brief) > 600:
        brief = brief[:597].rsplit(" ", 1)[0] + "…"
    return brief


def _classify_email(message, authentication: dict[str, str], sender_domain: str, reply_domain: str, return_path_domain: str, display_name_domain: str, repeated_received_by: str, links: list[dict], attachments: list[dict], body: str, risk_score: int) -> dict:
    evidence: list[dict[str, str | int]] = []
    phishing_score = 0
    spam_score = 0

    def add_signal(category: str, title: str, detail: str, points: int) -> None:
        nonlocal phishing_score, spam_score
        evidence.append({"category": category, "title": title, "detail": detail, "points": points})
        if category == "phishing":
            phishing_score += points
        else:
            spam_score += points

    for method, points in (("dmarc", 20), ("spf", 10), ("dkim", 10)):
        result = authentication[method]
        if result in {"fail", "softfail", "permerror"}:
            add_signal("phishing", f"{method.upper()} {result}", f"The message's Authentication-Results header reports {method}={result}.", points)

    if sender_domain and reply_domain and sender_domain != reply_domain:
        add_signal("phishing", "Sender and reply domains differ", f"The From domain is {sender_domain}, while Reply-To uses {reply_domain}.", 20)

    if sender_domain and return_path_domain and sender_domain != return_path_domain:
        add_signal("phishing", "From and Return-Path domains differ", f"The From domain is {sender_domain}, while Return-Path uses {return_path_domain}. Forwarding and mailing services can also cause this difference.", 5)

    if sender_domain and display_name_domain and sender_domain != display_name_domain:
        add_signal("phishing", "Display name claims a different domain", f"The From display name mentions {display_name_domain}, but the sender address uses {sender_domain}.", 5)

    if repeated_received_by:
        add_signal("phishing", "Repeated Received relay", f"The Received trace lists {repeated_received_by} as a receiving host more than once. This can indicate a routing loop, but legitimate mail routing can also repeat hosts.", 5)

    risky_hosts: set[str] = set()
    for link in links:
        host = str(link["host"])
        if link["suspicious"] and host not in risky_hosts:
            risky_hosts.add(host)
            add_signal("phishing", "Unusual link destination", f"A message link uses the suspicious host {host} (such as an IP address, punycode name, or URL shortener).", 15)
        if link["insecure"]:
            add_signal("phishing", "Unencrypted HTTP link", f"A message link does not use HTTPS: {link['url']}", 5)

    body_text = re.sub(r"\s+", " ", body)
    if re.search(r"\b(urgent|immediately|within\s+\d+\s+hours|account\s+(?:will\s+be\s+)?suspended|unusual\s+activity|act\s+now|final\s+notice)\b", body_text, re.IGNORECASE):
        add_signal("phishing", "Urgency or threat language", "The body pressures the reader to act quickly or warns of a negative consequence.", 8)
    if re.search(r"\b(?:verify|confirm|reset|update|validate|restore)\b.{0,60}\b(?:account|password|credentials|mailbox|login)\b|\b(?:account|password|credentials|mailbox|login)\b.{0,60}\b(?:verify|confirm|reset|update|validate|restore)\b", body_text, re.IGNORECASE):
        add_signal("phishing", "Sensitive account action requested", "The body asks the reader to verify, reset, or update account or sign-in information.", 15)

    for attachment in attachments:
        if attachment["risky"]:
            add_signal("phishing", "Potentially risky attachment type", f"The attachment {attachment['name']} uses a file extension commonly abused in phishing; its contents were not opened.", 8)

    if message.get_all("List-Unsubscribe", []):
        add_signal("spam", "Bulk-mail unsubscribe header", "List-Unsubscribe is present, which is common in newsletters and marketing email but does not prove a message is unsolicited.", 2)
    if str(message.get("Precedence", "")).lower() in {"bulk", "list", "junk"}:
        add_signal("spam", "Bulk-mail precedence header", "The Precedence header marks this message as bulk, list, or junk mail.", 2)
    if re.search(r"\b(limited[- ]time offer|special offer|discount|clearance|buy now|order today|free trial|claim your prize|unsubscribe)\b", body_text, re.IGNORECASE):
        add_signal("spam", "Promotional wording", "The body contains common marketing or bulk-message wording; this alone does not establish that the message is unwanted.", 3)

    phishing_score = min(phishing_score, 100)
    spam_score = min(spam_score, 100)
    if phishing_score >= 30:
        category, label = "phishing", "Phishing-like"
    elif spam_score >= 4 and phishing_score < 20:
        category, label = "spam", "Bulk or spam-like"
    elif phishing_score >= 10 or spam_score >= 3 or risk_score >= 20:
        category, label = "suspicious", "Suspicious — review"
    else:
        category, label = "clear", "No strong indicators found"

    return {
        "category": category,
        "label": label,
        "phishing_score": phishing_score,
        "spam_score": spam_score,
        "evidence": evidence,
        "note": "Rule-based triage, not a verified verdict. Bulk and promotional cues do not prove unsolicited spam; no strong indicators does not prove a message is safe.",
    }


def analyze_email(raw_email: str) -> dict:
    raw_bytes = raw_email.encode("utf-8", errors="replace")
    if len(raw_bytes) > MAX_EMAIL_BYTES:
        raise ValueError("Email exceeds the 1 MB analysis limit.")
    message = BytesParser(policy=policy.default).parsebytes(raw_bytes)

    from_value = str(message.get("From", ""))
    reply_to = str(message.get("Reply-To", ""))
    return_path = str(message.get("Return-Path", ""))
    received_headers = [str(value) for value in message.get_all("Received", [])]
    sender_addresses = _addresses(from_value)
    reply_addresses = _addresses(reply_to)
    return_path_addresses = _addresses(return_path)
    sender_domain = _domain(sender_addresses[0]) if sender_addresses else ""
    reply_domain = _domain(reply_addresses[0]) if reply_addresses else ""
    return_path_domain = _domain(return_path_addresses[0]) if return_path_addresses else ""
    display_name = parseaddr(from_value)[0]
    display_name_domain = _display_name_domain(display_name)
    repeated_received_by = _repeated_received_by(received_headers)

    auth = {"spf": "unknown", "dkim": "unknown", "dmarc": "unknown"}
    auth_headers = " ".join(str(value) for value in message.get_all("Authentication-Results", []))
    for method, result in re.findall(r"\b(spf|dkim|dmarc)\s*=\s*(pass|fail|softfail|neutral|none|temperror|permerror)\b", auth_headers, re.IGNORECASE):
        auth[method.lower()] = result.lower()

    body, links = _extract_body(message)
    attachments: list[dict[str, str | bool]] = []
    for part in message.walk():
        filename = part.get_filename()
        if not filename and part.get_content_disposition() != "attachment":
            continue
        safe_name = Path(str(filename or "unnamed attachment").replace("\\", "/")).name
        extension = Path(safe_name).suffix.lower()
        attachments.append({
            "name": safe_name,
            "type": part.get_content_type(),
            "risky": extension in RISKY_EXTENSIONS,
        })

    findings: list[dict[str, str]] = []
    score = 0

    def add_finding(severity: str, title: str, detail: str, points: int) -> None:
        nonlocal score
        findings.append({"severity": severity, "title": title, "detail": detail})
        score += points

    for method, points in (("dmarc", 25), ("spf", 15), ("dkim", 15)):
        result = auth[method]
        if result in {"fail", "softfail", "permerror"}:
            add_finding("high" if method == "dmarc" else "medium", f"{method.upper()} reported {result}", f"Authentication-Results contains {method}={result}.", points)

    if sender_addresses and reply_addresses and reply_domain and sender_domain != reply_domain:
        add_finding("high", "From and Reply-To domains differ", f"From uses {sender_domain}; Reply-To uses {reply_domain}.", 20)

    if sender_domain and return_path_domain and sender_domain != return_path_domain:
        add_finding("low", "From and Return-Path domains differ", f"From uses {sender_domain}; Return-Path uses {return_path_domain}. Forwarding and mailing services can also cause this difference.", 5)

    if sender_domain and display_name_domain and sender_domain != display_name_domain:
        add_finding("low", "Display name claims a different domain", f"The From display name mentions {display_name_domain}, but the sender address uses {sender_domain}.", 5)

    if repeated_received_by:
        add_finding("low", "Repeated Received relay", f"The Received trace lists {repeated_received_by} as a receiving host more than once. This can indicate a routing loop, but legitimate mail routing can also repeat hosts.", 5)

    parsed_links: list[dict[str, str | bool]] = []
    seen_hosts: set[str] = set()
    for url, label in links:
        parsed = urlsplit(url)
        host = (parsed.hostname or "").lower().rstrip(".")
        if not host:
            continue
        try:
            is_ip = bool(re.fullmatch(r"(?:\d{1,3}\.){3}\d{1,3}", host))
        except ValueError:
            is_ip = False
        suspicious_host = host.startswith("xn--") or ".xn--" in host
        shortener = host in SHORTENERS
        insecure = parsed.scheme.lower() == "http"
        if insecure:
            add_finding("medium", "Unencrypted link", f"Link uses HTTP: {url}", 8)
        if is_ip:
            add_finding("high", "Link uses an IP address", f"Link points directly to {host}.", 15)
        if suspicious_host:
            add_finding("high", "Internationalized domain name", f"Link contains a punycode hostname: {host}.", 15)
        if shortener:
            add_finding("medium", "Shortened link", f"Destination is obscured by {host}.", 8)
        parsed_links.append({"url": url, "host": host, "insecure": insecure, "suspicious": is_ip or suspicious_host or shortener})
        seen_hosts.add(host)

    if not links and re.search(r"\b(urgent|verify your account|password expires|wire transfer|payment overdue)\b", body, re.IGNORECASE):
        add_finding("low", "Urgent language detected", "The message uses common urgency or payment-pressure wording; review it in context.", 5)

    for attachment in attachments:
        if attachment["risky"]:
            add_finding("high", "Potentially risky attachment", f"Attachment {attachment['name']} has a commonly abused file extension. It was not opened or extracted.", 20)

    score = min(score, 100)
    risk = "high" if score >= 50 else "medium" if score >= 20 else "low"
    classification = _classify_email(message, auth, sender_domain, reply_domain, return_path_domain, display_name_domain, repeated_received_by, parsed_links, attachments, body, score)
    return {
        "subject": str(message.get("Subject", "(no subject)")),
        "from": from_value or "(unknown sender)",
        "to": str(message.get("To", ""))[:1000],
        "cc": str(message.get("Cc", ""))[:1000],
        "reply_to": reply_to,
        "date": str(message.get("Date", ""))[:500],
        "return_path": return_path[:500],
        "message_id": str(message.get("Message-ID", ""))[:500],
        "received_hops": [value[:500] for value in received_headers[:10]],
        "received_hops_total": len(received_headers),
        "sender_domain": sender_domain or "unknown",
        "body_summary": _summarize_body(body),
        "classification": classification,
        "authentication": auth,
        "links": parsed_links,
        "link_domains": sorted(seen_hosts),
        "attachments": attachments,
        "findings": findings,
        "risk_score": score,
        "risk_level": risk,
        "disclaimer": "Heuristic triage only. A low score does not prove an email is safe; verify findings with trusted security tools.",
    }


def analyze_domain(value: str) -> dict:
    raw_host = value.strip().rstrip(".")
    if not raw_host or any(character in raw_host for character in "@:/?#\\\\") or any(character.isspace() for character in raw_host):
        raise ValueError("Provide a hostname only, without a URL scheme, path, or email address.")
    try:
        host = raw_host.encode("idna").decode("ascii").lower()
    except UnicodeError as error:
        raise ValueError("The supplied hostname is not valid.") from error
    is_ip = False
    try:
        ipaddress.ip_address(host)
        is_ip = True
    except ValueError:
        labels = host.split(".")
        if len(host) > 253 or any(not label or len(label) > 63 or not re.fullmatch(r"[a-z0-9](?:[a-z0-9-]*[a-z0-9])?", label) for label in labels):
            raise ValueError("The supplied hostname is not valid.")

    evidence: list[dict[str, str | int]] = []
    findings: list[dict[str, str]] = []
    score = 0
    if is_ip:
        evidence.append({"category": "phishing", "title": "Input is an IP address", "detail": "Direct-IP destinations can be harder to recognize, but this is not proof of malicious activity.", "points": 10})
        findings.append({"severity": "low", "title": "IP address supplied", "detail": "This input is an IP address rather than a registered domain name."})
        score = 10
    if any(label.startswith("xn--") for label in host.split(".")):
        evidence.append({"category": "phishing", "title": "Internationalized hostname", "detail": "The hostname contains a punycode label. Some legitimate sites use internationalized names; review the displayed Unicode form carefully.", "points": 10})
        findings.append({"severity": "medium", "title": "Punycode label present", "detail": "Internationalized hostnames can resemble other names; this is a review cue, not a verdict."})
        score = min(score + 10, 100)
    category = "suspicious" if evidence else "clear"
    label = "Suspicious — review" if evidence else "No syntax indicators found"
    risk = "high" if score >= 50 else "medium" if score >= 20 else "low"
    return {
        "document_type": "domain",
        "subject": "Offline domain syntax review",
        "from": host,
        "sender_domain": host,
        "reply_to": "",
        "body_summary": f"Reviewed {host} on {_processing_location()} for basic hostname syntax, direct IP input, and punycode labels. No DNS, WHOIS, age, certificate, or reputation lookup was performed.",
        "classification": {"category": category, "label": label, "phishing_score": score, "spam_score": 0, "evidence": evidence, "note": "Offline syntax review only. A domain with no syntax indicators may still be malicious; reputation and registration data were not queried."},
        "authentication": {},
        "links": [],
        "attachments": [],
        "findings": findings,
        "risk_score": score,
        "risk_level": risk,
        "disclaimer": "Offline syntax checks only; this tool did not contact DNS, WHOIS, URLscan.io, VirusTotal, or any other service.",
    }


def analyze_pdf(content: bytes) -> dict:
    if len(content) > MAX_PDF_BYTES:
        raise ValueError("PDF exceeds the 5 MB analysis limit.")
    if not content.startswith(b"%PDF-"):
        raise ValueError("The selected file does not appear to be a PDF.")
    if PdfReader is None:
        raise ValueError("PDF text extraction requires pypdf. Install the project dependencies with: python -m pip install -r requirements.txt")
    try:
        reader = PdfReader(BytesIO(content), strict=False)
        if reader.is_encrypted:
            raise ValueError("Encrypted PDFs are not supported; no password was requested or stored.")
        page_count = len(reader.pages)
        if page_count > MAX_PDF_PAGES:
            raise ValueError(f"PDF exceeds the {MAX_PDF_PAGES}-page analysis limit.")
        text_parts: list[str] = []
        text_budget = 800_000
        pdf_links: list[str] = []
        for page in reader.pages:
            if text_budget:
                page_text = page.extract_text() or ""
                text_parts.append(page_text[:text_budget])
                text_budget -= min(len(page_text), text_budget)
            for annotation_ref in page.get("/Annots", []):
                annotation = annotation_ref.get_object()
                action_ref = annotation.get("/A", {})
                action = action_ref.get_object() if hasattr(action_ref, "get_object") else action_ref
                uri = action.get("/URI") if hasattr(action, "get") else None
                if isinstance(uri, str) and uri.lower().startswith(("http://", "https://")) and len(pdf_links) < 50:
                    pdf_links.append(uri[:1024])
        metadata = reader.metadata
        title = str(metadata.title or "")[:200] if metadata else ""
    except ValueError:
        raise
    except Exception as error:
        raise ValueError("The PDF could not be read. It may be damaged or use unsupported features.") from error
    extracted = "\n".join(text_parts)[:800_000]
    if pdf_links:
        extracted += "\nLinks found in PDF annotations:\n" + "\n".join(pdf_links)
    email_source = "Subject: PDF analysis" + (f" — {title}" if title else "") + "\nContent-Type: text/plain; charset=utf-8\n\n" + extracted
    result = analyze_email(email_source)
    result["document_type"] = "pdf"
    result["pdf_metadata"] = {"title": title or "(not set)", "pages": page_count, "text_characters": len(extracted)}
    result["disclaimer"] = f"PDF text and link annotations were extracted on {_processing_location()}. No embedded file was opened or executed; scanned pages may require OCR, which is not provided."
    return result


def analyze_input(kind: str, value: str = "", pdf_content: bytes | None = None) -> dict:
    if kind == "domain":
        return analyze_domain(value)
    if kind == "url":
        url = value.strip()
        parsed = urlsplit(url)
        if parsed.scheme.lower() not in {"http", "https"} or not parsed.hostname:
            raise ValueError("Provide a complete HTTP or HTTPS URL, including its scheme.")
        result = analyze_email(f"Subject: Submitted URL\nContent-Type: text/plain; charset=utf-8\n\nURL submitted for offline inspection: {url}")
        result["document_type"] = "url"
        result["disclaimer"] = f"The URL was inspected on {_processing_location()} only and was not visited. No DNS or reputation lookup was performed."
        return result
    if kind == "html":
        if not value.strip():
            raise ValueError("Provide HTML source to analyze.")
        result = analyze_email(f"Subject: Submitted HTML\nContent-Type: text/html; charset=utf-8\n\n{value}")
        result["document_type"] = "html"
        result["disclaimer"] = f"Visible HTML text and links were inspected on {_processing_location()}. Scripts were not executed, and links were not visited."
        return result
    if kind == "pdf":
        if pdf_content is None:
            raise ValueError("Choose a PDF file to analyze.")
        return analyze_pdf(pdf_content)
    raise ValueError("Choose a supported input type.")


def _analyze_request(path: str, payload: object) -> dict:
    if not isinstance(payload, dict):
        raise ValueError("The request body must be a JSON object.")
    if path == "/api/analyze":
        raw_email = payload.get("email")
        if not isinstance(raw_email, str) or not raw_email.strip():
            raise ValueError("Provide the raw contents of an .eml email.")
        return analyze_email(raw_email)

    kind = payload.get("kind")
    value = payload.get("value", "")
    if not isinstance(kind, str) or not isinstance(value, str):
        raise ValueError("Provide a supported analysis type and text input.")
    pdf_content = None
    if kind == "pdf":
        encoded_pdf = payload.get("pdf_base64")
        if not isinstance(encoded_pdf, str) or len(encoded_pdf) > 6_700_000:
            raise ValueError("Choose a PDF file no larger than 5 MB.")
        pdf_content = base64.b64decode(encoded_pdf, validate=True)
        if len(pdf_content) > MAX_PDF_BYTES:
            raise ValueError("PDF exceeds the 5 MB analysis limit.")
    return analyze_input(kind, value, pdf_content)


class Handler(BaseHTTPRequestHandler):
    server_version = "EMLYTICS/1.0"
    assets = {
        "/": ("index.html", "text/html; charset=utf-8"),
        "/styles.css": ("styles.css", "text/css; charset=utf-8"),
        "/app.js": ("app.js", "text/javascript; charset=utf-8"),
    }

    def _send(self, status: int, content_type: str, body: bytes) -> None:
        self.send_response(status)
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(len(body)))
        self.send_header("X-Content-Type-Options", "nosniff")
        self.send_header("X-Frame-Options", "DENY")
        self.send_header("Referrer-Policy", "no-referrer")
        self.send_header("Content-Security-Policy", "default-src 'self'; script-src 'self'; style-src 'self'; base-uri 'none'; frame-ancestors 'none'; form-action 'self'")
        self.send_header("Cache-Control", "no-store")
        self.end_headers()
        self.wfile.write(body)

    def do_GET(self) -> None:
        if self.path == "/api/config":
            body = json.dumps({"public_demo": os.environ.get("EMLYTICS_PUBLIC_DEMO") == "1"}).encode("utf-8")
            self._send(200, "application/json; charset=utf-8", body)
            return
        asset = self.assets.get(self.path)
        if not asset:
            self._send(404, "text/plain; charset=utf-8", b"Not found")
            return
        filename, content_type = asset
        self._send(200, content_type, (ROOT / filename).read_bytes())

    def do_POST(self) -> None:
        if self.path not in {"/api/analyze", "/api/analyze-input"}:
            self._send(404, "application/json; charset=utf-8", b'{"error":"Not found"}')
            return
        try:
            length = int(self.headers.get("Content-Length", "0"))
        except ValueError:
            length = 0
        if length <= 0 or length > MAX_TOOL_REQUEST_BYTES:
            self._send(413, "application/json; charset=utf-8", b'{"error":"Request is empty or exceeds the 7 MB request limit."}')
            return
        try:
            payload = json.loads(self.rfile.read(length))
            result = _analyze_request(self.path, payload)
        except (json.JSONDecodeError, UnicodeDecodeError, binascii.Error):
            self._send(400, "application/json; charset=utf-8", b'{"error":"Invalid JSON or base64 request."}')
            return
        except ValueError as error:
            response = json.dumps({"error": str(error)}).encode("utf-8")
            self._send(400, "application/json; charset=utf-8", response)
            return
        self._send(200, "application/json; charset=utf-8", json.dumps(result).encode("utf-8"))

    def log_message(self, format: str, *args) -> None:
        return


def main() -> None:
    host = os.environ.get("EMLYTICS_HOST", "127.0.0.1")
    try:
        port = int(os.environ.get("PORT") or os.environ.get("EMLYTICS_PORT", "8000"))
    except ValueError as error:
        raise SystemExit("EMLYTICS_PORT must be a valid port number.") from error
    if not 1 <= port <= 65535:
        raise SystemExit("EMLYTICS_PORT must be between 1 and 65535.")
    server = ThreadingHTTPServer((host, port), Handler)
    print(f"EMLYTICS is running at http://{host}:{port} (Ctrl+C to stop)")
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        print("\nStopping EMLYTICS...")
    finally:
        server.server_close()


if __name__ == "__main__":
    main()
