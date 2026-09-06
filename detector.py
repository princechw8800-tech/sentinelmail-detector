"""Small, transparent heuristic checker for RFC 822 (.eml) messages."""

from email import policy
from email.parser import BytesParser
from email.utils import parseaddr
import re
from urllib.parse import urlparse

URL_PATTERN = re.compile(r"https?://[^\s<>\"']+", re.IGNORECASE)
SUSPICIOUS_WORDS = re.compile(
    r"\b(urgent|verify|password|login|account suspended|wire transfer|gift card|click here|limited time)\b",
    re.IGNORECASE,
)


def _domain(address):
    _, email_address = parseaddr(address or "")
    return email_address.rsplit("@", 1)[-1].lower() if "@" in email_address else ""


def _body(message):
    parts = []
    for part in message.walk():
        if part.get_content_maintype() == "multipart":
            continue
        if part.get_content_type() in {"text/plain", "text/html"}:
            try:
                parts.append(part.get_content())
            except Exception:
                continue
    return "\n".join(str(part) for part in parts)


def _auth_status(authentication, mechanism):
    match = re.search(rf"\b{mechanism}=(pass|fail|softfail|neutral|none)\b", authentication, re.I)
    return match.group(1).upper() if match else "NOT FOUND"


def analyze_email(raw_email):
    if not raw_email:
        raise ValueError("The selected file is empty.")

    message = BytesParser(policy=policy.default).parsebytes(raw_email)
    sender = str(message.get("From", "Not available"))
    reply_to = str(message.get("Reply-To", "Not available"))
    return_path = str(message.get("Return-Path", "Not available"))
    subject = str(message.get("Subject", "(no subject)"))
    sender_domain = _domain(sender)
    reply_domain = _domain(reply_to)
    return_domain = _domain(return_path)
    received_count = len(message.get_all("Received", []))
    auth = "\n".join(str(value) for value in message.get_all("Authentication-Results", []))
    body = _body(message)
    urls = sorted(set(URL_PATTERN.findall(body)))
    url_details = []
    for url in urls:
        domain = (urlparse(url).hostname or "").lower()
        signals = []
        if sender_domain and domain and domain != sender_domain:
            signals.append("External domain")
        if "@" in url or re.search(r"\d{1,3}(?:\.\d{1,3}){3}", domain):
            signals.append("Obfuscated destination")
        url_details.append({"url": url, "domain": domain or "Unknown", "risk": "Review" if signals else "Low", "signals": signals or ["No obvious URL signal"]})

    score = 0
    reasons = []

    if not sender_domain:
        score += 25
        reasons.append("The From header does not contain a valid email address.")
    if reply_domain and sender_domain and reply_domain != sender_domain:
        score += 25
        reasons.append("The Reply-To domain differs from the sender domain.")
    if return_domain and sender_domain and return_domain != sender_domain:
        score += 15
        reasons.append("The Return-Path domain differs from the sender domain.")
    if not auth:
        score += 10
        reasons.append("No Authentication-Results header was found.")
    elif re.search(r"\b(spf|dkim|dmarc)=fail", auth, re.IGNORECASE):
        score += 35
        reasons.append("SPF, DKIM, or DMARC authentication failed.")
    if SUSPICIOUS_WORDS.search(f"{subject}\n{body}"):
        score += 15
        reasons.append("The message contains common phishing language.")
    if len(urls) >= 3:
        score += 10
        reasons.append("The message contains several web links.")
    if received_count == 0:
        score += 10
        reasons.append("No Received headers were found, which is unusual for a delivered email.")

    score = min(score, 100)
    if score >= 55:
        classification = "Likely suspicious"
    elif score >= 25:
        classification = "Needs caution"
    else:
        classification = "Low risk"
    if not reasons:
        reasons.append("No obvious phishing indicators were found in the available headers and text.")

    return {
        "classification": classification,
        "risk_score": score,
        "sender": sender,
        "domain": sender_domain or "Not available",
        "reply_to": reply_to,
        "return_path": return_path,
        "subject": subject,
        "received": received_count,
        "urls": len(urls),
        "authentication": auth or "No authentication information available.",
        "auth_status": {name.upper(): _auth_status(auth, name) for name in ("spf", "dkim", "dmarc")},
        "url_details": url_details,
        "body_preview": body[:4000],
        "reasons": reasons,
    }
