"""Small, transparent heuristic checker for RFC 822 (.eml) messages."""

from email import policy
from email.parser import BytesParser
from email.utils import parseaddr
import re


def _domain(address):
    _, email_address = parseaddr(address or "")
    return email_address.rsplit("@", 1)[-1].lower() if "@" in email_address else ""


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

    score = 0
    reasons = []

    if not sender_domain:
        score += 25
        reasons.append("The From header does not contain a valid sender address.")
    if reply_domain and sender_domain and reply_domain != sender_domain:
        score += 25
        reasons.append("The Reply-To domain differs from the sender domain.")
    if return_domain and sender_domain and return_domain != sender_domain:
        score += 15
        reasons.append("The Return-Path domain differs from the sender domain.")
    if not auth:
        score += 10
        reasons.append("No authentication result was found; sender identity cannot be verified.")
    elif re.search(r"\b(spf|dkim|dmarc)=fail", auth, re.IGNORECASE):
        score += 35
        reasons.append("SPF, DKIM, or DMARC authentication failed.")
    if received_count == 0:
        score += 10
        reasons.append("No Received headers were found, which is unusual for a delivered email.")

    score = min(score, 100)
    if score >= 55:
        classification = "Likely spoofed"
    elif score >= 25:
        classification = "Spoofing indicators found"
    else:
        classification = "No spoofing indicators"
    if not reasons:
        reasons.append("No sender identity mismatches or authentication failures were found.")

    return {
        "classification": classification,
        "risk_score": score,
        "sender": sender,
        "domain": sender_domain or "Not available",
        "reply_to": reply_to,
        "return_path": return_path,
        "subject": subject,
        "received": received_count,
        "authentication": auth or "No authentication information available.",
        "auth_status": {name.upper(): _auth_status(auth, name) for name in ("spf", "dkim", "dmarc")},
        "reasons": reasons,
    }

