"""
PhishX - Email Security & Header Parsing Module
Implements RFC 822 email header parsing, address spoofing detection,
SPF/DKIM/DMARC authentication analysis, body link inspection, and ML-assisted scoring.
"""

import email
from email import policy
from email.parser import Parser
import re
from typing import Dict, List, Any, Optional, Tuple
from urllib.parse import urlparse

from lib.typosquatting import detect_typosquatting, TARGET_BRANDS
from lib.ml_detector import predict_email_ml


# Common brands impersonated in email display names
IMPERSONATION_TARGETS = [
    "paypal", "google", "microsoft", "apple", "amazon", "netflix",
    "facebook", "instagram", "chase", "wells fargo", "bank of america",
    "dhl", "fedex", "usps", "dropbox", "security team", "it helpdesk",
    "account support", "billing department", "ceo", "chief executive"
]

FREE_WEBMAIL_DOMAINS = {
    "gmail.com", "yahoo.com", "hotmail.com", "outlook.com", "aol.com",
    "protonmail.com", "mail.com", "zoho.com", "yandex.com", "icloud.com"
}

URGENCY_PATTERNS = [
    (r"\b(urgent|immediately|action required|important notice)\b", 15, "High urgency phrasing detected in message."),
    (r"\b(account suspended|account disabled|access revoked|suspended)\b", 25, "Threat of account suspension or service termination."),
    (r"\b(within 24 hours|within 12 hours|expires today|immediately)\b", 15, "Artificial time pressure imposed on recipient."),
    (r"\b(verify your identity|confirm your password|login now|update payment)\b", 20, "Credential or sensitive information request."),
    (r"\b(gift card|wire transfer|crypto|bitcoin|invoice attached)\b", 20, "Suspicious financial or payment solicitation."),
]


def extract_email_address(raw_str: str) -> Tuple[str, str, str]:
    """
    Parses a string like 'PayPal Service <support@service.com>' into:
    (display_name, email_address, domain)
    """
    if not raw_str:
        return "", "", ""

    # Check for "Display Name <email@domain.com>"
    match = re.search(r"^(.*?)\s*<([^>]+)>", raw_str.strip())
    if match:
        display_name = match.group(1).strip().strip("\"'")
        addr = match.group(2).strip().lower()
    else:
        display_name = ""
        addr = raw_str.strip().lower()

    domain = addr.split("@")[-1] if "@" in addr else ""
    return display_name, addr, domain


def extract_urls_from_body(body: str) -> List[Dict[str, str]]:
    """
    Extracts all URLs and checks for HTML anchor mismatches (e.g., text says PayPal, href is attacker).
    """
    urls: List[Dict[str, str]] = []

    # Check HTML hrefs: <a href="target">visible text</a>
    anchor_pattern = re.compile(r'<a\s+(?:[^>]*?\s+)?href=["\']([^"\']+)["\'][^>]*>(.*?)</a>', re.IGNORECASE | re.DOTALL)
    for href, text in anchor_pattern.findall(body):
        clean_text = re.sub(r'<[^>]+>', '', text).strip()
        urls.append({
            "url": href,
            "anchor_text": clean_text,
            "mismatch": False
        })
        # Check if visible text resembles a different URL/domain than href
        if re.search(r'https?://[^\s]+', clean_text) or any(tld in clean_text for tld in [".com", ".net", ".org"]):
            urls[-1]["mismatch"] = True

    # Check raw plain text URLs
    raw_urls = re.findall(r'https?://[^\s<>"\']+', body)
    for raw_u in raw_urls:
        if not any(u["url"] == raw_u for u in urls):
            urls.append({"url": raw_u, "anchor_text": "", "mismatch": False})

    return urls


def parse_raw_eml(raw_eml_text: str) -> Dict[str, Any]:
    """Parses a full raw email / RFC 822 string into headers and body."""
    parser = Parser(policy=policy.default)
    try:
        msg = parser.parsestr(raw_eml_text)
    except Exception:
        return {
            "from": "",
            "reply_to": "",
            "return_path": "",
            "subject": "",
            "body": raw_eml_text,
            "headers": {}
        }

    from_header = str(msg.get("From", ""))
    reply_to = str(msg.get("Reply-To", ""))
    return_path = str(msg.get("Return-Path", ""))
    subject = str(msg.get("Subject", ""))

    # Extract body content
    body = ""
    try:
        if msg.is_multipart():
            for part in msg.walk():
                ctype = part.get_content_type()
                if ctype in ("text/plain", "text/html"):
                    try:
                        body += part.get_content() + "\n"
                    except Exception:
                        pass
        else:
            body = msg.get_content()
    except Exception:
        body = ""

    # Gather headers of security interest
    sec_headers = {
        "received_spf": str(msg.get("Received-SPF", "")),
        "auth_results": str(msg.get("Authentication-Results", "")),
        "dkim_signature": str(msg.get("DKIM-Signature", "")),
        "dmarc_status": str(msg.get("DMARC-Filter", "")),
        "message_id": str(msg.get("Message-ID", "")),
    }

    return {
        "from": from_header,
        "reply_to": reply_to,
        "return_path": return_path,
        "subject": subject,
        "body": body,
        "headers": sec_headers
    }


def analyze_email(
    from_header: str = "",
    reply_to: str = "",
    return_path: str = "",
    subject: str = "",
    body: str = "",
    raw_email: Optional[str] = None
) -> Dict[str, Any]:
    """
    Performs multi-vector email inspection:
    1. Header parsing & spoofing verification
    2. Display name deception analysis
    3. SPF/DKIM/DMARC status heuristics
    4. Heuristic body analysis & urgency triggers
    5. Embedded hyperlinks scanning
    6. Machine Learning NLP phishing classifier
    """
    # If raw email supplied, parse it first
    if raw_email and raw_email.strip():
        parsed = parse_raw_eml(raw_email)
        from_header = from_header or parsed["from"]
        reply_to = reply_to or parsed["reply_to"]
        return_path = return_path or parsed["return_path"]
        subject = subject or parsed["subject"]
        body = body or parsed["body"]
        headers_info = parsed["headers"]
    else:
        headers_info = {}

    findings: List[str] = []
    spoofing_signals: List[Dict[str, Any]] = []
    score = 0

    from_display, from_addr, from_domain = extract_email_address(from_header)
    reply_display, reply_addr, reply_domain = extract_email_address(reply_to)
    return_display, return_addr, return_domain = extract_email_address(return_path)

    # -------------------------------------------------------------
    # 1. Display Name Spoofing Check
    # -------------------------------------------------------------
    if from_display:
        from_display_lower = from_display.lower()
        for target in IMPERSONATION_TARGETS:
            if target in from_display_lower:
                # Check if the domain is legitimately associated with the target
                is_legit = False
                if target in TARGET_BRANDS:
                    for legit in TARGET_BRANDS[target]["legit_domains"]:
                        if from_domain == legit or from_domain.endswith("." + legit):
                            is_legit = True
                            break

                if not is_legit:
                    if from_domain in FREE_WEBMAIL_DOMAINS:
                        score += 45
                        finding = f"Display Name Deception: Sender claims to be '{from_display}' but uses free webmail ({from_domain})."
                    else:
                        score += 35
                        finding = f"Display Name Spoofing: Display name mimics '{target}' from unrelated domain '{from_domain}'."
                    findings.append(finding)
                    spoofing_signals.append({"type": "DISPLAY_NAME_SPOOFING", "severity": "HIGH", "detail": finding})
                    break

    # -------------------------------------------------------------
    # 2. From vs Reply-To Mismatch Check
    # -------------------------------------------------------------
    if reply_domain and from_domain and reply_domain != from_domain:
        # Penalize when domains don't match (classic credential redirect)
        score += 30
        finding = f"Reply-To Mismatch: Responses will be routed to '{reply_addr}' instead of sender '{from_addr}'."
        findings.append(finding)
        spoofing_signals.append({"type": "REPLY_TO_MISMATCH", "severity": "HIGH", "detail": finding})

    # -------------------------------------------------------------
    # 3. From vs Return-Path Mismatch Check
    # -------------------------------------------------------------
    if return_domain and from_domain and return_domain != from_domain:
        # Check if one is a subdomain of another
        if not (from_domain.endswith("." + return_domain) or return_domain.endswith("." + from_domain)):
            score += 20
            finding = f"Envelope Sender Mismatch: Return-Path '{return_domain}' does not align with From header '{from_domain}'."
            findings.append(finding)
            spoofing_signals.append({"type": "RETURN_PATH_MISMATCH", "severity": "MEDIUM", "detail": finding})

    # -------------------------------------------------------------
    # 4. Typosquatting in Sender Domain
    # -------------------------------------------------------------
    if from_domain:
        typo_res = detect_typosquatting(from_domain)
        if typo_res["detected"]:
            score += typo_res["risk_score"]
            findings.extend(typo_res["findings"])
            spoofing_signals.append({
                "type": "TYPOSQUATTED_SENDER",
                "severity": "CRITICAL",
                "detail": f"Sender domain '{from_domain}' is typosquatting '{typo_res['brand']}'."
            })

    # -------------------------------------------------------------
    # 5. SPF / DKIM / DMARC Header Authentication Analysis
    # -------------------------------------------------------------
    auth_header = (headers_info.get("auth_results", "") + " " + headers_info.get("received_spf", "")).lower()
    if auth_header.strip():
        if "spf=fail" in auth_header or "spf=softfail" in auth_header:
            score += 25
            findings.append("SPF Authentication Failed: Sending server is unauthorized to send on behalf of domain.")
            spoofing_signals.append({"type": "SPF_FAIL", "severity": "HIGH", "detail": "SPF check failed or softfailed."})
        elif "spf=pass" in auth_header:
            score = max(0, score - 10)

        if "dkim=fail" in auth_header:
            score += 25
            findings.append("DKIM Verification Failed: Email cryptographic signature is invalid or tampered.")
            spoofing_signals.append({"type": "DKIM_FAIL", "severity": "HIGH", "detail": "DKIM signature invalid."})
        elif "dkim=pass" in auth_header:
            score = max(0, score - 10)

        if "dmarc=fail" in auth_header:
            score += 30
            findings.append("DMARC Policy Rejection: Message violated domain DMARC policy.")
            spoofing_signals.append({"type": "DMARC_FAIL", "severity": "CRITICAL", "detail": "DMARC check failed."})

    # -------------------------------------------------------------
    # 6. Body & Subject Heuristic Patterns (Urgency, Coercion)
    # -------------------------------------------------------------
    full_content = f"{subject} {body}".lower()
    for pattern, penalty, reason in URGENCY_PATTERNS:
        if re.search(pattern, full_content, re.IGNORECASE):
            score += penalty
            findings.append(reason)

    # -------------------------------------------------------------
    # 7. Embedded Links Inspection
    # -------------------------------------------------------------
    extracted_links = extract_urls_from_body(body)
    has_mismatched_links = any(link["mismatch"] for link in extracted_links)
    if has_mismatched_links:
        score += 35
        findings.append("Deceptive Link Discovered: Anchor text displays one domain, but actual hyperlink directs to a different destination.")
        spoofing_signals.append({"type": "LINK_TEXT_MISMATCH", "severity": "CRITICAL", "detail": "Hidden URL redirection inside HTML anchor text."})

    if len(extracted_links) > 0:
        findings.append(f"Detected {len(extracted_links)} embedded hyperlink(s) in email content.")

    # -------------------------------------------------------------
    # 8. Machine Learning NLP Content Classification
    # -------------------------------------------------------------
    ml_result = predict_email_ml(subject, body)
    ml_score = ml_result["ml_score"]

    # Hybrid composite score combining heuristics and ML
    composite_score = int(min(100, round((score * 0.6) + (ml_score * 0.4))))
    if spoofing_signals and composite_score < 60:
        composite_score = max(composite_score, 65)

    # Determine Verdict
    if composite_score >= 60:
        verdict = "HIGH RISK"
    elif composite_score >= 30:
        verdict = "SUSPICIOUS"
    else:
        verdict = "LOW RISK"

    if not findings:
        findings.append("No spoofing or phishing indicators detected in email headers or body.")

    return {
        "verdict": verdict,
        "score": composite_score,
        "heuristic_score": min(100, score),
        "ml_analysis": ml_result,
        "spoofing_detected": len(spoofing_signals) > 0,
        "spoofing_signals": spoofing_signals,
        "header_details": {
            "from_name": from_display,
            "from_address": from_addr,
            "from_domain": from_domain,
            "reply_to": reply_addr,
            "return_path": return_addr,
        },
        "extracted_links": extracted_links[:10],
        "findings": findings,
    }
