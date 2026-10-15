"""
PhishX - Master URL Phishing Detection Engine
Combines:
1. Deep heuristic indicator analysis
2. String matching & typosquatting detection (Levenshtein, Homoglyphs)
3. Machine Learning classification (Random Forest model)
"""

import ipaddress
import re
from typing import Dict, List, Any
from urllib.parse import urlparse

from lib.typosquatting import detect_typosquatting
from lib.ml_detector import predict_url_ml

HIGH_RISK_TLDS = [
    ".xyz", ".top", ".click", ".work", ".info", ".buzz", ".fit",
    ".gq", ".tk", ".ml", ".cf", ".cam", ".rest", ".monster", ".cfd"
]

SUSPICIOUS_KEYWORDS = [
    r"login", r"verify", r"verification", r"secure", r"security",
    r"account", r"update", r"password", r"signin", r"confirm",
    r"bank", r"banking", r"wallet", r"kyc", r"auth", r"token",
    r"billing", r"support", r"credential", r"recovery", r"invoice"
]

KNOWN_SHORTENERS = [
    "bit.ly", "tinyurl.com", "t.co", "is.gd", "buff.ly", "ow.ly",
    "rb.gy", "cutt.ly", "rebrand.ly", "shorturl.at"
]


def analyze_url(input_url: str) -> Dict[str, Any]:
    """
    Analyzes a URL using heuristics, string-matching typosquatting, and machine learning.
    Returns composite risk score, verdict, findings, and vector breakdown.
    """
    if not input_url or not input_url.strip():
        return {
            "url": input_url or "",
            "domain": "",
            "verdict": "INVALID",
            "score": 0,
            "findings": ["No URL provided."],
            "heuristics": {"score": 0, "findings": []},
            "typosquatting": {"detected": False},
            "ml_analysis": {"phishing_probability": 0.0, "ml_score": 0}
        }

    raw_url = input_url.strip()
    had_explicit_protocol = raw_url.startswith(("http://", "https://"))
    url = raw_url if had_explicit_protocol else "https://" + raw_url

    try:
        parsed = urlparse(url)
        domain = parsed.hostname
        if not domain:
            raise ValueError("No hostname found")
    except Exception:
        return {
            "url": raw_url,
            "domain": "",
            "verdict": "INVALID",
            "score": 0,
            "findings": ["Invalid URL format."],
            "heuristics": {"score": 0, "findings": []},
            "typosquatting": {"detected": False},
            "ml_analysis": {"phishing_probability": 0.0, "ml_score": 0}
        }

    domain_lower = domain.lower()
    findings: List[str] = []
    heuristic_score = 0

    # 1. IP Address host check
    is_ip = False
    try:
        ipaddress.ip_address(domain_lower)
        is_ip = True
        heuristic_score += 35
        findings.append("Direct IP address used instead of domain name (bypasses domain reputation).")
    except ValueError:
        pass

    # 2. Protocol check
    if had_explicit_protocol and parsed.scheme.lower() == "http":
        heuristic_score += 10
        findings.append("Unencrypted connection: Uses HTTP instead of HTTPS.")

    # 3. URL Length
    if len(url) > 100:
        heuristic_score += 15
        findings.append(f"Excessive URL length ({len(url)} characters) often hides obfuscated parameters.")
    elif len(url) > 75:
        heuristic_score += 5
        findings.append("Unusually long URL.")

    # 4. Embedded credentials or '@' symbol
    if "@" in url:
        heuristic_score += 25
        findings.append("URL contains '@' character, potentially spoofing the displayed authority.")

    # 5. Open redirect / Double slash in path
    if parsed.path and "//" in parsed.path:
        heuristic_score += 15
        findings.append("Double slash found in URL path (frequently exploited for open redirection).")

    # 6. Non-standard ports
    if parsed.port and parsed.port not in (80, 443):
        heuristic_score += 15
        findings.append(f"Non-standard web port detected: :{parsed.port}")

    # 7. Subdomain count
    if not is_ip:
        labels = domain_lower.split(".")
        if len(labels) >= 4:
            heuristic_score += 15
            findings.append("Domain contains an excessive number of subdomains (subdomain spoofing risk).")

    # 8. High-abuse TLDs
    for tld in HIGH_RISK_TLDS:
        if domain_lower.endswith(tld):
            heuristic_score += 15
            findings.append(f"Domain uses high-abuse top-level domain: {tld}")
            break

    # 9. Hyphen-heavy domains
    hyphen_count = domain_lower.count("-")
    if hyphen_count >= 2:
        heuristic_score += 10
        findings.append(f"Domain contains multiple hyphens ({hyphen_count}), a common tactic in combodomains.")

    # 10. URL Shortener check
    if any(shortener in domain_lower for shortener in KNOWN_SHORTENERS):
        heuristic_score += 15
        findings.append("URL Shortener service detected; masks the final destination.")

    # 11. Sensitive keyword matching
    matched_kws = []
    for pattern in SUSPICIOUS_KEYWORDS:
        if re.search(pattern, url, re.IGNORECASE):
            matched_kws.append(pattern.replace(r"\b", ""))
    if matched_kws:
        heuristic_score += min(25, len(matched_kws) * 8)
        findings.append(f"Phishing keywords found: {', '.join(set(matched_kws[:4]))}")

    # 12. Typosquatting & String Matching
    typo_result = detect_typosquatting(domain_lower)
    if typo_result["detected"]:
        findings.extend(typo_result["findings"])

    # 13. Machine Learning Classification
    ml_result = predict_url_ml(url, typo_result.get("risk_score", 0))
    ml_score = ml_result["ml_score"]

    # Hybrid Score Calculation:
    # Heuristic base + Typosquatting + ML ensemble prediction
    typo_score = typo_result.get("risk_score", 0)
    composite = (heuristic_score * 0.40) + (typo_score * 0.30) + (ml_score * 0.30)

    # Force critical thresholds if high-confidence typosquatting or high ML probability
    if typo_score >= 40 or ml_score >= 85:
        composite = max(composite, 65)

    final_score = int(min(100, round(composite)))

    # Determine Verdict
    if final_score >= 60:
        verdict = "HIGH RISK"
    elif final_score >= 30:
        verdict = "SUSPICIOUS"
    else:
        verdict = "LOW RISK"

    if not findings:
        findings.append("No suspicious indicators or brand impersonations detected. URL appears safe.")

    return {
        "url": url,
        "domain": domain_lower,
        "verdict": verdict,
        "score": final_score,
        "findings": findings,
        "heuristics": {
            "score": min(100, heuristic_score),
            "is_ip": is_ip,
            "has_https": parsed.scheme.lower() == "https",
        },
        "typosquatting": typo_result,
        "ml_analysis": ml_result,
    }