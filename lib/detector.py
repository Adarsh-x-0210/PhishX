import re
import ipaddress
from urllib.parse import urlparse


# Common brands we want to protect against typosquatting
BRANDS = [
    "google",
    "microsoft",
    "paypal",
    "amazon",
    "apple",
    "facebook",
    "instagram",
    "linkedin",
    "netflix",
]


# TLDs that can sometimes be associated with suspicious domains.
# These are indicators, NOT automatic proof of phishing.
SUSPICIOUS_TLDS = [
    ".xyz",
    ".top",
    ".click",
    ".work",
    ".info",
]


def analyze_url(url):
    """
    Analyze a URL and return a phishing risk assessment.
    """

    findings = []
    score = 0

    # ---------------------------------
    # 1. Basic URL validation
    # ---------------------------------

    if not url:
        return {
            "verdict": "INVALID",
            "score": 0,
            "findings": ["No URL provided."]
        }

    # Add scheme if the user forgot it
    if not url.startswith(("http://", "https://")):
        url = "http://" + url

    try:
        parsed = urlparse(url)
        domain = parsed.hostname

        if not domain:
            raise ValueError

    except Exception:
        return {
            "verdict": "INVALID",
            "score": 0,
            "findings": ["Invalid URL format."]
        }

    # ---------------------------------
    # 2. Very long URL
    # ---------------------------------

    if len(url) > 100:
        score += 10
        findings.append("URL is unusually long.")

    # ---------------------------------
    # 3. IP address instead of domain
    # ---------------------------------

    try:
        ipaddress.ip_address(domain)
        score += 25
        findings.append("URL uses an IP address instead of a domain name.")
    except ValueError:
        pass

    # ---------------------------------
    # 4. @ symbol
    # ---------------------------------

    if "@" in url:
        score += 20
        findings.append("URL contains '@', which can hide the real destination.")

    # ---------------------------------
    # 5. Suspicious URL patterns
    # ---------------------------------

    suspicious_patterns = [
        r"login",
        r"verify",
        r"verification",
        r"secure",
        r"account",
        r"update",
        r"password",
        r"signin",
        r"confirm",
        r"bank",
    ]

    matched_patterns = []

    for pattern in suspicious_patterns:
        if re.search(pattern, url, re.IGNORECASE):
            matched_patterns.append(pattern)

    if matched_patterns:
        score += 10
        findings.append(
            "Suspicious keywords detected: "
            + ", ".join(matched_patterns)
        )

   # ---------------------------------
    # 6. Too many subdomains
    # ---------------------------------

    try:
        ipaddress.ip_address(domain)
        is_ip = True
    except ValueError:
        is_ip = False

    if not is_ip and len(domain.split(".")) >= 4:
        score += 15
        findings.append("Domain contains an unusually large number of subdomains.")
        
    # ---------------------------------
    # 7. Suspicious TLD
    # ---------------------------------

    for tld in SUSPICIOUS_TLDS:
        if domain.lower().endswith(tld):
            score += 10
            findings.append(f"Domain uses potentially suspicious TLD: {tld}")
            break

    # ---------------------------------
    # 8. Hyphen-heavy domain
    # ---------------------------------

    if domain.count("-") >= 2:
        score += 10
        findings.append("Domain contains multiple hyphens.")

    # ---------------------------------
    # 9. Possible typosquatting
    # ---------------------------------

    domain_without_tld = domain.split(".")[0].lower()

    for brand in BRANDS:

        # Simple character similarity check
        if brand != domain_without_tld:

            # Same brand appearing inside a different domain
            if brand in domain_without_tld:
                score += 25
                findings.append(
                    f"Possible brand impersonation involving '{brand}'."
                )
                break

    # ---------------------------------
    # 10. HTTP instead of HTTPS
    # ---------------------------------

    if parsed.scheme.lower() == "http":
        score += 5
        findings.append("Connection does not use HTTPS.")

    # ---------------------------------
    # 11. Limit score to 100
    # ---------------------------------

    score = min(score, 100)

    # ---------------------------------
    # 12. Determine verdict
    # ---------------------------------

    if score >= 60:
        verdict = "HIGH RISK"

    elif score >= 30:
        verdict = "SUSPICIOUS"

    else:
        verdict = "LOW RISK"

    # If nothing suspicious was detected
    if not findings:
        findings.append("No obvious phishing indicators detected.")

    return {
        "url": url,
        "domain": domain,
        "verdict": verdict,
        "score": score,
        "findings": findings,
    }