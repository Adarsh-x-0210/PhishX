"""
PhishX - Typosquatting and Suspicious Domain Detection Module
Implements string-matching algorithms (Levenshtein, Damerau-Levenshtein, homoglyphs)
and regular expressions to detect typosquatting, brand impersonation, and combodomain attacks.
"""

import re
from typing import Dict, List, Optional, Tuple

# Comprehensive database of frequently targeted brands and their legitimate primary domains
TARGET_BRANDS: Dict[str, Dict] = {
    "google": {"legit_domains": ["google.com", "google.co", "google.co.in", "google.co.uk", "google.de", "google.fr", "google.ca", "google.org", "gmail.com", "youtube.com"]},
    "microsoft": {"legit_domains": ["microsoft.com", "office.com", "live.com", "outlook.com", "microsoftonline.com", "azure.com", "bing.com"]},
    "apple": {"legit_domains": ["apple.com", "icloud.com", "itunes.com"]},
    "amazon": {"legit_domains": ["amazon.com", "amazon.co.uk", "amazon.de", "amazon.in", "amazon.ca", "amazon.co.jp", "aws.amazon.com"]},
    "paypal": {"legit_domains": ["paypal.com", "paypal.me"]},
    "netflix": {"legit_domains": ["netflix.com"]},
    "facebook": {"legit_domains": ["facebook.com", "fb.com", "meta.com"]},
    "instagram": {"legit_domains": ["instagram.com"]},
    "linkedin": {"legit_domains": ["linkedin.com"]},
    "whatsapp": {"legit_domains": ["whatsapp.com"]},
    "twitter": {"legit_domains": ["twitter.com", "x.com"]},
    "chase": {"legit_domains": ["chase.com"]},
    "wellsfargo": {"legit_domains": ["wellsfargo.com"]},
    "bankofamerica": {"legit_domains": ["bankofamerica.com", "bofa.com"]},
    "citibank": {"legit_domains": ["citibank.com", "citi.com"]},
    "binance": {"legit_domains": ["binance.com"]},
    "coinbase": {"legit_domains": ["coinbase.com"]},
    "dropbox": {"legit_domains": ["dropbox.com"]},
    "spotify": {"legit_domains": ["spotify.com"]},
    "adobe": {"legit_domains": ["adobe.com"]},
    "steam": {"legit_domains": ["steampowered.com", "steamcommunity.com"]},
    "ebay": {"legit_domains": ["ebay.com"]},
    "yahoo": {"legit_domains": ["yahoo.com"]},
    "dhl": {"legit_domains": ["dhl.com"]},
    "fedex": {"legit_domains": ["fedex.com"]},
    "usps": {"legit_domains": ["usps.com"]},
}

# Homoglyph and visual character substitution mapping
HOMOGLYPH_MAP = {
    "0": ["o"],
    "o": ["0"],
    "1": ["l", "i"],
    "l": ["1", "i"],
    "i": ["1", "l"],
    "vv": ["w"],
    "w": ["vv"],
    "rn": ["m"],
    "m": ["rn"],
    "cl": ["d"],
    "d": ["cl"],
    "@": ["a"],
    "5": ["s"],
    "s": ["5"],
    "3": ["e"],
    "e": ["3"],
}

# Common phishing prefixes/suffixes used in combo-squatting
SUSPICIOUS_AFFIXES = [
    "login", "signin", "verify", "verification", "secure", "security",
    "account", "update", "support", "billing", "service", "help",
    "portal", "auth", "confirm", "alert", "notice", "kyc", "recovery"
]


def damerau_levenshtein_distance(s1: str, s2: str) -> int:
    """
    Computes Damerau-Levenshtein distance between two strings,
    accounting for insertions, deletions, substitutions, and transpositions.
    """
    len1, len2 = len(s1), len(s2)
    d = {}

    for i in range(-1, len1 + 1):
        d[(i, -1)] = i + 1
    for j in range(-1, len2 + 1):
        d[(-1, j)] = j + 1

    for i in range(len1):
        for j in range(len2):
            cost = 0 if s1[i] == s2[j] else 1
            d[(i, j)] = min(
                d[(i - 1, j)] + 1,        # deletion
                d[(i, j - 1)] + 1,        # insertion
                d[(i - 1, j - 1)] + cost  # substitution
            )
            # Transposition check
            if i > 0 and j > 0 and s1[i] == s2[j - 1] and s1[i - 1] == s2[j]:
                d[(i, j)] = min(d[(i, j)], d[(i - 2, j - 2)] + 1)

    return d[(len1 - 1, len2 - 1)]


def normalize_homoglyphs(text: str) -> str:
    """Replaces common visual substitutes (homoglyphs) with canonical characters."""
    normalized = text.lower()
    for char, replacements in HOMOGLYPH_MAP.items():
        for rep in replacements:
            normalized = normalized.replace(char, rep)
    return normalized


def is_legitimate_domain(hostname: str, brand: str) -> bool:
    """Checks if hostname belongs to the legitimate brand domain list."""
    info = TARGET_BRANDS.get(brand.lower())
    if not info:
        return False
    
    clean_host = hostname.lower()
    for legit in info["legit_domains"]:
        if clean_host == legit or clean_host.endswith("." + legit):
            return True
    return False


def detect_typosquatting(domain: str) -> Dict:
    """
    Comprehensive typosquatting detection using:
    1. Exact brand containment in suspicious subdomains or combodomains
    2. Damerau-Levenshtein edit distance for character swaps/omissions
    3. Homoglyph / visual character replacement detection
    4. Combo-squatting with suspicious security affixes
    """
    domain = domain.lower().strip()
    if not domain:
        return {"detected": False, "findings": [], "risk_score": 0}

    # Extract base domain part without TLD
    domain_parts = domain.split(".")
    if len(domain_parts) >= 2:
        # e.g., for paypa1.com -> "paypa1"; for login.paypal.com.evil.xyz -> test parts
        core_label = domain_parts[-2] if len(domain_parts) == 2 else domain_parts[0]
    else:
        core_label = domain

    findings: List[str] = []
    risk_score = 0
    matched_brand: Optional[str] = None
    technique: Optional[str] = None

    normalized_domain = normalize_homoglyphs(domain)
    normalized_core = normalize_homoglyphs(core_label)

    for brand, data in TARGET_BRANDS.items():
        # Skip if domain is legitimately owned by this brand
        if is_legitimate_domain(domain, brand):
            continue

        # 1. Direct brand containment in an unauthorized domain
        # e.g., paypal-security.com, login-microsoft-update.net, account-google.xyz
        if brand in domain:
            matched_brand = brand
            # Check for combo-squatting with high-risk words
            has_affix = any(affix in domain for affix in SUSPICIOUS_AFFIXES)
            if has_affix:
                technique = "Combo-squatting"
                risk_score = max(risk_score, 40)
                findings.append(f"Combo-squatting detected: Brand '{brand}' combined with security keywords in unauthorized domain '{domain}'.")
            else:
                technique = "Brand Impersonation"
                risk_score = max(risk_score, 30)
                findings.append(f"Brand impersonation detected: Unauthorized use of brand '{brand}' in domain '{domain}'.")
            break

        # 2. Homoglyph substitution
        # e.g., pаypal.com (cyrillic), paypa1.com, g00gle.com, rnicrosoft.com
        if brand in normalized_domain or brand in normalized_core:
            matched_brand = brand
            technique = "Homoglyph Attack"
            risk_score = max(risk_score, 45)
            findings.append(f"Homoglyph spoofing detected: Visual lookalike character substitution targeting '{brand}'.")
            break

        # 3. Damerau-Levenshtein edit distance check (1 or 2 edits away)
        # e.g., amzon.com (distance 1), goolge.com (transposition distance 1), micrsoft.com (distance 1)
        # Test core domain name and each subdomain segment
        for segment in domain_parts[:-1]:
            # Clean segment of hyphens and digits for base distance comparison
            clean_segment = re.sub(r"[0-9\-]", "", segment)
            if len(clean_segment) >= 4 and abs(len(clean_segment) - len(brand)) <= 2:
                dist = damerau_levenshtein_distance(clean_segment, brand)
                if dist == 1:
                    matched_brand = brand
                    technique = "Typosquatting (Edit Distance 1)"
                    risk_score = max(risk_score, 45)
                    findings.append(f"Typosquatting detected: '{segment}' is only 1 edit away from high-value brand '{brand}' (transposition/omission).")
                    break
                elif dist == 2 and len(brand) >= 6:
                    matched_brand = brand
                    technique = "Typosquatting (Edit Distance 2)"
                    risk_score = max(risk_score, 30)
                    findings.append(f"Potential typosquatting: '{segment}' closely resembles targeted brand '{brand}'.")
                    break

        if matched_brand:
            break

    # Subdomain spoofing check: e.g., paypal.com.login-verify.site
    if not matched_brand:
        for brand in TARGET_BRANDS:
            if is_legitimate_domain(domain, brand):
                continue
            pattern = rf"(^|\.){re.escape(brand)}\.(com|net|org|co)\."
            if re.search(pattern, domain):
                matched_brand = brand
                technique = "Subdomain Deception"
                risk_score = max(risk_score, 50)
                findings.append(f"Subdomain deception: Fake domain structure mimicking '{brand}' inside a foreign host.")
                break

    return {
        "detected": risk_score > 0,
        "brand": matched_brand,
        "technique": technique,
        "risk_score": risk_score,
        "findings": findings,
    }
