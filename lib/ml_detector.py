"""
PhishX - Machine Learning Detection Engine
Provides pre-trained and dynamically trained machine learning models for:
1. URL Phishing Classification (Random Forest / Feature Extraction)
2. Email Phishing & Social Engineering Classification (TF-IDF + Calibrated Classifier)
"""

import os
import math
import re
from typing import Dict, List, Any, Tuple
from urllib.parse import urlparse
import joblib
import numpy as np

# Ensure models directory exists
MODELS_DIR = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "models")
os.makedirs(MODELS_DIR, exist_ok=True)

URL_MODEL_PATH = os.path.join(MODELS_DIR, "url_phish_model.joblib")
EMAIL_MODEL_PATH = os.path.join(MODELS_DIR, "email_phish_model.joblib")

HIGH_ABUSE_TLDS = {
    ".xyz", ".top", ".click", ".work", ".info", ".buzz", ".fit", ".gq",
    ".tk", ".ml", ".cf", ".cam", ".rest", ".monster", ".bar", ".cfd"
}

SENSITIVE_KEYWORDS = [
    "login", "signin", "verify", "verification", "secure", "security",
    "account", "update", "password", "bank", "banking", "confirm",
    "wallet", "kyc", "auth", "token", "support", "billing", "service"
]


def calculate_entropy(text: str) -> float:
    """Calculates the Shannon entropy of a string (measures randomness)."""
    if not text:
        return 0.0
    prob_map = {}
    for c in text:
        prob_map[c] = prob_map.get(c, 0) + 1
    entropy = 0.0
    text_len = len(text)
    for count in prob_map.values():
        p = count / text_len
        entropy -= p * math.log2(p)
    return round(entropy, 4)


def extract_url_features(url: str, typosquatting_score: float = 0.0) -> np.ndarray:
    """
    Extracts 18 structural, lexical, and statistical features from a URL.
    Returns a 1D numpy array of float values.
    """
    url_clean = url.strip()
    if not url_clean.startswith(("http://", "https://")):
        url_clean = "https://" + url_clean

    try:
        parsed = urlparse(url_clean)
        hostname = (parsed.hostname or "").lower()
        path = parsed.path or ""
        query = parsed.query or ""
    except Exception:
        hostname = ""
        path = ""
        query = ""

    url_len = len(url_clean)
    host_len = len(hostname)
    dot_count = url_clean.count(".")
    subdomains = max(0, len(hostname.split(".")) - 2) if hostname else 0
    hyphen_count = hostname.count("-")
    digit_count = sum(c.isdigit() for c in url_clean)
    digit_ratio = (digit_count / url_len) if url_len > 0 else 0.0
    special_chars = sum(url_clean.count(c) for c in ["@", "?", "=", "&", "%", "_", "~"])
    entropy = calculate_entropy(hostname)
    
    # Check IP address host
    has_ip = 1.0 if re.match(r"^\d{1,3}(\.\d{1,3}){3}$", hostname) else 0.0
    has_at = 1.0 if "@" in url_clean else 0.0
    has_double_slash = 1.0 if "//" in path else 0.0
    
    keyword_count = sum(1 for kw in SENSITIVE_KEYWORDS if kw in url_clean.lower())
    suspicious_tld = 1.0 if any(hostname.endswith(tld) for tld in HIGH_ABUSE_TLDS) else 0.0
    is_https = 1.0 if parsed.scheme.lower() == "https" else 0.0
    path_len = len(path)
    query_len = len(query)

    features = [
        float(url_len),
        float(host_len),
        float(dot_count),
        float(subdomains),
        float(hyphen_count),
        float(digit_count),
        float(digit_ratio),
        float(special_chars),
        float(entropy),
        float(has_ip),
        float(has_at),
        float(has_double_slash),
        float(keyword_count),
        float(suspicious_tld),
        float(is_https),
        float(path_len),
        float(query_len),
        float(typosquatting_score),
    ]
    return np.array(features, dtype=np.float32)


FEATURE_NAMES = [
    "URL Length",
    "Domain Length",
    "Dot Count",
    "Subdomain Count",
    "Hyphen Count",
    "Digit Count",
    "Digit Ratio",
    "Special Characters",
    "Shannon Entropy",
    "IP Address Host",
    "@ Symbol Present",
    "Double Slash in Path",
    "Phishing Keywords Count",
    "Suspicious TLD",
    "HTTPS Enabled",
    "Path Length",
    "Query Length",
    "Typosquatting Risk Factor",
]


def _build_url_training_dataset() -> Tuple[List[str], List[int]]:
    """Curated representative dataset of benign and phishing URLs."""
    benign_urls = [
        "https://www.google.com",
        "https://google.com/search?q=machine+learning",
        "https://mail.google.com/mail/u/0/#inbox",
        "https://en.wikipedia.org/wiki/Phishing",
        "https://github.com/torvalds/linux",
        "https://www.microsoft.com/en-us/windows",
        "https://apple.com/iphone",
        "https://amazon.com/dp/B08N5WRWNW",
        "https://netflix.com/browse",
        "https://stackoverflow.com/questions/tagged/python",
        "https://linkedin.com/feed",
        "https://medium.com/@user/article-title",
        "https://nytimes.com/section/technology",
        "https://docs.python.org/3/library/urllib.parse.html",
        "https://scikit-learn.org/stable/modules/ensemble.html",
        "https://cnn.com/world",
        "https://bbc.com/news",
        "https://reddit.com/r/MachineLearning",
        "https://youtube.com/watch?v=dQw4w9WgXcQ",
        "https://fastapi.tiangolo.com/tutorial",
        "https://paypal.com/signin",
        "https://chase.com",
        "https://wellsfargo.com",
        "https://bankofamerica.com",
        "https://openai.com/research",
        "https://cloud.google.com/vertex-ai",
        "https://aws.amazon.com/console",
        "https://developer.mozilla.org/en-US/docs/Web",
        "https://cloudflare.com",
        "https://www.dropbox.com/home",
    ]

    phishing_urls = [
        "http://paypal.com.verify-login.xyz/account/login.php",
        "http://192.168.1.100/secure/bankofamerica/login.htm",
        "https://micros0ft-support-alert.top/renew-license",
        "http://apple-id-verify.click/signin?user=target",
        "http://secure-update-paypal.work/auth/confirm",
        "https://login.google.com.account-recovery.info/signin",
        "http://paypa1-security-verification.buzz/update",
        "http://netflix-billing-issue-resolution.xyz/update-card",
        "http://amazon-order-suspended.cfd/verify-identity",
        "http://chase-bank-online-secure-auth.xyz/customer/login",
        "http://218.45.122.9/login/ebay.com/",
        "http://secure.wellsfargo.com.attackerdomain.top/auth",
        "https://wallet-connect-crypto-kyc.xyz/claim-airdrop",
        "http://binance-safety-warning-code.work/kyc-submit",
        "http://instagram-copyright-infringement.click/appeal",
        "http://facebook-security-check.monster/confirm",
        "http://dropbox-file-transfer-download.top/doc.exe",
        "http://dhl-tracking-package-fee.rest/pay",
        "https://usps-address-confirm-redelivery.xyz/reschedule",
        "http://steam-community-gift-trade.fit/free-skins",
        "http://coinbase-fraud-prevention-desk.top/urgent",
        "http://it-support-password-reset.work/exchange/login.aspx",
        "http://adobe-pdf-shared-document-view.xyz/read?id=99",
        "http://zoom-meeting-security-join.click/webinar",
        "http://tax-refund-gov-service.buzz/claim/direct",
        "http://www.paypa1.com",
        "http://www.goolge.com/login",
        "http://185.220.101.5/admin/login.php?ref=mail",
        "http://account-update-notice-alert.xyz/verify",
        "http://service-alert-suspension-resolve.work/auth",
    ]

    urls = benign_urls + phishing_urls
    labels = [0] * len(benign_urls) + [1] * len(phishing_urls)
    return urls, labels


def get_or_train_url_model():
    """Loads existing URL ML model or trains a fresh Random Forest model and saves it."""
    if os.path.exists(URL_MODEL_PATH):
        try:
            return joblib.load(URL_MODEL_PATH)
        except Exception:
            pass

    from sklearn.ensemble import RandomForestClassifier

    urls, labels = _build_url_training_dataset()
    X = np.array([extract_url_features(u) for u in urls])
    y = np.array(labels)

    # Train Random Forest Classifier
    rf = RandomForestClassifier(
        n_estimators=100,
        max_depth=6,
        random_state=42,
        class_weight="balanced"
    )
    rf.fit(X, y)

    # Persist model
    try:
        joblib.dump(rf, URL_MODEL_PATH)
    except Exception:
        pass

    return rf


def _build_email_training_dataset() -> Tuple[List[str], List[int]]:
    """Curated dataset for email phishing and social engineering detection."""
    benign_emails = [
        "Hi Team, attached is the weekly project status report. Let me know if you have any questions.",
        "Here are the meeting notes from today's sprint planning. Next sprint starts on Monday.",
        "Your order #98234 has been shipped and is scheduled for delivery this Thursday via FedEx.",
        "Hi John, would you like to schedule coffee tomorrow to catch up on the design deliverables?",
        "Please review the pull request for the authentication module when you get a chance.",
        "Monthly newsletter: updates on our new product features, open source tools, and team spotlights.",
        "Your subscription receipt for October 2026. Thank you for being a valued customer.",
        "Reminder: The quarterly all-hands meeting will begin at 2:00 PM EST via Google Meet.",
        "Welcome to the team! Here is your onboarding checklist and links to internal documentation.",
        "The server maintenance window has completed successfully with zero downtime reported.",
    ]

    phishing_emails = [
        "URGENT: Your PayPal account has been suspended due to suspicious activity. Verify your identity immediately or your account will be permanently closed.",
        "Your Microsoft 365 password expires today! Click here immediately to keep your current password and avoid losing mailbox access.",
        "Unauthorized transaction detected on your Chase debit card for $1,499.00. If this was not you, cancel the transaction right now by clicking below.",
        "Action Required: We could not process your Netflix membership payment. Update your payment method within 24 hours to prevent account cancellation.",
        "Notice of Impending Legal Action: Review the attached confidential document and confirm receipt to avoid immediate penalty.",
        "From CEO: I am in a board meeting and need you to urgently purchase 5 Apple gift cards for a client presentation. Do not call, reply to this email.",
        "USPS Delivery Failure: Your package is on hold due to missing address details. Pay $2.99 redelivery fee immediately to release the shipment.",
        "Bank of America Security Alert: High risk login attempt from unknown device in Russia. Confirm your credentials now.",
        "Your payroll direct deposit information has failed. Submit your updated banking routing number immediately to receive this month's salary.",
        "Meta / Facebook Copyright Violation: Your account has been reported for trademark infringement. Appeal within 12 hours or page will be deleted.",
    ]

    texts = benign_emails + phishing_emails
    labels = [0] * len(benign_emails) + [1] * len(phishing_emails)
    return texts, labels


def get_or_train_email_model():
    """Loads existing Email ML model or trains a fresh TF-IDF + MultinomialNB pipeline."""
    if os.path.exists(EMAIL_MODEL_PATH):
        try:
            return joblib.load(EMAIL_MODEL_PATH)
        except Exception:
            pass

    from sklearn.feature_extraction.text import TfidfVectorizer
    from sklearn.naive_bayes import MultinomialNB
    from sklearn.pipeline import Pipeline

    texts, labels = _build_email_training_dataset()

    pipeline = Pipeline([
        ("tfidf", TfidfVectorizer(ngram_range=(1, 2), stop_words="english", max_features=1000)),
        ("clf", MultinomialNB(alpha=0.5))
    ])
    pipeline.fit(texts, labels)

    try:
        joblib.dump(pipeline, EMAIL_MODEL_PATH)
    except Exception:
        pass

    return pipeline


# Cache models in memory
_url_model = None
_email_model = None


def predict_url_ml(url: str, typosquatting_score: float = 0.0) -> Dict[str, Any]:
    """
    Applies the Machine Learning model to evaluate phishing probability of a URL.
    Returns: probability, risk score, verdict, and feature contributions.
    """
    global _url_model
    if _url_model is None:
        _url_model = get_or_train_url_model()

    features = extract_url_features(url, typosquatting_score)
    features_2d = features.reshape(1, -1)

    try:
        # Get class probability for phishing (class 1)
        probs = _url_model.predict_proba(features_2d)[0]
        phishing_prob = float(probs[1])
    except Exception:
        phishing_prob = 0.5

    # Compute top contributing features based on feature importances
    importances = getattr(_url_model, "feature_importances_", None)
    top_signals = []
    if importances is not None:
        scored_features = []
        for name, val, imp in zip(FEATURE_NAMES, features, importances):
            # If feature value is active / high
            if val > 0:
                scored_features.append((name, val, float(imp * (val if val <= 1 else math.log1p(val)))))
        scored_features.sort(key=lambda x: x[2], reverse=True)
        for name, val, impact in scored_features[:4]:
            top_signals.append(f"{name}: {val:.2f}" if isinstance(val, float) else f"{name}: {val}")

    ml_score = int(round(phishing_prob * 100))
    if ml_score >= 65:
        ml_verdict = "HIGH RISK (ML Phishing)"
    elif ml_score >= 35:
        ml_verdict = "SUSPICIOUS (ML Warning)"
    else:
        ml_verdict = "LOW RISK (ML Benign)"

    return {
        "phishing_probability": round(phishing_prob, 3),
        "ml_score": ml_score,
        "ml_verdict": ml_verdict,
        "model_type": "Random Forest Classifier (Ensemble)",
        "top_signals": top_signals
    }


def predict_email_ml(subject: str, body: str) -> Dict[str, Any]:
    """
    Evaluates email subject and body content using NLP TF-IDF and Naive Bayes classifier.
    """
    global _email_model
    if _email_model is None:
        _email_model = get_or_train_email_model()

    full_text = f"{subject}\n{body}".strip()
    if not full_text:
        return {
            "phishing_probability": 0.0,
            "ml_score": 0,
            "ml_verdict": "LOW RISK (Clean)",
            "model_type": "TF-IDF + Multinomial Naive Bayes",
            "extracted_urgency": False
        }

    try:
        probs = _email_model.predict_proba([full_text])[0]
        phishing_prob = float(probs[1])
    except Exception:
        phishing_prob = 0.5

    # Keyword check for explainability
    urgency_keywords = ["urgent", "immediately", "suspended", "password", "expires", "unauthorized", "verify", "action required", "legal", "gift card"]
    matched = [kw for kw in urgency_keywords if kw in full_text.lower()]

    ml_score = int(round(phishing_prob * 100))
    if ml_score >= 65:
        ml_verdict = "HIGH RISK (Phishing Content)"
    elif ml_score >= 35:
        ml_verdict = "SUSPICIOUS (Social Engineering Indicators)"
    else:
        ml_verdict = "LOW RISK (Legitimate Correspondence)"

    return {
        "phishing_probability": round(phishing_prob, 3),
        "ml_score": ml_score,
        "ml_verdict": ml_verdict,
        "model_type": "TF-IDF + Multinomial Naive Bayes",
        "matched_triggers": matched,
    }
