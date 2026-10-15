"""
PhishX - QR Code (Quishing) Detection Engine
Decodes QR codes from image files, buffers, or base64 data,
extracts encoded payloads, and inspects embedded URLs and parameters for phishing threats.
"""

import base64
import io
import re
from typing import Dict, Any, Optional
from PIL import Image, ImageEnhance, ImageOps
import pyzbar.pyzbar as pyzbar

from lib.detector import analyze_url


def _decode_qr_from_pil(img: Image.Image) -> Optional[str]:
    """Attempts to decode QR code with progressive contrast/preprocessing fallbacks."""
    # Attempt 1: Direct decode
    results = pyzbar.decode(img)
    if results:
        return results[0].data.decode("utf-8", errors="ignore")

    # Attempt 2: Grayscale
    gray = img.convert("L")
    results = pyzbar.decode(gray)
    if results:
        return results[0].data.decode("utf-8", errors="ignore")

    # Attempt 3: High contrast
    enhancer = ImageEnhance.Contrast(gray)
    high_contrast = enhancer.enhance(2.0)
    results = pyzbar.decode(high_contrast)
    if results:
        return results[0].data.decode("utf-8", errors="ignore")

    # Attempt 4: Thresholding
    threshold = high_contrast.point(lambda p: 255 if p > 128 else 0)
    results = pyzbar.decode(threshold)
    if results:
        return results[0].data.decode("utf-8", errors="ignore")

    return None


def analyze_qr_code(
    image_bytes: Optional[bytes] = None,
    image_path: Optional[str] = None,
    base64_str: Optional[str] = None
) -> Dict[str, Any]:
    """
    Decodes and analyzes a QR code from bytes, file path, or base64 string.
    Returns payload details, quishing classification, and nested URL inspection.
    """
    img: Optional[Image.Image] = None

    try:
        if base64_str:
            # Handle data:image/png;base64,... header if present
            if "," in base64_str:
                base64_str = base64_str.split(",", 1)[1]
            raw_data = base64.b64decode(base64_str)
            img = Image.open(io.BytesIO(raw_data))
        elif image_bytes:
            img = Image.open(io.BytesIO(image_bytes))
        elif image_path:
            img = Image.open(image_path)
        else:
            return {
                "success": False,
                "error": "No image data provided for QR analysis.",
                "verdict": "INVALID",
                "score": 0,
                "findings": ["No image supplied."]
            }
    except Exception as e:
        return {
            "success": False,
            "error": f"Failed to load image: {str(e)}",
            "verdict": "INVALID",
            "score": 0,
            "findings": ["Corrupt or unreadable image file."]
        }

    decoded_payload = _decode_qr_from_pil(img)

    if not decoded_payload:
        return {
            "success": False,
            "error": "No QR code could be detected in this image.",
            "verdict": "INVALID",
            "score": 0,
            "findings": ["No readable QR code pattern detected in the provided image."]
        }

    payload = decoded_payload.strip()
    findings = ["QR code successfully decoded."]
    quishing_signals = []
    payload_type = "TEXT"
    url_analysis_result = None
    score = 0

    # Classify payload type
    if payload.startswith(("http://", "https://")) or re.match(r"^[a-zA-Z0-9-]+\.[a-zA-Z]{2,}(/.*)?$", payload):
        payload_type = "URL"
        # Run through Master URL detector
        url_analysis_result = analyze_url(payload)
        url_score = url_analysis_result["score"]
        score = url_score
        verdict = url_analysis_result["verdict"]

        findings.extend(url_analysis_result["findings"])

        # Quishing-specific heuristics
        if url_score >= 60:
            quishing_signals.append({
                "type": "MALICIOUS_QUISHING_URL",
                "severity": "CRITICAL",
                "detail": "QR code encodes a high-risk phishing URL designed for mobile credential theft."
            })
            findings.insert(1, "QUISHING DETECTED: QR code directs mobile users to a malicious phishing landing page.")
        elif url_score >= 30:
            quishing_signals.append({
                "type": "SUSPICIOUS_QR_URL",
                "severity": "MEDIUM",
                "detail": "QR code leads to a suspicious or untrusted domain."
            })
        else:
            findings.append("Encoded URL appears legitimate and safe.")

    elif payload.startswith("mailto:"):
        payload_type = "EMAIL_LINK"
        score = 25
        verdict = "SUSPICIOUS"
        findings.append("QR code triggers an email composition action (mailto: scheme).")

    elif payload.startswith("tel:"):
        payload_type = "PHONE_CALL"
        score = 20
        verdict = "LOW RISK"
        findings.append("QR code triggers a telephone call action.")

    elif payload.startswith("WIFI:"):
        payload_type = "WIFI_CONFIG"
        score = 15
        verdict = "LOW RISK"
        findings.append("QR code encodes Wi-Fi network credentials.")

    else:
        # Generic text payload
        verdict = "LOW RISK"
        score = 0
        findings.append("QR code contains plain text payload.")

    return {
        "success": True,
        "payload": payload,
        "payload_type": payload_type,
        "verdict": verdict if "verdict" in locals() else "LOW RISK",
        "score": score,
        "quishing_detected": len(quishing_signals) > 0,
        "quishing_signals": quishing_signals,
        "url_analysis": url_analysis_result,
        "findings": findings
    }
