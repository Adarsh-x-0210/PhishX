"""
PhishX - Automated Unit & Integration Tests
Tests all three vectors (URL, Email, QR Code) and Machine Learning models.
"""

import io
import unittest
from lib.detector import analyze_url
from lib.email_detector import analyze_email
from lib.qr_detector import analyze_qr_code
from lib.typosquatting import detect_typosquatting, damerau_levenshtein_distance
from lib.ml_detector import predict_url_ml, predict_email_ml
import qrcode


class TestTyposquatting(unittest.TestCase):
    def test_damerau_levenshtein(self):
        self.assertEqual(damerau_levenshtein_distance("paypal", "paypa1"), 1)
        self.assertEqual(damerau_levenshtein_distance("google", "goolge"), 1)  # transposition
        self.assertEqual(damerau_levenshtein_distance("amazon", "amzon"), 1)   # omission

    def test_typosquatting_detection(self):
        # Paypa1 (homoglyph/edit distance 1)
        res = detect_typosquatting("paypa1.com")
        self.assertTrue(res["detected"])
        self.assertEqual(res["brand"], "paypal")

        # Legitimate Google should NOT be flagged
        res_legit = detect_typosquatting("google.com")
        self.assertFalse(res_legit["detected"])

        # Combosquatting
        res_combo = detect_typosquatting("paypal-security.com")
        self.assertTrue(res_combo["detected"])
        self.assertEqual(res_combo["technique"], "Combo-squatting")


class TestMLDetector(unittest.TestCase):
    def test_url_ml_classifier(self):
        safe_res = predict_url_ml("https://www.google.com")
        self.assertLess(safe_res["phishing_probability"], 0.3)
        self.assertIn("Random Forest", safe_res["model_type"])

        phish_res = predict_url_ml("http://paypal.com.verify-login.xyz/account/login.php")
        self.assertGreater(phish_res["phishing_probability"], 0.7)

    def test_email_ml_classifier(self):
        clean_res = predict_email_ml("Sprint planning", "Here are the notes for next sprint.")
        self.assertLess(clean_res["phishing_probability"], 0.4)

        phish_res = predict_email_ml("URGENT ACCOUNT SUSPENSION", "Your account has been suspended. Confirm password immediately.")
        self.assertGreater(phish_res["phishing_probability"], 0.6)


class TestMasterURLDetector(unittest.TestCase):
    def test_benign_url(self):
        res = analyze_url("https://www.google.com")
        self.assertEqual(res["verdict"], "LOW RISK")
        self.assertLess(res["score"], 30)

    def test_phishing_url(self):
        res = analyze_url("http://paypal.com.verify-login.xyz/account/login.php")
        self.assertEqual(res["verdict"], "HIGH RISK")
        self.assertGreaterEqual(res["score"], 60)
        self.assertTrue(res["typosquatting"]["detected"])


class TestEmailDetector(unittest.TestCase):
    def test_display_name_spoofing(self):
        res = analyze_email(
            from_header='"PayPal Support" <attacker123@gmail.com>',
            reply_to="attacker123@gmail.com",
            subject="Action required: verify account",
            body="Click here immediately to verify account."
        )
        self.assertTrue(res["spoofing_detected"])
        self.assertEqual(res["verdict"], "HIGH RISK")

    def test_reply_to_mismatch(self):
        res = analyze_email(
            from_header='"Support" <support@service.com>',
            reply_to="stealth-inbox@attacker.xyz",
            subject="Invoice details",
            body="Review your invoice."
        )
        self.assertTrue(res["spoofing_detected"])
        self.assertTrue(any(s["type"] == "REPLY_TO_MISMATCH" for s in res["spoofing_signals"]))

    def test_benign_email(self):
        res = analyze_email(
            from_header='"Alice" <alice@google.com>',
            reply_to="alice@google.com",
            subject="Meeting notes",
            body="Here are the notes from today's meeting."
        )
        self.assertFalse(res["spoofing_detected"])
        self.assertEqual(res["verdict"], "LOW RISK")


class TestQRDetector(unittest.TestCase):
    def test_qr_detection(self):
        # Generate QR code in memory
        img = qrcode.make("http://paypal.com.verify-login.xyz/account/login.php")
        buf = io.BytesIO()
        img.save(buf, format="PNG")

        res = analyze_qr_code(image_bytes=buf.getvalue())
        self.assertTrue(res["success"])
        self.assertEqual(res["payload_type"], "URL")
        self.assertTrue(res["quishing_detected"])
        self.assertEqual(res["verdict"], "HIGH RISK")


if __name__ == "__main__":
    unittest.main()
