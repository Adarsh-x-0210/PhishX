"""
PhishX - Unified Command Line Interface & Runner
Allows executing any detection vector via JSON CLI or child process.
"""

import argparse
import json
import sys

from lib.detector import analyze_url
from lib.email_detector import analyze_email
from lib.qr_detector import analyze_qr_code


def main():
    parser = argparse.ArgumentParser(description="PhishX Multi-Vector Detection Runner")
    parser.add_argument("--vector", choices=["url", "email", "qr"], required=True, help="Detection vector")
    parser.add_argument("--data", type=str, help="Input data (URL string, JSON string, or Base64 image)")
    parser.add_argument("--file", type=str, help="File path for QR image or raw EML email")

    args = parser.parse_args()

    try:
        if args.vector == "url":
            url = args.data or ""
            # If JSON passed
            if url.startswith("{"):
                try:
                    payload = json.loads(url)
                    url = payload.get("url", "")
                except Exception:
                    pass
            result = analyze_url(url)

        elif args.vector == "email":
            raw_input = args.data or ""
            if args.file:
                with open(args.file, "r", encoding="utf-8", errors="ignore") as f:
                    raw_eml = f.read()
                result = analyze_email(raw_email=raw_eml)
            else:
                try:
                    payload = json.loads(raw_input)
                except Exception:
                    payload = {"body": raw_input}

                result = analyze_email(
                    from_header=payload.get("from", "") or payload.get("from_header", ""),
                    reply_to=payload.get("reply_to", ""),
                    return_path=payload.get("return_path", ""),
                    subject=payload.get("subject", ""),
                    body=payload.get("body", ""),
                    raw_email=payload.get("raw_email", None)
                )

        elif args.vector == "qr":
            if args.file:
                result = analyze_qr_code(image_path=args.file)
            else:
                data_str = args.data or ""
                # Check if data_str is a JSON payload
                if data_str.startswith("{"):
                    try:
                        payload = json.loads(data_str)
                        data_str = payload.get("image", "") or payload.get("base64", "")
                    except Exception:
                        pass
                result = analyze_qr_code(base64_str=data_str)

        print(json.dumps(result))
        sys.exit(0)

    except Exception as e:
        err_res = {
            "error": str(e),
            "verdict": "ERROR",
            "score": 0,
            "findings": [f"Execution error: {str(e)}"]
        }
        print(json.dumps(err_res))
        sys.exit(1)


if __name__ == "__main__":
    main()
