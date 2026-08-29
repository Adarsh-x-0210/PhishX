from http.server import BaseHTTPRequestHandler
import json

from lib.detector import analyze_url


class handler(BaseHTTPRequestHandler):

    def do_POST(self):
        try:
            # Read request body
            content_length = int(self.headers.get("Content-Length", 0))
            body = self.rfile.read(content_length)

            # Convert JSON to Python
            data = json.loads(body)

            # Get URL
            url = data.get("url", "").strip()

            if not url:
                self.send_response(400)
                self.send_header("Content-Type", "application/json")
                self.end_headers()

                self.wfile.write(
                    json.dumps({
                        "error": "URL is required"
                    }).encode()
                )
                return

            # Analyze URL
            result = analyze_url(url)

            # Send result
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.end_headers()

            self.wfile.write(
                json.dumps(result).encode()
            )

        except Exception as e:

            self.send_response(500)
            self.send_header("Content-Type", "application/json")
            self.end_headers()

            self.wfile.write(
                json.dumps({
                    "error": str(e)
                }).encode()
            )