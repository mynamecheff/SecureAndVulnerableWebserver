import json
import logging
import http.server
import socketserver
import urllib.parse
import time

logger = logging.getLogger(__name__)

class Record:
    def __init__(self, r):
        self.remote_addr = r.client_address[0]
        self.method = r.command
        self.request_uri = r.path
        self.headers = dict(r.headers.items())  # Convert headers to dictionary
        self.user_agent = self.headers.get("User-Agent", "")
        self.post_data = self.parse_post_data(r)
        self.event_time = int(time.time())
        self.honeypot_name = "honeypot"

    def parse_post_data(self, r):
        # Parse POST data based on content type
        content_type = self.headers.get("Content-Type", "")
        if "application/x-www-form-urlencoded" in content_type:
            return urllib.parse.parse_qs(r.rfile.read(int(self.headers.get("Content-Length", 0))).decode("utf-8"))
        elif "application/json" in content_type:
            # Assuming JSON data in the POST body
            return json.loads(r.rfile.read(int(self.headers.get("Content-Length", 0))).decode("utf-8"))
        else:
            return {}

def log_record(record):
    logger.info(json.dumps(record.__dict__))

class HoneypotHandler(http.server.BaseHTTPRequestHandler):
    def do_GET(self):
        try:
            self.handle_request()
        except ConnectionResetError:
            logger.error("ConnectionResetError occurred during GET request")

    def do_POST(self):
        try:
            self.handle_request()
        except ConnectionResetError:
            logger.error("ConnectionResetError occurred during POST request")

    def handle_request(self):
        try:
            record = Record(self)
            log_record(record)
            self.send_response(200)
            self.send_header("Content-type", "text/html")
            self.end_headers()
            self.wfile.write(b"hello </br>")
        except ConnectionResetError:
            logger.error("ConnectionResetError occurred during request handling")

def main():
    logging.basicConfig(filename="honeypot.log", level=logging.INFO)
    logger.info("Starting Server")

    with socketserver.TCPServer(("", 80), HoneypotHandler) as httpd:
        httpd.serve_forever()

if __name__ == "__main__":
    main()
