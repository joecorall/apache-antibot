from http.server import BaseHTTPRequestHandler, HTTPServer
import json


class Handler(BaseHTTPRequestHandler):
    def do_GET(self):
        if self.path == "/healthcheck":
            self.send_response(200)
            self.send_header("Content-type", "text/html")
            self.end_headers()
            self.wfile.write(b"OK")
        else:
            self.send_response(429)
            self.send_header("Content-type", "text/html")
            self.end_headers()
            self.wfile.write(b"Too Many Requests")

    def do_POST(self):
        content_length = int(self.headers.get("Content-Length", 0))
        body = self.rfile.read(content_length)
        self.send_response(200)
        self.end_headers()
        self.wfile.write(body)


HTTPServer(("", 9000), Handler).serve_forever()
