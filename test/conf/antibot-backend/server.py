from http.server import BaseHTTPRequestHandler, HTTPServer


class Handler(BaseHTTPRequestHandler):
    def do_GET(self):
        self.send_response(429 if self.path != "/healthcheck" else 200)
        self.end_headers()

    def do_POST(self):
        self.send_response(403)
        self.end_headers()


HTTPServer(("", 9000), Handler).serve_forever()
