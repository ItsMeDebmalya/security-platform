"""A stdlib server that leaks a real Python traceback for unknown paths. Lab only."""

import html
import traceback
from http.server import BaseHTTPRequestHandler, HTTPServer

ROUTES = {"/": "<!doctype html><html><head><title>pytrace lab</title></head><body>ok</body></html>"}


class Handler(BaseHTTPRequestHandler):
    def do_GET(self):
        try:
            body, status = ROUTES[self.path.split("?")[0]], 200
        except KeyError:
            body, status = "<pre>" + html.escape(traceback.format_exc()) + "</pre>", 500
        data = body.encode()
        self.send_response(status)
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self.send_header("Content-Length", str(len(data)))
        self.end_headers()
        self.wfile.write(data)


HTTPServer(("0.0.0.0", 8000), Handler).serve_forever()
