import asyncio
import threading
from http.server import BaseHTTPRequestHandler, HTTPServer

from app.scanners.web_discovery import discover_web

class Handler(BaseHTTPRequestHandler):
    def do_GET(self):
        if self.path == "/":
            body = b"""<!doctype html><html><head><meta name='generator' content='TestCMS'></head>
            <body>
              <a href='/next'>Next</a>
              <form action='/api/login' method='post'></form>
              <script src='/app.js'></script>
            </body></html>"""
            self.send_response(200)
            self.send_header("Content-Type", "text/html")
            self.end_headers()
            self.wfile.write(body)
        elif self.path == "/next":
            body = b"<html><body>next</body></html>"
            self.send_response(200)
            self.send_header("Content-Type", "text/html")
            self.end_headers()
            self.wfile.write(body)
        elif self.path == "/app.js":
            body = b"""fetch('/api/users'); axios.post('/api/login', {}); //# sourceMappingURL=app.js.map"""
            self.send_response(200)
            self.send_header("Content-Type", "application/javascript")
            self.end_headers()
            self.wfile.write(body)
        else:
            self.send_response(404)
            self.end_headers()

    def log_message(self, fmt, *args):
        pass

def test_safe_web_discovery_extracts_pages_scripts_routes_and_maps():
    server = HTTPServer(("127.0.0.1", 8933), Handler)
    threading.Thread(target=server.serve_forever, daemon=True).start()
    try:
        result = asyncio.run(discover_web(
            "http://127.0.0.1:8933/",
            ["127.0.0.1"],
            timeout=2,
            max_pages=5,
            max_scripts=5,
        ))
        assert result["ok"] is True
        assert len(result["pages"]) >= 2
        assert len(result["scripts"]) == 1
        paths = {(r["method"], r["path"]) for r in result["routes"]}
        assert ("GET", "/api/users") in paths
        assert ("POST", "/api/login") in paths or ("POST", "http://127.0.0.1:8933/api/login") in paths
        assert result["scripts"][0]["source_maps"]
        assert "TestCMS" in result["technologies"]
    finally:
        server.shutdown()
