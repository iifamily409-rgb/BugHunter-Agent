"""Deliberately vulnerable mock target for testing the bug hunter agent.

Run:  python tests/mock_target.py        (serves on 127.0.0.1:8765)
"""
import html
import sqlite3
import subprocess
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

DB = sqlite3.connect(":memory:", check_same_thread=False)
DB.execute("CREATE TABLE users (id INTEGER, name TEXT, email TEXT)")
DB.executemany("INSERT INTO users VALUES (?,?,?)",
               [(1, "alice", "alice@example.com"), (2, "bob", "bob@example.com"),
                (3, "admin", "admin@example.com")])
DB.commit()

PAGE = """<html><head><title>Mock App</title></head><body>
<h1>Mock Vulnerable App</h1>
<form action="/search" method="GET"><input name="q"><button>Go</button></form>
<form action="/login" method="POST"><input name="username"><input name="password" type="password"><button>Login</button></form>
<a href="/user?id=1">user 1</a> <a href="/file?path=readme.txt">file</a>
<a href="/redirect?url=https://example.com">redirect</a> <a href="/admin">admin</a>
<script>document.write(location.hash.slice(1));</script>
</body></html>"""


class Handler(BaseHTTPRequestHandler):
    def log_message(self, *a):
        pass

    def _send(self, code, body, ctype="text/html", extra=None):
        data = body.encode()
        self.send_response(code)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(data)))
        self.send_header("Set-Cookie", "session=abc123; Path=/")
        for k, v in (extra or {}).items():
            self.send_header(k, v)
        self.end_headers()
        self.wfile.write(data)

    def do_GET(self):
        from urllib.parse import urlparse, parse_qs, unquote
        u = urlparse(self.path)
        q = {k: v[0] for k, v in parse_qs(u.query).items()}

        if u.path == "/":
            self._send(200, PAGE)
        elif u.path == "/search":
            term = q.get("q", "")
            self._send(200, f"<p>Results for: {term}</p>" + PAGE)
        elif u.path == "/user":
            uid = q.get("id", "1")
            try:
                rows = DB.execute(f"SELECT name, email FROM users WHERE id = {uid}").fetchall()
            except sqlite3.Error as exc:
                self._send(200, f"<p>error: sqlite3.OperationalError: {exc}</p>")
                return
            if rows:
                self._send(200, f"<p>User: {html.escape(str(rows))}</p>")
            else:
                self._send(200, f"<p>error: no rows for '{uid}'</p>")
        elif u.path == "/file":
            try:
                with open("/etc/passwd") if False else open("tests/" + q.get("path", "x")) as fh:
                    pass
            except Exception:
                pass
            path = q.get("path", "")
            try:
                with open("/etc/hostname" if ".." in path else "tests/" + path) as fh:
                    self._send(200, "<pre>root:x:0:0:root:/root:/bin/bash\n" + fh.read() + "</pre>")
            except OSError:
                self._send(404, "not found")
        elif u.path == "/redirect":
            loc = q.get("url", "/")
            self._send(302, "", extra={"Location": loc})
        elif u.path == "/admin":
            self._send(403, "forbidden")
        elif u.path == "/.env":
            self._send(200, "SECRET_KEY=supersecret123\nAWS_ACCESS_KEY_ID=AKIAIOSFODNN7EXAMPLE\n")
        elif u.path == "/robots.txt":
            self._send(200, "User-agent: *\nDisallow: /admin\n")
        else:
            self._send(404, "not found")

    def do_POST(self):
        length = int(self.headers.get("Content-Length", 0))
        body = self.rfile.read(length).decode()
        if self.path == "/login":
            self._send(200, "login failed: bad credentials")  # no rate limit


if __name__ == "__main__":
    print("Mock target on http://127.0.0.1:8765")
    ThreadingHTTPServer(("127.0.0.1", 8765), Handler).serve_forever()
