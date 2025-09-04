from http.server import BaseHTTPRequestHandler, HTTPServer
from urllib.parse import parse_qs
from datetime import datetime

class _LoginHandler(BaseHTTPRequestHandler):
    server_version = "Apache/2.4.41 (Ubuntu)"
    sys_version = ""

    def do_GET(self):
        if self.path.startswith("/login") or self.path == "/":
            self._serve_login_page()
        else:
            self.send_response(404)
            self.end_headers()

    def do_POST(self):
        if self.path.startswith("/login"):
            length = int(self.headers.get("Content-Length", 0))
            body = self.rfile.read(length).decode("utf-8", errors="ignore")
            data = parse_qs(body)
            user = data.get("username", [""])[0]
            pw = data.get("password", [""])[0]
            print(f"[{datetime.utcnow().isoformat()}Z] Web login attempt from {self.client_address[0]} username='{user}' password='***'")
            self._serve_login_page(message="Invalid credentials")
        else:
            self.send_response(404)
            self.end_headers()

    def _serve_login_page(self, message: str | None = None):
        content = f"""
<!DOCTYPE html>
<html>
<head>
  <meta charset="utf-8" />
  <title>Admin Login</title>
  <style>
    body {{ font-family: Arial, sans-serif; margin: 2rem; }}
    .card {{ width: 320px; padding: 1.5rem; border: 1px solid #ddd; border-radius: 8px; }}
    .field {{ margin-bottom: 0.75rem; }}
    label {{ display:block; margin-bottom: 0.25rem; }}
    input {{ width: 100%; padding: 0.5rem; }}
    button {{ padding: 0.5rem 1rem; }}
    .msg {{ color: #b00020; margin-top: 0.5rem; }}
  </style>
  <meta name="robots" content="noindex" />
  <meta http-equiv="Cache-Control" content="no-store" />
  <meta http-equiv="Pragma" content="no-cache" />
  <meta http-equiv="Expires" content="0" />
  <script>window.history.replaceState(null, '', '/login');</script>
  <script>document.addEventListener('contextmenu', event => event.preventDefault());</script>
  <script>document.addEventListener('keydown', e => {{ if ((e.ctrlKey||e.metaKey)&&e.key==='s') {{ e.preventDefault(); }} }});</script>
  <script>console.log('honeypot active');</script>
  <meta property="og:title" content="Admin" />
  <meta property="og:type" content="website" />
  <meta property="og:url" content="/login" />
  <meta property="og:image" content="/favicon.ico" />
  <meta name="viewport" content="width=device-width, initial-scale=1" />
  <link rel="icon" href="data:image/svg+xml,<svg xmlns='http://www.w3.org/2000/svg' viewBox='0 0 128 128'><text y='1em' font-size='96'>🔐</text></svg>" />
  <meta name="description" content="Administration Login" />
  <meta name="generator" content="honeypot" />
  <meta name="x-honeypot" content="1" />
</head>
<body>
  <div class="card">
    <h3>Admin Login</h3>
    <form method="POST" action="/login"> 
      <div class="field">
        <label>Username</label>
        <input name="username" placeholder="admin" />
      </div>
      <div class="field">
        <label>Password</label>
        <input type="password" name="password" placeholder="password" />
      </div>
      <button type="submit">Sign in</button>
      {f"<div class='msg'>{message}</div>" if message else ""}
    </form>
  </div>
</body>
</html>
"""
        data = content.encode("utf-8")
        self.send_response(200)
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self.send_header("Content-Length", str(len(data)))
        self.end_headers()
        self.wfile.write(data)

def start_web_honeypot(address: str, port: int, username: str | None, password: str | None) -> None:
    server = HTTPServer((address, port), _LoginHandler)
    try:
        print(f"[i] Web honeypot serving fake admin login at http://{address}:{port}/login")
        server.serve_forever(poll_interval=0.5)
    except KeyboardInterrupt:
        print("\n[!] Stopping web honeypot...")
    finally:
        server.server_close()
        print("[+] Web honeypot stopped")

# Add this to make the script runnable directly
if __name__ == '__main__':
    import argparse
    parser = argparse.ArgumentParser(description="HTTP Honeypot: Fake admin login page")
    parser.add_argument('-a', '--address', default='0.0.0.0', help='IP address to bind to (default: 0.0.0.0)')
    parser.add_argument('-p', '--port', type=int, default=8080, help='Port to listen on (default: 8080)')
    parser.add_argument('-u', '--username', default='admin', help='Username for login page (default: admin)')
    parser.add_argument('-pw', '--password', default='password', help='Password for login page (default: password)')
    args = parser.parse_args()
    start_web_honeypot(args.address, args.port, args.username, args.password)