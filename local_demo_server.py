"""Local Demo Website Server with intentional SEO & Security flaws for offline testing."""
from http.server import HTTPServer, BaseHTTPRequestHandler
import sys


class DemoHandler(BaseHTTPRequestHandler):
    def log_message(self, format, *args):
        pass  # Suppress noisy standard logs

    def do_GET(self):
        # 1. Sensitive files probe test
        if self.path == "/.env":
            self.send_response(200)
            self.send_header("Content-Type", "text/plain")
            self.send_header("Server", "Apache/2.4.41 (Ubuntu)")
            self.send_header("X-Powered-By", "PHP/7.4.3")
            self.end_headers()
            self.wfile.write(b"APP_ENV=production\nDB_PASSWORD=SuperSecretPass123!\n")
            return

        # 2. Redirect chain test
        if self.path == "/redirect-1":
            self.send_response(301)
            self.send_header("Location", "/redirect-2")
            self.end_headers()
            return
        if self.path == "/redirect-2":
            self.send_response(302)
            self.send_header("Location", "/")
            self.end_headers()
            return

        # 3. 404 Broken link test
        if self.path == "/broken-link":
            self.send_response(404)
            self.send_header("Content-Type", "text/html")
            self.end_headers()
            self.wfile.write(b"<html><body><h1>404 Not Found</h1></body></html>")
            return

        # 4. Thin content page
        if self.path == "/thin-page":
            self.send_response(200)
            self.send_header("Content-Type", "text/html")
            self.end_headers()
            self.wfile.write(b"""<!DOCTYPE html>
<html>
<head><title>Thin Page Test</title></head>
<body>
<h1>Short Content</h1>
<p>This page only has twenty words or so to test thin content detection.</p>
</body>
</html>""")
            return

        # 5. About page with skipped heading hierarchy
        if self.path == "/about":
            self.send_response(200)
            self.send_header("Content-Type", "text/html")
            self.end_headers()
            self.wfile.write(b"""<!DOCTYPE html>
<html lang="en">
<head>
    <title>About Our Demo Company - Complete Overview Guide</title>
    <meta name="description" content="Learn all about our company, our values, our team, and how we deliver cutting-edge SEO auditing technology.">
    <link rel="canonical" href="http://127.0.0.1:9000/about">
</head>
<body>
    <h1>About Our Platform</h1>
    <h3>Skipped Level 3 Heading</h3>
    <p>We are dedicated to building robust automated web diagnostic software for developers and security analysts.</p>
    <img src="/logo.webp" alt="Company Logo" />
    <a href="/">Back to Home</a>
</body>
</html>""")
            return

        # 6. Home page with multiple flaws
        self.send_response(200)
        self.send_header("Content-Type", "text/html")
        # Intentionally expose server information
        self.send_header("Server", "Apache/2.4.41 (Ubuntu)")
        self.send_header("X-Powered-By", "PHP/7.4.3")
        # Notice: Missing HSTS, CSP, X-Frame-Options, X-Content-Type-Options
        self.end_headers()

        html = """<!DOCTYPE html>
<html>
<head>
    <title>Demo Website for SEO and Security Audit Testing</title>
    <!-- Missing meta description -->
    <!-- Missing canonical -->
</head>
<body>
    <h1>Welcome to the Demo Test Site</h1>
    <h1>Accidental Duplicate H1 Tag</h1>
    <p>This is a simulated local website built to demonstrate our All-in-One SEO, Security, and UI diagnostic crawler right on your local machine.</p>
    <p>It includes intentional issues like missing security headers, exposed server banners, missing image alt tags, redirect chains, and thin content pages so you can see the audit report and remediation code in action!</p>
    <img src="/banner.jpg" /> <!-- Missing alt -->
    <ul>
        <li><a href="/about">About Us Page</a></li>
        <li><a href="/thin-page">Thin Content Page</a></li>
        <li><a href="/redirect-1">Redirect Chain Hop</a></li>
        <li><a href="/broken-link">Broken 404 Link</a></li>
    </ul>
</body>
</html>"""
        self.wfile.write(html.encode("utf-8"))


def run(port=9000):
    server = HTTPServer(("127.0.0.1", port), DemoHandler)
    print(f"[*] Local Demo Test Website running at http://127.0.0.1:{port}")
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        pass
    server.server_close()


if __name__ == "__main__":
    port = int(sys.argv[1]) if len(sys.argv) > 1 else 9000
    run(port)
