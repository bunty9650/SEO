"""Website Security, SSL/TLS Hygiene, and Advanced Vulnerability Auditor."""
from __future__ import annotations

import asyncio
from datetime import datetime, timezone
import re
import socket
import ssl
from typing import Any, Dict, List, Optional
from urllib.parse import urlparse
import httpx
from bs4 import BeautifulSoup
from auditors.base import AuditIssue, AuditResult, Category, Severity
from solutions.solution_database import SolutionDatabase


class SecurityAuditor:
    """Evaluates SSL certificates, HTTP security headers, cookies, CORS, info leakage, DNS email security, and sensitive file exposures."""

    # Sensitive paths for non-intrusive configuration probing
    SENSITIVE_PROBES = [
        {"path": "/.env", "type": "Environment configuration file", "signature": r"(APP_ENV|DB_|SECRET|KEY=)"},
        {"path": "/.env.local", "type": "Local environment file", "signature": r"(APP_ENV|DB_|SECRET|KEY=)"},
        {"path": "/.env.production", "type": "Production environment file", "signature": r"(APP_ENV|DB_|SECRET|KEY=)"},
        {"path": "/.git/HEAD", "type": "Git repository metadata", "signature": r"ref:\s+refs/"},
        {"path": "/.git/config", "type": "Git repository configuration", "signature": r"(\[core\]|\[remote)"},
        {"path": "/docker-compose.yml", "type": "Docker compose configuration", "signature": r"(services:|version:)"},
        {"path": "/wp-config.php.bak", "type": "WordPress config backup", "signature": r"(DB_PASSWORD|table_prefix)"},
        {"path": "/backup.sql", "type": "Database SQL dump", "signature": r"(CREATE TABLE|INSERT INTO)"},
        {"path": "/phpinfo.php", "type": "PHP configuration page", "signature": r"(PHP Version|phpinfo\(\))"},
        {"path": "/server-status", "type": "Apache server status page", "signature": r"(Apache Server Status|Server Version)"},
        {"path": "/swagger.json", "type": "Swagger API schema", "signature": r"(\"swagger\":|\"openapi\":)"},
        {"path": "/openapi.json", "type": "OpenAPI specification", "signature": r"\"openapi\":"},
        {"path": "/.DS_Store", "type": "macOS folder metadata file", "signature": r"(\x00\x00\x00\x01Bud1|Bud1)"},
    ]

    def __init__(self, target_url: str):
        self.target_url = target_url
        self.parsed = urlparse(target_url if "://" in target_url else f"https://{target_url}")
        self.domain = self.parsed.netloc.split(":")[0]
        self.port = self.parsed.port or (443 if self.parsed.scheme == "https" else 80)
        self.is_https = self.parsed.scheme == "https"

        self.issues: List[AuditIssue] = []
        self.passed_checks: List[str] = []
        self.metrics: Dict[str, Any] = {}

    def _is_local_or_ip(self) -> bool:
        """Determines if domain is localhost or raw IP address."""
        d = self.domain.lower()
        return d in ["localhost", "127.0.0.1", "0.0.0.0"] or d.endswith(".local") or d.replace(".", "").isdigit()

    async def run(
        self,
        headers: Optional[Dict[str, str]] = None,
        insecure_resources: Optional[List[Dict[str, str]]] = None,
        raw_html: Optional[str] = None,
        cookies: Optional[List[str]] = None,
    ) -> AuditResult:
        """Executes full suite of enterprise security diagnostics."""
        self.issues.clear()
        self.passed_checks.clear()

        # Fetch telemetry if missing
        if headers is None or raw_html is None or cookies is None:
            fetched_headers, fetched_cookies, fetched_html = await self._fetch_page_telemetry()
            if headers is None:
                headers = fetched_headers
            if cookies is None:
                cookies = fetched_cookies
            if raw_html is None:
                raw_html = fetched_html

        self.metrics["headers"] = headers

        # 1. SSL/TLS Certificate Audit
        ssl_info = await self._audit_ssl()
        self.metrics["ssl"] = ssl_info

        # 2. HTTP Security Headers & Deep CSP & CORS Audit
        self._audit_security_headers(headers)
        self._audit_cors(headers)
        self._audit_information_leakage(headers)

        # 3. Cookie Security Audit
        self._audit_cookies(cookies)

        # 4. Mixed Content Audit
        if insecure_resources:
            self._audit_mixed_content(insecure_resources)

        # 5. HTML Insecure Form, SRI & Secret Exposure Audits
        if raw_html:
            self._audit_sri(raw_html)
            self._audit_insecure_forms(raw_html)
            self._audit_exposed_secrets(raw_html)

        # 6. Email Security & Domain Spoofing Audit (DMARC & SPF)
        if not self._is_local_or_ip():
            await self._audit_email_security()

        # 7. Safe Sensitive Files Exposure Probe
        await self._probe_sensitive_files()

        result = AuditResult(
            category=Category.SECURITY,
            issues=self.issues,
            passed_checks=self.passed_checks,
            metrics=self.metrics,
        )
        result.calculate_score()
        return result

    async def _fetch_headers(self) -> Dict[str, str]:
        """Backwards compatibility helper."""
        h, _, _ = await self._fetch_page_telemetry()
        return h

    async def _fetch_page_telemetry(self) -> tuple[Dict[str, str], List[str], str]:
        """Fetches root headers, set-cookie headers, and HTML for comprehensive security audit."""
        headers: Dict[str, str] = {}
        cookies: List[str] = []
        html: str = ""
        try:
            async with httpx.AsyncClient(verify=False, follow_redirects=True, timeout=8.0) as client:
                resp = await client.get(self.target_url)
                headers = {k.lower(): v for k, v in resp.headers.items()}
                cookies = resp.headers.get_list("set-cookie")
                html = resp.text
        except Exception:
            pass
        return headers, cookies, html

    async def _audit_ssl(self) -> Dict[str, Any]:
        """Validates SSL certificate chain, protocol version, issuer, and days until expiry."""
        info: Dict[str, Any] = {
            "valid": False,
            "protocol": None,
            "issuer": None,
            "expiry_date": None,
            "days_remaining": None,
            "san": [],
            "error": None,
        }

        if not self.is_https:
            self.issues.append(
                SolutionDatabase.build_issue(
                    issue_id="SEC_NO_HTTPS",
                    evidence=f"Target URL scheme is {self.parsed.scheme}:// (Unencrypted cleartext)",
                    url=self.target_url,
                )
            )
            return info

        loop = asyncio.get_running_loop()

        def _get_cert_sync() -> Dict[str, Any]:
            import certifi

            # Try verified context with certifi bundle first
            try:
                context = ssl.create_default_context(cafile=certifi.where())
            except Exception:
                context = ssl.create_default_context()

            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(6.0)
            try:
                sock.connect((self.domain, self.port))
                try:
                    ssl_sock = context.wrap_socket(sock, server_hostname=self.domain)
                    is_trusted = True
                except ssl.SSLCertVerificationError:
                    # Retry with unverified context to inspect the certificate metadata directly
                    sock.close()
                    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                    sock.settimeout(6.0)
                    sock.connect((self.domain, self.port))
                    unverified_ctx = ssl._create_unverified_context()
                    ssl_sock = unverified_ctx.wrap_socket(sock, server_hostname=self.domain)
                    is_trusted = False

                cert = ssl_sock.getpeercert()
                protocol = ssl_sock.version()

                issuer_name = "Unknown"
                exp_date_iso = None
                days_left = None
                san_list = []

                if cert:
                    # Parse issuer
                    issuer_dict = dict(x[0] for x in cert.get("issuer", []))
                    issuer_name = issuer_dict.get("organizationName") or issuer_dict.get("commonName") or "Unknown"

                    # Parse expiration
                    not_after_str = cert.get("notAfter")
                    if not_after_str:
                        exp_date = datetime.strptime(not_after_str, "%b %d %H:%M:%S %Y %Z").replace(tzinfo=timezone.utc)
                        now = datetime.now(timezone.utc)
                        days_left = (exp_date - now).days
                        exp_date_iso = exp_date.isoformat()

                    san_list = [entry[1] for entry in cert.get("subjectAltName", []) if entry[0] == "DNS"]

                ssl_sock.close()
                return {
                    "valid": is_trusted,
                    "protocol": protocol,
                    "issuer": issuer_name,
                    "expiry_date": exp_date_iso,
                    "days_remaining": days_left,
                    "san": san_list,
                    "error": None if is_trusted else "Self-signed or untrusted certificate authority",
                }
            except Exception as e:
                return {"valid": False, "error": str(e)}
            finally:
                try:
                    sock.close()
                except Exception:
                    pass

        try:
            info = await loop.run_in_executor(None, _get_cert_sync)
        except Exception as exc:
            info["error"] = str(exc)

        # Evaluate SSL findings
        self._evaluate_ssl_info(info)
        return info

    def _evaluate_ssl_info(self, info: Dict[str, Any]):
        """Evaluates SSL certificate validity, expiration, and protocol version."""
        if not info.get("valid"):
            self.issues.append(
                SolutionDatabase.build_issue(
                    issue_id="SEC_SSL_EXPIRED",
                    evidence=f"SSL Handshake failed on {self.domain}: {info.get('error')}",
                    url=self.target_url,
                )
            )
            return

        days_left = info.get("days_remaining", 0)
        if days_left is not None and days_left < 0:
            self.issues.append(
                SolutionDatabase.build_issue(
                    issue_id="SEC_SSL_EXPIRED",
                    evidence=f"Certificate for {self.domain} expired {abs(days_left)} days ago on {info.get('expiry_date')}.",
                    url=self.target_url,
                )
            )
        elif days_left is not None and days_left <= 30:
            self.issues.append(
                SolutionDatabase.build_issue(
                    issue_id="SEC_SSL_EXPIRING_SOON",
                    evidence=f"Certificate for {self.domain} expires in {days_left} days ({info.get('expiry_date')}).",
                    url=self.target_url,
                )
            )
        else:
            self.passed_checks.append(
                f"SSL certificate is valid and active (Issuer: {info.get('issuer')}, expires in {days_left} days)."
            )

        # Protocol version evaluation with exact set matching
        protocol = (info.get("protocol") or "").strip()
        legacy_protocols = {"SSLv2", "SSLv3", "TLSv1", "TLSv1.0", "TLSv1.1"}
        modern_protocols = {"TLSv1.2", "TLSv1.3"}

        if protocol in legacy_protocols:
            self.issues.append(
                SolutionDatabase.build_issue(
                    issue_id="SEC_SSL_LEGACY_PROTOCOL",
                    evidence=f"Negotiated deprecated protocol version: {protocol}.",
                    url=self.target_url,
                )
            )
        elif protocol in modern_protocols:
            self.passed_checks.append(f"Modern TLS protocol negotiated ({protocol}).")
        elif protocol:
            self.passed_checks.append(f"Negotiated protocol: {protocol}.")

    def _audit_security_headers(self, headers: Dict[str, str]):
        """Evaluates HSTS, CSP, X-Frame-Options, X-Content-Type-Options, Referrer-Policy, and Permissions-Policy."""
        # 1. HSTS
        hsts = headers.get("strict-transport-security")
        if not hsts:
            self.issues.append(
                SolutionDatabase.build_issue(
                    issue_id="SEC_MISSING_HSTS",
                    evidence="Response lacks 'Strict-Transport-Security' header.",
                    url=self.target_url,
                )
            )
        else:
            max_age_match = re.search(r"max-age=(\d+)", hsts, re.I)
            max_age = int(max_age_match.group(1)) if max_age_match else 0
            if max_age < 31536000 or "includesubdomains" not in hsts.lower():
                self.issues.append(
                    SolutionDatabase.build_issue(
                        issue_id="SEC_WEAK_HSTS",
                        evidence=f"HSTS header present but suboptimal: '{hsts}' (recommended: max-age >= 31536000 and includeSubDomains)",
                        url=self.target_url,
                    )
                )
            else:
                self.passed_checks.append("Strict-Transport-Security (HSTS) is robustly configured.")

        # 2. CSP & Deep CSP Analysis
        csp = headers.get("content-security-policy")
        if not csp:
            self.issues.append(
                SolutionDatabase.build_issue(
                    issue_id="SEC_MISSING_CSP",
                    evidence="Response lacks 'Content-Security-Policy' header.",
                    url=self.target_url,
                )
            )
        else:
            self.passed_checks.append("Content-Security-Policy (CSP) is implemented.")
            self._audit_csp_depth(csp)

        # 3. X-Frame-Options
        xfo = headers.get("x-frame-options")
        if not xfo:
            if not csp or "frame-ancestors" not in csp.lower():
                self.issues.append(
                    SolutionDatabase.build_issue(
                        issue_id="SEC_MISSING_X_FRAME_OPTIONS",
                        evidence="Response lacks 'X-Frame-Options' header (Clickjacking vulnerability).",
                        url=self.target_url,
                    )
                )
            else:
                self.passed_checks.append("Clickjacking protection enabled via CSP frame-ancestors.")
        else:
            val = xfo.strip().upper()
            if val in ["DENY", "SAMEORIGIN"]:
                self.passed_checks.append(f"Clickjacking protection enabled (X-Frame-Options: {val}).")
            else:
                self.issues.append(
                    SolutionDatabase.build_issue(
                        issue_id="SEC_MISSING_X_FRAME_OPTIONS",
                        evidence=f"Non-standard X-Frame-Options value: '{xfo}'",
                        url=self.target_url,
                    )
                )

        # 4. X-Content-Type-Options
        xcto = headers.get("x-content-type-options")
        if not xcto or "nosniff" not in xcto.lower():
            self.issues.append(
                SolutionDatabase.build_issue(
                    issue_id="SEC_MISSING_X_CONTENT_TYPE_OPTIONS",
                    evidence=f"Missing or invalid X-Content-Type-Options header: '{xcto or 'None'}'",
                    url=self.target_url,
                )
            )
        else:
            self.passed_checks.append("X-Content-Type-Options: nosniff is active.")

        # 5. Referrer-Policy
        ref_pol = headers.get("referrer-policy")
        if not ref_pol:
            self.issues.append(
                SolutionDatabase.build_issue(
                    issue_id="SEC_MISSING_REFERRER_POLICY",
                    evidence="Response lacks 'Referrer-Policy' header.",
                    url=self.target_url,
                )
            )
        else:
            self.passed_checks.append(f"Referrer-Policy configured ({ref_pol}).")

        # 6. Permissions-Policy
        perm_pol = headers.get("permissions-policy") or headers.get("feature-policy")
        if not perm_pol:
            self.issues.append(
                SolutionDatabase.build_issue(
                    issue_id="SEC_MISSING_PERMISSIONS_POLICY",
                    evidence="Response lacks 'Permissions-Policy' header.",
                    url=self.target_url,
                )
            )
        else:
            self.passed_checks.append("Permissions-Policy is active.")

    def _audit_csp_depth(self, csp_val: str):
        """Analyzes Content Security Policy directives for dangerous bypasses."""
        csp_lower = csp_val.lower()

        # Check for unsafe-inline or unsafe-eval in scripts
        has_unsafe_inline = "'unsafe-inline'" in csp_lower
        has_unsafe_eval = "'unsafe-eval'" in csp_lower

        if has_unsafe_inline or has_unsafe_eval:
            evidence_parts = []
            if has_unsafe_inline:
                evidence_parts.append("'unsafe-inline'")
            if has_unsafe_eval:
                evidence_parts.append("'unsafe-eval'")
            self.issues.append(
                SolutionDatabase.build_issue(
                    issue_id="SEC_CSP_UNSAFE_DIRECTIVE",
                    evidence=f"CSP contains bypass directives: {', '.join(evidence_parts)} in script execution policy.",
                    url=self.target_url,
                )
            )

        # Check for wildcards in script-src / default-src
        if re.search(r"(script-src|default-src)[^;]*\s\*", csp_val):
            self.issues.append(
                SolutionDatabase.build_issue(
                    issue_id="SEC_CSP_WILDCARD",
                    evidence="CSP script-src or default-src uses permissive wildcard '*' allowing scripts from any origin.",
                    url=self.target_url,
                )
            )
        elif not (has_unsafe_inline or has_unsafe_eval):
            self.passed_checks.append("Content-Security-Policy enforces strict script origin restrictions.")

    def _audit_cors(self, headers: Dict[str, str]):
        """Evaluates Cross-Origin Resource Sharing (CORS) security configuration."""
        acao = headers.get("access-control-allow-origin")
        if not acao:
            self.passed_checks.append("Strict origin isolation enforced (No open CORS headers detected).")
            return

        acao_val = acao.strip().lower()
        if acao_val == "*":
            acac = headers.get("access-control-allow-credentials", "").lower()
            if "true" in acac:
                self.issues.append(
                    SolutionDatabase.build_issue(
                        issue_id="SEC_CORS_WILDCARD",
                        evidence="Dangerous CORS policy: Access-Control-Allow-Origin: * with Allow-Credentials: true",
                        url=self.target_url,
                        custom_severity=Severity.CRITICAL,
                    )
                )
            else:
                self.issues.append(
                    SolutionDatabase.build_issue(
                        issue_id="SEC_CORS_WILDCARD",
                        evidence="CORS wildcard configured: Access-Control-Allow-Origin: *",
                        url=self.target_url,
                    )
                )
        elif acao_val == "null":
            self.issues.append(
                SolutionDatabase.build_issue(
                    issue_id="SEC_CORS_NULL_ORIGIN",
                    evidence="Access-Control-Allow-Origin permits untrusted 'null' origin.",
                    url=self.target_url,
                )
            )
        else:
            self.passed_checks.append(f"CORS restricted to authorized origin ({acao}).")

    def _audit_cookies(self, cookies: Optional[List[str]]):
        """Evaluates cookie security flags: Secure, HttpOnly, and SameSite."""
        if not cookies:
            self.metrics["cookies"] = {
                "total_cookies": 0,
                "insecure_count": 0,
                "no_httponly_count": 0,
                "weak_samesite_count": 0,
            }
            return

        insecure_cookies = []
        no_httponly_cookies = []
        weak_samesite_cookies = []

        session_keywords = {"session", "sess", "token", "auth", "jwt", "id", "phpsessid", "jsessionid", "connect.sid", "laravel"}

        for cookie_str in cookies:
            cookie_lower = cookie_str.lower()
            name_val = cookie_str.split(";")[0]
            cookie_name = name_val.split("=")[0].strip()

            # Check Secure flag on HTTPS origins
            if self.is_https and "secure" not in cookie_lower:
                insecure_cookies.append(cookie_name)

            # Check HttpOnly flag (especially for session-like cookies)
            is_session_like = any(k in cookie_name.lower() for k in session_keywords)
            if "httponly" not in cookie_lower:
                if is_session_like:
                    no_httponly_cookies.append(f"{cookie_name} (Session Token)")
                else:
                    no_httponly_cookies.append(cookie_name)

            # Check SameSite flag
            if "samesite" not in cookie_lower:
                weak_samesite_cookies.append(cookie_name)
            elif "samesite=none" in cookie_lower and "secure" not in cookie_lower:
                weak_samesite_cookies.append(f"{cookie_name} (SameSite=None without Secure)")

        if insecure_cookies:
            self.issues.append(
                SolutionDatabase.build_issue(
                    issue_id="SEC_COOKIE_INSECURE",
                    evidence=f"Cookie(s) missing 'Secure' flag over HTTPS: {', '.join(insecure_cookies[:3])}",
                    url=self.target_url,
                )
            )
        elif self.is_https:
            self.passed_checks.append("All declared cookies include the 'Secure' attribute.")

        if any("(Session Token)" in c for c in no_httponly_cookies):
            self.issues.append(
                SolutionDatabase.build_issue(
                    issue_id="SEC_COOKIE_NO_HTTPONLY",
                    evidence=f"Authentication/session cookie(s) missing 'HttpOnly': {', '.join(no_httponly_cookies[:3])}",
                    url=self.target_url,
                    custom_severity=Severity.HIGH,
                )
            )
        elif no_httponly_cookies:
            self.issues.append(
                SolutionDatabase.build_issue(
                    issue_id="SEC_COOKIE_NO_HTTPONLY",
                    evidence=f"Cookie(s) missing 'HttpOnly' flag: {', '.join(no_httponly_cookies[:3])}",
                    url=self.target_url,
                    custom_severity=Severity.MEDIUM,
                )
            )
        else:
            self.passed_checks.append("Session cookies protected with 'HttpOnly' against XSS theft.")

        if weak_samesite_cookies:
            self.issues.append(
                SolutionDatabase.build_issue(
                    issue_id="SEC_COOKIE_WEAK_SAMESITE",
                    evidence=f"Cookie(s) missing SameSite protection (CSRF risk): {', '.join(weak_samesite_cookies[:3])}",
                    url=self.target_url,
                )
            )
        else:
            self.passed_checks.append("Cookies configured with explicit SameSite CSRF protection.")

        self.metrics["cookies"] = {
            "total_cookies": len(cookies),
            "insecure_count": len(insecure_cookies),
            "no_httponly_count": len(no_httponly_cookies),
            "weak_samesite_count": len(weak_samesite_cookies),
        }

    def _audit_sri(self, raw_html: str):
        """Checks if third-party CDN scripts use Subresource Integrity (SRI)."""
        if not raw_html:
            return

        soup = BeautifulSoup(raw_html, "html.parser")
        scripts = soup.find_all("script", src=True)

        cdn_domains = [
            "cdn.jsdelivr.net", "cdnjs.cloudflare.com", "unpkg.com",
            "code.jquery.com", "stackpath.bootstrapcdn.com", "cdn.bootcdn.net",
            "ajax.googleapis.com"
        ]
        missing_sri = []

        for s in scripts:
            src = s.get("src", "")
            if any(cdn in src for cdn in cdn_domains):
                if not s.get("integrity"):
                    missing_sri.append(src)

        if missing_sri:
            preview = ", ".join(missing_sri[:2])
            self.issues.append(
                SolutionDatabase.build_issue(
                    issue_id="SEC_SRI_MISSING",
                    evidence=f"{len(missing_sri)} external CDN script(s) loaded without SRI hash verification (e.g. {preview})",
                    url=self.target_url,
                )
            )
        elif len(scripts) > 0:
            self.passed_checks.append("External CDN scripts are protected with SRI integrity hashes.")

    def _audit_insecure_forms(self, raw_html: str):
        """Checks for password/auth forms submitting over unencrypted HTTP."""
        if not raw_html:
            return

        soup = BeautifulSoup(raw_html, "html.parser")
        forms = soup.find_all("form")

        for f in forms:
            has_password = bool(f.find("input", type="password"))
            action = (f.get("action") or "").strip().lower()
            if has_password and (action.startswith("http://") or (not self.is_https and not action.startswith("https://"))):
                self.issues.append(
                    SolutionDatabase.build_issue(
                        issue_id="SEC_INSECURE_PASSWORD_FORM",
                        evidence=f"Password form submits credentials to unencrypted action: '{action or self.target_url}'",
                        url=self.target_url,
                    )
                )
                break

    def _audit_exposed_secrets(self, raw_html: str):
        """Scans frontend HTML and inline scripts for hardcoded sensitive cloud tokens."""
        if not raw_html:
            return

        secret_patterns = [
            ("AWS Access Key", r"\b(AKIA[0-9A-Z]{16})\b"),
            ("Private Cryptographic Key", r"-----BEGIN\s+(RSA|EC|DSA|OPENSSH)\s+PRIVATE\s+KEY-----"),
            ("High-Entropy API Secret", r"""(?i)(api[_-]?secret|jwt[_-]?secret|private[_-]?key)\s*[:=]\s*['"][a-zA-Z0-9_\-]{24,}['"]"""),
        ]

        for name, pattern in secret_patterns:
            match = re.search(pattern, raw_html)
            if match:
                masked_val = match.group(0)[:6] + "..." + match.group(0)[-4:] if len(match.group(0)) > 10 else "***"
                self.issues.append(
                    SolutionDatabase.build_issue(
                        issue_id="SEC_EXPOSED_SECRET",
                        evidence=f"Exposed {name} detected in page source (Sample: {masked_val})",
                        url=self.target_url,
                    )
                )

    async def _audit_email_security(self):
        """Checks domain DNS email spoofing protections: DMARC and SPF using DNS-over-HTTPS."""
        async with httpx.AsyncClient(timeout=4.0) as client:
            # 1. DMARC query
            try:
                dmarc_resp = await client.get(f"https://dns.google/resolve?name=_dmarc.{self.domain}&type=TXT")
                if dmarc_resp.status_code == 200:
                    dmarc_data = dmarc_resp.json()
                    answers = dmarc_data.get("Answer", [])
                    dmarc_records = [a.get("data", "").strip('"') for a in answers if "v=DMARC" in a.get("data", "").upper()]

                    if not dmarc_records:
                        self.issues.append(
                            SolutionDatabase.build_issue(
                                issue_id="SEC_MISSING_DMARC",
                                evidence=f"No DMARC TXT record found at _dmarc.{self.domain}.",
                                url=self.target_url,
                            )
                        )
                    else:
                        record_str = dmarc_records[0]
                        self.metrics["dmarc"] = record_str
                        if "p=none" in record_str.lower():
                            self.issues.append(
                                SolutionDatabase.build_issue(
                                    issue_id="SEC_WEAK_DMARC",
                                    evidence=f"DMARC policy is set to monitoring only (p=none): '{record_str}'",
                                    url=self.target_url,
                                )
                            )
                        else:
                            policy_match = re.search(r"p=(quarantine|reject)", record_str, re.I)
                            pol = policy_match.group(1) if policy_match else "active"
                            self.passed_checks.append(f"DMARC email protection actively enforces policy ({pol}).")
            except Exception:
                pass

            # 2. SPF query
            try:
                spf_resp = await client.get(f"https://dns.google/resolve?name={self.domain}&type=TXT")
                if spf_resp.status_code == 200:
                    spf_data = spf_resp.json()
                    answers = spf_data.get("Answer", [])
                    spf_records = [a.get("data", "").strip('"') for a in answers if "v=spf1" in a.get("data", "").lower()]

                    if not spf_records:
                        self.issues.append(
                            SolutionDatabase.build_issue(
                                issue_id="SEC_MISSING_SPF",
                                evidence=f"No SPF (v=spf1) TXT record found on {self.domain}.",
                                url=self.target_url,
                            )
                        )
                    else:
                        spf_str = spf_records[0]
                        self.metrics["spf"] = spf_str
                        if "+all" in spf_str.lower():
                            self.issues.append(
                                SolutionDatabase.build_issue(
                                    issue_id="SEC_PERMISSIVE_SPF",
                                    evidence=f"SPF record contains '+all' authorizing any server globally: '{spf_str}'",
                                    url=self.target_url,
                                )
                            )
                        else:
                            self.passed_checks.append("SPF email authentication record is active on domain.")
            except Exception:
                pass

    def _audit_information_leakage(self, headers: Dict[str, str]):
        """Detects exposed server names, PHP/runtime versions, and framework fingerprints."""
        server = headers.get("server")
        if server:
            if re.search(r"[\d\.]+", server):
                self.issues.append(
                    SolutionDatabase.build_issue(
                        issue_id="SEC_SERVER_HEADER_EXPOSED",
                        evidence=f"Server header exposes software version: 'Server: {server}'",
                        url=self.target_url,
                    )
                )
            else:
                self.passed_checks.append("Server banner does not expose detailed version numbers.")
        else:
            self.passed_checks.append("Server banner header is hidden.")

        x_powered_by = headers.get("x-powered-by")
        if x_powered_by:
            self.issues.append(
                SolutionDatabase.build_issue(
                    issue_id="SEC_X_POWERED_BY_EXPOSED",
                    evidence=f"Backend technology disclosed: 'X-Powered-By: {x_powered_by}'",
                    url=self.target_url,
                )
            )
        else:
            self.passed_checks.append("X-Powered-By technology fingerprint is suppressed.")

    def _audit_mixed_content(self, insecure_resources: List[Dict[str, str]]):
        """Identifies any HTTP assets referenced on HTTPS origin."""
        if not self.is_https or not insecure_resources:
            return

        preview = ", ".join([f"{r['type']}: {r['src']}" for r in insecure_resources[:3]])
        self.issues.append(
            SolutionDatabase.build_issue(
                issue_id="SEC_MIXED_CONTENT",
                evidence=f"{len(insecure_resources)} insecure HTTP asset(s) loaded on HTTPS page: {preview}",
                url=self.target_url,
            )
        )

    async def _probe_sensitive_files(self):
        """Non-intrusive probe for publicly accessible configuration/backup files."""
        base_origin = f"{self.parsed.scheme}://{self.parsed.netloc}"

        async with httpx.AsyncClient(verify=False, follow_redirects=False, timeout=4.0) as client:
            tasks = [self._probe_single_path(client, base_origin, probe) for probe in self.SENSITIVE_PROBES]
            await asyncio.gather(*tasks)

    async def _probe_single_path(
        self, client: httpx.AsyncClient, base_origin: str, probe: Dict[str, str]
    ):
        target_path = probe["path"]
        probe_url = f"{base_origin}{target_path}"
        try:
            resp = await client.get(probe_url)
            if resp.status_code == 200:
                content_type = resp.headers.get("content-type", "").lower()
                body = resp.text[:1000]

                # Ensure it is not a soft 404 HTML error page
                if "text/html" in content_type and not target_path.endswith(".html"):
                    if "<!doctype" in body.lower() or "<html" in body.lower() or "<head" in body.lower():
                        return  # False positive / SPA 404 fallback

                if re.search(probe["signature"], body, re.I):
                    self.issues.append(
                        SolutionDatabase.build_issue(
                            issue_id="SEC_SENSITIVE_FILE_EXPOSED",
                            evidence=f"Sensitive file publicly accessible: {probe_url} (Detected {probe['type']})",
                            url=probe_url,
                        )
                    )
        except Exception:
            pass
