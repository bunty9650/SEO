"""Website Security, SSL/TLS Hygiene, and Configuration Auditor."""
from __future__ import annotations

import asyncio
from datetime import datetime, timezone
import re
import socket
import ssl
from typing import Any, Dict, List, Optional
from urllib.parse import urlparse
import httpx
from auditors.base import AuditIssue, AuditResult, Category, Severity
from solutions.solution_database import SolutionDatabase


class SecurityAuditor:
    """Evaluates SSL certificates, HTTP security headers, info leakage, and sensitive file exposures."""

    # Sensitive paths for non-intrusive configuration probing
    SENSITIVE_PROBES = [
        {"path": "/.env", "type": "Environment file", "signature": r"(APP_ENV|DB_|SECRET|KEY=)"},
        {"path": "/.git/HEAD", "type": "Git repository metadata", "signature": r"ref:\s+refs/"},
        {"path": "/docker-compose.yml", "type": "Docker compose configuration", "signature": r"(services:|version:)"},
        {"path": "/wp-config.php.bak", "type": "WordPress config backup", "signature": r"(DB_PASSWORD|table_prefix)"},
        {"path": "/backup.sql", "type": "Database SQL dump", "signature": r"(CREATE TABLE|INSERT INTO)"},
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

    async def run(
        self,
        headers: Optional[Dict[str, str]] = None,
        insecure_resources: Optional[List[Dict[str, str]]] = None,
    ) -> AuditResult:
        """Executes full security audit including SSL validation, header analysis, and safe file probes."""
        self.issues.clear()
        self.passed_checks.clear()

        # 1. SSL/TLS Certificate Audit
        ssl_info = await self._audit_ssl()
        self.metrics["ssl"] = ssl_info

        # 2. HTTP Headers Audit
        if headers is None:
            headers = await self._fetch_headers()
        self.metrics["headers"] = headers
        self._audit_security_headers(headers)
        self._audit_information_leakage(headers)

        # 3. Mixed Content Audit
        if insecure_resources:
            self._audit_mixed_content(insecure_resources)

        # 4. Safe Sensitive Files Exposure Probe
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
        """Fetches root headers if not supplied by the crawler."""
        headers: Dict[str, str] = {}
        try:
            async with httpx.AsyncClient(verify=False, follow_redirects=True, timeout=8.0) as client:
                resp = await client.get(self.target_url)
                headers = {k.lower(): v for k, v in resp.headers.items()}
        except Exception:
            pass
        return headers

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
                AuditIssue(
                    issue_id="SEC_NO_HTTPS",
                    title="Website Does Not Enforce HTTPS",
                    category=Category.SECURITY,
                    severity=Severity.CRITICAL,
                    description="The site is served over unencrypted HTTP, leaving all traffic vulnerable to interception and tampering.",
                    evidence=f"Target URL scheme is {self.parsed.scheme}://",
                    url=self.target_url,
                    solution_apache="""RewriteEngine On
RewriteCond %{HTTPS} off
RewriteRule ^(.*)$ https://%{HTTP_HOST}%{REQUEST_URI} [L,R=301]""",
                    solution_nginx="""return 301 https://$host$request_uri;""",
                    solution_code=None,
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

                # If unverified, getpeercert() binary der can be decoded or parsed
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
            # Check max-age
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

        # 2. CSP
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

        # 3. X-Frame-Options
        xfo = headers.get("x-frame-options")
        if not xfo:
            # CSP frame-ancestors is also an acceptable modern alternative
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

    def _audit_information_leakage(self, headers: Dict[str, str]):
        """Detects exposed server names, PHP/runtime versions, and framework fingerprints."""
        server = headers.get("server")
        if server:
            # If server reveals version numbers like Apache/2.4.41 or nginx/1.18.0
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
            # Must return 200 OK
            if resp.status_code == 200:
                content_type = resp.headers.get("content-type", "").lower()
                body = resp.text[:1000]

                # Ensure it is not a soft 404 HTML error page
                if "text/html" in content_type and not target_path.endswith(".html"):
                    # Check if body contains HTML tags
                    if "<!doctype" in body.lower() or "<html" in body.lower() or "<head" in body.lower():
                        return  # False positive / SPA 404 fallback

                # Validate with signature regex
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
