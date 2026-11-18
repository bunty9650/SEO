"""Central Solution & Remediation Engine.

Provides authoritative explanations, severity levels, and copy-paste
configuration code for Apache, Nginx, HTML, and WordPress for all audit issues.
"""
from __future__ import annotations

from typing import Dict, Optional
from pydantic import BaseModel
from auditors.base import AuditIssue, Category, Severity


class RemediationCode(BaseModel):
    apache: Optional[str] = None
    nginx: Optional[str] = None
    code: Optional[str] = None
    description: str
    impact: Severity
    learn_more_url: Optional[str] = None


class IssueSolution(BaseModel):
    issue_id: str
    title: str
    category: Category
    default_severity: Severity
    description: str
    remediation: RemediationCode
    bad_sign: Optional[str] = None
    why_bad: Optional[str] = None


class SolutionDatabase:
    """Repository of pre-configured remediation playbooks."""

    _CATALOG: Dict[str, IssueSolution] = {
        # -------------------------------------------------------------
        # SECURITY & SSL ISSUES (ADVANCED DIAGNOSTICS)
        # -------------------------------------------------------------
        "SEC_NO_HTTPS": IssueSolution(
            issue_id="SEC_NO_HTTPS",
            title="Website Does Not Enforce HTTPS Encryption",
            category=Category.SECURITY,
            default_severity=Severity.CRITICAL,
            description="The site is served over unencrypted HTTP, leaving all traffic vulnerable to interception, tampering, and session hijacking.",
            bad_sign="Cleartext HTTP connection without TLS encryption.",
            why_bad="Attackers on the same network (public Wi-Fi, ISP, or rogue routers) can eavesdrop on every byte transferred, intercept login credentials, and inject malicious scripts or ads into the page.",
            remediation=RemediationCode(
                apache="""RewriteEngine On
RewriteCond %{HTTPS} off
RewriteRule ^(.*)$ https://%{HTTP_HOST}%{REQUEST_URI} [L,R=301]""",
                nginx="""return 301 https://$host$request_uri;""",
                code=None,
                description="Enforce HTTP to HTTPS 301 permanent redirect globally.",
                impact=Severity.CRITICAL,
            ),
        ),

        "SEC_MISSING_HSTS": IssueSolution(
            issue_id="SEC_MISSING_HSTS",
            title="Missing HTTP Strict Transport Security (HSTS) Header",
            category=Category.SECURITY,
            default_severity=Severity.HIGH,
            description="Forces browsers to communicate exclusively over HTTPS, blocking SSL-stripping attacks.",
            bad_sign="Missing 'Strict-Transport-Security' response header.",
            why_bad="Without HSTS, a user's initial unencrypted HTTP connection can be downgraded by a Man-in-the-Middle (MitM) attacker using tools like sslstrip, intercepting traffic before an HTTPS upgrade occurs.",
            remediation=RemediationCode(
                apache="""<IfModule mod_headers.c>
    Header always set Strict-Transport-Security "max-age=31536000; includeSubDomains; preload"
</IfModule>""",
                nginx="""add_header Strict-Transport-Security "max-age=31536000; includeSubDomains; preload" always;""",
                code="""// In WordPress functions.php:
add_action('send_headers', function() {
    header("Strict-Transport-Security: max-age=31536000; includeSubDomains; preload");
});""",
                description="Add the Strict-Transport-Security header with at least 1-year max-age (31536000 seconds).",
                impact=Severity.HIGH,
                learn_more_url="https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Strict-Transport-Security",
            ),
        ),

        "SEC_WEAK_HSTS": IssueSolution(
            issue_id="SEC_WEAK_HSTS",
            title="Suboptimal HSTS Header Configuration",
            category=Category.SECURITY,
            default_severity=Severity.MEDIUM,
            description="The HSTS max-age is set to less than 1 year or lacks 'includeSubDomains' / 'preload'.",
            bad_sign="HSTS header duration is too short or leaves subdomains unprotected.",
            why_bad="Short expiration times reduce the window of protection, and omitting 'includeSubDomains' leaves subdomain APIs and staging environments vulnerable to SSL-stripping.",
            remediation=RemediationCode(
                apache="""<IfModule mod_headers.c>
    Header always set Strict-Transport-Security "max-age=31536000; includeSubDomains; preload"
</IfModule>""",
                nginx="""add_header Strict-Transport-Security "max-age=31536000; includeSubDomains; preload" always;""",
                code=None,
                description="Increase max-age to 31536000 (1 year) and append 'includeSubDomains; preload'.",
                impact=Severity.MEDIUM,
            ),
        ),

        "SEC_MISSING_CSP": IssueSolution(
            issue_id="SEC_MISSING_CSP",
            title="Missing Content-Security-Policy (CSP) Header",
            category=Category.SECURITY,
            default_severity=Severity.HIGH,
            description="CSP is an essential defense-in-depth layer that restricts allowable resource origins.",
            bad_sign="No Content-Security-Policy header defined on the server.",
            why_bad="If an attacker finds any Cross-Site Scripting (XSS) vulnerability or malicious HTML injection on your site, there is no browser policy to prevent them from executing arbitrary external JavaScript or exfiltrating user cookies and tokens.",
            remediation=RemediationCode(
                apache="""<IfModule mod_headers.c>
    Header always set Content-Security-Policy "default-src 'self'; script-src 'self' https:; style-src 'self' https: 'unsafe-inline'; img-src 'self' data: https:; font-src 'self' https: data:; connect-src 'self' https:; frame-ancestors 'self';"
</IfModule>""",
                nginx="""add_header Content-Security-Policy "default-src 'self'; script-src 'self' https:; style-src 'self' https: 'unsafe-inline'; img-src 'self' data: https:; font-src 'self' https: data:; connect-src 'self' https:; frame-ancestors 'self';" always;""",
                code="""<meta http-equiv="Content-Security-Policy" content="default-src 'self'; script-src 'self' https:; style-src 'self' https:;">""",
                description="Define an explicit Content-Security-Policy restricting allowed script and frame origins.",
                impact=Severity.HIGH,
                learn_more_url="https://developer.mozilla.org/en-US/docs/Web/HTTP/CSP",
            ),
        ),

        "SEC_CSP_UNSAFE_DIRECTIVE": IssueSolution(
            issue_id="SEC_CSP_UNSAFE_DIRECTIVE",
            title="Content Security Policy Contains Insecure Directives ('unsafe-inline' or 'unsafe-eval')",
            category=Category.SECURITY,
            default_severity=Severity.MEDIUM,
            description="CSP policy includes 'unsafe-inline' or 'unsafe-eval' in script execution directives.",
            bad_sign="CSP allows execution of inline scripts or eval() string-to-code compilation.",
            why_bad="The main purpose of CSP is defeating XSS. Permitting 'unsafe-inline' allows attackers to execute injected inline `<script>` tags, and 'unsafe-eval' allows dynamic string execution, severely undermining your site's XSS immunity.",
            remediation=RemediationCode(
                apache=None,
                nginx="""# Replace 'unsafe-inline' with cryptographic script nonces:
# script-src 'self' 'nonce-$RANDOM_NONCE';""",
                code="""<!-- Use nonces for necessary inline scripts instead of unsafe-inline -->
<script nonce="EDNnf03nceIzorTkBnQgxA==">/* Safe inline script */</script>""",
                description="Refactor inline scripts into external files or protect them using CSP nonces/hashes.",
                impact=Severity.MEDIUM,
            ),
        ),

        "SEC_CSP_WILDCARD": IssueSolution(
            issue_id="SEC_CSP_WILDCARD",
            title="Content Security Policy Allows Scripts from Any Origin (Wildcard '*')",
            category=Category.SECURITY,
            default_severity=Severity.HIGH,
            description="CSP policy uses wildcard '*' in script-src or default-src.",
            bad_sign="Permissive '*' wildcard allows scripts to be loaded from any website on the internet.",
            why_bad="Attackers can host malicious JavaScript payloads on any public cloud bucket (AWS S3, Firebase, GitHub) and execute them on your site without violating the CSP policy.",
            remediation=RemediationCode(
                apache=None,
                nginx="""add_header Content-Security-Policy "default-src 'self'; script-src 'self' https://trusted-cdn.com;" always;""",
                code=None,
                description="Remove '*' and replace with an explicit whitelist of trusted script hostnames.",
                impact=Severity.HIGH,
            ),
        ),

        "SEC_MISSING_X_FRAME_OPTIONS": IssueSolution(
            issue_id="SEC_MISSING_X_FRAME_OPTIONS",
            title="Missing X-Frame-Options Header (Clickjacking Risk)",
            category=Category.SECURITY,
            default_severity=Severity.HIGH,
            description="Prevents other sites from embedding your pages inside hidden iframes.",
            bad_sign="Page can be framed by arbitrary external websites.",
            why_bad="Attackers can embed your site in an invisible iframe overlay on an external phishing page. When users click on what looks like a harmless button or game, they unknowingly click sensitive actions on your site (Clickjacking).",
            remediation=RemediationCode(
                apache="""<IfModule mod_headers.c>
    Header always set X-Frame-Options "SAMEORIGIN"
</IfModule>""",
                nginx="""add_header X-Frame-Options "SAMEORIGIN" always;""",
                code="""// In WordPress functions.php:
add_action('send_headers', function() {
    header("X-Frame-Options: SAMEORIGIN");
});""",
                description="Set X-Frame-Options to DENY or SAMEORIGIN.",
                impact=Severity.HIGH,
                learn_more_url="https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/X-Frame-Options",
            ),
        ),

        "SEC_MISSING_X_CONTENT_TYPE_OPTIONS": IssueSolution(
            issue_id="SEC_MISSING_X_CONTENT_TYPE_OPTIONS",
            title="Missing X-Content-Type-Options Header (MIME-Sniffing Risk)",
            category=Category.SECURITY,
            default_severity=Severity.MEDIUM,
            description="Prevents browsers from MIME-sniffing a response away from declared content-type.",
            bad_sign="X-Content-Type-Options header is absent or not set to 'nosniff'.",
            why_bad="Browsers may inspect the content of user-uploaded files (like images or text) and execute disguised HTML or JavaScript inside them, enabling Stored XSS attacks through file uploads.",
            remediation=RemediationCode(
                apache="""<IfModule mod_headers.c>
    Header always set X-Content-Type-Options "nosniff"
</IfModule>""",
                nginx="""add_header X-Content-Type-Options "nosniff" always;""",
                code=None,
                description="Set X-Content-Type-Options to 'nosniff'.",
                impact=Severity.MEDIUM,
            ),
        ),

        "SEC_MISSING_REFERRER_POLICY": IssueSolution(
            issue_id="SEC_MISSING_REFERRER_POLICY",
            title="Missing Referrer-Policy Header",
            category=Category.SECURITY,
            default_severity=Severity.LOW,
            description="Controls how much referrer information is leaked when navigating away from your site.",
            bad_sign="No Referrer-Policy specified.",
            why_bad="Sensitive query parameters (e.g. session tokens, password reset links, email addresses) can leak to external third-party sites in the HTTP Referer header when users click outbound links.",
            remediation=RemediationCode(
                apache="""<IfModule mod_headers.c>
    Header always set Referrer-Policy "strict-origin-when-cross-origin"
</IfModule>""",
                nginx="""add_header Referrer-Policy "strict-origin-when-cross-origin" always;""",
                code="""<meta name="referrer" content="strict-origin-when-cross-origin">""",
                description="Set Referrer-Policy to 'strict-origin-when-cross-origin'.",
                impact=Severity.LOW,
            ),
        ),

        "SEC_MISSING_PERMISSIONS_POLICY": IssueSolution(
            issue_id="SEC_MISSING_PERMISSIONS_POLICY",
            title="Missing Permissions-Policy Header",
            category=Category.SECURITY,
            default_severity=Severity.LOW,
            description="Allows site operators to explicitly disable risky browser APIs (camera, mic, geolocation).",
            bad_sign="Permissions-Policy header is missing.",
            why_bad="Third-party embedded widgets, iframes, or ad networks could request access to device hardware (microphone, camera, GPS location, payment requests) under your domain's trust context.",
            remediation=RemediationCode(
                apache="""<IfModule mod_headers.c>
    Header always set Permissions-Policy "geolocation=(), microphone=(), camera=()"
</IfModule>""",
                nginx="""add_header Permissions-Policy "geolocation=(), microphone=(), camera=()" always;""",
                code=None,
                description="Restrict unused browser capabilities via Permissions-Policy.",
                impact=Severity.LOW,
            ),
        ),

        "SEC_COOKIE_INSECURE": IssueSolution(
            issue_id="SEC_COOKIE_INSECURE",
            title="Cookie Missing 'Secure' Flag Over HTTPS",
            category=Category.SECURITY,
            default_severity=Severity.HIGH,
            description="Cookies transmitted without the 'Secure' attribute can be sent over unencrypted HTTP.",
            bad_sign="Cookie lacks the 'Secure' flag on an HTTPS website.",
            why_bad="If a user accidentally visits an http:// link or resource on the domain, the browser will send this cookie in cleartext over the network, allowing local Wi-Fi eavesdroppers to intercept session cookies.",
            remediation=RemediationCode(
                apache="""# In .htaccess:
Header always edit Set-Cookie ^(.*)$ "$1; Secure" """,
                nginx="""# In proxy config:
proxy_cookie_flags ~ secure;""",
                code="""// In PHP:
session_set_cookie_params(['secure' => true]);

// In Express.js:
res.cookie('token', val, { secure: true });""",
                description="Ensure all Set-Cookie directives append the 'Secure' attribute.",
                impact=Severity.HIGH,
            ),
        ),

        "SEC_COOKIE_NO_HTTPONLY": IssueSolution(
            issue_id="SEC_COOKIE_NO_HTTPONLY",
            title="Session / Auth Cookie Missing 'HttpOnly' Flag",
            category=Category.SECURITY,
            default_severity=Severity.HIGH,
            description="Authentication or session cookie is accessible to client-side JavaScript.",
            bad_sign="Session cookie missing 'HttpOnly' protection.",
            why_bad="Any JavaScript running on the page (via XSS or a compromised npm package/analytics script) can read `document.cookie` and immediately steal the user's session token, leading to instant account takeover without password cracking.",
            remediation=RemediationCode(
                apache="""# In .htaccess:
Header always edit Set-Cookie ^(.*)$ "$1; HttpOnly" """,
                nginx="""# In proxy config:
proxy_cookie_flags ~ httponly;""",
                code="""// In PHP:
session_set_cookie_params(['httponly' => true]);

// In Express.js:
res.cookie('session_id', val, { httpOnly: true });""",
                description="Set the HttpOnly flag on all session and authentication cookies.",
                impact=Severity.HIGH,
            ),
        ),

        "SEC_COOKIE_WEAK_SAMESITE": IssueSolution(
            issue_id="SEC_COOKIE_WEAK_SAMESITE",
            title="Cookie Missing or Weak 'SameSite' Attribute",
            category=Category.SECURITY,
            default_severity=Severity.MEDIUM,
            description="Cookie lacks SameSite=Lax or SameSite=Strict protection.",
            bad_sign="Cookie lacks an explicit SameSite restriction against cross-site requests.",
            why_bad="Enables Cross-Site Request Forgery (CSRF). Malicious external websites can trick a user's browser into submitting unauthorized authenticated requests to your site while the user is logged in.",
            remediation=RemediationCode(
                apache="""Header always edit Set-Cookie ^(.*)$ "$1; SameSite=Lax" """,
                nginx="""proxy_cookie_flags ~ samesite=lax;""",
                code="""// In PHP:
session_set_cookie_params(['samesite' => 'Lax']);""",
                description="Configure cookies with SameSite=Lax or SameSite=Strict.",
                impact=Severity.MEDIUM,
            ),
        ),

        "SEC_CORS_WILDCARD": IssueSolution(
            issue_id="SEC_CORS_WILDCARD",
            title="Insecure CORS Policy Allows Wildcard Origin (*)",
            category=Category.SECURITY,
            default_severity=Severity.HIGH,
            description="Access-Control-Allow-Origin header is set to wildcard '*' on potentially sensitive endpoints.",
            bad_sign="CORS header permits any arbitrary external origin to access responses.",
            why_bad="Any malicious website visited by your users can send fetch() requests to your domain and read the response body, completely bypassing the browser's Same-Origin Policy (SOP).",
            remediation=RemediationCode(
                apache="""# Specify exact allowed origin instead of wildcard:
Header set Access-Control-Allow-Origin "https://trusted.example.com" """,
                nginx="""# Restrict CORS to authorized origins:
add_header Access-Control-Allow-Origin "https://trusted.example.com";""",
                code=None,
                description="Replace wildcard '*' with an explicit whitelist of trusted domain origins.",
                impact=Severity.HIGH,
            ),
        ),

        "SEC_CORS_NULL_ORIGIN": IssueSolution(
            issue_id="SEC_CORS_NULL_ORIGIN",
            title="Insecure CORS Policy Allows 'null' Origin",
            category=Category.SECURITY,
            default_severity=Severity.HIGH,
            description="Access-Control-Allow-Origin header reflects or permits 'null'.",
            bad_sign="CORS permits untrusted 'null' origin.",
            why_bad="Sandboxed iframes and local HTML files generate a 'null' origin. Attackers can embed a sandboxed iframe on a phishing website to exploit this and steal private responses.",
            remediation=RemediationCode(
                apache=None,
                nginx="""# Do NOT allow null origin:
if ($http_origin ~* "^null$") { return 403; }""",
                code=None,
                description="Remove 'null' from accepted CORS origins list.",
                impact=Severity.HIGH,
            ),
        ),

        "SEC_MISSING_DMARC": IssueSolution(
            issue_id="SEC_MISSING_DMARC",
            title="Missing Domain DMARC Email Authentication Record",
            category=Category.SECURITY,
            default_severity=Severity.HIGH,
            description="Domain lacks a DMARC DNS record to protect against brand email spoofing.",
            bad_sign="No TXT record found at `_dmarc.<domain>`.",
            why_bad="Without DMARC, cybercriminals can easily forge emails pretending to come directly from your domain (e.g. ceo@yourdomain.com, accounts@yourdomain.com) to execute phishing attacks and invoice scams against your customers.",
            remediation=RemediationCode(
                code="""# Add this DNS TXT record to your domain's DNS zone:
# Name: _dmarc.yourdomain.com
# Type: TXT
# Value:
v=DMARC1; p=reject; sp=reject; rua=mailto:dmarc-reports@yourdomain.com; aspf=r; adkim=r;""",
                description="Publish a strict DMARC TXT record with p=quarantine or p=reject.",
                impact=Severity.HIGH,
                learn_more_url="https://dmarc.org/",
            ),
        ),

        "SEC_WEAK_DMARC": IssueSolution(
            issue_id="SEC_WEAK_DMARC",
            title="Weak DMARC Policy (p=none - Monitoring Only)",
            category=Category.SECURITY,
            default_severity=Severity.MEDIUM,
            description="DMARC record exists but policy is set to 'p=none', which does not block spoofed emails.",
            bad_sign="DMARC policy set to 'p=none' instead of 'quarantine' or 'reject'.",
            why_bad="A 'p=none' policy only sends telemetry reports but takes NO protective action. Fraudulent emails sent by attackers will still land directly in recipient inboxes.",
            remediation=RemediationCode(
                code="""# Upgrade DMARC TXT record:
v=DMARC1; p=quarantine; rua=mailto:dmarc@yourdomain.com;""",
                description="Upgrade DMARC policy from p=none to p=quarantine or p=reject.",
                impact=Severity.MEDIUM,
            ),
        ),

        "SEC_MISSING_SPF": IssueSolution(
            issue_id="SEC_MISSING_SPF",
            title="Missing SPF (Sender Policy Framework) DNS Record",
            category=Category.SECURITY,
            default_severity=Severity.HIGH,
            description="Domain has no SPF record specifying authorized outgoing mail servers.",
            bad_sign="Root domain lacks an SPF TXT record (`v=spf1 ...`).",
            why_bad="Receiving mail servers cannot determine which servers are authorized to send email for your domain, allowing unauthorized servers to spoof your domain name.",
            remediation=RemediationCode(
                code="""# Add DNS TXT record for your root domain:
# Name: @ (or yourdomain.com)
# Type: TXT
# Value (Google Workspace example):
v=spf1 include:_spf.google.com ~all""",
                description="Publish an SPF record listing your authorized mail provider servers.",
                impact=Severity.HIGH,
            ),
        ),

        "SEC_PERMISSIVE_SPF": IssueSolution(
            issue_id="SEC_PERMISSIVE_SPF",
            title="Permissive SPF Record Authorizes Global Senders (+all)",
            category=Category.SECURITY,
            default_severity=Severity.HIGH,
            description="SPF record concludes with '+all', authorizing any IP address to send email.",
            bad_sign="SPF terminates with '+all' (pass all).",
            why_bad="This completely disables SPF email protection by explicitly telling the world that every server on the internet is authorized to send email on your behalf.",
            remediation=RemediationCode(
                code="""# Change '+all' to '~all' (SoftFail) or '-all' (HardFail):
v=spf1 include:_spf.google.com -all""",
                description="Replace '+all' with '-all' or '~all' in your SPF record.",
                impact=Severity.HIGH,
            ),
        ),

        "SEC_SRI_MISSING": IssueSolution(
            issue_id="SEC_SRI_MISSING",
            title="Third-Party Scripts Loaded Without Subresource Integrity (SRI)",
            category=Category.SECURITY,
            default_severity=Severity.LOW,
            description="External scripts loaded from public CDNs lack integrity checksum hashes.",
            bad_sign="<script src='https://cdn...'> tag has no 'integrity' cryptographic hash.",
            why_bad="If the external CDN or DNS provider is compromised (supply chain attack), attackers can modify the hosted script to inject card skimmers (Magecart) or malware into your visitors' browsers.",
            remediation=RemediationCode(
                code="""<!-- Add integrity sha384/sha512 hash and crossorigin attribute -->
<script src="https://cdn.example.com/lib.min.js" 
        integrity="sha384-oqVuAfXRKap7fdgcCY5uykM6+R9GqQ8K/uxy9rx7HNQlGYl1kPzQho1wx4JwY8wC" 
        crossorigin="anonymous"></script>""",
                description="Add Subresource Integrity (SRI) hashes to all external script tags.",
                impact=Severity.LOW,
                learn_more_url="https://developer.mozilla.org/en-US/docs/Web/Security/Subresource_Integrity",
            ),
        ),

        "SEC_INSECURE_PASSWORD_FORM": IssueSolution(
            issue_id="SEC_INSECURE_PASSWORD_FORM",
            title="Password or Authentication Form Submitted Insecurely",
            category=Category.SECURITY,
            default_severity=Severity.CRITICAL,
            description="Form containing a password input field submits to an unencrypted destination.",
            bad_sign="`<input type='password'>` form target starts with http:// instead of https://.",
            why_bad="User passwords and usernames are transmitted across the network in plaintext. Any attacker on the local network or Wi-Fi can capture credentials using packet sniffers.",
            remediation=RemediationCode(
                code="""<!-- Ensure form action explicitly targets HTTPS -->
<form action="https://yourdomain.com/login" method="POST">""",
                description="Ensure all login and authentication forms submit exclusively to https:// endpoints.",
                impact=Severity.CRITICAL,
            ),
        ),

        "SEC_EXPOSED_SECRET": IssueSolution(
            issue_id="SEC_EXPOSED_SECRET",
            title="High-Risk Secret or API Key Hardcoded in Public HTML/Scripts",
            category=Category.SECURITY,
            default_severity=Severity.HIGH,
            description="Hardcoded cloud credentials, private keys, or API tokens detected in frontend source code.",
            bad_sign="High-entropy private key, AWS token, or sensitive API key found in public HTML/JS.",
            why_bad="Anyone viewing page source or automated web scraping bots can harvest these credentials and gain unauthorized access to backend databases, cloud infrastructure, or third-party APIs.",
            remediation=RemediationCode(
                code="""// Move secrets to backend server environment variables:
const API_KEY = process.env.API_SECRET_KEY; // Never expose on client!""",
                description="Immediately revoke the exposed secret and move all private keys to backend environment variables.",
                impact=Severity.HIGH,
            ),
        ),

        "SEC_ROBOTS_TXT_LEAK": IssueSolution(
            issue_id="SEC_ROBOTS_TXT_LEAK",
            title="Robots.txt Discloses Sensitive Internal Paths",
            category=Category.SECURITY,
            default_severity=Severity.LOW,
            description="robots.txt disallows private admin, staging, or backup directory paths.",
            bad_sign="Public robots.txt file lists private administrative or secret directories.",
            why_bad="robots.txt is public and readable by anyone. Attackers actively check robots.txt to discover hidden administration panels, staging servers, and backup repositories.",
            remediation=RemediationCode(
                code="""# In robots.txt, avoid listing secret paths. Protect them with authentication instead:
User-agent: *
Allow: /""",
                description="Remove confidential admin paths from robots.txt; protect them with authentication and firewalls.",
                impact=Severity.LOW,
            ),
        ),

        "SEC_SERVER_HEADER_EXPOSED": IssueSolution(
            issue_id="SEC_SERVER_HEADER_EXPOSED",
            title="Server Banner & Version Information Leaked",
            category=Category.SECURITY,
            default_severity=Severity.LOW,
            description="The web server exposes its exact software name and version in the 'Server' header.",
            bad_sign="'Server' header reveals exact web server software and version number.",
            why_bad="Attackers use exact version banners (e.g. Apache/2.4.41 or nginx/1.18.0) to quickly search CVE vulnerability databases and target unpatched security bugs specifically for that version.",
            remediation=RemediationCode(
                apache="""# In httpd.conf or apache2.conf:
ServerTokens Prod
ServerSignature Off""",
                nginx="""# In nginx.conf inside http { ... }:
server_tokens off;""",
                code=None,
                description="Disable detailed server version tokens in web server configuration.",
                impact=Severity.LOW,
            ),
        ),

        "SEC_X_POWERED_BY_EXPOSED": IssueSolution(
            issue_id="SEC_X_POWERED_BY_EXPOSED",
            title="Application Technology Leaked via X-Powered-By",
            category=Category.SECURITY,
            default_severity=Severity.MEDIUM,
            description="The response leaks underlying backend tech (PHP, Express, ASP.NET) in X-Powered-By.",
            bad_sign="Backend framework fingerprint exposed in HTTP response header.",
            why_bad="Provides attackers with immediate architectural knowledge, allowing them to target framework-specific exploit payloads (e.g., PHP deserialization, Express prototype pollution).",
            remediation=RemediationCode(
                apache="""<IfModule mod_headers.c>
    Header unset X-Powered-By
</IfModule>""",
                nginx="""proxy_hide_header X-Powered-By;
fastcgi_hide_header X-Powered-By;""",
                code="""// In php.ini:
expose_php = Off

// In Express.js:
app.disable('x-powered-by');""",
                description="Strip the X-Powered-By header in your application or reverse proxy.",
                impact=Severity.MEDIUM,
            ),
        ),

        "SEC_MIXED_CONTENT": IssueSolution(
            issue_id="SEC_MIXED_CONTENT",
            title="Mixed Content Detected (Insecure HTTP Assets on HTTPS)",
            category=Category.SECURITY,
            default_severity=Severity.CRITICAL,
            description="Your HTTPS page loads resources (scripts, stylesheets, images) over insecure HTTP.",
            bad_sign="HTTP asset links loaded inside an encrypted HTTPS origin.",
            why_bad="Browsers will block mixed scripts or mark the site as 'Not Secure'. Insecure scripts allow attackers to inject code into an otherwise secure HTTPS session.",
            remediation=RemediationCode(
                apache="""RewriteEngine On
RewriteCond %{HTTPS} off
RewriteRule ^(.*)$ https://%{HTTP_HOST}%{REQUEST_URI} [L,R=301]""",
                nginx="""add_header Content-Security-Policy "upgrade-insecure-requests;" always;""",
                code="""<meta http-equiv="Content-Security-Policy" content="upgrade-insecure-requests">""",
                description="Update all internal asset URLs to https:// and enforce upgrade-insecure-requests.",
                impact=Severity.CRITICAL,
            ),
        ),

        "SEC_SENSITIVE_FILE_EXPOSED": IssueSolution(
            issue_id="SEC_SENSITIVE_FILE_EXPOSED",
            title="Critical Sensitive File Publicly Accessible",
            category=Category.SECURITY,
            default_severity=Severity.CRITICAL,
            description="A sensitive configuration, environment (.env), or repository (.git) file is publicly accessible.",
            bad_sign="Sensitive configuration, source code repo, or backup file returns HTTP 200 OK.",
            why_bad="Direct exposure of database passwords, API secrets, JWT secret keys, and application source code, leading to total server compromise.",
            remediation=RemediationCode(
                apache=r"""# In .htaccess:
<FilesMatch "^(\.env|\.git|\.docker|.*\.sql|.*\.bak|composer\.(json|lock)|package\.json)">
    Order allow,deny
    Deny from all
</FilesMatch>""",
                nginx=r"""# In nginx.conf inside server block:
location ~ /\.(env|git|svn|htaccess) {
    deny all;
    return 404;
}
location ~* \.(sql|bak|old|orig|tar|gz|zip)$ {
    deny all;
    return 404;
}""",
                code=None,
                description="Immediately restrict public web server access to dotfiles, backup files, and git repositories.",
                impact=Severity.CRITICAL,
            ),
        ),

        "SEC_SSL_EXPIRED": IssueSolution(
            issue_id="SEC_SSL_EXPIRED",
            title="SSL/TLS Certificate is Expired or Untrusted",
            category=Category.SECURITY,
            default_severity=Severity.CRITICAL,
            description="The SSL certificate has expired or cannot be verified by a trusted root authority.",
            bad_sign="Expired or untrusted TLS certificate.",
            why_bad="Browsers will display an alarming full-page interstitial warning (NET::ERR_CERT_DATE_INVALID), blocking 99%+ of visitors and destroying trust.",
            remediation=RemediationCode(
                apache="""certbot renew --apache""",
                nginx="""certbot renew --nginx""",
                code="""certbot certonly --standalone -d yourdomain.com""",
                description="Renew your SSL certificate immediately through your CA or Let's Encrypt Certbot.",
                impact=Severity.CRITICAL,
            ),
        ),

        "SEC_SSL_EXPIRING_SOON": IssueSolution(
            issue_id="SEC_SSL_EXPIRING_SOON",
            title="SSL/TLS Certificate Expiring Soon (< 30 Days)",
            category=Category.SECURITY,
            default_severity=Severity.HIGH,
            description="The SSL certificate will expire in less than 30 days.",
            bad_sign="Certificate valid lifetime is running out.",
            why_bad="If automated renewal fails or is not monitored, the site will suffer an unexpected outage the moment the certificate expires.",
            remediation=RemediationCode(
                apache="""certbot renew --dry-run""",
                nginx="""certbot renew --dry-run""",
                code=None,
                description="Verify and execute certificate renewal before expiration date.",
                impact=Severity.HIGH,
            ),
        ),

        "SEC_SSL_LEGACY_PROTOCOL": IssueSolution(
            issue_id="SEC_SSL_LEGACY_PROTOCOL",
            title="Obsolete TLS Protocol Version Allowed",
            category=Category.SECURITY,
            default_severity=Severity.HIGH,
            description="The server supports deprecated TLS 1.0 or TLS 1.1 protocols.",
            bad_sign="Deprecated TLS 1.0 or 1.1 protocol supported by web server.",
            why_bad="Legacy TLS versions have well-known cryptographic weaknesses (POODLE, BEAST attacks), violate PCI-DSS compliance, and are blocked by modern browsers.",
            remediation=RemediationCode(
                apache="""# In ssl.conf:
SSLProtocol -all +TLSv1.2 +TLSv1.3""",
                nginx="""# In nginx.conf:
ssl_protocols TLSv1.2 TLSv1.3;""",
                code=None,
                description="Disable TLS 1.0 and 1.1; enable exclusively TLS 1.2 and TLS 1.3.",
                impact=Severity.HIGH,
            ),
        ),

        # -------------------------------------------------------------
        # ON-PAGE & TECHNICAL SEO ISSUES
        # -------------------------------------------------------------
        "SEO_MISSING_TITLE": IssueSolution(
            issue_id="SEO_MISSING_TITLE",
            title="Missing <title> Tag",
            category=Category.SEO,
            default_severity=Severity.CRITICAL,
            description=(
                "The page lacks a <title> element in the <head>. Search engines rely on titles "
                "as the primary headline in search engine result pages (SERPs)."
            ),
            remediation=RemediationCode(
                apache=None,
                nginx=None,
                code="""<!-- Inside HTML <head> -->
<title>Descriptive Primary Keyword - Secondary Keyword | Brand Name</title>""",
                description="Add an informative, unique <title> tag between 50 and 60 characters.",
                impact=Severity.CRITICAL,
                learn_more_url="https://developers.google.com/search/docs/appearance/title-link",
            ),
        ),

        "SEO_TITLE_TOO_SHORT": IssueSolution(
            issue_id="SEO_TITLE_TOO_SHORT",
            title="Page Title Too Short (< 30 characters)",
            category=Category.SEO,
            default_severity=Severity.MEDIUM,
            description=(
                "The title tag is too brief to provide adequate keyword context to search engines "
                "or encourage high click-through rates from users."
            ),
            remediation=RemediationCode(
                apache=None,
                nginx=None,
                code="""<title>Comprehensive Target Topic Guide - Brand Name</title>""",
                description="Expand the title tag to 50-60 characters incorporating relevant keywords.",
                impact=Severity.MEDIUM,
            ),
        ),

        "SEO_TITLE_TOO_LONG": IssueSolution(
            issue_id="SEO_TITLE_TOO_LONG",
            title="Page Title Exceeds Recommended Length (> 60 characters)",
            category=Category.SEO,
            default_severity=Severity.MEDIUM,
            description=(
                "Titles over 60 characters or ~600px width will be truncated with an ellipsis "
                "(...) in Google search results, potentially cutting off key branding or keywords."
            ),
            remediation=RemediationCode(
                apache=None,
                nginx=None,
                code="""<!-- Shorten title to 50-60 characters -->
<title>Succinct Keyword Focus & Benefits | Brand</title>""",
                description="Condense title to under 60 characters (~580px width).",
                impact=Severity.MEDIUM,
            ),
        ),

        "SEO_DUPLICATE_TITLE": IssueSolution(
            issue_id="SEO_DUPLICATE_TITLE",
            title="Duplicate Page Title Detected",
            category=Category.SEO,
            default_severity=Severity.HIGH,
            description=(
                "Multiple pages share the exact same title tag, creating internal keyword "
                "cannibalization and confusing search engine indexers."
            ),
            remediation=RemediationCode(
                code="""<!-- Ensure each URL renders a distinct page title tailored to its specific content -->""",
                description="Provide a unique, topic-specific title for each indexable page.",
                impact=Severity.HIGH,
            ),
        ),

        "SEO_MISSING_META_DESC": IssueSolution(
            issue_id="SEO_MISSING_META_DESC",
            title="Missing Meta Description Tag",
            category=Category.SEO,
            default_severity=Severity.HIGH,
            description=(
                "Without a meta description, search engines auto-generate snippets from page body "
                "text, which often results in disjointed or uncompelling SERP snippets."
            ),
            remediation=RemediationCode(
                code="""<!-- Inside HTML <head> -->
<meta name="description" content="Discover actionable insights and comprehensive tools to optimize your website. Learn best practices and boost your organic performance today.">""",
                description="Add a compelling meta description between 120 and 160 characters with a clear call-to-action.",
                impact=Severity.HIGH,
            ),
        ),

        "SEO_META_DESC_TOO_SHORT": IssueSolution(
            issue_id="SEO_META_DESC_TOO_SHORT",
            title="Meta Description Too Short (< 70 characters)",
            category=Category.SEO,
            default_severity=Severity.LOW,
            description=(
                "The meta description is too brief to effectively communicate the page value proposition "
                "and maximize click-through rate (CTR)."
            ),
            remediation=RemediationCode(
                code="""<meta name="description" content="Expand your description to 120-160 characters describing the unique value and encouraging user engagement.">""",
                description="Expand description to 120-160 characters.",
                impact=Severity.LOW,
            ),
        ),

        "SEO_META_DESC_TOO_LONG": IssueSolution(
            issue_id="SEO_META_DESC_TOO_LONG",
            title="Meta Description Exceeds Recommended Length (> 160 characters)",
            category=Category.SEO,
            default_severity=Severity.LOW,
            description=(
                "Descriptions over 160 characters are typically truncated by search engine result "
                "pages, cutting off important call-to-actions."
            ),
            remediation=RemediationCode(
                code="""<meta name="description" content="Keep your primary message and target keywords within 155 characters for full SERP visibility.">""",
                description="Trim meta description to under 160 characters.",
                impact=Severity.LOW,
            ),
        ),

        "SEO_DUPLICATE_META_DESC": IssueSolution(
            issue_id="SEO_DUPLICATE_META_DESC",
            title="Duplicate Meta Description Detected Across Pages",
            category=Category.SEO,
            default_severity=Severity.MEDIUM,
            description=(
                "Reusing the identical meta description across multiple pages diminishes SERP relevance "
                "and may cause Google to ignore it in favor of extracted text snippets."
            ),
            remediation=RemediationCode(
                code="""<!-- Craft unique meta descriptions for every crawled page -->""",
                description="Write unique meta descriptions tailored to each individual page.",
                impact=Severity.MEDIUM,
            ),
        ),

        "SEO_MISSING_H1": IssueSolution(
            issue_id="SEO_MISSING_H1",
            title="Missing <h1> Main Heading Tag",
            category=Category.SEO,
            default_severity=Severity.HIGH,
            description=(
                "The page lacks an <h1> tag. The primary heading gives search engines and screen readers "
                "the overarching context of the page topic."
            ),
            remediation=RemediationCode(
                code="""<!-- Add one top-level <h1> heading in main content -->
<h1>Main Descriptive Subject of the Page</h1>""",
                description="Include exactly one prominent <h1> tag that describes the page core theme.",
                impact=Severity.HIGH,
            ),
        ),

        "SEO_MULTIPLE_H1": IssueSolution(
            issue_id="SEO_MULTIPLE_H1",
            title="Multiple <h1> Headings Found",
            category=Category.SEO,
            default_severity=Severity.MEDIUM,
            description=(
                "Multiple <h1> tags were found on the same page. While HTML5 permits this in sectioning tags, "
                "standard SEO practice recommends a single primary <h1> to clarify the page hierarchy."
            ),
            remediation=RemediationCode(
                code="""<!-- Keep one <h1> and downgrade subordinate headings to <h2> -->
<h1>Primary Page Subject</h1>
...
<h2>Sub-topic Section Header</h2>""",
                description="Retain one primary <h1> and convert secondary headings to <h2> and <h3>.",
                impact=Severity.MEDIUM,
            ),
        ),

        "SEO_HEADING_HIERARCHY_SKIPPED": IssueSolution(
            issue_id="SEO_HEADING_HIERARCHY_SKIPPED",
            title="Skipped Heading Levels (e.g. H1 directly to H3)",
            category=Category.SEO,
            default_severity=Severity.LOW,
            description=(
                "Heading levels should follow a sequential hierarchy (H1 -> H2 -> H3) without skipping "
                "levels for accessibility and semantic document structure."
            ),
            remediation=RemediationCode(
                code="""<h1>Primary Topic</h1>
  <h2>Section Topic</h2>
    <h3>Sub-section Detail</h3>""",
                description="Ensure headings descend sequentially without skipping levels.",
                impact=Severity.LOW,
            ),
        ),

        "SEO_MISSING_CANONICAL": IssueSolution(
            issue_id="SEO_MISSING_CANONICAL",
            title="Missing Canonical Tag (<link rel='canonical'>)",
            category=Category.SEO,
            default_severity=Severity.MEDIUM,
            description=(
                "Without a canonical tag, URL variations (query parameters, tracking codes, trailing slashes) "
                "may split link equity and result in duplicate content indexing."
            ),
            remediation=RemediationCode(
                code="""<!-- Inside HTML <head> -->
<link rel="canonical" href="https://example.com/authoritative-page-url/" />""",
                description="Add an absolute self-referencing canonical URL tag to each page.",
                impact=Severity.MEDIUM,
            ),
        ),

        "SEO_NOINDEX_FLAGGED": IssueSolution(
            issue_id="SEO_NOINDEX_FLAGGED",
            title="Page Instructs Search Engines Not to Index ('noindex')",
            category=Category.SEO,
            default_severity=Severity.CRITICAL,
            description=(
                "A 'noindex' directive was found in meta robots or X-Robots-Tag header. "
                "Search engines will exclude this page completely from search results."
            ),
            remediation=RemediationCode(
                code="""<!-- If page should be indexed, change to index, follow -->
<meta name="robots" content="index, follow">""",
                description="Remove 'noindex' if this page is intended to receive organic traffic.",
                impact=Severity.CRITICAL,
            ),
        ),

        "SEO_MISSING_LANG": IssueSolution(
            issue_id="SEO_MISSING_LANG",
            title="Missing or Empty HTML 'lang' Attribute",
            category=Category.SEO,
            default_severity=Severity.LOW,
            description=(
                "The <html> tag is missing the 'lang' attribute. Screen readers and translation engines "
                "rely on this to correctly pronounce and render text."
            ),
            remediation=RemediationCode(
                code="""<!DOCTYPE html>
<html lang="en">""",
                description="Specify the appropriate BCP 47 language code (e.g., lang='en').",
                impact=Severity.LOW,
            ),
        ),

        "SEO_THIN_CONTENT": IssueSolution(
            issue_id="SEO_THIN_CONTENT",
            title="Thin Content Detected (< 300 words)",
            category=Category.SEO,
            default_severity=Severity.MEDIUM,
            description=(
                "The page contains fewer than 300 words of indexable text. Pages with minimal "
                "original content struggle to rank well in competitive search queries."
            ),
            remediation=RemediationCode(
                code="""<!-- Provide rich, comprehensive answers and contextual copy for users -->""",
                description="Expand the content with detailed explanations, FAQs, and original analysis.",
                impact=Severity.MEDIUM,
            ),
        ),

        "SEO_MISSING_OG_TAGS": IssueSolution(
            issue_id="SEO_MISSING_OG_TAGS",
            title="Incomplete Open Graph (Social Sharing) Meta Tags",
            category=Category.SEO,
            default_severity=Severity.LOW,
            description=(
                "Missing essential OpenGraph tags (og:title, og:description, og:image, og:url). "
                "Social shares on Facebook, LinkedIn, and WhatsApp will lack rich previews."
            ),
            remediation=RemediationCode(
                code="""<!-- Inside HTML <head> -->
<meta property="og:type" content="website">
<meta property="og:title" content="Page Title">
<meta property="og:description" content="Engaging social preview description.">
<meta property="og:image" content="https://example.com/images/og-preview.jpg">
<meta property="og:url" content="https://example.com/current-page">""",
                description="Implement standard Open Graph meta tags for high-engagement social cards.",
                impact=Severity.LOW,
            ),
        ),

        "SEO_MISSING_TWITTER_CARD": IssueSolution(
            issue_id="SEO_MISSING_TWITTER_CARD",
            title="Missing Twitter / X Card Meta Tags",
            category=Category.SEO,
            default_severity=Severity.LOW,
            description=(
                "Without twitter:card and twitter:title tags, shares on X / Twitter will not display "
                "an expanded visual media card."
            ),
            remediation=RemediationCode(
                code="""<!-- Inside HTML <head> -->
<meta name="twitter:card" content="summary_large_image">
<meta name="twitter:title" content="Page Title">
<meta name="twitter:description" content="Page description.">
<meta name="twitter:image" content="https://example.com/images/card-image.jpg">""",
                description="Include twitter:card and twitter tags for rich social snippets.",
                impact=Severity.LOW,
            ),
        ),

        "SEO_MISSING_SCHEMA": IssueSolution(
            issue_id="SEO_MISSING_SCHEMA",
            title="No JSON-LD Structured Data Schema Detected",
            category=Category.SEO,
            default_severity=Severity.MEDIUM,
            description=(
                "Structured data (Schema.org) enables search engines to understand entities and "
                "qualifies the page for rich results (stars, breadcrumbs, FAQs, sitelinks)."
            ),
            remediation=RemediationCode(
                code="""<!-- Add JSON-LD in HTML <head> or <body> -->
<script type="application/ld+json">
{
  "@context": "https://schema.org",
  "@type": "WebSite",
  "name": "Site Name",
  "url": "https://example.com/"
}
</script>""",
                description="Integrate JSON-LD schema (Organization, WebSite, Article, Product, or BreadcrumbList).",
                impact=Severity.MEDIUM,
                learn_more_url="https://schema.org",
            ),
        ),

        "SEO_IMG_MISSING_ALT": IssueSolution(
            issue_id="SEO_IMG_MISSING_ALT",
            title="Images Missing Descriptive 'alt' Attribute",
            category=Category.SEO,
            default_severity=Severity.MEDIUM,
            description=(
                "Images without alt attributes harm web accessibility (WCAG) for visually impaired "
                "users and miss Google Images ranking opportunities."
            ),
            remediation=RemediationCode(
                code="""<!-- Add descriptive alt text reflecting image context -->
<img src="/path/to/diagram.png" alt="SEO audit architecture flowchart showing crawler and auditor modules">""",
                description="Ensure all informative <img> elements have accurate, descriptive alt text.",
                impact=Severity.MEDIUM,
            ),
        ),

        "SEO_BROKEN_LINK": IssueSolution(
            issue_id="SEO_BROKEN_LINK",
            title="Broken Internal Link (4xx or 5xx Status Code)",
            category=Category.SEO,
            default_severity=Severity.HIGH,
            description=(
                "The crawler encountered a link leading to a 404 (Not Found) or 500 error page. "
                "Broken links degrade user experience and waste search engine crawl budget."
            ),
            remediation=RemediationCode(
                apache="""# Redirect broken legacy URL to new location:
Redirect 301 /broken-path /new-path""",
                nginx="""# Redirect broken legacy URL:
rewrite ^/broken-path$ /new-path permanent;""",
                code=None,
                description="Update the link destination in HTML or configure a permanent 301 redirect.",
                impact=Severity.HIGH,
            ),
        ),

        "SEO_REDIRECT_CHAIN": IssueSolution(
            issue_id="SEO_REDIRECT_CHAIN",
            title="Redirect Chain Detected (Multiple Hops)",
            category=Category.SEO,
            default_severity=Severity.MEDIUM,
            description=(
                "A URL traversed two or more redirect hops (e.g. A -> B -> C). Chains increase "
                "page latency, dilute PageRank equity, and may cause timeouts."
            ),
            remediation=RemediationCode(
                apache="""# Point direct to final target:
Redirect 301 /initial-page https://example.com/final-destination/""",
                nginx="""rewrite ^/initial-page$ https://example.com/final-destination/ permanent;""",
                code=None,
                description="Update internal links and redirect rules to point directly to the final destination.",
                impact=Severity.MEDIUM,
            ),
        ),

        # -------------------------------------------------------------
        # UI, CORE WEB VITALS & PERFORMANCE ISSUES
        # -------------------------------------------------------------
        "PERF_POOR_SCORE": IssueSolution(
            issue_id="PERF_POOR_SCORE",
            title="Low Performance / Core Web Vitals Score (< 50/100)",
            category=Category.PERFORMANCE,
            default_severity=Severity.HIGH,
            description=(
                "The page fails Core Web Vitals performance benchmarks. Slow render and load "
                "speeds degrade conversion rates and hurt mobile search rankings."
            ),
            remediation=RemediationCode(
                apache="""# Enable Gzip / Brotli compression
<IfModule mod_deflate.c>
    AddOutputFilterByType DEFLATE text/html text/plain text/xml text/css application/javascript application/json
</IfModule>""",
                nginx="""# Enable gzip compression
gzip on;
gzip_types text/plain text/css application/json application/javascript text/xml;
gzip_min_length 1000;""",
                code="""<!-- Defer non-critical JavaScript -->
<script src="/path/to/script.js" defer></script>""",
                description="Enable server compression (Gzip/Brotli), minify scripts, and defer non-critical assets.",
                impact=Severity.HIGH,
            ),
        ),

        "PERF_SLOW_LCP": IssueSolution(
            issue_id="PERF_SLOW_LCP",
            title="Slow Largest Contentful Paint (LCP > 2.5s)",
            category=Category.PERFORMANCE,
            default_severity=Severity.HIGH,
            description=(
                "The largest visual element took longer than 2.5 seconds to render. LCP is a critical "
                "Google Core Web Vital determining how fast users see primary content."
            ),
            remediation=RemediationCode(
                apache=None,
                nginx=None,
                code="""<!-- Preload hero image or main banner -->
<link rel="preload" as="image" href="/images/hero-banner.webp" fetchpriority="high">""",
                description="Preload the LCP hero element and use modern image formats (WebP/AVIF).",
                impact=Severity.HIGH,
            ),
        ),

        "PERF_HIGH_CLS": IssueSolution(
            issue_id="PERF_HIGH_CLS",
            title="High Cumulative Layout Shift (CLS > 0.1)",
            category=Category.PERFORMANCE,
            default_severity=Severity.MEDIUM,
            description=(
                "Visual elements jumped unexpectedly during page load (CLS > 0.1), causing "
                "accidental clicks and a jarring reading experience."
            ),
            remediation=RemediationCode(
                apache=None,
                nginx=None,
                code="""<!-- Always include explicit width and height on images & videos -->
<img src="/banner.webp" width="1200" height="600" alt="Hero banner">""",
                description="Set explicit width and height dimensions or CSS aspect-ratio on all media.",
                impact=Severity.MEDIUM,
            ),
        ),

        "PERF_SLOW_FCP": IssueSolution(
            issue_id="PERF_SLOW_FCP",
            title="Slow First Contentful Paint (FCP > 1.8s)",
            category=Category.PERFORMANCE,
            default_severity=Severity.MEDIUM,
            description=(
                "Users wait over 1.8 seconds before seeing any text or graphics on screen. Often "
                "caused by render-blocking CSS, slow server TTFB, or third-party fonts."
            ),
            remediation=RemediationCode(
                nginx="""# Add browser caching headers
expires 1y;
add_header Cache-Control "public, no-transform";""",
                code="""<!-- Preconnect to third-party font origins -->
<link rel="preconnect" href="https://fonts.googleapis.com">
<link rel="preconnect" href="https://fonts.gstatic.com" crossorigin>""",
                description="Inline critical CSS, preconnect font hosts, and eliminate render-blocking resources.",
                impact=Severity.MEDIUM,
            ),
        ),

        "PERF_MISSING_VIEWPORT": IssueSolution(
            issue_id="PERF_MISSING_VIEWPORT",
            title="Missing Mobile Viewport Meta Tag",
            category=Category.PERFORMANCE,
            default_severity=Severity.CRITICAL,
            description=(
                "The HTML head lacks `<meta name='viewport'>`. Mobile browsers will render the page "
                "as a fixed desktop layout, failing Google's Mobile-Friendly evaluation."
            ),
            remediation=RemediationCode(
                code="""<!-- Add to HTML <head> -->
<meta name="viewport" content="width=device-width, initial-scale=1.0">""",
                description="Include the standard responsive mobile viewport tag.",
                impact=Severity.CRITICAL,
            ),
        ),

        # -------------------------------------------------------------
        # OFF-PAGE & AUTHORITY SIGNALS
        # -------------------------------------------------------------
        "OFFPAGE_LOW_DOMAIN_RANK": IssueSolution(
            issue_id="OFFPAGE_LOW_DOMAIN_RANK",
            title="Low Domain Authority / PageRank Score",
            category=Category.OFFPAGE,
            default_severity=Severity.LOW,
            description=(
                "The domain has a low OpenPageRank authority score, indicating a need for higher-quality "
                "backlinks, editorial references, and external domain trust."
            ),
            remediation=RemediationCode(
                code="""Build high-authority industry backlinks, guest contributions, and PR outreach.""",
                description="Develop a digital PR and content-led link acquisition strategy.",
                impact=Severity.LOW,
            ),
        ),

        "OFFPAGE_MISSING_SOCIAL_SIGNALS": IssueSolution(
            issue_id="OFFPAGE_MISSING_SOCIAL_SIGNALS",
            title="Missing Social Profile Links",
            category=Category.OFFPAGE,
            default_severity=Severity.INFO,
            description=(
                "No direct links to brand social media channels (LinkedIn, X, YouTube, Instagram) were detected. "
                "Social links enhance brand trust and reinforce Knowledge Graph entities."
            ),
            remediation=RemediationCode(
                code="""<!-- Add verified social profile links in header or footer -->
<a href="https://linkedin.com/company/yourbrand" rel="noopener">LinkedIn</a>
<a href="https://x.com/yourbrand" rel="noopener">X / Twitter</a>""",
                description="Add verified social profile links in the website header or footer.",
                impact=Severity.INFO,
            ),
        ),
    }

    @classmethod
    def get(cls, issue_id: str) -> Optional[IssueSolution]:
        return cls._CATALOG.get(issue_id)

    @classmethod
    def build_issue(
        cls,
        issue_id: str,
        evidence: str,
        url: Optional[str] = None,
        custom_severity: Optional[Severity] = None,
        custom_title: Optional[str] = None,
        custom_bad_sign: Optional[str] = None,
        custom_why_bad: Optional[str] = None,
    ) -> AuditIssue:
        """Helper to create an AuditIssue populated with standard solutions and bad sign explanations."""
        solution = cls.get(issue_id)
        if not solution:
            # Fallback for dynamic or novel issues
            return AuditIssue(
                issue_id=issue_id,
                title=custom_title or issue_id,
                category=Category.SEO,
                severity=custom_severity or Severity.MEDIUM,
                description=f"Issue detected: {issue_id}",
                evidence=evidence,
                url=url,
                bad_sign=custom_bad_sign or f"Anomaly detected in {issue_id}",
                why_bad=custom_why_bad or f"Potential misconfiguration in {issue_id}",
            )

        severity = custom_severity or solution.default_severity
        title = custom_title or solution.title
        rem = solution.remediation

        return AuditIssue(
            issue_id=solution.issue_id,
            title=title,
            category=solution.category,
            severity=severity,
            description=solution.description,
            evidence=evidence,
            url=url,
            bad_sign=custom_bad_sign or solution.bad_sign,
            why_bad=custom_why_bad or solution.why_bad,
            solution_apache=rem.apache,
            solution_nginx=rem.nginx,
            solution_code=rem.code,
            learn_more_url=rem.learn_more_url,
        )
