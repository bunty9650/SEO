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


class SolutionDatabase:
    """Repository of pre-configured remediation playbooks."""

    _CATALOG: Dict[str, IssueSolution] = {
        # -------------------------------------------------------------
        # SECURITY & SSL ISSUES
        # -------------------------------------------------------------
        "SEC_MISSING_HSTS": IssueSolution(
            issue_id="SEC_MISSING_HSTS",
            title="Missing HTTP Strict Transport Security (HSTS) Header",
            category=Category.SECURITY,
            default_severity=Severity.HIGH,
            description=(
                "The Strict-Transport-Security header forces browsers to communicate "
                "with your domain exclusively over HTTPS, preventing SSL-stripping and "
                "man-in-the-middle (MitM) cookie hijacking."
            ),
            remediation=RemediationCode(
                apache="""<IfModule mod_headers.c>
    Header always set Strict-Transport-Security "max-age=31536000; includeSubDomains; preload"
</IfModule>""",
                nginx="""# Add inside server { ... } block for SSL port 443
add_header Strict-Transport-Security "max-age=31536000; includeSubDomains; preload" always;""",
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
            description=(
                "The HSTS max-age is set to less than 1 year (31,536,000s) or is missing "
                "the 'includeSubDomains' or 'preload' directives required for browser HSTS preload list eligibility."
            ),
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
            description=(
                "Content-Security-Policy (CSP) is an essential defense-in-depth layer that "
                "mitigates Cross-Site Scripting (XSS), malicious script injections, and data exfiltration."
            ),
            remediation=RemediationCode(
                apache="""<IfModule mod_headers.c>
    Header always set Content-Security-Policy "default-src 'self'; script-src 'self' https: 'unsafe-inline'; style-src 'self' https: 'unsafe-inline'; img-src 'self' data: https:; font-src 'self' https: data:; connect-src 'self' https:; frame-ancestors 'self';"
</IfModule>""",
                nginx="""add_header Content-Security-Policy "default-src 'self'; script-src 'self' https: 'unsafe-inline'; style-src 'self' https: 'unsafe-inline'; img-src 'self' data: https:; font-src 'self' https: data:; connect-src 'self' https:; frame-ancestors 'self';" always;""",
                code="""<!-- In HTML <head> (fallback if web server headers cannot be modified) -->
<meta http-equiv="Content-Security-Policy" content="default-src 'self'; script-src 'self' https:; style-src 'self' https:; img-src 'self' data: https:;">""",
                description="Define an explicit Content-Security-Policy restricting allowed resource origins.",
                impact=Severity.HIGH,
                learn_more_url="https://developer.mozilla.org/en-US/docs/Web/HTTP/CSP",
            ),
        ),

        "SEC_MISSING_X_FRAME_OPTIONS": IssueSolution(
            issue_id="SEC_MISSING_X_FRAME_OPTIONS",
            title="Missing X-Frame-Options Header (Clickjacking Risk)",
            category=Category.SECURITY,
            default_severity=Severity.HIGH,
            description=(
                "Without X-Frame-Options, attackers can embed your website into an invisible <iframe> "
                "on an external phishing site and trick users into clicking buttons (Clickjacking)."
            ),
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
            description=(
                "Prevents browsers from MIME-sniffing a response away from the declared content-type. "
                "Without this, malicious uploaded text or images can be executed as JavaScript."
            ),
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
            description=(
                "Controls how much referrer information (including query parameters or internal URLs) "
                "is leaked in the Referer header when navigating away from your site."
            ),
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
            description=(
                "Allows site operators to explicitly disable risky browser APIs (camera, microphone, "
                "geolocation, payment) that third-party scripts or embedded iframes might abuse."
            ),
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

        "SEC_SERVER_HEADER_EXPOSED": IssueSolution(
            issue_id="SEC_SERVER_HEADER_EXPOSED",
            title="Server Banner & Version Information Leaked",
            category=Category.SECURITY,
            default_severity=Severity.LOW,
            description=(
                "The web server exposes its exact software name and version in the 'Server' header, "
                "aiding automated fingerprinting by vulnerability scanners."
            ),
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
            description=(
                "The response leaks underlying backend tech (PHP, Express, ASP.NET) in the "
                "X-Powered-By header, allowing attackers to target framework-specific CVEs."
            ),
            remediation=RemediationCode(
                apache="""<IfModule mod_headers.c>
    Header unset X-Powered-By
</IfModule>""",
                nginx="""# In nginx.conf or proxy config:
proxy_hide_header X-Powered-By;
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
            description=(
                "Your HTTPS page loads active or passive resources (scripts, stylesheets, images) "
                "over insecure HTTP. Browsers will block scripts or show 'Not Secure' warnings."
            ),
            remediation=RemediationCode(
                apache="""# Enforce HTTPS redirect for all requests
RewriteEngine On
RewriteCond %{HTTPS} off
RewriteRule ^(.*)$ https://%{HTTP_HOST}%{REQUEST_URI} [L,R=301]""",
                nginx="""# Upgrade all insecure requests via CSP
add_header Content-Security-Policy "upgrade-insecure-requests;" always;""",
                code="""<!-- Add to HTML <head> to auto-upgrade requests -->
<meta http-equiv="Content-Security-Policy" content="upgrade-insecure-requests">""",
                description="Update all internal asset URLs to https:// and enforce upgrade-insecure-requests.",
                impact=Severity.CRITICAL,
            ),
        ),

        "SEC_SENSITIVE_FILE_EXPOSED": IssueSolution(
            issue_id="SEC_SENSITIVE_FILE_EXPOSED",
            title="Critical Sensitive File Publicly Accessible",
            category=Category.SECURITY,
            default_severity=Severity.CRITICAL,
            description=(
                "A sensitive configuration, environment (.env), or repository (.git) file is publicly "
                "accessible without authentication, risking immediate database and API credential exposure."
            ),
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
            title="SSL/TLS Certificate is Expired",
            category=Category.SECURITY,
            default_severity=Severity.CRITICAL,
            description=(
                "The SSL certificate has expired. Browsers will completely block visitors "
                "with interstitial security warnings (NET::ERR_CERT_DATE_INVALID)."
            ),
            remediation=RemediationCode(
                apache="""# Renew certificate using Certbot:
certbot renew --apache""",
                nginx="""# Renew certificate using Certbot:
certbot renew --nginx""",
                code="""# Force renewal via certbot:
certbot certonly --standalone -d yourdomain.com""",
                description="Renew your SSL certificate immediately through your CA or Let's Encrypt Certbot.",
                impact=Severity.CRITICAL,
            ),
        ),

        "SEC_SSL_EXPIRING_SOON": IssueSolution(
            issue_id="SEC_SSL_EXPIRING_SOON",
            title="SSL/TLS Certificate Expiring Soon (< 30 Days)",
            category=Category.SECURITY,
            default_severity=Severity.HIGH,
            description=(
                "The SSL certificate will expire in less than 30 days. Automated renewal should be verified "
                "to prevent unexpected site outages."
            ),
            remediation=RemediationCode(
                apache="""certbot renew --dry-run""",
                nginx="""certbot renew --dry-run""",
                code=None,
                description="Test and execute automatic certificate renewal before expiration.",
                impact=Severity.HIGH,
            ),
        ),

        "SEC_SSL_LEGACY_PROTOCOL": IssueSolution(
            issue_id="SEC_SSL_LEGACY_PROTOCOL",
            title="Obsolete TLS Protocol Version Allowed",
            category=Category.SECURITY,
            default_severity=Severity.HIGH,
            description=(
                "The server supports legacy TLS 1.0 or TLS 1.1, which contain known cryptographic flaws "
                "(POODLE, BEAST) and violate PCI-DSS compliance."
            ),
            remediation=RemediationCode(
                apache="""# In ssl.conf:
SSLProtocol -all +TLSv1.2 +TLSv1.3""",
                nginx="""# In nginx.conf:
ssl_protocols TLSv1.2 TLSv1.3;""",
                code=None,
                description="Disable TLS 1.0 and 1.1; enable only TLS 1.2 and TLS 1.3.",
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
    ) -> AuditIssue:
        """Helper to create an AuditIssue populated with standard solutions."""
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
            solution_apache=rem.apache,
            solution_nginx=rem.nginx,
            solution_code=rem.code,
            learn_more_url=rem.learn_more_url,
        )
