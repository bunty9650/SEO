# All-in-One Website Audit, SEO, Security, Performance & UI Diagnostic Suite

A 100% Free, production-grade, unlimited Website Audit, SEO, Security, and UI/Performance Analyzer tool with automated solution generation and multi-format reporting (Interactive Web Dashboard, Multi-Tab Excel, and Executive PDF).

---

## 🏗️ Architecture Overview

```text
SEO Agent/
├── crawler/
│   ├── spider.py           # Async BFS crawler, robots.txt parsing, depth & URL limits, redirect tracking
│   └── parser.py           # High-speed DOM parsing, tag extraction, image/asset analysis
├── auditors/
│   ├── base.py             # Base models, Severity, Category, and AuditResult
│   ├── seo_auditor.py      # Module A: Technical & On-Page SEO rules, title/meta, headings, duplicates, schema
│   ├── security_auditor.py # Module B: SSL/TLS validation, HTTP security headers, info leakage, mixed content, safe probes
│   ├── performance_auditor.py # Module C: Google PageSpeed Insights & Core Web Vitals
│   └── offpage_auditor.py  # Module D: OpenPageRank & Brand Social Signals
├── solutions/
│   └── solution_database.py # Module E: Remediation catalog with Apache (.htaccess), Nginx, and HTML/WP fixes
├── reports/
│   ├── excel_generator.py  # Module F: Multi-tab XLSX export engine
│   └── pdf_generator.py    # Module F: Branded PDF report engine
├── ui/
│   └── app.py              # Interactive Streamlit dashboard
├── tests/                  # Pytest automated test suites (25 unit tests)
├── app.py                  # Streamlit application entry point
├── cli.py                  # Rich interactive terminal runner with Excel/PDF export
├── local_demo_server.py    # Local test website for offline audit testing
└── requirements.txt
```

---

## 🚀 Key Modules & Capabilities

### Module A: Technical & On-Page SEO Engine
- **Recursive BFS Crawler (`crawler/spider.py`):** Asynchronous crawling respecting `robots.txt`, concurrency controls, URL normalizer, depth limits, and redirect chain detection.
- **DOM & Content Extraction (`crawler/parser.py`):** Title tag character & pixel width estimation, meta description validation, canonical URL resolution, heading hierarchy & sequence checking (e.g. skipped H1 to H3), JSON-LD structured data extraction, Open Graph & Twitter cards, and image asset auditing.
- **SEO Rules & Scorer (`auditors/seo_auditor.py`):** Comprehensive rules for missing/short/long titles, duplicate titles/descriptions across the site, missing H1, multiple H1s, thin content (<300 words), missing canonicals, noindex directives, broken links (4xx/5xx), and redirect chains.

### Module B: Website Security & SSL Auditor
- **SSL/TLS Validation (`auditors/security_auditor.py`):** Live SSL certificate chain inspection, SAN extraction, exact TLS protocol negotiation (TLS 1.2/1.3 vs legacy SSL/TLS), certificate expiry tracking, and days remaining.
- **HTTP Security Headers:** Analyzes `Strict-Transport-Security` (max-age, subdomains, preload), `Content-Security-Policy`, `X-Frame-Options` (Clickjacking), `X-Content-Type-Options` (nosniff), `Referrer-Policy`, and `Permissions-Policy`.
- **Information Leakage Detection:** Scans for server software/version disclosure in `Server`, backend framework signatures in `X-Powered-By`, and related headers.
- **Mixed Content Detection:** Flags active or passive `http://` resources requested on HTTPS origins.
- **Sensitive Files Probe:** Safe, non-intrusive checks for accidental exposures (`.env`, `.git/HEAD`, `docker-compose.yml`, backup files) with signature validation to avoid false positives.

### Module C: UI, Design & Performance Diagnostics
- **Google PageSpeed Insights API:** Queries official PageSpeed API for Mobile & Desktop Performance scores and Core Web Vitals (LCP, CLS, FCP, TBT).
- **Zero-Failure Synthetic Heuristics:** Automatically calculates synthetic local performance metrics (TTFB, DOM complexity, script weight, image load penalty) for offline/local IP addresses or when API is unreachable.
- **Mobile Responsive Evaluation:** Audits responsive mobile viewport configuration (`<meta name="viewport">`).
- **Playwright Visual Capture Helper:** Captures full Desktop (1920x1080) and Mobile (390x844 iPhone viewport) screenshots.

### Module D: Off-Page & Authority Signals
- **Domain Authority (OpenPageRank API):** Retrieves global rank and PageRank authority score.
- **Brand Social Footprint:** Scans for active brand profiles across LinkedIn, X / Twitter, Facebook, Instagram, YouTube, and GitHub.
- **Outbound Link Analysis:** Computes external vs. internal link counts, dofollow/nofollow ratio, and anchor text hygiene.

### Module E: Automated Solution & Remediation Engine
- **Remediation Database (`solutions/solution_database.py`):** Direct copy-paste configuration snippets for:
  - Apache (`.htaccess`)
  - Nginx (`nginx.conf`)
  - HTML / WordPress (`functions.php`)

### Module F: Multi-Format Client Reports
- **Multi-Tab Excel Workbook (`reports/excel_generator.py`):** Tab 1: Executive Summary, Tab 2: Crawled URLs, Tab 3: Actionable Issues & Fixes, Tab 4: Image Assets Audit.
- **Branded Executive PDF (`reports/pdf_generator.py`):** Clean PDF layout with color-coded severity badges, scorecard table, passed health checks, and priority remediation roadmap.

---

## 💻 Quickstart & Usage

### 1. Installation
```bash
# Clone the repository
git clone https://github.com/bunty9650/SEO.git
cd SEO

# Create virtual environment
python -m venv .venv
.\.venv\Scripts\activate

# Install dependencies
pip install -r requirements.txt
```

### 2. Launch Interactive Web Dashboard
```bash
streamlit run app.py
```
Open **`http://localhost:8501`** in your browser.

### 3. Run via Command Line Interface (CLI)
```bash
# Audit any live URL:
python cli.py https://example.com --max-urls 10 --max-depth 2

# Export directly to Excel and PDF:
python cli.py https://example.com --excel audit_report.xlsx --pdf audit_report.pdf
```

### 4. Run Automated Test Suite
```bash
pytest -v
```
All 25 automated unit tests pass with 100% coverage.
