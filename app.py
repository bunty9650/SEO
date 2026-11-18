"""Production FastAPI Web Application & Vercel Serverless Entrypoint.

Exports a top-level `app` variable for Vercel deployment and local Uvicorn runs.
Includes a modern Tailwind CSS interactive dashboard, REST audit API, and report download endpoints.
"""
from __future__ import annotations

import asyncio
import io
import os
import traceback
from typing import Any, Dict, List, Optional
from urllib.parse import urlparse

# Ensure ReportLab pure-python mode on serverless Linux
os.environ["RL_BUILD_ACCEL"] = "0"

from fastapi import FastAPI, HTTPException, Request, Response
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import HTMLResponse, JSONResponse
from pydantic import BaseModel, Field

from crawler.spider import WebSpider, CrawlResult
from auditors.seo_auditor import SEOAuditor
from auditors.security_auditor import SecurityAuditor
from auditors.performance_auditor import PerformanceAuditor
from auditors.offpage_auditor import OffPageAuditor
from auditors.base import Category, Severity, AuditResult, AuditIssue

# Top-level ASGI entrypoint for Vercel
app = FastAPI(
    title="All-in-One Website Audit & Security Diagnostic Suite",
    description="Production-grade website audit, SEO, security, UI & performance analyzer.",
    version="2.0.0",
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


class AuditRequest(BaseModel):
    url: str = Field(..., description="Target website URL")
    max_urls: int = Field(default=10, ge=1, le=30)
    max_depth: int = Field(default=2, ge=1, le=4)
    pagespeed_key: Optional[str] = None
    openpagerank_key: Optional[str] = None


async def execute_audit(req: AuditRequest):
    # 1. Crawl
    spider = WebSpider(seed_url=req.url, max_urls=req.max_urls, max_depth=req.max_depth)
    crawl_result = await spider.crawl()

    seed_page = crawl_result.pages[0] if crawl_result.pages else None
    seed_headers = seed_page.headers if seed_page else None
    insecure_assets = seed_page.insecure_resources if seed_page else None
    seed_html = seed_page.raw_html if seed_page else None
    seed_ttfb = seed_page.response_time_ms if seed_page else 150.0

    # 2. SEO
    seo_auditor = SEOAuditor(crawl_result)
    seo_res = seo_auditor.run()

    # 3. Security
    sec_auditor = SecurityAuditor(req.url)
    sec_res = await sec_auditor.run(
        headers=seed_headers,
        insecure_resources=insecure_assets,
        raw_html=seed_html,
    )

    # 4. Performance
    perf_auditor = PerformanceAuditor(
        target_url=req.url,
        api_key=req.pagespeed_key,
        html_content=seed_html,
        ttfb_ms=seed_ttfb,
    )
    perf_res = await perf_auditor.run()

    # 5. Off-Page
    offpage_auditor = OffPageAuditor(crawl_result=crawl_result, openpagerank_key=req.openpagerank_key)
    offpage_res = await offpage_auditor.run()

    audit_results = {
        Category.SEO: seo_res,
        Category.SECURITY: sec_res,
        Category.PERFORMANCE: perf_res,
        Category.OFFPAGE: offpage_res,
    }

    all_issues = []
    for res in audit_results.values():
        all_issues.extend(res.issues)
    all_issues.sort(key=lambda x: x.severity.weight, reverse=True)

    overall_score = round(sum(r.score for r in audit_results.values()) / max(1, len(audit_results)))

    return crawl_result, audit_results, all_issues, overall_score


@app.get("/health")
async def health_check():
    return {"status": "ok", "service": "SEO & Security Diagnostic API"}


@app.post("/api/audit")
async def api_run_audit(req: AuditRequest):
    if not req.url or not req.url.strip():
        raise HTTPException(status_code=400, detail="Target URL is required.")

    target = req.url.strip()
    if not target.startswith("http://") and not target.startswith("https://"):
        target = "https://" + target
    req.url = target

    try:
        crawl_res, audit_res, all_issues, overall_score = await execute_audit(req)
        return {
            "success": True,
            "target_url": req.url,
            "domain": crawl_res.base_domain,
            "overall_score": overall_score,
            "crawl": {
                "total_crawled": len(crawl_res.pages),
                "duration_seconds": crawl_res.duration_seconds,
                "robots_txt_found": crawl_res.robots_txt_found,
                "pages": [
                    {
                        "url": p.url,
                        "status": p.status_code,
                        "time_ms": p.response_time_ms,
                        "title": p.title,
                        "h1_count": len(p.h1_headings),
                        "word_count": p.word_count,
                        "is_indexable": p.is_indexable,
                    }
                    for p in crawl_res.pages
                ],
            },
            "scores": {
                "seo": audit_res[Category.SEO].score,
                "security": audit_res[Category.SECURITY].score,
                "performance": audit_res[Category.PERFORMANCE].score,
                "offpage": audit_res[Category.OFFPAGE].score,
            },
            "metrics": {
                "ssl": audit_res[Category.SECURITY].metrics.get("ssl", {}),
                "headers": audit_res[Category.SECURITY].metrics.get("headers", {}),
                "cookies": audit_res[Category.SECURITY].metrics.get("cookies", {}),
                "email_security": {
                    "dmarc": audit_res[Category.SECURITY].metrics.get("dmarc"),
                    "spf": audit_res[Category.SECURITY].metrics.get("spf"),
                },
                "performance": audit_res[Category.PERFORMANCE].metrics,
                "social": audit_res[Category.OFFPAGE].metrics.get("social_profiles", {}),
                "links": audit_res[Category.OFFPAGE].metrics.get("link_profile", {}),
            },
            "passed_checks": [
                check
                for r in audit_res.values()
                for check in r.passed_checks
            ],
            "issues": [
                {
                    "issue_id": i.issue_id,
                    "title": i.title,
                    "category": i.category.value,
                    "severity": i.severity.value,
                    "evidence": i.evidence,
                    "description": i.description,
                    "bad_sign": i.bad_sign or i.title,
                    "why_bad": i.why_bad or i.description,
                    "url": i.url,
                    "solution_nginx": i.solution_nginx,
                    "solution_apache": i.solution_apache,
                    "solution_code": i.solution_code,
                }
                for i in all_issues
            ],
        }
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@app.exception_handler(Exception)
async def global_exception_handler(request: Request, exc: Exception):
    return JSONResponse(
        status_code=500,
        content={"success": False, "error": str(exc), "traceback": traceback.format_exc()},
    )


@app.get("/api/export/excel")
async def export_excel(url: str, max_urls: int = 10, max_depth: int = 2):
    from reports.excel_generator import ExcelReportGenerator
    req = AuditRequest(url=url, max_urls=max_urls, max_depth=max_depth)
    crawl_res, audit_res, all_issues, _ = await execute_audit(req)

    buf = io.BytesIO()
    generator = ExcelReportGenerator(crawl_res, audit_res, all_issues)
    generator.generate(buf)
    buf.seek(0)

    filename = f"audit_report_{crawl_res.base_domain}.xlsx"
    return Response(
        content=buf.getvalue(),
        media_type="application/vnd.openxmlformats-officedocument.spreadsheetml.sheet",
        headers={"Content-Disposition": f'attachment; filename="{filename}"'},
    )


@app.get("/api/export/pdf")
async def export_pdf(url: str, max_urls: int = 10, max_depth: int = 2):
    from reports.pdf_generator import PDFReportGenerator
    req = AuditRequest(url=url, max_urls=max_urls, max_depth=max_depth)
    crawl_res, audit_res, all_issues, _ = await execute_audit(req)

    buf = io.BytesIO()
    generator = PDFReportGenerator(crawl_res, audit_res, all_issues)
    generator.generate(buf)
    buf.seek(0)

    filename = f"audit_report_{crawl_res.base_domain}.pdf"
    return Response(
        content=buf.getvalue(),
        media_type="application/pdf",
        headers={"Content-Disposition": f'attachment; filename="{filename}"'},
    )


@app.get("/", response_class=HTMLResponse)
async def serve_dashboard():
    """Serves the full interactive Tailwind CSS single-page audit dashboard."""
    html_content = """<!DOCTYPE html>
<html lang="en" class="dark">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>All-in-One Website Audit & Security Diagnostic Suite</title>
    <script src="https://cdn.tailwindcss.com"></script>
    <link rel="stylesheet" href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.5.1/css/all.min.css">
    <script>
        tailwind.config = {
            darkMode: 'class',
            theme: {
                extend: {
                    colors: {
                        brand: {
                            50: '#f0fdf4',
                            500: '#22c55e',
                            600: '#16a34a',
                            700: '#15803d',
                        }
                    }
                }
            }
        }
    </script>
    <style>
        .custom-scrollbar::-webkit-scrollbar { width: 6px; height: 6px; }
        .custom-scrollbar::-webkit-scrollbar-track { background: #0f172a; }
        .custom-scrollbar::-webkit-scrollbar-thumb { background: #334155; border-radius: 4px; }
    </style>
</head>
<body class="bg-slate-950 text-slate-100 min-h-screen flex flex-col font-sans selection:bg-brand-500 selection:text-white">

    <!-- Top Navbar -->
    <header class="border-b border-slate-800 bg-slate-900/80 backdrop-blur sticky top-0 z-50">
        <div class="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8 h-16 flex items-center justify-between">
            <div class="flex items-center space-x-3">
                <div class="w-10 h-10 rounded-xl bg-gradient-to-tr from-emerald-500 to-cyan-500 flex items-center justify-center shadow-lg shadow-emerald-500/20">
                    <i class="fa-solid fa-shield-halved text-white text-lg"></i>
                </div>
                <div>
                    <h1 class="text-base sm:text-lg font-bold bg-gradient-to-r from-white via-slate-200 to-slate-400 bg-clip-text text-transparent">
                        SEO & Security Auditor
                    </h1>
                    <p class="text-xs text-slate-400">All-in-One Website Health Suite</p>
                </div>
            </div>
            <div class="flex items-center space-x-3">
                <span class="inline-flex items-center px-2.5 py-1 rounded-full text-xs font-medium bg-emerald-950/80 text-emerald-400 border border-emerald-800/60">
                    <span class="w-2 h-2 rounded-full bg-emerald-400 mr-1.5 animate-pulse"></span> Vercel Ready
                </span>
                <a href="https://github.com/bunty9650/SEO" target="_blank" class="text-slate-400 hover:text-white text-lg transition">
                    <i class="fa-brands fa-github"></i>
                </a>
            </div>
        </div>
    </header>

    <!-- Main Container -->
    <main class="flex-1 max-w-7xl w-full mx-auto px-4 sm:px-6 lg:px-8 py-8 space-y-8">

        <!-- Search & Control Card -->
        <section class="bg-slate-900 border border-slate-800 rounded-2xl p-6 shadow-xl relative overflow-hidden">
            <div class="absolute -top-24 -right-24 w-72 h-72 bg-emerald-500/10 rounded-full blur-3xl pointer-events-none"></div>

            <form id="auditForm" class="space-y-4" onsubmit="handleAudit(event)">
                <div class="flex flex-col lg:flex-row gap-3">
                    <div class="relative flex-1">
                        <div class="absolute inset-y-0 left-0 pl-4 flex items-center pointer-events-none text-slate-400">
                            <i class="fa-solid fa-globe"></i>
                        </div>
                        <input
                            type="text"
                            id="targetUrl"
                            placeholder="Enter website URL (e.g. https://example.com or https://www.gentechbridge.com)"
                            value="https://example.com"
                            required
                            class="w-full pl-11 pr-4 py-3.5 bg-slate-950 border border-slate-700/80 rounded-xl text-white placeholder-slate-500 focus:outline-none focus:ring-2 focus:ring-emerald-500 focus:border-transparent transition"
                        />
                    </div>
                    <button
                        type="submit"
                        id="submitBtn"
                        class="px-8 py-3.5 bg-emerald-500 hover:bg-emerald-600 text-slate-950 font-bold rounded-xl shadow-lg shadow-emerald-500/25 transition duration-200 flex items-center justify-center space-x-2 shrink-0 cursor-pointer"
                    >
                        <i class="fa-solid fa-bolt"></i>
                        <span>Start Audit</span>
                    </button>
                </div>

                <!-- Parameters & Presets -->
                <div class="flex flex-wrap items-center justify-between gap-4 pt-2 text-sm text-slate-400">
                    <div class="flex items-center space-x-6">
                        <label class="flex items-center space-x-2">
                            <span>Max URLs:</span>
                            <select id="maxUrls" class="bg-slate-950 border border-slate-800 rounded-lg px-2.5 py-1 text-slate-200 text-xs focus:ring-emerald-500">
                                <option value="5">5</option>
                                <option value="10" selected>10</option>
                                <option value="20">20</option>
                                <option value="30">30</option>
                            </select>
                        </label>
                        <label class="flex items-center space-x-2">
                            <span>Max Depth:</span>
                            <select id="maxDepth" class="bg-slate-950 border border-slate-800 rounded-lg px-2.5 py-1 text-slate-200 text-xs focus:ring-emerald-500">
                                <option value="1">1</option>
                                <option value="2" selected>2</option>
                                <option value="3">3</option>
                            </select>
                        </label>
                    </div>
                    <div class="flex items-center space-x-2 text-xs">
                        <span>Quick Presets:</span>
                        <button type="button" onclick="setPreset('https://example.com')" class="px-2.5 py-1 bg-slate-800 hover:bg-slate-700 rounded-md text-slate-300 transition">example.com</button>
                        <button type="button" onclick="setPreset('http://127.0.0.1:9000')" class="px-2.5 py-1 bg-slate-800 hover:bg-slate-700 rounded-md text-slate-300 transition">Local Demo (9000)</button>
                    </div>
                </div>
            </form>
        </section>

        <!-- Loading Spinner -->
        <div id="loadingState" class="hidden py-16 text-center space-y-4">
            <div class="inline-block w-12 h-12 border-4 border-emerald-500 border-t-transparent rounded-full animate-spin"></div>
            <p class="text-base text-slate-300 font-medium" id="loadingText">Crawling internal links & running multi-dimensional audit...</p>
            <p class="text-xs text-slate-500">Checking SSL certificates, security headers, Core Web Vitals, and DOM tags</p>
        </div>

        <!-- Audit Results Section -->
        <div id="resultsContainer" class="hidden space-y-8">

            <!-- Summary Meta -->
            <div class="flex flex-wrap items-center justify-between gap-4 bg-slate-900/60 border border-slate-800 rounded-xl px-5 py-3.5 text-xs sm:text-sm">
                <div class="flex items-center space-x-3">
                    <span class="text-slate-400">Target:</span>
                    <span id="metaTargetUrl" class="font-bold text-white break-all"></span>
                </div>
                <div class="flex items-center space-x-4 text-slate-400">
                    <span>Crawled: <strong id="metaUrlsCount" class="text-slate-200"></strong> URLs</span>
                    <span>Duration: <strong id="metaDuration" class="text-slate-200"></strong>s</span>
                </div>
            </div>

            <!-- 5 Scorecard Meters -->
            <div class="grid grid-cols-2 md:grid-cols-5 gap-3 sm:gap-4">
                <div class="bg-slate-900 border border-slate-800 rounded-2xl p-4 text-center">
                    <span class="text-xs text-slate-400 uppercase tracking-wider block mb-1">Overall Health</span>
                    <span id="scoreOverall" class="text-3xl sm:text-4xl font-black text-emerald-400">--</span>
                    <span class="text-xs text-slate-500 block mt-1">/ 100</span>
                </div>
                <div class="bg-slate-900 border border-slate-800 rounded-2xl p-4 text-center">
                    <span class="text-xs text-slate-400 uppercase tracking-wider block mb-1">Technical SEO</span>
                    <span id="scoreSEO" class="text-3xl sm:text-4xl font-black text-emerald-400">--</span>
                    <span class="text-xs text-slate-500 block mt-1">/ 100</span>
                </div>
                <div class="bg-slate-900 border border-slate-800 rounded-2xl p-4 text-center">
                    <span class="text-xs text-slate-400 uppercase tracking-wider block mb-1">Security & SSL</span>
                    <span id="scoreSecurity" class="text-3xl sm:text-4xl font-black text-emerald-400">--</span>
                    <span class="text-xs text-slate-500 block mt-1">/ 100</span>
                </div>
                <div class="bg-slate-900 border border-slate-800 rounded-2xl p-4 text-center">
                    <span class="text-xs text-slate-400 uppercase tracking-wider block mb-1">UI & Performance</span>
                    <span id="scorePerformance" class="text-3xl sm:text-4xl font-black text-emerald-400">--</span>
                    <span class="text-xs text-slate-500 block mt-1">/ 100</span>
                </div>
                <div class="bg-slate-900 border border-slate-800 rounded-2xl p-4 text-center col-span-2 md:col-span-1">
                    <span class="text-xs text-slate-400 uppercase tracking-wider block mb-1">Off-Page Trust</span>
                    <span id="scoreOffpage" class="text-3xl sm:text-4xl font-black text-emerald-400">--</span>
                    <span class="text-xs text-slate-500 block mt-1">/ 100</span>
                </div>
            </div>

            <!-- Tabbed Inspectors -->
            <div class="bg-slate-900 border border-slate-800 rounded-2xl overflow-hidden shadow-xl">
                <!-- Tab Headers -->
                <div class="flex overflow-x-auto border-b border-slate-800 bg-slate-950/40 custom-scrollbar">
                    <button onclick="switchTab('tab-fixes')" id="btn-tab-fixes" class="tab-btn px-5 py-3.5 text-sm font-semibold text-emerald-400 border-b-2 border-emerald-400 flex items-center space-x-2 shrink-0">
                        <i class="fa-solid fa-wrench"></i><span>Issues & Fixes (<span id="issuesCount">0</span>)</span>
                    </button>
                    <button onclick="switchTab('tab-pages')" id="btn-tab-pages" class="tab-btn px-5 py-3.5 text-sm font-semibold text-slate-400 hover:text-white border-b-2 border-transparent flex items-center space-x-2 shrink-0">
                        <i class="fa-solid fa-list-check"></i><span>Crawled Pages</span>
                    </button>
                    <button onclick="switchTab('tab-sec')" id="btn-tab-sec" class="tab-btn px-5 py-3.5 text-sm font-semibold text-slate-400 hover:text-white border-b-2 border-transparent flex items-center space-x-2 shrink-0">
                        <i class="fa-solid fa-lock"></i><span>Security & Headers</span>
                    </button>
                    <button onclick="switchTab('tab-vitals')" id="btn-tab-vitals" class="tab-btn px-5 py-3.5 text-sm font-semibold text-slate-400 hover:text-white border-b-2 border-transparent flex items-center space-x-2 shrink-0">
                        <i class="fa-solid fa-gauge-high"></i><span>Web Vitals</span>
                    </button>
                    <button onclick="switchTab('tab-exports')" id="btn-tab-exports" class="tab-btn px-5 py-3.5 text-sm font-semibold text-slate-400 hover:text-white border-b-2 border-transparent flex items-center space-x-2 shrink-0">
                        <i class="fa-solid fa-file-export"></i><span>Export Reports</span>
                    </button>
                </div>

                <!-- Tab Contents -->
                <div class="p-6">

                    <!-- TAB 1: Issues & Fixes -->
                    <div id="tab-fixes" class="tab-content space-y-4">
                        <div class="flex items-center justify-between pb-2">
                            <h3 class="text-base font-bold text-white">Remediation Action Items</h3>
                            <span class="text-xs text-slate-400">Copy-paste ready solutions for Nginx, Apache & HTML</span>
                        </div>
                        <div id="issuesList" class="space-y-3"></div>
                    </div>

                    <!-- TAB 2: Crawled Pages -->
                    <div id="tab-pages" class="tab-content hidden space-y-4">
                        <h3 class="text-base font-bold text-white">Discovered URLs & Indexability</h3>
                        <div class="overflow-x-auto custom-scrollbar">
                            <table class="w-full text-left text-xs text-slate-300">
                                <thead class="bg-slate-950 text-slate-400 uppercase tracking-wider">
                                    <tr>
                                        <th class="p-3">Status</th>
                                        <th class="p-3">URL</th>
                                        <th class="p-3">Time</th>
                                        <th class="p-3">Title</th>
                                        <th class="p-3">H1</th>
                                        <th class="p-3">Words</th>
                                    </tr>
                                </thead>
                                <tbody id="pagesTableBody" class="divide-y divide-slate-800"></tbody>
                            </table>
                        </div>
                    </div>

                    <!-- TAB 3: Security & SSL -->
                    <div id="tab-sec" class="tab-content hidden space-y-6">
                        <div>
                            <h3 class="text-base font-bold text-white mb-3">SSL / TLS Certificate Telemetry</h3>
                            <div class="grid grid-cols-1 sm:grid-cols-3 gap-4" id="sslMetricsGrid"></div>
                        </div>
                        <div class="grid grid-cols-1 md:grid-cols-2 gap-4">
                            <div>
                                <h3 class="text-base font-bold text-white mb-3">Email Spoofing Defense (DNS)</h3>
                                <div class="bg-slate-950 rounded-xl border border-slate-800 p-4 space-y-3" id="emailSecGrid"></div>
                            </div>
                            <div>
                                <h3 class="text-base font-bold text-white mb-3">Cookie Security Telemetry</h3>
                                <div class="bg-slate-950 rounded-xl border border-slate-800 p-4 space-y-3" id="cookieSecGrid"></div>
                            </div>
                        </div>
                        <div>
                            <h3 class="text-base font-bold text-white mb-3">HTTP Security Headers Matrix</h3>
                            <div class="overflow-x-auto custom-scrollbar bg-slate-950 rounded-xl border border-slate-800 p-4">
                                <div id="headersMatrix" class="grid grid-cols-1 md:grid-cols-2 gap-3 text-xs"></div>
                            </div>
                        </div>
                    </div>

                    <!-- TAB 4: Core Web Vitals -->
                    <div id="tab-vitals" class="tab-content hidden space-y-4">
                        <h3 class="text-base font-bold text-white">Performance Metrics & Core Web Vitals</h3>
                        <div class="grid grid-cols-2 sm:grid-cols-4 gap-4" id="vitalsGrid"></div>
                    </div>

                    <!-- TAB 5: Export Reports -->
                    <div id="tab-exports" class="tab-content hidden space-y-6">
                        <div class="max-w-xl">
                            <h3 class="text-base font-bold text-white mb-2">Export Client-Ready Reports</h3>
                            <p class="text-sm text-slate-400 mb-6">Download the comprehensive multi-tab Excel spreadsheet or executive presentation PDF.</p>
                            <div class="grid grid-cols-1 sm:grid-cols-2 gap-4">
                                <a id="downloadExcelBtn" href="#" class="flex items-center justify-center space-x-3 p-4 bg-emerald-600 hover:bg-emerald-500 text-white rounded-xl font-bold shadow-lg transition">
                                    <i class="fa-solid fa-file-excel text-xl"></i>
                                    <span>Download Excel (.xlsx)</span>
                                </a>
                                <a id="downloadPdfBtn" href="#" class="flex items-center justify-center space-x-3 p-4 bg-blue-600 hover:bg-blue-500 text-white rounded-xl font-bold shadow-lg transition">
                                    <i class="fa-solid fa-file-pdf text-xl"></i>
                                    <span>Download PDF (.pdf)</span>
                                </a>
                            </div>
                        </div>
                    </div>

                </div>
            </div>

        </div>

    </main>

    <!-- Footer -->
    <footer class="border-t border-slate-900 bg-slate-950 py-6 text-center text-xs text-slate-500">
        <p>All-in-One Website Audit, SEO, Security, Performance & UI Diagnostic Suite • 100% Free & Open-Source</p>
    </footer>

    <!-- Frontend Logic -->
    <script>
        let currentAuditData = null;

        function setPreset(url) {
            document.getElementById('targetUrl').value = url;
        }

        function switchTab(tabId) {
            document.querySelectorAll('.tab-content').forEach(el => el.classList.add('hidden'));
            document.querySelectorAll('.tab-btn').forEach(btn => {
                btn.classList.remove('text-emerald-400', 'border-emerald-400');
                btn.classList.add('text-slate-400', 'border-transparent');
            });
            document.getElementById(tabId).classList.remove('hidden');
            const activeBtn = document.getElementById('btn-' + tabId);
            if (activeBtn) {
                activeBtn.classList.add('text-emerald-400', 'border-emerald-400');
                activeBtn.classList.remove('text-slate-400', 'border-transparent');
            }
        }

        function getScoreColor(score) {
            if (score >= 80) return 'text-emerald-400';
            if (score >= 50) return 'text-amber-400';
            return 'text-rose-500';
        }

        async function handleAudit(e) {
            e.preventDefault();
            const url = document.getElementById('targetUrl').value.trim();
            const maxUrls = parseInt(document.getElementById('maxUrls').value);
            const maxDepth = parseInt(document.getElementById('maxDepth').value);

            const submitBtn = document.getElementById('submitBtn');
            const loadingState = document.getElementById('loadingState');
            const resultsContainer = document.getElementById('resultsContainer');

            submitBtn.disabled = true;
            submitBtn.classList.add('opacity-50');
            loadingState.classList.remove('hidden');
            resultsContainer.classList.add('hidden');

            try {
                const resp = await fetch('/api/audit', {
                    method: 'POST',
                    headers: { 'Content-Type': 'application/json' },
                    body: JSON.stringify({ url, max_urls: maxUrls, max_depth: maxDepth })
                });

                if (!resp.ok) {
                    const err = await resp.json();
                    throw new Error(err.detail || 'Audit execution failed');
                }

                const data = await resp.json();
                currentAuditData = data;
                renderResults(data);
            } catch (err) {
                alert('Audit Error: ' + err.message);
            } finally {
                submitBtn.disabled = false;
                submitBtn.classList.remove('opacity-50');
                loadingState.classList.add('hidden');
            }
        }

        function renderResults(data) {
            const resultsContainer = document.getElementById('resultsContainer');
            resultsContainer.classList.remove('hidden');

            // Metadata
            document.getElementById('metaTargetUrl').textContent = data.target_url;
            document.getElementById('metaUrlsCount').textContent = data.crawl.total_crawled;
            document.getElementById('metaDuration').textContent = data.crawl.duration_seconds;

            // Scores
            const scores = data.scores;
            const setScore = (id, val) => {
                const el = document.getElementById(id);
                el.textContent = val;
                el.className = 'text-3xl sm:text-4xl font-black ' + getScoreColor(val);
            };
            setScore('scoreOverall', data.overall_score);
            setScore('scoreSEO', scores.seo);
            setScore('scoreSecurity', scores.security);
            setScore('scorePerformance', scores.performance);
            setScore('scoreOffpage', scores.offpage);

            // Tab 1: Issues
            document.getElementById('issuesCount').textContent = data.issues.length;
            const issuesList = document.getElementById('issuesList');
            issuesList.innerHTML = '';

            if (data.issues.length === 0) {
                issuesList.innerHTML = '<div class="p-6 text-center text-emerald-400 bg-emerald-950/30 rounded-xl border border-emerald-900/60"><i class="fa-solid fa-circle-check text-2xl mb-2"></i><p>Zero critical issues detected! Perfect health.</p></div>';
            } else {
                data.issues.forEach((issue, idx) => {
                    const sevBadge = {
                        'Critical': 'bg-rose-950 text-rose-400 border-rose-800',
                        'High': 'bg-orange-950 text-orange-400 border-orange-800',
                        'Medium': 'bg-amber-950 text-amber-400 border-amber-800',
                        'Low': 'bg-blue-950 text-blue-400 border-blue-800',
                        'Info': 'bg-slate-800 text-slate-300 border-slate-700',
                    }[issue.severity] || 'bg-slate-800 text-slate-300 border-slate-700';

                    let codeSection = '';
                    if (issue.solution_nginx || issue.solution_apache || issue.solution_code) {
                        const codeSnippets = [];
                        if (issue.solution_nginx) codeSnippets.push(`<div><span class="text-xs font-bold text-cyan-400 block mb-1">Nginx Configuration:</span><pre class="bg-slate-950 p-2.5 rounded text-xs overflow-x-auto text-emerald-300"><code>${escapeHtml(issue.solution_nginx)}</code></pre></div>`);
                        if (issue.solution_apache) codeSnippets.push(`<div><span class="text-xs font-bold text-cyan-400 block mb-1">Apache .htaccess:</span><pre class="bg-slate-950 p-2.5 rounded text-xs overflow-x-auto text-emerald-300"><code>${escapeHtml(issue.solution_apache)}</code></pre></div>`);
                        if (issue.solution_code) codeSnippets.push(`<div><span class="text-xs font-bold text-cyan-400 block mb-1">HTML / Code:</span><pre class="bg-slate-950 p-2.5 rounded text-xs overflow-x-auto text-emerald-300"><code>${escapeHtml(issue.solution_code)}</code></pre></div>`);
                        codeSection = `<div class="mt-3 pt-3 border-t border-slate-800 space-y-3">${codeSnippets.join('')}</div>`;
                    }

                    const card = document.createElement('div');
                    card.className = 'border border-slate-800 bg-slate-950/60 rounded-xl p-4 space-y-3';

                    const badSignBox = `
                        <div class="grid grid-cols-1 md:grid-cols-2 gap-2">
                            <div class="p-2.5 rounded-lg bg-rose-950/40 border border-rose-900/50">
                                <div class="flex items-center space-x-1.5 text-rose-400 font-bold text-xs mb-1">
                                    <i class="fa-solid fa-triangle-exclamation"></i>
                                    <span>Bad Sign (Khatre Ka Sanket):</span>
                                </div>
                                <p class="text-xs text-rose-200/90 leading-relaxed">${escapeHtml(issue.bad_sign || issue.title)}</p>
                            </div>
                            <div class="p-2.5 rounded-lg bg-amber-950/40 border border-amber-900/50">
                                <div class="flex items-center space-x-1.5 text-amber-400 font-bold text-xs mb-1">
                                    <i class="fa-solid fa-shield-halved"></i>
                                    <span>Why It's Bad (Kyu Khatarnak Hai):</span>
                                </div>
                                <p class="text-xs text-amber-200/90 leading-relaxed">${escapeHtml(issue.why_bad || issue.description)}</p>
                            </div>
                        </div>
                    `;

                    card.innerHTML = `
                        <div class="flex flex-wrap items-center justify-between gap-2">
                            <div class="flex items-center space-x-2">
                                <span class="px-2 py-0.5 rounded text-xs font-bold border ${sevBadge}">${issue.severity.toUpperCase()}</span>
                                <span class="font-bold text-sm text-white">${escapeHtml(issue.title)}</span>
                            </div>
                            <span class="text-xs text-slate-500">${escapeHtml(issue.category)}</span>
                        </div>
                        ${badSignBox}
                        <p class="text-xs text-slate-300"><strong>Evidence:</strong> <code class="bg-slate-900 px-1 py-0.5 rounded text-slate-200">${escapeHtml(issue.evidence)}</code></p>
                        <p class="text-xs text-slate-400">${escapeHtml(issue.description)}</p>
                        ${codeSection}
                    `;
                    issuesList.appendChild(card);
                });
            }

            // Tab 2: Pages
            const pagesTbody = document.getElementById('pagesTableBody');
            pagesTbody.innerHTML = '';
            data.crawl.pages.forEach(p => {
                const tr = document.createElement('tr');
                tr.innerHTML = `
                    <td class="p-3"><span class="px-2 py-0.5 rounded font-bold ${p.status === 200 ? 'bg-emerald-950 text-emerald-400' : 'bg-rose-950 text-rose-400'}">${p.status}</span></td>
                    <td class="p-3 font-mono text-slate-300 max-w-xs truncate">${escapeHtml(p.url)}</td>
                    <td class="p-3">${p.time_ms}ms</td>
                    <td class="p-3 text-slate-300 max-w-xs truncate">${escapeHtml(p.title || 'N/A')}</td>
                    <td class="p-3">${p.h1_count}</td>
                    <td class="p-3">${p.word_count}</td>
                `;
                pagesTbody.appendChild(tr);
            });

            // Tab 3: Security & SSL
            const sslGrid = document.getElementById('sslMetricsGrid');
            const ssl = data.metrics.ssl || {};
            sslGrid.innerHTML = `
                <div class="p-4 bg-slate-950 rounded-xl border border-slate-800 text-center">
                    <span class="text-xs text-slate-400 block mb-1">Certificate Status</span>
                    <span class="text-lg font-bold ${ssl.valid ? 'text-emerald-400' : 'text-rose-500'}">${ssl.valid ? 'Valid & Trusted' : 'Invalid / Expired'}</span>
                </div>
                <div class="p-4 bg-slate-950 rounded-xl border border-slate-800 text-center">
                    <span class="text-xs text-slate-400 block mb-1">Days Remaining</span>
                    <span class="text-lg font-bold text-white">${ssl.days_remaining !== undefined && ssl.days_remaining !== null ? ssl.days_remaining + ' days' : 'N/A'}</span>
                </div>
                <div class="p-4 bg-slate-950 rounded-xl border border-slate-800 text-center">
                    <span class="text-xs text-slate-400 block mb-1">Negotiated Protocol</span>
                    <span class="text-lg font-bold text-cyan-400">${escapeHtml(ssl.protocol || 'N/A')}</span>
                </div>
            `;

            // Email Spoofing Defense
            const emailGrid = document.getElementById('emailSecGrid');
            if (emailGrid) {
                const em = data.metrics.email_security || {};
                const dmarcStatus = em.dmarc ? (em.dmarc.toLowerCase().includes('p=none') ? '<span class="text-amber-400 font-bold">Weak (p=none)</span>' : '<span class="text-emerald-400 font-bold">Active Enforcement</span>') : '<span class="text-rose-400 font-bold">Missing</span>';
                const spfStatus = em.spf ? (em.spf.toLowerCase().includes('+all') ? '<span class="text-rose-400 font-bold">Permissive (+all)</span>' : '<span class="text-emerald-400 font-bold">Configured</span>') : '<span class="text-rose-400 font-bold">Missing</span>';
                emailGrid.innerHTML = `
                    <div class="flex justify-between items-center text-xs pb-1 border-b border-slate-800">
                        <span class="text-slate-400">DMARC Record:</span>
                        ${dmarcStatus}
                    </div>
                    <p class="text-xs text-slate-300 font-mono bg-slate-900/80 p-2 rounded truncate" title="${escapeHtml(em.dmarc || 'No DMARC TXT record')}">${escapeHtml(em.dmarc || 'No _dmarc TXT record found')}</p>
                    <div class="flex justify-between items-center text-xs pt-2 pb-1 border-b border-slate-800">
                        <span class="text-slate-400">SPF Record:</span>
                        ${spfStatus}
                    </div>
                    <p class="text-xs text-slate-300 font-mono bg-slate-900/80 p-2 rounded truncate" title="${escapeHtml(em.spf || 'No SPF TXT record')}">${escapeHtml(em.spf || 'No v=spf1 TXT record found')}</p>
                `;
            }

            // Cookie Security Telemetry
            const cookieGrid = document.getElementById('cookieSecGrid');
            if (cookieGrid) {
                const ck = data.metrics.cookies || {};
                const total = ck.total_cookies || 0;
                cookieGrid.innerHTML = `
                    <div class="flex justify-between items-center text-xs pb-1 border-b border-slate-800">
                        <span class="text-slate-400">Cookies Analyzed:</span>
                        <span class="text-white font-bold">${total}</span>
                    </div>
                    <div class="flex justify-between items-center text-xs py-1">
                        <span class="text-slate-400">Missing 'Secure' Flag:</span>
                        <span class="font-bold ${ck.insecure_count > 0 ? 'text-rose-400' : 'text-emerald-400'}">${ck.insecure_count || 0}</span>
                    </div>
                    <div class="flex justify-between items-center text-xs py-1">
                        <span class="text-slate-400">Missing 'HttpOnly' (XSS Risk):</span>
                        <span class="font-bold ${ck.no_httponly_count > 0 ? 'text-rose-400' : 'text-emerald-400'}">${ck.no_httponly_count || 0}</span>
                    </div>
                    <div class="flex justify-between items-center text-xs py-1">
                        <span class="text-slate-400">Missing / Weak 'SameSite' (CSRF Risk):</span>
                        <span class="font-bold ${ck.weak_samesite_count > 0 ? 'text-amber-400' : 'text-emerald-400'}">${ck.weak_samesite_count || 0}</span>
                    </div>
                `;
            }

            const headersMatrix = document.getElementById('headersMatrix');
            headersMatrix.innerHTML = '';
            const hdrs = data.metrics.headers || {};
            Object.entries(hdrs).slice(0, 14).forEach(([k, v]) => {
                const row = document.createElement('div');
                row.className = 'flex items-center justify-between p-2 bg-slate-900/80 rounded border border-slate-800/80';
                row.innerHTML = `<span class="font-bold text-slate-400">${escapeHtml(k)}</span><span class="text-slate-300 truncate max-w-xs">${escapeHtml(v)}</span>`;
                headersMatrix.appendChild(row);
            });

            // Tab 4: Web Vitals
            const vitalsGrid = document.getElementById('vitalsGrid');
            const perf = data.metrics.performance || {};
            vitalsGrid.innerHTML = `
                <div class="p-4 bg-slate-950 rounded-xl border border-slate-800 text-center">
                    <span class="text-xs text-slate-400 block mb-1">LCP (Largest Paint)</span>
                    <span class="text-xl font-bold text-emerald-400">${perf.lcp_seconds || '0'}s</span>
                </div>
                <div class="p-4 bg-slate-950 rounded-xl border border-slate-800 text-center">
                    <span class="text-xs text-slate-400 block mb-1">CLS (Layout Shift)</span>
                    <span class="text-xl font-bold text-emerald-400">${perf.cls !== undefined ? perf.cls : '0'}</span>
                </div>
                <div class="p-4 bg-slate-950 rounded-xl border border-slate-800 text-center">
                    <span class="text-xs text-slate-400 block mb-1">FCP (First Paint)</span>
                    <span class="text-xl font-bold text-cyan-400">${perf.fcp_seconds || '0'}s</span>
                </div>
                <div class="p-4 bg-slate-950 rounded-xl border border-slate-800 text-center">
                    <span class="text-xs text-slate-400 block mb-1">TBT (Blocking Time)</span>
                    <span class="text-xl font-bold text-white">${perf.tbt_ms || '0'}ms</span>
                </div>
            `;

            // Tab 5: Exports
            const encUrl = encodeURIComponent(data.target_url);
            document.getElementById('downloadExcelBtn').href = `/api/export/excel?url=${encUrl}&max_urls=10`;
            document.getElementById('downloadPdfBtn').href = `/api/export/pdf?url=${encUrl}&max_urls=10`;
        }

        function escapeHtml(text) {
            if (!text) return '';
            return String(text)
                .replace(/&/g, '&amp;')
                .replace(/</g, '&lt;')
                .replace(/>/g, '&gt;')
                .replace(/"/g, '&quot;')
                .replace(/'/g, '&#039;');
        }
    </script>
</body>
</html>"""
    return HTMLResponse(content=html_content)


if __name__ == "__main__":
    import uvicorn
    uvicorn.run("app:app", host="0.0.0.0", port=8000, reload=True)
