"""UI, Design & Performance Diagnostics Auditor (Google PageSpeed Insights & Playwright)."""
from __future__ import annotations

import asyncio
import os
from pathlib import Path
from typing import Any, Dict, List, Optional
from urllib.parse import urlparse
import httpx

from auditors.base import AuditIssue, AuditResult, Category, Severity
from solutions.solution_database import SolutionDatabase


class PerformanceAuditor:
    """Evaluates Core Web Vitals (LCP, CLS, FCP, TBT) and captures visual UI screenshots."""

    PAGESPEED_API_URL = "https://www.googleapis.com/pagespeedonline/v5/runPagespeed"

    def __init__(
        self,
        target_url: str,
        api_key: Optional[str] = None,
        html_content: Optional[str] = None,
        ttfb_ms: Optional[float] = None,
    ):
        self.target_url = target_url
        self.api_key = api_key
        self.html_content = html_content or ""
        self.ttfb_ms = ttfb_ms or 150.0

        self.issues: List[AuditIssue] = []
        self.passed_checks: List[str] = []
        self.metrics: Dict[str, Any] = {}

    def _is_local_or_private_url(self) -> bool:
        """Determines if the target URL is a local or internal network address."""
        parsed = urlparse(self.target_url)
        hostname = (parsed.hostname or "").lower()
        return hostname in ["localhost", "127.0.0.1", "0.0.0.0"] or hostname.endswith(".local") or hostname.startswith("192.168.") or hostname.startswith("10.")

    async def run(self) -> AuditResult:
        """Runs performance diagnostics using Google PageSpeed Insights API with heuristic fallback."""
        self.issues.clear()
        self.passed_checks.clear()

        # Check mobile viewport tag locally
        self._audit_viewport()

        # If it's a private or local address, or no internet, run synthetic heuristic evaluation
        if self._is_local_or_private_url():
            self._evaluate_local_heuristics()
        else:
            try:
                # Query Google PageSpeed Insights API
                psi_data = await self._fetch_pagespeed_api()
                if psi_data:
                    self._parse_pagespeed_metrics(psi_data)
                else:
                    self._evaluate_local_heuristics()
            except Exception:
                self._evaluate_local_heuristics()

        result = AuditResult(
            category=Category.PERFORMANCE,
            issues=self.issues,
            passed_checks=self.passed_checks,
            metrics=self.metrics,
        )
        result.calculate_score()
        return result

    def _audit_viewport(self):
        """Checks for the responsive mobile viewport meta tag."""
        if self.html_content:
            has_viewport = 'name="viewport"' in self.html_content.lower() or "name='viewport'" in self.html_content.lower()
            if not has_viewport:
                self.issues.append(
                    SolutionDatabase.build_issue(
                        issue_id="PERF_MISSING_VIEWPORT",
                        evidence="HTML <head> is missing responsive `<meta name='viewport'>` element.",
                        url=self.target_url,
                    )
                )
            else:
                self.passed_checks.append("Mobile responsive viewport meta tag is configured.")

    async def _fetch_pagespeed_api(self) -> Optional[Dict[str, Any]]:
        """Asynchronously calls the official Google PageSpeed Insights API."""
        params: Dict[str, Any] = {
            "url": self.target_url,
            "strategy": "mobile",
            "category": "performance",
        }
        if self.api_key:
            params["key"] = self.api_key

        async with httpx.AsyncClient(timeout=15.0) as client:
            resp = await client.get(self.PAGESPEED_API_URL, params=params)
            if resp.status_code == 200:
                return resp.json()
        return None

    def _parse_pagespeed_metrics(self, data: Dict[str, Any]):
        """Extracts Lighthouse score and Core Web Vitals from PageSpeed API response."""
        lighthouse = data.get("lighthouseResult", {})
        categories = lighthouse.get("categories", {})
        audits = lighthouse.get("audits", {})

        perf_category = categories.get("performance", {})
        score_val = perf_category.get("score")
        perf_score = int(score_val * 100) if score_val is not None else 85

        # Core Web Vitals
        lcp_val = audits.get("largest-contentful-paint", {}).get("numericValue", 0) / 1000.0  # seconds
        cls_val = audits.get("cumulative-layout-shift", {}).get("numericValue", 0)
        fcp_val = audits.get("first-contentful-paint", {}).get("numericValue", 0) / 1000.0  # seconds
        tbt_val = audits.get("total-blocking-time", {}).get("numericValue", 0)  # ms

        self.metrics = {
            "source": "Google PageSpeed Insights API",
            "performance_score": perf_score,
            "lcp_seconds": round(lcp_val, 2),
            "cls": round(cls_val, 3),
            "fcp_seconds": round(fcp_val, 2),
            "tbt_ms": round(tbt_val, 1),
        }

        # Issue evaluation
        if perf_score < 50:
            self.issues.append(
                SolutionDatabase.build_issue(
                    issue_id="PERF_POOR_SCORE",
                    evidence=f"Mobile Performance Score: {perf_score}/100",
                    url=self.target_url,
                )
            )
        elif perf_score >= 80:
            self.passed_checks.append(f"Strong overall performance score: {perf_score}/100.")

        if lcp_val > 2.5:
            self.issues.append(
                SolutionDatabase.build_issue(
                    issue_id="PERF_SLOW_LCP",
                    evidence=f"Largest Contentful Paint took {lcp_val:.2f}s (threshold: 2.5s)",
                    url=self.target_url,
                )
            )
        else:
            self.passed_checks.append(f"Healthy Largest Contentful Paint (LCP: {lcp_val:.2f}s).")

        if cls_val > 0.1:
            self.issues.append(
                SolutionDatabase.build_issue(
                    issue_id="PERF_HIGH_CLS",
                    evidence=f"Cumulative Layout Shift is {cls_val:.3f} (threshold: 0.1)",
                    url=self.target_url,
                )
            )
        else:
            self.passed_checks.append(f"Good layout stability (CLS: {cls_val:.3f}).")

        if fcp_val > 1.8:
            self.issues.append(
                SolutionDatabase.build_issue(
                    issue_id="PERF_SLOW_FCP",
                    evidence=f"First Contentful Paint took {fcp_val:.2f}s (threshold: 1.8s)",
                    url=self.target_url,
                )
            )

    def _evaluate_local_heuristics(self):
        """Synthetic local performance calculation based on DOM complexity and response latency."""
        html_len = len(self.html_content)
        img_count = self.html_content.lower().count("<img")
        script_count = self.html_content.lower().count("<script")

        # Estimate synthetic metrics
        est_fcp = max(0.4, round(self.ttfb_ms / 500.0, 2))
        est_lcp = max(est_fcp, round(est_fcp + (img_count * 0.15) + (html_len / 50000.0), 2))
        est_cls = 0.02 if ('width="' in self.html_content or "width='" in self.html_content) else 0.08
        est_tbt = min(500.0, script_count * 25.0)

        # Base score penalty calculation
        score = 100
        if self.ttfb_ms > 800:
            score -= 20
        elif self.ttfb_ms > 400:
            score -= 10

        if script_count > 15:
            score -= 15
        elif script_count > 8:
            score -= 8

        if est_lcp > 2.5:
            score -= 15

        score = max(30, min(100, score))

        self.metrics = {
            "source": "Local Synthetic Heuristics",
            "performance_score": score,
            "lcp_seconds": est_lcp,
            "cls": est_cls,
            "fcp_seconds": est_fcp,
            "tbt_ms": est_tbt,
            "script_tags": script_count,
            "img_tags": img_count,
            "dom_size_chars": html_len,
        }

        if score >= 80:
            self.passed_checks.append(f"Fast initial load speed and DOM efficiency ({score}/100).")
        if est_lcp <= 2.5:
            self.passed_checks.append(f"Estimated LCP is within optimal bounds ({est_lcp}s).")
        if est_cls <= 0.1:
            self.passed_checks.append(f"Estimated visual stability is optimal (CLS: {est_cls}).")


async def capture_screenshots(
    url: str,
    output_dir: str = "screenshots",
    timeout_ms: int = 15000,
) -> Dict[str, str]:
    """Captures Desktop (1920x1080) and Mobile (390x844) viewport screenshots via Playwright."""
    result: Dict[str, str] = {}
    try:
        from playwright.async_api import async_playwright
    except ImportError:
        return result

    out_path = Path(output_dir)
    out_path.mkdir(parents=True, exist_ok=True)

    parsed = urlparse(url)
    slug = parsed.netloc.replace(":", "_").replace(".", "_")

    desktop_file = str(out_path / f"{slug}_desktop.png")
    mobile_file = str(out_path / f"{slug}_mobile.png")

    try:
        async with async_playwright() as p:
            # Launch chromium headless
            browser = await p.chromium.launch(headless=True)

            # 1. Desktop viewport
            desktop_page = await browser.new_page(viewport={"width": 1920, "height": 1080})
            await desktop_page.goto(url, timeout=timeout_ms, wait_until="load")
            await desktop_page.screenshot(path=desktop_file, full_page=False)
            result["desktop"] = desktop_file
            await desktop_page.close()

            # 2. Mobile viewport (iPhone 14 / modern mobile)
            mobile_page = await browser.new_page(
                viewport={"width": 390, "height": 844},
                user_agent="Mozilla/5.0 (iPhone; CPU iPhone OS 16_5 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/16.5 Mobile/15E148 Safari/604.1",
            )
            await mobile_page.goto(url, timeout=timeout_ms, wait_until="load")
            await mobile_page.screenshot(path=mobile_file, full_page=False)
            result["mobile"] = mobile_file
            await mobile_page.close()

            await browser.close()
    except Exception:
        # Gracefully return whatever was captured or empty
        pass

    return result
