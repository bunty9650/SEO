"""Unit tests for PerformanceAuditor."""
import pytest
from auditors.performance_auditor import PerformanceAuditor
from auditors.base import Category, Severity


@pytest.mark.asyncio
async def test_performance_auditor_flags_missing_viewport():
    html_without_viewport = """<!DOCTYPE html><html><head><title>No Viewport</title></head><body><h1>Content</h1></body></html>"""
    auditor = PerformanceAuditor(
        target_url="http://127.0.0.1:9000",
        html_content=html_without_viewport,
        ttfb_ms=200.0,
    )
    result = await auditor.run()
    assert result.category == Category.PERFORMANCE
    issue_ids = [i.issue_id for i in result.issues]
    assert "PERF_MISSING_VIEWPORT" in issue_ids


@pytest.mark.asyncio
async def test_performance_auditor_passes_with_viewport_and_fast_ttfb():
    html_with_viewport = """<!DOCTYPE html><html><head><meta name="viewport" content="width=device-width, initial-scale=1.0"><title>Good</title></head><body><h1>Content</h1></body></html>"""
    auditor = PerformanceAuditor(
        target_url="http://127.0.0.1:9000",
        html_content=html_with_viewport,
        ttfb_ms=100.0,
    )
    result = await auditor.run()
    assert result.category == Category.PERFORMANCE
    assert result.score >= 80
    assert any("Mobile responsive viewport" in c for c in result.passed_checks)


def test_performance_auditor_parse_pagespeed():
    auditor = PerformanceAuditor(target_url="https://example.com")
    mock_psi_data = {
        "lighthouseResult": {
            "categories": {"performance": {"score": 0.45}},
            "audits": {
                "largest-contentful-paint": {"numericValue": 3800},
                "cumulative-layout-shift": {"numericValue": 0.25},
                "first-contentful-paint": {"numericValue": 2100},
                "total-blocking-time": {"numericValue": 350},
            },
        }
    }
    auditor._parse_pagespeed_metrics(mock_psi_data)
    issue_ids = [i.issue_id for i in auditor.issues]

    assert "PERF_POOR_SCORE" in issue_ids
    assert "PERF_SLOW_LCP" in issue_ids
    assert "PERF_HIGH_CLS" in issue_ids
    assert "PERF_SLOW_FCP" in issue_ids
