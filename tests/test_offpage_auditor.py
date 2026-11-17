"""Unit tests for OffPageAuditor."""
import pytest
from auditors.offpage_auditor import OffPageAuditor
from auditors.base import Category
from crawler.spider import CrawlResult, PageData


@pytest.mark.asyncio
async def test_offpage_auditor_detects_social_profiles():
    html = """
    <html>
    <body>
        <footer>
            <a href="https://www.linkedin.com/company/mybrand">LinkedIn</a>
            <a href="https://twitter.com/mybrand">Twitter / X</a>
            <a href="https://github.com/mybrand">GitHub</a>
        </footer>
    </body>
    </html>
    """
    page = PageData(
        url="https://example.com",
        final_url="https://example.com",
        status_code=200,
        response_time_ms=100.0,
        raw_html=html,
        internal_links_count=5,
        external_links_count=3,
        nofollow_links_count=1,
    )
    crawl_result = CrawlResult(
        seed_url="https://example.com",
        base_domain="example.com",
        pages=[page],
        total_crawled=1,
    )

    auditor = OffPageAuditor(crawl_result)
    result = await auditor.run()

    assert result.category == Category.OFFPAGE
    assert "LinkedIn" in result.metrics["social_profiles"]
    assert "X / Twitter" in result.metrics["social_profiles"]
    assert "GitHub" in result.metrics["social_profiles"]
    assert result.metrics["link_profile"]["total_internal_links"] == 5
    assert result.metrics["link_profile"]["total_external_links"] == 3


@pytest.mark.asyncio
async def test_offpage_auditor_flags_missing_social():
    page = PageData(
        url="https://example.com",
        final_url="https://example.com",
        status_code=200,
        response_time_ms=100.0,
        raw_html="<html><body><p>No social links here</p></body></html>",
    )
    crawl_result = CrawlResult(
        seed_url="https://example.com",
        base_domain="example.com",
        pages=[page],
        total_crawled=1,
    )

    auditor = OffPageAuditor(crawl_result)
    result = await auditor.run()

    issue_ids = [i.issue_id for i in result.issues]
    assert "OFFPAGE_MISSING_SOCIAL_SIGNALS" in issue_ids
