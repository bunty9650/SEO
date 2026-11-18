"""Unit tests for SEOAuditor."""
import pytest
from auditors.seo_auditor import SEOAuditor
from crawler.spider import CrawlResult, PageData


def test_seo_auditor_flags_missing_title_and_h1():
    page = PageData(
        url="https://example.com/bad-page",
        final_url="https://example.com/bad-page",
        status_code=200,
        response_time_ms=120.0,
        title=None,  # Missing
        meta_description=None,  # Missing
        h1_headings=[],  # Missing H1
        word_count=50,  # Thin content
    )
    crawl_result = CrawlResult(
        seed_url="https://example.com",
        base_domain="example.com",
        pages=[page],
        total_crawled=1,
    )

    auditor = SEOAuditor(crawl_result)
    result = auditor.run()

    issue_ids = [i.issue_id for i in result.issues]
    assert "SEO_MISSING_TITLE" in issue_ids
    assert "SEO_MISSING_META_DESC" in issue_ids
    assert "SEO_MISSING_H1" in issue_ids
    assert "SEO_THIN_CONTENT" in issue_ids
    assert result.score < 60


def test_seo_auditor_flags_duplicates():
    page1 = PageData(
        url="https://example.com/p1",
        final_url="https://example.com/p1",
        status_code=200,
        response_time_ms=100.0,
        title="Exact Same Title For Both Pages Here - Test",
        meta_description="Exact same description across pages for testing duplicate detection logic.",
        h1_headings=["Heading 1"],
        canonical="https://example.com/p1",
        word_count=500,
    )
    page2 = PageData(
        url="https://example.com/p2",
        final_url="https://example.com/p2",
        status_code=200,
        response_time_ms=105.0,
        title="Exact Same Title For Both Pages Here - Test",
        meta_description="Exact same description across pages for testing duplicate detection logic.",
        h1_headings=["Heading 2"],
        canonical="https://example.com/p2",
        word_count=550,
    )
    crawl_result = CrawlResult(
        seed_url="https://example.com",
        base_domain="example.com",
        pages=[page1, page2],
        total_crawled=2,
    )

    auditor = SEOAuditor(crawl_result)
    result = auditor.run()

    issue_ids = [i.issue_id for i in result.issues]
    assert "SEO_DUPLICATE_TITLE" in issue_ids
    assert "SEO_DUPLICATE_META_DESC" in issue_ids


def test_seo_auditor_flags_broken_link():
    page = PageData(
        url="https://example.com/missing-404",
        final_url="https://example.com/missing-404",
        status_code=404,
        response_time_ms=50.0,
        error_message="Not Found",
    )
    crawl_result = CrawlResult(
        seed_url="https://example.com",
        base_domain="example.com",
        pages=[page],
        total_crawled=1,
    )

    auditor = SEOAuditor(crawl_result)
    result = auditor.run()

    issue_ids = [i.issue_id for i in result.issues]
    assert "SEO_BROKEN_LINK" in issue_ids


def test_seo_auditor_multipage_score_normalization():
    """Verify that multi-page crawls normalize penalties so healthy sites do not drop to 0."""
    pages = [
        PageData(
            url=f"https://example.com/page-{i}",
            final_url=f"https://example.com/page-{i}",
            status_code=200,
            response_time_ms=80.0,
            title=f"Healthy Descriptive Page Title {i} - Brand Name",
            meta_description="A good descriptive meta description exceeding optimal length guidelines for search.",
            h1_headings=[f"Main Heading {i}"],
            canonical=f"https://example.com/page-{i}",
            word_count=450,
            # Only 1 minor issue: missing twitter card
        )
        for i in range(10)
    ]
    crawl_result = CrawlResult(
        seed_url="https://example.com",
        base_domain="example.com",
        pages=pages,
        total_crawled=10,
    )

    auditor = SEOAuditor(crawl_result)
    result = auditor.run()

    # Even though 10 pages have missing schema/og/twitter tags, normalized score should be >= 80, NOT 0
    assert result.score >= 80

