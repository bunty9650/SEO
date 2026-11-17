"""Technical & On-Page SEO Auditor Engine."""
from __future__ import annotations

from collections import defaultdict
from typing import Dict, List, Optional
from auditors.base import AuditIssue, AuditResult, Category, Severity
from crawler.spider import CrawlResult, PageData, WebSpider
from solutions.solution_database import SolutionDatabase


class SEOAuditor:
    """Evaluates crawled pages for technical SEO, indexing, content, and metadata hygiene."""

    def __init__(self, crawl_result: CrawlResult):
        self.crawl_result = crawl_result
        self.pages: List[PageData] = crawl_result.pages
        self.issues: List[AuditIssue] = []
        self.passed_checks: List[str] = []
        self.metrics: Dict[str, any] = {}

    @classmethod
    async def audit_url(
        cls,
        target_url: str,
        max_urls: int = 15,
        max_depth: int = 2,
    ) -> AuditResult:
        """Convenience runner that crawls and audits a target URL."""
        spider = WebSpider(seed_url=target_url, max_urls=max_urls, max_depth=max_depth)
        crawl_result = await spider.crawl()
        auditor = cls(crawl_result)
        return auditor.run()

    def run(self) -> AuditResult:
        """Executes full suite of technical SEO and on-page checks."""
        self.issues.clear()
        self.passed_checks.clear()

        # Track duplicates across site
        title_occurrences = defaultdict(list)
        desc_occurrences = defaultdict(list)

        total_images = 0
        total_images_missing_alt = 0
        total_broken_links = 0
        total_redirect_chains = 0
        pages_with_schema = 0
        pages_with_og = 0

        # Per-page audits
        for page in self.pages:
            self._audit_status_and_redirects(page)
            if page.status_code >= 400:
                total_broken_links += 1
                continue  # Skip HTML-specific checks on failed fetches

            # Track duplicates
            if page.title:
                title_occurrences[page.title.strip().lower()].append(page.url)
            if page.meta_description:
                desc_occurrences[page.meta_description.strip().lower()].append(page.url)

            # Metadata checks
            self._audit_title(page)
            self._audit_meta_description(page)
            self._audit_headings(page)
            self._audit_indexability(page)
            self._audit_content_and_lang(page)
            self._audit_social_and_schema(page)
            self._audit_images(page)

            # Counters
            total_images += page.images_total
            total_images_missing_alt += len(page.images_missing_alt)
            if page.structured_data:
                pages_with_schema += 1
            if page.open_graph:
                pages_with_og += 1
            if len(page.redirect_chain) > 1:
                total_redirect_chains += 1

        # Site-wide duplicate audits
        self._audit_duplicates(title_occurrences, desc_occurrences)

        # Calculate metrics
        self.metrics = {
            "total_crawled_urls": len(self.pages),
            "robots_txt_found": self.crawl_result.robots_txt_found,
            "total_broken_links": total_broken_links,
            "total_redirect_chains": total_redirect_chains,
            "total_images": total_images,
            "total_images_missing_alt": total_images_missing_alt,
            "pages_with_schema": pages_with_schema,
            "pages_with_og": pages_with_og,
        }

        # Check positive passed checks
        if not any(i.issue_id == "SEO_MISSING_TITLE" for i in self.issues):
            self.passed_checks.append("All crawled pages contain a <title> tag.")
        if not any(i.issue_id == "SEO_MISSING_H1" for i in self.issues):
            self.passed_checks.append("All indexable pages possess an <h1> main heading.")
        if not any(i.issue_id == "SEO_MISSING_CANONICAL" for i in self.issues):
            self.passed_checks.append("Canonical URL tags are present across crawled pages.")
        if total_images > 0 and total_images_missing_alt == 0:
            self.passed_checks.append("All detected images include descriptive alt attributes.")
        if total_broken_links == 0:
            self.passed_checks.append("Zero broken internal links (4xx/5xx) found.")
        if self.crawl_result.robots_txt_found:
            self.passed_checks.append("robots.txt is present and configured on the server.")

        result = AuditResult(
            category=Category.SEO,
            issues=self.issues,
            passed_checks=self.passed_checks,
            metrics=self.metrics,
        )
        result.calculate_score()
        return result

    def _audit_status_and_redirects(self, page: PageData):
        if page.status_code >= 400:
            self.issues.append(
                SolutionDatabase.build_issue(
                    issue_id="SEO_BROKEN_LINK",
                    evidence=f"URL: {page.url} returned HTTP {page.status_code} ({page.error_message or 'Error'})",
                    url=page.url,
                )
            )

        if len(page.redirect_chain) > 1:
            hops_str = " -> ".join([f"{h['status_code']} ({h['url']})" for h in page.redirect_chain])
            self.issues.append(
                SolutionDatabase.build_issue(
                    issue_id="SEO_REDIRECT_CHAIN",
                    evidence=f"Redirect chain of {len(page.redirect_chain)} hops detected: {hops_str} -> {page.final_url}",
                    url=page.url,
                )
            )

    def _audit_title(self, page: PageData):
        if not page.title:
            self.issues.append(
                SolutionDatabase.build_issue(
                    issue_id="SEO_MISSING_TITLE",
                    evidence=f"URL: {page.url} has no <title> tag.",
                    url=page.url,
                )
            )
            return

        title_len = len(page.title)
        if title_len < 30:
            self.issues.append(
                SolutionDatabase.build_issue(
                    issue_id="SEO_TITLE_TOO_SHORT",
                    evidence=f"Title is {title_len} chars (optimal: 50-60). Content: '{page.title}'",
                    url=page.url,
                )
            )
        elif title_len > 60:
            self.issues.append(
                SolutionDatabase.build_issue(
                    issue_id="SEO_TITLE_TOO_LONG",
                    evidence=f"Title is {title_len} chars (exceeds 60 char limit). Content: '{page.title}'",
                    url=page.url,
                )
            )

    def _audit_meta_description(self, page: PageData):
        if not page.meta_description:
            self.issues.append(
                SolutionDatabase.build_issue(
                    issue_id="SEO_MISSING_META_DESC",
                    evidence=f"URL: {page.url} has no <meta name='description'> tag.",
                    url=page.url,
                )
            )
            return

        desc_len = len(page.meta_description)
        if desc_len < 70:
            self.issues.append(
                SolutionDatabase.build_issue(
                    issue_id="SEO_META_DESC_TOO_SHORT",
                    evidence=f"Meta description is {desc_len} chars (optimal: 120-160). Content: '{page.meta_description}'",
                    url=page.url,
                )
            )
        elif desc_len > 160:
            self.issues.append(
                SolutionDatabase.build_issue(
                    issue_id="SEO_META_DESC_TOO_LONG",
                    evidence=f"Meta description is {desc_len} chars (exceeds 160 chars). Content: '{page.meta_description}'",
                    url=page.url,
                )
            )

    def _audit_headings(self, page: PageData):
        h1_count = len(page.h1_headings)
        if h1_count == 0:
            self.issues.append(
                SolutionDatabase.build_issue(
                    issue_id="SEO_MISSING_H1",
                    evidence=f"URL: {page.url} has no <h1> heading tag.",
                    url=page.url,
                )
            )
        elif h1_count > 1:
            h1_preview = " | ".join(page.h1_headings[:3])
            self.issues.append(
                SolutionDatabase.build_issue(
                    issue_id="SEO_MULTIPLE_H1",
                    evidence=f"Found {h1_count} <h1> tags on {page.url}: '{h1_preview}'",
                    url=page.url,
                )
            )

        if page.skipped_headings:
            skipped_str = "; ".join(page.skipped_headings[:2])
            self.issues.append(
                SolutionDatabase.build_issue(
                    issue_id="SEO_HEADING_HIERARCHY_SKIPPED",
                    evidence=f"Skipped heading hierarchy on {page.url}: {skipped_str}",
                    url=page.url,
                )
            )

    def _audit_indexability(self, page: PageData):
        if not page.is_indexable or "noindex" in page.meta_robots:
            self.issues.append(
                SolutionDatabase.build_issue(
                    issue_id="SEO_NOINDEX_FLAGGED",
                    evidence=f"URL: {page.url} specifies 'noindex' (Meta robots: {page.meta_robots})",
                    url=page.url,
                )
            )

        if not page.canonical:
            self.issues.append(
                SolutionDatabase.build_issue(
                    issue_id="SEO_MISSING_CANONICAL",
                    evidence=f"URL: {page.url} lacks a <link rel='canonical'> tag.",
                    url=page.url,
                )
            )

    def _audit_content_and_lang(self, page: PageData):
        if not page.lang:
            self.issues.append(
                SolutionDatabase.build_issue(
                    issue_id="SEO_MISSING_LANG",
                    evidence=f"URL: {page.url} has no lang attribute on the <html> tag.",
                    url=page.url,
                )
            )

        # Only flag thin content on 200 OK HTML pages
        if page.status_code == 200 and page.word_count < 300:
            self.issues.append(
                SolutionDatabase.build_issue(
                    issue_id="SEO_THIN_CONTENT",
                    evidence=f"URL: {page.url} contains only {page.word_count} words (recommendation: >= 300).",
                    url=page.url,
                )
            )

    def _audit_social_and_schema(self, page: PageData):
        req_og = {"og:title", "og:description", "og:image", "og:url"}
        missing_og = req_og - set(page.open_graph.keys())
        if missing_og:
            self.issues.append(
                SolutionDatabase.build_issue(
                    issue_id="SEO_MISSING_OG_TAGS",
                    evidence=f"URL: {page.url} is missing Open Graph tags: {', '.join(sorted(missing_og))}",
                    url=page.url,
                )
            )

        if not page.twitter_card:
            self.issues.append(
                SolutionDatabase.build_issue(
                    issue_id="SEO_MISSING_TWITTER_CARD",
                    evidence=f"URL: {page.url} has no twitter:card meta tags.",
                    url=page.url,
                )
            )

        if not page.structured_data:
            self.issues.append(
                SolutionDatabase.build_issue(
                    issue_id="SEO_MISSING_SCHEMA",
                    evidence=f"URL: {page.url} contains no JSON-LD structured data.",
                    url=page.url,
                )
            )

    def _audit_images(self, page: PageData):
        if page.images_missing_alt:
            missing_count = len(page.images_missing_alt)
            preview = ", ".join(page.images_missing_alt[:2])
            self.issues.append(
                SolutionDatabase.build_issue(
                    issue_id="SEO_IMG_MISSING_ALT",
                    evidence=f"{missing_count} image(s) on {page.url} missing alt text (e.g. {preview})",
                    url=page.url,
                )
            )

    def _audit_duplicates(
        self,
        title_occurrences: Dict[str, List[str]],
        desc_occurrences: Dict[str, List[str]],
    ):
        for title, urls in title_occurrences.items():
            if len(urls) > 1:
                self.issues.append(
                    SolutionDatabase.build_issue(
                        issue_id="SEO_DUPLICATE_TITLE",
                        evidence=f"Identical title '{title}' shared across {len(urls)} URLs: {', '.join(urls[:3])}",
                        url=urls[0],
                    )
                )

        for desc, urls in desc_occurrences.items():
            if len(urls) > 1:
                self.issues.append(
                    SolutionDatabase.build_issue(
                        issue_id="SEO_DUPLICATE_META_DESC",
                        evidence=f"Identical meta description shared across {len(urls)} URLs: {', '.join(urls[:3])}",
                        url=urls[0],
                    )
                )
