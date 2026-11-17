"""Asynchronous recursive BFS crawler with robots.txt compliance and redirect tracking."""
from __future__ import annotations

import asyncio
import time
from typing import Any, Callable, Dict, List, Optional, Set
from urllib.parse import urljoin, urlparse
from urllib.robotparser import RobotFileParser
import httpx
from pydantic import BaseModel, Field

from .parser import DOMParser


class PageData(BaseModel):
    """Captured telemetry and parsed DOM for a single crawled URL."""
    url: str
    final_url: str
    status_code: int
    response_time_ms: float
    content_type: str = ""
    headers: Dict[str, str] = Field(default_factory=dict)
    redirect_chain: List[Dict[str, Any]] = Field(default_factory=list)
    depth: int = 0
    raw_html: Optional[str] = None
    title: Optional[str] = None
    meta_description: Optional[str] = None
    meta_robots: List[str] = Field(default_factory=list)
    canonical: Optional[str] = None
    lang: Optional[str] = None
    h1_headings: List[str] = Field(default_factory=list)
    h2_headings: List[str] = Field(default_factory=list)
    h3_headings: List[str] = Field(default_factory=list)
    word_count: int = 0
    skipped_headings: List[str] = Field(default_factory=list)
    open_graph: Dict[str, str] = Field(default_factory=dict)
    twitter_card: Dict[str, str] = Field(default_factory=dict)
    structured_data: List[Dict[str, Any]] = Field(default_factory=list)
    images_total: int = 0
    images: List[Dict[str, Any]] = Field(default_factory=list)
    images_missing_alt: List[str] = Field(default_factory=list)
    images_insecure: List[str] = Field(default_factory=list)
    insecure_resources: List[Dict[str, str]] = Field(default_factory=list)
    internal_links_count: int = 0
    external_links_count: int = 0
    external_links: List[str] = Field(default_factory=list)
    nofollow_links_count: int = 0
    discovered_links: List[str] = Field(default_factory=list)
    is_indexable: bool = True
    error_message: Optional[str] = None


class CrawlResult(BaseModel):
    """Aggregated result of the entire crawl session."""
    seed_url: str
    base_domain: str
    total_crawled: int = 0
    pages: List[PageData] = Field(default_factory=list)
    duration_seconds: float = 0.0
    robots_txt_found: bool = False
    robots_rules_summary: Optional[str] = None


class WebSpider:
    """Async BFS crawler respecting domain boundaries, depth limits, and robots.txt."""

    DEFAULT_USER_AGENT = (
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
        "(KHTML, like Gecko) Chrome/126.0.0.0 Safari/537.36 (SEO-Audit-Agent/1.0)"
    )

    def __init__(
        self,
        seed_url: str,
        max_urls: int = 30,
        max_depth: int = 3,
        concurrency: int = 5,
        timeout: float = 12.0,
        user_agent: Optional[str] = None,
        respect_robots: bool = True,
        on_page_crawled: Optional[Callable[[PageData, int, int], None]] = None,
    ):
        self.seed_url = self._normalize_url(seed_url)
        self.max_urls = max_urls
        self.max_depth = max_depth
        self.concurrency = concurrency
        self.timeout = timeout
        self.user_agent = user_agent or self.DEFAULT_USER_AGENT
        self.respect_robots = respect_robots
        self.on_page_crawled = on_page_crawled

        parsed = urlparse(self.seed_url)
        self.base_domain = parsed.netloc.lower()
        self.scheme = parsed.scheme.lower() or "https"

        self.visited_urls: Set[str] = set()
        self.crawled_pages: List[PageData] = []
        self.robot_parser: Optional[RobotFileParser] = None
        self.robots_found = False

    @staticmethod
    def _normalize_url(url: str) -> str:
        """Strips fragments, trailing spaces, and standardizes slash."""
        if not url:
            return ""
        parsed = urlparse(url.strip())
        if not parsed.scheme:
            url = "https://" + url.strip()
            parsed = urlparse(url)

        # Normalize netloc and path
        netloc = parsed.netloc.lower()
        path = parsed.path or "/"
        # Avoid duplicate slashes
        while "//" in path:
            path = path.replace("//", "/")

        return parsed._replace(netloc=netloc, path=path, fragment="").geturl()

    def _is_internal_url(self, url: str) -> bool:
        """Determines if a target URL belongs to the seed domain."""
        parsed = urlparse(url)
        target_domain = parsed.netloc.lower()
        # Same domain or subdomain of base_domain
        return target_domain == self.base_domain or target_domain.endswith("." + self.base_domain)

    async def _fetch_robots_txt(self, client: httpx.AsyncClient):
        """Asynchronously loads and parses /robots.txt."""
        robots_url = f"{self.scheme}://{self.base_domain}/robots.txt"
        try:
            resp = await client.get(robots_url, timeout=5.0)
            if resp.status_code == 200:
                self.robots_found = True
                self.robot_parser = RobotFileParser()
                self.robot_parser.set_url(robots_url)
                self.robot_parser.parse(resp.text.splitlines())
        except Exception:
            self.robots_found = False

    def _is_allowed_by_robots(self, url: str) -> bool:
        """Checks if URL is allowed according to robots.txt rules."""
        if not self.respect_robots or not self.robots_found or not self.robot_parser:
            return True
        try:
            return self.robot_parser.can_fetch(self.user_agent, url)
        except Exception:
            return True

    async def _crawl_page(
        self, client: httpx.AsyncClient, semaphore: asyncio.Semaphore, url: str, depth: int
    ) -> PageData:
        """Crawls a single URL, measuring response time and parsing DOM."""
        page = PageData(url=url, final_url=url, status_code=0, response_time_ms=0.0, depth=depth)

        async with semaphore:
            start_t = time.perf_counter()
            try:
                # Follow redirects so we can record the full redirect trail
                resp = await client.get(
                    url,
                    follow_redirects=True,
                    timeout=self.timeout,
                    headers={"Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8"},
                )
                elapsed_ms = (time.perf_counter() - start_t) * 1000.0

                page.status_code = resp.status_code
                page.final_url = str(resp.url)
                page.response_time_ms = round(elapsed_ms, 2)
                page.headers = {k.lower(): v for k, v in resp.headers.items()}
                page.content_type = page.headers.get("content-type", "")

                # Record redirect history
                if resp.history:
                    for hop in resp.history:
                        page.redirect_chain.append({
                            "status_code": hop.status_code,
                            "url": str(hop.url),
                            "location": hop.headers.get("location", ""),
                        })

                # If response is HTML, parse DOM
                if "text/html" in page.content_type or resp.text.startswith("<!DOCTYPE") or "<html" in resp.text[:200].lower():
                    page.raw_html = resp.text
                    dom = DOMParser(resp.text, page.final_url)

                    page.title = dom.get_title()
                    page.meta_description = dom.get_meta_description()
                    page.meta_robots = dom.get_meta_robots()
                    page.canonical = dom.get_canonical()
                    page.lang = dom.get_lang()

                    headings = dom.get_headings()
                    page.h1_headings = headings["h1"]
                    page.h2_headings = headings["h2"]
                    page.h3_headings = headings["h3"]
                    page.skipped_headings = dom.check_skipped_heading_hierarchy()
                    page.word_count = dom.get_word_count()

                    page.open_graph = dom.get_open_graph()
                    page.twitter_card = dom.get_twitter_card()
                    page.structured_data = dom.get_structured_data()

                    images = dom.get_images()
                    page.images_total = len(images)
                    page.images = [
                        {
                            "src": img.src,
                            "alt": img.alt,
                            "has_alt": not (img.is_missing_alt or img.is_empty_alt),
                            "format": img.format,
                        }
                        for img in images
                    ]
                    page.images_missing_alt = [img.src for img in images if img.is_missing_alt or img.is_empty_alt]
                    page.images_insecure = [img.src for img in images if img.is_insecure]

                    insecure_res = dom.get_insecure_resources()
                    page.insecure_resources = [{"type": t, "src": s} for t, s in insecure_res]

                    links = dom.get_links()
                    page.internal_links_count = sum(1 for l in links if not l.is_external)
                    page.external_links_count = sum(1 for l in links if l.is_external)
                    page.external_links = [l.resolved_url for l in links if l.is_external]
                    page.nofollow_links_count = sum(1 for l in links if l.is_nofollow)

                    # Extract internal links for next crawl levels
                    for l in links:
                        if not l.is_external:
                            clean = self._normalize_url(l.resolved_url)
                            # Avoid downloadable static files
                            if not any(clean.endswith(ext) for ext in [
                                ".pdf", ".zip", ".rar", ".png", ".jpg", ".jpeg",
                                ".gif", ".webp", ".svg", ".css", ".js", ".mp4", ".mp3"
                            ]):
                                page.discovered_links.append(clean)

                    # Determine indexability
                    if "noindex" in page.meta_robots:
                        page.is_indexable = False
                    if "x-robots-tag" in page.headers and "noindex" in page.headers["x-robots-tag"].lower():
                        page.is_indexable = False

            except httpx.TimeoutException:
                page.status_code = 408
                page.error_message = "Request timed out"
                page.response_time_ms = round((time.perf_counter() - start_t) * 1000.0, 2)
            except httpx.HTTPError as exc:
                page.status_code = 599
                page.error_message = f"HTTP error: {type(exc).__name__}: {str(exc)}"
                page.response_time_ms = round((time.perf_counter() - start_t) * 1000.0, 2)
            except Exception as exc:
                page.status_code = 500
                page.error_message = f"Crawling error: {str(exc)}"
                page.response_time_ms = round((time.perf_counter() - start_t) * 1000.0, 2)

        return page

    async def crawl(self) -> CrawlResult:
        """Executes BFS crawl over internal links until depth or max_urls is reached."""
        start_time = time.perf_counter()
        semaphore = asyncio.Semaphore(self.concurrency)

        headers = {
            "User-Agent": self.user_agent,
            "Accept-Language": "en-US,en;q=0.9",
        }

        async with httpx.AsyncClient(headers=headers, verify=False, follow_redirects=True) as client:
            await self._fetch_robots_txt(client)

            # Queue contains tuples of (url, depth)
            queue: List[tuple[str, int]] = [(self.seed_url, 0)]
            self.visited_urls.add(self.seed_url)

            while queue and len(self.crawled_pages) < self.max_urls:
                # Process URLs in batches of current queue size up to remaining limit
                batch_size = min(len(queue), self.concurrency, self.max_urls - len(self.crawled_pages))
                current_batch = [queue.pop(0) for _ in range(batch_size)]

                tasks = []
                for url, depth in current_batch:
                    if not self._is_allowed_by_robots(url):
                        continue
                    tasks.append(self._crawl_page(client, semaphore, url, depth))

                if not tasks:
                    continue

                results: List[PageData] = await asyncio.gather(*tasks)

                for page in results:
                    self.crawled_pages.append(page)
                    if self.on_page_crawled:
                        self.on_page_crawled(page, len(self.crawled_pages), self.max_urls)

                    # Add new links if within depth limit
                    if page.depth < self.max_depth:
                        for next_url in page.discovered_links:
                            if (
                                next_url not in self.visited_urls
                                and self._is_internal_url(next_url)
                                and len(self.visited_urls) < (self.max_urls * 3)
                            ):
                                self.visited_urls.add(next_url)
                                queue.append((next_url, page.depth + 1))

        duration = time.perf_counter() - start_time
        return CrawlResult(
            seed_url=self.seed_url,
            base_domain=self.base_domain,
            total_crawled=len(self.crawled_pages),
            pages=self.crawled_pages,
            duration_seconds=round(duration, 2),
            robots_txt_found=self.robots_found,
        )
