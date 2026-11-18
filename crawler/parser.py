"""High-performance HTML / DOM parsing and content feature extraction."""
from __future__ import annotations

import json
import re
from typing import Any, Dict, List, Optional, Set, Tuple
from urllib.parse import urljoin, urlparse
from bs4 import BeautifulSoup, Comment
from pydantic import BaseModel, Field


class ImageData(BaseModel):
    src: str
    alt: Optional[str] = None
    is_missing_alt: bool = False
    is_empty_alt: bool = False
    format: str = ""
    is_modern_format: bool = False
    is_insecure: bool = False


class LinkData(BaseModel):
    href: str
    resolved_url: str
    anchor_text: str
    is_external: bool
    rel: List[str] = Field(default_factory=list)
    is_nofollow: bool = False


class DOMParser:
    """Extracts SEO, social, schema, and asset metadata from HTML documents."""

    # Character pixel width approximations based on standard Arial 18px (typical SERP title font)
    # Average width for upper/lower/punctuation
    _CHAR_WIDTH_MAP = {
        "W": 18, "M": 17, "m": 15, "w": 14, "O": 14, "Q": 14, "D": 13, "G": 13,
        "i": 4, "l": 4, "I": 5, "j": 5, "t": 6, "f": 6, "r": 6, " ": 5,
        "a": 10, "b": 10, "c": 9, "d": 10, "e": 10, "g": 10, "h": 10, "n": 10,
        "o": 10, "p": 10, "q": 10, "s": 8, "u": 10, "v": 9, "x": 9, "y": 9, "z": 9
    }

    def __init__(self, html: str, base_url: str):
        self.html = html or ""
        self.base_url = base_url
        self.parsed_base = urlparse(base_url)
        self.base_domain = self.parsed_base.netloc.lower()
        self.is_https = self.parsed_base.scheme.lower() == "https"

        # Try lxml parser first; fall back to html.parser if unavailable
        try:
            self.soup = BeautifulSoup(self.html, "lxml")
        except Exception:
            self.soup = BeautifulSoup(self.html, "html.parser")

    @classmethod
    def estimate_pixel_width(cls, text: str) -> int:
        """Estimates Google SERP display width in pixels for title text."""
        if not text:
            return 0
        total_width = 0
        for ch in text:
            total_width += cls._CHAR_WIDTH_MAP.get(ch, 10)
        return total_width

    def get_title(self) -> Optional[str]:
        title_tag = self.soup.find("title")
        if title_tag and title_tag.string:
            return title_tag.string.strip()
        return None

    def get_meta_description(self) -> Optional[str]:
        desc_tag = self.soup.find("meta", attrs={"name": re.compile(r"^description$", re.I)})
        if desc_tag and desc_tag.get("content"):
            return desc_tag["content"].strip()
        return None

    def get_meta_robots(self) -> List[str]:
        robots_tag = self.soup.find("meta", attrs={"name": re.compile(r"^robots$", re.I)})
        if robots_tag and robots_tag.get("content"):
            directives = [d.strip().lower() for d in robots_tag["content"].split(",")]
            return directives
        return []

    def get_canonical(self) -> Optional[str]:
        canonical_tag = self.soup.find("link", attrs={"rel": lambda x: x and "canonical" in [v.lower() for v in (x if isinstance(x, list) else [x])]})
        if canonical_tag and canonical_tag.get("href"):
            raw_href = canonical_tag["href"].strip()
            return urljoin(self.base_url, raw_href)
        return None

    def get_lang(self) -> Optional[str]:
        html_tag = self.soup.find("html")
        if html_tag and html_tag.get("lang"):
            return html_tag["lang"].strip()
        return None

    def get_headings(self) -> Dict[str, Any]:
        """Returns heading texts, counts, and sequence hierarchy."""
        h_data: Dict[str, Any] = {
            "h1": [],
            "h2": [],
            "h3": [],
            "h4_count": 0,
            "h5_count": 0,
            "h6_count": 0,
            "sequence": [],  # List of tuples: [("h1", "text"), ("h2", "text"), ...]
        }

        # Extract in document order
        for heading in self.soup.find_all(re.compile(r"^h[1-6]$", re.I)):
            tag_name = heading.name.lower()
            text = heading.get_text(strip=True)
            if not text:
                continue

            h_data["sequence"].append((tag_name, text))
            if tag_name == "h1":
                h_data["h1"].append(text)
            elif tag_name == "h2":
                h_data["h2"].append(text)
            elif tag_name == "h3":
                h_data["h3"].append(text)
            elif tag_name == "h4":
                h_data["h4_count"] += 1
            elif tag_name == "h5":
                h_data["h5_count"] += 1
            elif tag_name == "h6":
                h_data["h6_count"] += 1

        return h_data

    def check_skipped_heading_hierarchy(self) -> List[str]:
        """Detects if heading levels skip (e.g. H1 directly followed by H3)."""
        headings = self.get_headings()["sequence"]
        skipped: List[str] = []
        if not headings:
            return skipped

        prev_level = None
        for tag_name, text in headings:
            try:
                curr_level = int(tag_name[1])
            except ValueError:
                continue

            if prev_level is not None:
                # If current level jumped more than 1 deeper (e.g. 1 -> 3, 2 -> 4)
                if curr_level > prev_level + 1:
                    skipped.append(
                        f"Skipped from <h{prev_level}> to <h{curr_level}> at heading: '{text[:50]}...'"
                    )
            prev_level = curr_level

        return skipped

    def get_word_count(self) -> int:
        """Calculates visible text word count, excluding scripts, styles, comments."""
        # Work on a clone or copy so we don't destroy soup
        body = self.soup.find("body")
        if not body:
            return 0

        # Remove invisible/script elements
        for element in body(["script", "style", "noscript", "svg", "header", "footer", "nav"]):
            element.extract()
        for comment in body.find_all(string=lambda t: isinstance(t, Comment)):
            comment.extract()

        text = body.get_text(separator=" ", strip=True)
        words = re.findall(r"\b\w+\b", text)
        return len(words)

    def get_open_graph(self) -> Dict[str, str]:
        og: Dict[str, str] = {}
        for tag in self.soup.find_all("meta", attrs={"property": re.compile(r"^og:", re.I)}):
            prop = tag.get("property", "").lower()
            content = tag.get("content", "").strip()
            if prop and content:
                og[prop] = content
        return og

    def get_twitter_card(self) -> Dict[str, str]:
        tw: Dict[str, str] = {}
        for tag in self.soup.find_all("meta", attrs={"name": re.compile(r"^twitter:", re.I)}):
            name = tag.get("name", "").lower()
            content = tag.get("content", "").strip()
            if name and content:
                tw[name] = content
        return tw

    def get_structured_data(self) -> List[Dict[str, Any]]:
        """Parses all JSON-LD schema blocks."""
        schemas: List[Dict[str, Any]] = []
        for script in self.soup.find_all("script", attrs={"type": "application/ld+json"}):
            raw_text = script.string
            if not raw_text:
                continue
            try:
                data = json.loads(raw_text.strip())
                if isinstance(data, list):
                    schemas.extend(data)
                elif isinstance(data, dict):
                    schemas.append(data)
            except Exception:
                # Malformed JSON-LD
                schemas.append({"_error": "Malformed JSON-LD syntax", "_raw": raw_text[:100]})
        return schemas

    def get_images(self) -> List[ImageData]:
        """Audits all images in the document for alt text, format, and HTTP insecurity."""
        results: List[ImageData] = []
        img_tags = self.soup.find_all("img")
        for img in img_tags:
            src = img.get("src") or img.get("data-src") or ""
            src = src.strip()
            if not src:
                continue

            resolved_src = urljoin(self.base_url, src)
            alt = img.get("alt")

            is_missing = alt is None
            is_empty = alt is not None and len(alt.strip()) == 0

            # Determine format
            path = urlparse(resolved_src).path.lower()
            ext = path.split(".")[-1] if "." in path else ""
            modern_formats = {"webp", "avif", "svg"}
            is_modern = ext in modern_formats

            # Check insecure asset on HTTPS
            is_insecure = self.is_https and resolved_src.startswith("http://")

            results.append(
                ImageData(
                    src=resolved_src,
                    alt=alt.strip() if alt else None,
                    is_missing_alt=is_missing,
                    is_empty_alt=is_empty,
                    format=ext,
                    is_modern_format=is_modern,
                    is_insecure=is_insecure,
                )
            )
        return results

    def get_insecure_resources(self) -> List[Tuple[str, str]]:
        """Finds any active or passive HTTP resource loaded on an HTTPS page."""
        insecure: List[Tuple[str, str]] = []
        if not self.is_https:
            return insecure

        # Scripts
        for s in self.soup.find_all("script", src=True):
            src = urljoin(self.base_url, s["src"])
            if src.startswith("http://"):
                insecure.append(("script", src))

        # Stylesheets
        for link in self.soup.find_all("link", href=True):
            rel = link.get("rel", [])
            rel_list = [r.lower() for r in (rel if isinstance(rel, list) else [rel])]
            if "stylesheet" in rel_list:
                href = urljoin(self.base_url, link["href"])
                if href.startswith("http://"):
                    insecure.append(("stylesheet", href))

        # Images
        for img in self.soup.find_all("img", src=True):
            src = urljoin(self.base_url, img["src"])
            if src.startswith("http://"):
                insecure.append(("img", src))

        # Iframes
        for iframe in self.soup.find_all("iframe", src=True):
            src = urljoin(self.base_url, iframe["src"])
            if src.startswith("http://"):
                insecure.append(("iframe", src))

        return insecure

    def _is_internal_netloc(self, target_netloc: str) -> bool:
        """Robust internal domain matcher supporting www/non-www and subdomains."""
        if not target_netloc:
            return True
        t = target_netloc.lower().split(":")[0]
        b = self.base_domain.split(":")[0]
        if t == b:
            return True
        t_root = t[4:] if t.startswith("www.") else t
        b_root = b[4:] if b.startswith("www.") else b
        if t_root == b_root:
            return True
        return t.endswith("." + b_root) or b.endswith("." + t_root)

    def get_links(self) -> List[LinkData]:
        """Extracts and resolves all <a> hyperlinks."""
        links: List[LinkData] = []
        seen_urls: Set[str] = set()

        for a in self.soup.find_all("a", href=True):
            raw_href = a["href"].strip()
            if not raw_href or raw_href.startswith(("javascript:", "mailto:", "tel:", "#")):
                continue

            resolved = urljoin(self.base_url, raw_href)
            # Remove fragment
            parsed_res = urlparse(resolved)
            clean_url = parsed_res._replace(fragment="").geturl()

            if clean_url in seen_urls:
                continue
            seen_urls.add(clean_url)

            is_external = not self._is_internal_netloc(parsed_res.netloc)
            rel = a.get("rel", [])
            rel_list = [r.lower() for r in (rel if isinstance(rel, list) else [rel])]
            is_nofollow = "nofollow" in rel_list

            anchor_text = a.get_text(strip=True)

            links.append(
                LinkData(
                    href=raw_href,
                    resolved_url=clean_url,
                    anchor_text=anchor_text,
                    is_external=is_external,
                    rel=rel_list,
                    is_nofollow=is_nofollow,
                )
            )

        return links
