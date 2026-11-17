"""Unit tests for DOMParser."""
import pytest
from crawler.parser import DOMParser


SAMPLE_HTML = """
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <title>Optimal Example Title for Testing SEO Capabilities</title>
    <meta name="description" content="This is an optimal meta description that fits nicely between 120 and 160 characters for search engine result pages.">
    <link rel="canonical" href="https://example.com/canonical-page" />
    <meta property="og:title" content="Open Graph Title">
    <meta property="og:description" content="Open Graph Description">
    <meta property="og:image" content="https://example.com/image.jpg">
    <meta property="og:url" content="https://example.com/">
    <script type="application/ld+json">
    {
        "@context": "https://schema.org",
        "@type": "WebSite",
        "name": "Example Test Site"
    }
    </script>
</head>
<body>
    <h1>Primary Main Header</h1>
    <h3>Skipped Sub-header Directly To Level 3</h3>
    <p>This is a paragraph with enough content for testing words and elements.</p>
    <img src="/images/logo.png" alt="Company Logo" />
    <img src="/images/banner.jpg" /> <!-- Missing alt -->
    <a href="/about">About Us</a>
    <a href="https://external.com" rel="nofollow">External Link</a>
</body>
</html>
"""


def test_dom_parser_title_and_description():
    parser = DOMParser(SAMPLE_HTML, "https://example.com")
    assert parser.get_title() == "Optimal Example Title for Testing SEO Capabilities"
    assert "optimal meta description" in parser.get_meta_description()
    assert parser.get_canonical() == "https://example.com/canonical-page"
    assert parser.get_lang() == "en"


def test_dom_parser_pixel_width():
    width = DOMParser.estimate_pixel_width("Optimal Example Title")
    assert width > 100
    assert width < 500


def test_dom_parser_headings_and_skipped():
    parser = DOMParser(SAMPLE_HTML, "https://example.com")
    headings = parser.get_headings()
    assert len(headings["h1"]) == 1
    assert headings["h1"][0] == "Primary Main Header"
    assert len(headings["h3"]) == 1

    skipped = parser.check_skipped_heading_hierarchy()
    assert len(skipped) == 1
    assert "Skipped from <h1" in skipped[0]


def test_dom_parser_images():
    parser = DOMParser(SAMPLE_HTML, "https://example.com")
    images = parser.get_images()
    assert len(images) == 2

    # First image has alt
    assert not images[0].is_missing_alt
    assert images[0].alt == "Company Logo"

    # Second image is missing alt
    assert images[1].is_missing_alt


def test_dom_parser_links():
    parser = DOMParser(SAMPLE_HTML, "https://example.com")
    links = parser.get_links()
    assert len(links) == 2

    internal_link = next(l for l in links if not l.is_external)
    assert internal_link.resolved_url == "https://example.com/about"

    external_link = next(l for l in links if l.is_external)
    assert external_link.is_nofollow is True


def test_dom_parser_structured_data():
    parser = DOMParser(SAMPLE_HTML, "https://example.com")
    schemas = parser.get_structured_data()
    assert len(schemas) == 1
    assert schemas[0].get("@type") == "WebSite"
