"""Crawler package for recursive web crawling and DOM parsing."""
from .spider import WebSpider, CrawlResult, PageData
from .parser import DOMParser

__all__ = ["WebSpider", "CrawlResult", "PageData", "DOMParser"]
