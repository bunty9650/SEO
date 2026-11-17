"""Auditors package for SEO, Security, Performance, and Off-page analysis."""
from .base import BaseAuditor, AuditIssue, Severity, Category, AuditResult
from .seo_auditor import SEOAuditor
from .security_auditor import SecurityAuditor
from .performance_auditor import PerformanceAuditor, capture_screenshots
from .offpage_auditor import OffPageAuditor

__all__ = [
    "BaseAuditor",
    "AuditIssue",
    "Severity",
    "Category",
    "AuditResult",
    "SEOAuditor",
    "SecurityAuditor",
    "PerformanceAuditor",
    "OffPageAuditor",
    "capture_screenshots",
]
