"""Unit tests for SolutionDatabase."""
from auditors.base import Category, Severity
from solutions.solution_database import SolutionDatabase


def test_solution_database_retrieval():
    sol = SolutionDatabase.get("SEC_MISSING_HSTS")
    assert sol is not None
    assert sol.category == Category.SECURITY
    assert sol.default_severity == Severity.HIGH
    assert sol.remediation.apache is not None
    assert "Strict-Transport-Security" in sol.remediation.apache
    assert sol.remediation.nginx is not None
    assert "Strict-Transport-Security" in sol.remediation.nginx


def test_solution_database_build_issue():
    issue = SolutionDatabase.build_issue(
        issue_id="SEO_MISSING_TITLE",
        evidence="Title missing on homepage",
        url="https://example.com/",
    )
    assert issue.issue_id == "SEO_MISSING_TITLE"
    assert issue.severity == Severity.CRITICAL
    assert issue.solution_code is not None
    assert "<title>" in issue.solution_code
    assert issue.url == "https://example.com/"
