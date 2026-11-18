"""Base models and abstract classes for audit engines."""
from __future__ import annotations

from enum import Enum
from typing import Any, Dict, List, Optional
from pydantic import BaseModel, ConfigDict, Field


class Severity(str, Enum):
    CRITICAL = "Critical"
    HIGH = "High"
    MEDIUM = "Medium"
    LOW = "Low"
    INFO = "Info"

    @property
    def weight(self) -> int:
        """Penalty points for scoring calculation."""
        weights = {
            Severity.CRITICAL: 25,
            Severity.HIGH: 15,
            Severity.MEDIUM: 8,
            Severity.LOW: 3,
            Severity.INFO: 0,
        }
        return weights.get(self, 0)

    @property
    def color(self) -> str:
        colors = {
            Severity.CRITICAL: "#DC2626",  # Red
            Severity.HIGH: "#EA580C",      # Orange
            Severity.MEDIUM: "#D97706",    # Amber
            Severity.LOW: "#2563EB",       # Blue
            Severity.INFO: "#4B5563",      # Gray
        }
        return colors.get(self, "#4B5563")


class Category(str, Enum):
    SEO = "On-Page & Technical SEO"
    SECURITY = "Website Security & SSL"
    PERFORMANCE = "UI & Performance"
    OFFPAGE = "Off-Page & Authority"


class AuditIssue(BaseModel):
    """Represents a discrete audit finding with actionable remediation."""
    model_config = ConfigDict(frozen=False)

    issue_id: str
    title: str
    category: Category
    severity: Severity
    description: str
    evidence: str
    url: Optional[str] = None
    solution_apache: Optional[str] = None
    solution_nginx: Optional[str] = None
    solution_code: Optional[str] = None
    learn_more_url: Optional[str] = None


class AuditResult(BaseModel):
    """Encapsulates the findings and score of a specific audit domain."""
    category: Category
    score: int = Field(default=100, ge=0, le=100)
    issues: List[AuditIssue] = Field(default_factory=list)
    passed_checks: List[str] = Field(default_factory=list)
    metrics: Dict[str, Any] = Field(default_factory=dict)

    def calculate_score(self, starting_score: int = 100, total_units: Optional[int] = None) -> int:
        """Calculates normalized score (0-100) based on issue penalties.

        For multi-page/multi-unit audits, penalties are scaled by the proportion of
        items affected so that minor repeated issues across pages do not unfairly zero out the score.
        """
        if not self.issues:
            self.score = starting_score
            return starting_score

        if total_units is None:
            urls = {i.url for i in self.issues if i.url}
            total_units = max(1, len(urls))
        else:
            total_units = max(1, total_units)

        if total_units > 1:
            from collections import defaultdict
            issues_by_id = defaultdict(list)
            for issue in self.issues:
                issues_by_id[issue.issue_id].append(issue)

            total_penalty = 0.0
            for issue_id, occurrences in issues_by_id.items():
                base_weight = occurrences[0].severity.weight
                ratio = min(1.0, len(occurrences) / total_units)
                total_penalty += base_weight * ratio
            calculated = max(0, min(100, round(starting_score - total_penalty)))
        else:
            penalty = sum(issue.severity.weight for issue in self.issues)
            calculated = max(0, min(100, starting_score - penalty))

        self.score = calculated
        return calculated


class BaseAuditor:
    """Abstract base class for all audit modules."""

    def __init__(self, target_url: str):
        self.target_url = target_url

    async def run(self) -> AuditResult:
        raise NotImplementedError("Subclasses must implement run()")
