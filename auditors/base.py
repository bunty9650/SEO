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

    def calculate_score(self, starting_score: int = 100) -> int:
        """Calculates normalized score (0-100) based on issue penalties."""
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
