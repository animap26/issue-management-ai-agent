from __future__ import annotations

from datetime import datetime
from typing import Optional
from pydantic import BaseModel, Field

from config import ControlDomain, IssueType, Severity, Status


class AuditEntry(BaseModel):
    timestamp: str = Field(default_factory=lambda: datetime.now().isoformat())
    action: str
    field: Optional[str] = None
    old_value: Optional[str] = None
    new_value: Optional[str] = None
    performed_by: str = "AI Agent"


class Issue(BaseModel):
    id: str
    title: str
    description: str
    issue_type: IssueType
    control_domain: ControlDomain
    severity: Severity
    status: Status = Status.OPEN

    # Ownership
    owner: Optional[str] = None
    business_unit: Optional[str] = None

    # Control references
    control_id: Optional[str] = None          # Internal control ID (e.g. IT-AC-001)
    framework_references: dict[str, str] = Field(default_factory=dict)
    is_sox_relevant: bool = False
    regulatory_impact: Optional[str] = None

    # Root cause & remediation
    root_cause: Optional[str] = None
    remediation_plan: Optional[str] = None
    remediation_evidence: Optional[str] = None

    # Dates & SLA
    due_date: Optional[str] = None            # ISO date string (YYYY-MM-DD)
    sla_days: Optional[int] = None
    created_date: str = Field(default_factory=lambda: datetime.now().isoformat())
    updated_date: str = Field(default_factory=lambda: datetime.now().isoformat())
    closed_date: Optional[str] = None

    # Notes & audit trail
    notes: list[str] = Field(default_factory=list)
    audit_trail: list[AuditEntry] = Field(default_factory=list)

    def is_overdue(self) -> bool:
        if self.status in (Status.CLOSED, Status.ACCEPTED_RISK):
            return False
        if not self.due_date:
            return False
        return datetime.now().date() > datetime.fromisoformat(self.due_date).date()

    def days_until_due(self) -> Optional[int]:
        if not self.due_date:
            return None
        delta = datetime.fromisoformat(self.due_date).date() - datetime.now().date()
        return delta.days

    def to_summary(self) -> dict:
        """Compact dict for list views and reports."""
        return {
            "id": self.id,
            "title": self.title,
            "type": self.issue_type,
            "domain": self.control_domain,
            "severity": self.severity,
            "status": self.status,
            "owner": self.owner or "Unassigned",
            "due_date": self.due_date or "No due date",
            "days_until_due": self.days_until_due(),
            "overdue": self.is_overdue(),
            "sox_relevant": self.is_sox_relevant,
        }
