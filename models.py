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


class ControlImpact(BaseModel):
    """A specific IT control impacted by the issue."""
    control_id: Optional[str] = None          # e.g. IT-AC-003
    control_name: str
    gap_description: str                       # What specifically is compromised
    risk_rating: str                           # Critical / High / Medium / Low
    framework_refs: dict[str, str] = Field(default_factory=dict)  # SOX_ITGC, COBIT, ISO_27001, etc.


class ActionItem(BaseModel):
    """A discrete remediation task within an issue's action plan."""
    id: str                                    # AI-001, AI-002, …
    task: str
    owner: Optional[str] = None               # Named individual
    team: Optional[str] = None                # First-line team responsible
    priority: str = "Medium"                  # Critical / High / Medium / Low
    target_date: Optional[str] = None         # YYYY-MM-DD
    estimated_days: Optional[int] = None      # Days from today
    dependencies: list[str] = Field(default_factory=list)  # IDs of action items this depends on
    status: str = "Pending"                   # Pending / In Progress / Completed / Blocked
    notes: Optional[str] = None
    created_date: str = Field(default_factory=lambda: datetime.now().isoformat())
    completed_date: Optional[str] = None


class Checkpoint(BaseModel):
    """A recorded review meeting between the risk analyst and first-line team."""
    id: str                                    # CP-001, CP-002, …
    date: str                                  # YYYY-MM-DD
    attendees: list[str] = Field(default_factory=list)
    agenda: Optional[str] = None
    discussion_summary: Optional[str] = None
    decisions: list[str] = Field(default_factory=list)
    agreed_actions: list[str] = Field(default_factory=list)
    next_steps: Optional[str] = None
    next_checkpoint_date: Optional[str] = None
    recorded_by: str = "AI Agent"
    created_date: str = Field(default_factory=lambda: datetime.now().isoformat())


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
    first_line_team: Optional[str] = None     # Responsible first-line team

    # Control references
    control_id: Optional[str] = None          # Internal control ID (e.g. IT-AC-001)
    framework_references: dict[str, str] = Field(default_factory=dict)
    is_sox_relevant: bool = False
    regulatory_impact: Optional[str] = None

    # Root cause & remediation
    root_cause: Optional[str] = None
    remediation_plan: Optional[str] = None
    remediation_evidence: Optional[str] = None

    # AI-generated analysis artifacts
    problem_statement: Optional[str] = None
    control_impacts: list[ControlImpact] = Field(default_factory=list)
    action_items: list[ActionItem] = Field(default_factory=list)
    analysis_generated: bool = False
    analysis_generated_date: Optional[str] = None

    # Checkpoint reviews
    checkpoints: list[Checkpoint] = Field(default_factory=list)

    # Dates & SLA
    due_date: Optional[str] = None            # ISO date string (YYYY-MM-DD)
    sla_days: Optional[int] = None
    created_date: str = Field(default_factory=lambda: datetime.now().isoformat())
    updated_date: str = Field(default_factory=lambda: datetime.now().isoformat())
    closed_date: Optional[str] = None

    # GRC provenance
    source_id: Optional[str] = None           # Original ID from the GRC tool

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

    def next_action_item_id(self) -> str:
        if not self.action_items:
            return "AI-001"
        nums = [int(a.id.split("-")[1]) for a in self.action_items if "-" in a.id]
        return f"AI-{max(nums) + 1:03d}"

    def next_checkpoint_id(self) -> str:
        if not self.checkpoints:
            return "CP-001"
        nums = [int(c.id.split("-")[1]) for c in self.checkpoints if "-" in c.id]
        return f"CP-{max(nums) + 1:03d}"

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
            "first_line_team": self.first_line_team or "Unassigned",
            "due_date": self.due_date or "No due date",
            "days_until_due": self.days_until_due(),
            "overdue": self.is_overdue(),
            "sox_relevant": self.is_sox_relevant,
            "analysis_ready": self.analysis_generated,
            "open_actions": sum(1 for a in self.action_items if a.status != "Completed"),
            "checkpoints": len(self.checkpoints),
        }
