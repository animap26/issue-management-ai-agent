"""
Tool definitions and implementations for the IT Issue Management Agent.

Each tool has:
  - A JSON schema (for Claude's tool use API)
  - An implementation function that returns a plain string result
"""

from __future__ import annotations

import base64
import json
from datetime import date, datetime, timedelta
from pathlib import Path
from typing import Any

import anthropic

import data_store
from config import (
    DOMAIN_TO_TEAM,
    FRAMEWORK_REFERENCES,
    SLA_DAYS,
    ControlDomain,
    IssueType,
    Severity,
    Status,
)
from models import ActionItem, AuditEntry, Checkpoint, ControlImpact, Issue

# ---------------------------------------------------------------------------
# GRC PDF extraction prompt
# ---------------------------------------------------------------------------

EXTRACTION_PROMPT = """\
Extract every IT risk issue, control deficiency, and finding from this GRC tool export PDF.

Map each item to the following JSON structure (omit any field that has no value):
{
  "title": "short issue title",
  "description": "full description or details",
  "issue_type": one of ["Control Deficiency","Self-Identified Issue","Audit Finding",
                        "Regulatory Finding","Incident-Derived Issue","Vulnerability","Process Gap"],
  "control_domain": one of ["Access Management","Change Management","IT Operations",
                             "Information Security","Data Management","Vendor Management",
                             "Business Continuity & DR","Software Development",
                             "Infrastructure & Networks","Incident Management"],
  "severity": one of ["Critical","High","Medium","Low"],
  "status": one of ["Open","In Remediation","Pending Validation","Closed",
                    "Escalated","Overdue","Accepted Risk"],
  "owner": "assigned owner or team name",
  "business_unit": "business unit or department",
  "control_id": "internal control reference (e.g. IT-AC-001, CTRL-123)",
  "is_sox_relevant": true or false,
  "regulatory_impact": "SOX, PCI-DSS, GDPR, etc.",
  "root_cause": "root cause analysis text",
  "remediation_plan": "corrective action plan",
  "due_date": "YYYY-MM-DD",
  "source_id": "original GRC tool ID (e.g. INC0001234, RISK-456, SN-789)"
}

Severity mapping:
  ServiceNow Priority: P1 → Critical | P2 → High | P3 → Medium | P4 → Low
  Archer / generic:    Critical/Very High → Critical | High → High | Medium → Medium | Low → Low

Status mapping:
  Open / New / Draft                    → "Open"
  In Progress / Assigned / Work in Progress → "In Remediation"
  Resolved / Pending Review             → "Pending Validation"
  Closed / Complete                     → "Closed"
  Escalated                             → "Escalated"
  Overdue / Past Due                    → "Overdue"
  Accepted / Risk Accepted              → "Accepted Risk"

Control Domain guidance:
  User access, provisioning, privileged access, access reviews → "Access Management"
  Change requests, unauthorised changes, SDLC change control   → "Change Management"
  Backups, monitoring, job scheduling, availability            → "IT Operations"
  Vulnerabilities, patches, encryption, firewall, DLP         → "Information Security"
  Data integrity, retention, classification                    → "Data Management"
  Third-party risk, vendor assessments                         → "Vendor Management"
  BCP, DR, RTO/RPO                                             → "Business Continuity & DR"
  SDLC, code review, testing                                   → "Software Development"
  Network, servers, cloud infrastructure                       → "Infrastructure & Networks"
  Incident response, security events                           → "Incident Management"

Return ONLY a valid JSON array of issue objects.
If no issues are found, return an empty array [].
"""


# ---------------------------------------------------------------------------
# Issue analysis prompt
# ---------------------------------------------------------------------------

ANALYSIS_PROMPT_TEMPLATE = """\
You are a senior IT risk analyst helping a first-line risk team analyse a control deficiency \
or self-identified issue. Produce a comprehensive structured analysis of the issue below.

=== ISSUE DETAILS ===
{issue_details}

=== FIRST-LINE TEAMS AVAILABLE ===
- Infrastructure Services (owns: Infrastructure & Networks, IT Operations, Incident Management)
- Application Development (owns: Software Development, Change Management)
- Service Continuity & Disaster Recovery (owns: Business Continuity & DR)
- Information Security (owns: Information Security, Access Management, Data Management)
- Third Party Risk Management (owns: Vendor Management)

=== REQUIRED OUTPUT ===
Return a single valid JSON object with exactly these three keys:

{{
  "problem_statement": "<3–5 sentence statement covering: what the issue is, \
why it is a risk, which processes/systems are affected, and the consequence if \
not remediated>",

  "control_impacts": [
    {{
      "control_name": "<name of the specific IT control that is impacted>",
      "control_id": "<internal control ID if known, else null>",
      "gap_description": "<exactly what is broken or missing in this control>",
      "risk_rating": "<Critical|High|Medium|Low>",
      "framework_refs": {{
        "SOX_ITGC": "<relevant ITGC category or null>",
        "COBIT": "<relevant COBIT process or null>",
        "ISO_27001": "<relevant clause or null>",
        "NIST_CSF": "<relevant function/category or null>"
      }}
    }}
  ],

  "action_items": [
    {{
      "task": "<specific, actionable remediation step>",
      "team": "<one of the first-line teams above>",
      "priority": "<Critical|High|Medium|Low>",
      "estimated_days": <integer number of days from today>,
      "dependencies": [<list of task descriptions this step depends on, or empty list>],
      "notes": "<any important caveats or guidance for this step, or null>"
    }}
  ]
}}

Rules:
- problem_statement must be a plain string, not an object.
- List action items in dependency order (prerequisites first).
- Be specific — name the systems, processes, teams, and controls involved.
- Return ONLY the JSON object. No markdown, no explanatory text.
"""


# ---------------------------------------------------------------------------
# Tool schemas (passed to Claude)
# ---------------------------------------------------------------------------

TOOL_SCHEMAS: list[dict] = [
    {
        "name": "create_issue",
        "description": (
            "Log a new IT control deficiency or self-identified issue (SII). "
            "Automatically assigns an ID, sets the SLA due date based on severity, "
            "and maps the issue to relevant IT control frameworks (SOX ITGC, COBIT, ISO 27001, NIST CSF)."
        ),
        "input_schema": {
            "type": "object",
            "properties": {
                "title": {
                    "type": "string",
                    "description": "Short, clear title of the issue (max ~100 chars).",
                },
                "description": {
                    "type": "string",
                    "description": "Detailed description of the deficiency or issue.",
                },
                "issue_type": {
                    "type": "string",
                    "enum": [t.value for t in IssueType],
                    "description": "Classification of the issue type.",
                },
                "control_domain": {
                    "type": "string",
                    "enum": [d.value for d in ControlDomain],
                    "description": "IT control domain this issue falls under.",
                },
                "severity": {
                    "type": "string",
                    "enum": [s.value for s in Severity],
                    "description": (
                        "Critical = Material Weakness; High = Significant Deficiency; "
                        "Medium = Deficiency; Low = Observation."
                    ),
                },
                "owner": {
                    "type": "string",
                    "description": "Name or email of the issue owner responsible for remediation.",
                },
                "business_unit": {
                    "type": "string",
                    "description": "Business unit or team where the issue originates.",
                },
                "control_id": {
                    "type": "string",
                    "description": "Internal control reference ID (e.g. IT-AC-001), if known.",
                },
                "is_sox_relevant": {
                    "type": "boolean",
                    "description": "Whether this issue impacts SOX ITGC compliance.",
                },
                "regulatory_impact": {
                    "type": "string",
                    "description": "Any regulatory frameworks affected (e.g. PCI-DSS, GDPR).",
                },
                "root_cause": {
                    "type": "string",
                    "description": "Known or suspected root cause of the issue.",
                },
                "remediation_plan": {
                    "type": "string",
                    "description": "Planned remediation actions and approach.",
                },
            },
            "required": ["title", "description", "issue_type", "control_domain", "severity"],
        },
    },
    {
        "name": "get_issue",
        "description": "Retrieve full details of a specific issue by its ID.",
        "input_schema": {
            "type": "object",
            "properties": {
                "issue_id": {
                    "type": "string",
                    "description": "The issue ID (e.g. IIT-0001).",
                },
            },
            "required": ["issue_id"],
        },
    },
    {
        "name": "update_issue",
        "description": (
            "Update one or more fields on an existing issue. "
            "All changes are recorded in the audit trail."
        ),
        "input_schema": {
            "type": "object",
            "properties": {
                "issue_id": {
                    "type": "string",
                    "description": "The issue ID to update.",
                },
                "status": {
                    "type": "string",
                    "enum": [s.value for s in Status],
                    "description": "New status for the issue.",
                },
                "severity": {
                    "type": "string",
                    "enum": [s.value for s in Severity],
                    "description": "Revised severity rating.",
                },
                "owner": {
                    "type": "string",
                    "description": "New or updated owner name / email.",
                },
                "remediation_plan": {
                    "type": "string",
                    "description": "Updated remediation plan.",
                },
                "remediation_evidence": {
                    "type": "string",
                    "description": "Evidence that remediation has been completed.",
                },
                "root_cause": {
                    "type": "string",
                    "description": "Updated root cause analysis.",
                },
                "due_date": {
                    "type": "string",
                    "description": "Revised due date in YYYY-MM-DD format.",
                },
                "is_sox_relevant": {
                    "type": "boolean",
                    "description": "Update SOX relevance flag.",
                },
                "regulatory_impact": {
                    "type": "string",
                    "description": "Updated regulatory impact description.",
                },
            },
            "required": ["issue_id"],
        },
    },
    {
        "name": "add_note",
        "description": "Append a timestamped note to an issue's log.",
        "input_schema": {
            "type": "object",
            "properties": {
                "issue_id": {
                    "type": "string",
                    "description": "The issue ID.",
                },
                "note": {
                    "type": "string",
                    "description": "The note text to append.",
                },
            },
            "required": ["issue_id", "note"],
        },
    },
    {
        "name": "list_issues",
        "description": (
            "List and filter issues. Returns a summary table of matching issues. "
            "All filters are optional — omit to list all issues."
        ),
        "input_schema": {
            "type": "object",
            "properties": {
                "status": {
                    "type": "string",
                    "description": "Filter by status (e.g. Open, In Remediation, Overdue).",
                },
                "severity": {
                    "type": "string",
                    "description": "Filter by severity (Critical, High, Medium, Low).",
                },
                "domain": {
                    "type": "string",
                    "description": "Filter by control domain (partial match).",
                },
                "owner": {
                    "type": "string",
                    "description": "Filter by owner name / email (partial match).",
                },
                "issue_type": {
                    "type": "string",
                    "description": "Filter by issue type (partial match).",
                },
                "overdue_only": {
                    "type": "boolean",
                    "description": "If true, return only overdue issues.",
                },
                "sox_only": {
                    "type": "boolean",
                    "description": "If true, return only SOX-relevant issues.",
                },
            },
            "required": [],
        },
    },
    {
        "name": "check_overdue_issues",
        "description": (
            "Scan all open issues and flag those past their SLA due date. "
            "Updates their status to Overdue and returns the list."
        ),
        "input_schema": {
            "type": "object",
            "properties": {},
            "required": [],
        },
    },
    {
        "name": "generate_report",
        "description": (
            "Generate a management report on the current issue inventory. "
            "report_type options: 'summary' (counts by severity/status), "
            "'overdue' (all overdue items), 'sox' (SOX-relevant issues), "
            "'by_domain' (breakdown by control domain), 'full' (all open issues)."
        ),
        "input_schema": {
            "type": "object",
            "properties": {
                "report_type": {
                    "type": "string",
                    "enum": ["summary", "overdue", "sox", "by_domain", "full"],
                    "description": "Type of report to generate.",
                },
            },
            "required": ["report_type"],
        },
    },
    {
        "name": "close_issue",
        "description": (
            "Mark an issue as Closed after remediation is validated. "
            "Requires evidence of remediation. Records the closed date."
        ),
        "input_schema": {
            "type": "object",
            "properties": {
                "issue_id": {
                    "type": "string",
                    "description": "The issue ID to close.",
                },
                "remediation_evidence": {
                    "type": "string",
                    "description": "Evidence confirming the issue has been remediated.",
                },
            },
            "required": ["issue_id", "remediation_evidence"],
        },
    },
    {
        "name": "read_pdf_from_grc",
        "description": (
            "Read a PDF exported from a GRC tool (ServiceNow, Archer, MetricStream, etc.) "
            "and extract all IT issues into structured data. "
            "Returns a JSON payload with the issues found — review them before importing. "
            "Call import_extracted_issues afterwards to create them in the register."
        ),
        "input_schema": {
            "type": "object",
            "properties": {
                "file_path": {
                    "type": "string",
                    "description": "Absolute or relative path to the PDF file on disk.",
                },
            },
            "required": ["file_path"],
        },
    },
    {
        "name": "import_extracted_issues",
        "description": (
            "Bulk-create issues from a list of issue objects previously extracted from a GRC PDF. "
            "Preserves the GRC source ID in each issue's notes. "
            "Respects the status from the GRC tool (e.g. In Remediation, Pending Validation). "
            "Always show the user a preview from read_pdf_from_grc and confirm before calling this."
        ),
        "input_schema": {
            "type": "object",
            "properties": {
                "issues": {
                    "type": "array",
                    "description": "Array of issue objects from read_pdf_from_grc.",
                    "items": {"type": "object"},
                },
            },
            "required": ["issues"],
        },
    },
    {
        "name": "analyse_issue",
        "description": (
            "Generate a structured analysis for an issue: a problem statement, "
            "a list of impacted IT controls with framework references, and a "
            "recommended action plan with first-line team assignments and timelines. "
            "This is the primary work product the risk analyst shares with first-line "
            "teams at the first checkpoint review. "
            "Stores the analysis on the issue record."
        ),
        "input_schema": {
            "type": "object",
            "properties": {
                "issue_id": {
                    "type": "string",
                    "description": "ID of the issue to analyse (e.g. IIT-0001).",
                },
            },
            "required": ["issue_id"],
        },
    },
    {
        "name": "get_issue_analysis",
        "description": (
            "Retrieve the full analysis for an issue: problem statement, control impacts, "
            "action plan, and checkpoint history. Use this to prepare for a review meeting "
            "or to check current progress."
        ),
        "input_schema": {
            "type": "object",
            "properties": {
                "issue_id": {
                    "type": "string",
                    "description": "ID of the issue.",
                },
            },
            "required": ["issue_id"],
        },
    },
    {
        "name": "update_action_item",
        "description": (
            "Update the status or details of a specific action item within an issue. "
            "Use this after a checkpoint review to reflect what was agreed."
        ),
        "input_schema": {
            "type": "object",
            "properties": {
                "issue_id": {
                    "type": "string",
                    "description": "The issue ID.",
                },
                "action_item_id": {
                    "type": "string",
                    "description": "The action item ID (e.g. AI-001).",
                },
                "status": {
                    "type": "string",
                    "enum": ["Pending", "In Progress", "Completed", "Blocked"],
                    "description": "New status of the action item.",
                },
                "owner": {
                    "type": "string",
                    "description": "Named owner assigned to this action item.",
                },
                "target_date": {
                    "type": "string",
                    "description": "Revised target date in YYYY-MM-DD format.",
                },
                "notes": {
                    "type": "string",
                    "description": "Progress notes or blockers.",
                },
            },
            "required": ["issue_id", "action_item_id"],
        },
    },
    {
        "name": "log_checkpoint",
        "description": (
            "Record the outcome of a checkpoint review meeting between the risk analyst "
            "and the first-line team. Captures attendees, discussion summary, decisions "
            "made, agreed actions, and the next checkpoint date. "
            "Every checkpoint is permanently recorded in the issue audit trail."
        ),
        "input_schema": {
            "type": "object",
            "properties": {
                "issue_id": {
                    "type": "string",
                    "description": "The issue ID.",
                },
                "date": {
                    "type": "string",
                    "description": "Date of the review meeting in YYYY-MM-DD format.",
                },
                "attendees": {
                    "type": "array",
                    "items": {"type": "string"},
                    "description": "Names of attendees (risk analyst and first-line team members).",
                },
                "agenda": {
                    "type": "string",
                    "description": "Topics covered in the review meeting.",
                },
                "discussion_summary": {
                    "type": "string",
                    "description": "Summary of the discussion and findings.",
                },
                "decisions": {
                    "type": "array",
                    "items": {"type": "string"},
                    "description": "Formal decisions made during the meeting.",
                },
                "agreed_actions": {
                    "type": "array",
                    "items": {"type": "string"},
                    "description": "Specific actions agreed, with owner and target date where known.",
                },
                "next_steps": {
                    "type": "string",
                    "description": "Summary of what happens between now and the next checkpoint.",
                },
                "next_checkpoint_date": {
                    "type": "string",
                    "description": "Date of the next scheduled review in YYYY-MM-DD format.",
                },
            },
            "required": ["issue_id", "date", "attendees", "discussion_summary"],
        },
    },
]


# ---------------------------------------------------------------------------
# Tool implementations
# ---------------------------------------------------------------------------

def create_issue(
    title: str,
    description: str,
    issue_type: str,
    control_domain: str,
    severity: str,
    owner: str | None = None,
    business_unit: str | None = None,
    control_id: str | None = None,
    is_sox_relevant: bool = False,
    regulatory_impact: str | None = None,
    root_cause: str | None = None,
    remediation_plan: str | None = None,
) -> str:
    issue_id = data_store.next_issue_id()
    sla = SLA_DAYS.get(severity, 90)
    due = (date.today() + timedelta(days=sla)).isoformat()

    domain_enum = ControlDomain(control_domain)
    framework_refs = FRAMEWORK_REFERENCES.get(domain_enum, {})

    issue = Issue(
        id=issue_id,
        title=title,
        description=description,
        issue_type=IssueType(issue_type),
        control_domain=domain_enum,
        severity=Severity(severity),
        status=Status.OPEN,
        owner=owner,
        business_unit=business_unit,
        control_id=control_id,
        framework_references=framework_refs,
        is_sox_relevant=is_sox_relevant,
        regulatory_impact=regulatory_impact,
        root_cause=root_cause,
        remediation_plan=remediation_plan,
        due_date=due,
        sla_days=sla,
        audit_trail=[
            AuditEntry(action="created", new_value=f"Issue {issue_id} created")
        ],
    )

    data_store.save_issue(issue)

    return (
        f"Issue created successfully.\n"
        f"  ID:            {issue_id}\n"
        f"  Severity:      {severity}  →  SLA: {sla} days  →  Due: {due}\n"
        f"  Control Domain:{control_domain}\n"
        f"  SOX Relevant:  {is_sox_relevant}\n"
        f"  Framework refs:\n"
        + "\n".join(f"    {k}: {v}" for k, v in framework_refs.items())
    )


def get_issue(issue_id: str) -> str:
    issue = data_store.get_issue(issue_id)
    if issue is None:
        return f"Issue '{issue_id}' not found."
    return json.dumps(issue.model_dump(), indent=2, default=str)


def update_issue(issue_id: str, **kwargs: Any) -> str:
    updates = {k: v for k, v in kwargs.items() if v is not None and k != "issue_id"}
    issue = data_store.update_issue(issue_id, updates)
    if issue is None:
        return f"Issue '{issue_id}' not found."
    return (
        f"Issue {issue_id} updated.\n"
        f"  Fields changed: {', '.join(updates.keys())}\n"
        f"  Current status: {issue.status}  |  Severity: {issue.severity}"
    )


def add_note(issue_id: str, note: str) -> str:
    issue = data_store.get_issue(issue_id)
    if issue is None:
        return f"Issue '{issue_id}' not found."
    stamped = f"[{datetime.now().strftime('%Y-%m-%d %H:%M')}] {note}"
    issue.notes.append(stamped)
    issue.audit_trail.append(AuditEntry(action="note_added", new_value=note))
    issue.updated_date = datetime.now().isoformat()
    data_store.save_issue(issue)
    return f"Note added to {issue_id}."


def list_issues(
    status: str | None = None,
    severity: str | None = None,
    domain: str | None = None,
    owner: str | None = None,
    issue_type: str | None = None,
    overdue_only: bool = False,
    sox_only: bool = False,
) -> str:
    issues = data_store.filter_issues(
        status=status,
        severity=severity,
        domain=domain,
        owner=owner,
        issue_type=issue_type,
        overdue_only=overdue_only,
        sox_only=sox_only,
    )
    if not issues:
        return "No issues match the specified criteria."

    lines = [f"{'ID':<10} {'Severity':<10} {'Status':<20} {'Domain':<25} {'Owner':<20} {'Due':<12} {'OVR':>3}"]
    lines.append("-" * 105)
    for i in issues:
        overdue_flag = "!" if i.is_overdue() else " "
        sox_flag = "[SOX]" if i.is_sox_relevant else ""
        lines.append(
            f"{i.id:<10} {i.severity:<10} {i.status:<20} {i.control_domain:<25} "
            f"{(i.owner or 'Unassigned'):<20} {(i.due_date or 'N/A'):<12} {overdue_flag}  {sox_flag}"
        )
        lines.append(f"  └─ {i.title}")
    lines.append(f"\nTotal: {len(issues)} issue(s)")
    return "\n".join(lines)


def check_overdue_issues() -> str:
    issues = data_store.get_all_issues()
    overdue = []
    for issue in issues:
        if issue.is_overdue() and issue.status not in (Status.CLOSED, Status.ACCEPTED_RISK, Status.ESCALATED):
            data_store.update_issue(issue.id, {"status": Status.OVERDUE.value})
            overdue.append(issue)

    if not overdue:
        return "No overdue issues found. All issues are within SLA."

    lines = [f"Flagged {len(overdue)} overdue issue(s):\n"]
    for i in overdue:
        days_late = abs(i.days_until_due() or 0)
        lines.append(
            f"  {i.id} [{i.severity}] — {i.title}\n"
            f"    Owner: {i.owner or 'Unassigned'}  |  Due: {i.due_date}  |  {days_late} day(s) overdue"
        )
    return "\n".join(lines)


def generate_report(report_type: str) -> str:
    issues = data_store.get_all_issues()

    if report_type == "summary":
        total = len(issues)
        by_severity: dict[str, int] = {}
        by_status: dict[str, int] = {}
        for i in issues:
            by_severity[i.severity] = by_severity.get(i.severity, 0) + 1
            by_status[i.status] = by_status.get(i.status, 0) + 1

        overdue_count = sum(1 for i in issues if i.is_overdue())
        sox_count = sum(1 for i in issues if i.is_sox_relevant)

        lines = [
            "=== IT Issue Management — Summary Report ===",
            f"Generated: {datetime.now().strftime('%Y-%m-%d %H:%M')}",
            f"\nTotal Issues: {total}",
            f"  Overdue:      {overdue_count}",
            f"  SOX-Relevant: {sox_count}",
            "\nBy Severity:",
        ]
        for sev in ["Critical", "High", "Medium", "Low"]:
            lines.append(f"  {sev:<10}: {by_severity.get(sev, 0)}")
        lines.append("\nBy Status:")
        for st, cnt in sorted(by_status.items(), key=lambda x: -x[1]):
            lines.append(f"  {st:<22}: {cnt}")
        return "\n".join(lines)

    elif report_type == "overdue":
        overdue = [i for i in issues if i.is_overdue()]
        if not overdue:
            return "No overdue issues."
        lines = ["=== Overdue Issues Report ===", f"Generated: {datetime.now().strftime('%Y-%m-%d %H:%M')}\n"]
        for i in sorted(overdue, key=lambda x: x.severity):
            days_late = abs(i.days_until_due() or 0)
            lines += [
                f"[{i.id}] {i.title}",
                f"  Severity: {i.severity}  |  Domain: {i.control_domain}",
                f"  Owner: {i.owner or 'Unassigned'}  |  Due: {i.due_date} ({days_late}d overdue)",
                f"  SOX: {'Yes' if i.is_sox_relevant else 'No'}",
                "",
            ]
        return "\n".join(lines)

    elif report_type == "sox":
        sox_issues = [i for i in issues if i.is_sox_relevant]
        if not sox_issues:
            return "No SOX-relevant issues on record."
        lines = ["=== SOX ITGC Issues Report ===", f"Generated: {datetime.now().strftime('%Y-%m-%d %H:%M')}\n"]
        for i in sorted(sox_issues, key=lambda x: x.severity):
            lines += [
                f"[{i.id}] {i.title}",
                f"  Type: {i.issue_type}  |  Severity: {i.severity}  |  Status: {i.status}",
                f"  Domain: {i.control_domain}  |  Owner: {i.owner or 'Unassigned'}",
                f"  Due: {i.due_date or 'N/A'}  |  Overdue: {'YES' if i.is_overdue() else 'No'}",
                f"  SOX Ref: {i.framework_references.get('SOX_ITGC', 'N/A')}",
                "",
            ]
        return "\n".join(lines)

    elif report_type == "by_domain":
        domain_map: dict[str, list[Issue]] = {}
        for i in issues:
            domain_map.setdefault(i.control_domain, []).append(i)
        lines = ["=== Issues by Control Domain ===", f"Generated: {datetime.now().strftime('%Y-%m-%d %H:%M')}\n"]
        for domain, domain_issues in sorted(domain_map.items()):
            open_count = sum(1 for i in domain_issues if i.status != Status.CLOSED)
            critical = sum(1 for i in domain_issues if i.severity == Severity.CRITICAL)
            high = sum(1 for i in domain_issues if i.severity == Severity.HIGH)
            lines.append(f"{domain} — {len(domain_issues)} total, {open_count} open, {critical} Critical, {high} High")
        return "\n".join(lines)

    elif report_type == "full":
        open_issues = [i for i in issues if i.status not in (Status.CLOSED,)]
        if not open_issues:
            return "No open issues on record."
        lines = ["=== Full Open Issue Register ===", f"Generated: {datetime.now().strftime('%Y-%m-%d %H:%M')}\n"]
        for i in sorted(open_issues, key=lambda x: (x.severity, x.due_date or "")):
            lines += [
                f"[{i.id}] {i.title}",
                f"  Type: {i.issue_type}  |  Severity: {i.severity}  |  Status: {i.status}",
                f"  Domain: {i.control_domain}  |  Owner: {i.owner or 'Unassigned'}",
                f"  Due: {i.due_date or 'N/A'}  |  SOX: {'Yes' if i.is_sox_relevant else 'No'}",
                f"  Remediation: {i.remediation_plan or 'Not yet defined'}",
                "",
            ]
        return "\n".join(lines)

    return f"Unknown report type: {report_type}"


def close_issue(issue_id: str, remediation_evidence: str) -> str:
    issue = data_store.get_issue(issue_id)
    if issue is None:
        return f"Issue '{issue_id}' not found."
    if issue.status == Status.CLOSED:
        return f"Issue '{issue_id}' is already closed."

    updates = {
        "status": Status.CLOSED.value,
        "remediation_evidence": remediation_evidence,
        "closed_date": datetime.now().isoformat(),
    }
    data_store.update_issue(issue_id, updates)
    return (
        f"Issue {issue_id} closed.\n"
        f"  Evidence recorded: {remediation_evidence[:120]}{'...' if len(remediation_evidence) > 120 else ''}"
    )


def analyse_issue(issue_id: str) -> str:
    """
    Generate a problem statement, control impact analysis, and action plan
    for the given issue using Claude, then store the analysis on the record.
    """
    issue = data_store.get_issue(issue_id)
    if issue is None:
        return f"Issue '{issue_id}' not found."

    # Build a rich issue description for the analysis prompt
    framework_text = "\n".join(f"  {k}: {v}" for k, v in issue.framework_references.items())
    issue_details = (
        f"ID: {issue.id}\n"
        f"Title: {issue.title}\n"
        f"Type: {issue.issue_type}\n"
        f"Control Domain: {issue.control_domain}\n"
        f"Severity: {issue.severity}  (Critical=Material Weakness, High=Significant Deficiency, "
        f"Medium=Deficiency, Low=Observation)\n"
        f"SOX Relevant: {issue.is_sox_relevant}\n"
        f"Regulatory Impact: {issue.regulatory_impact or 'None stated'}\n"
        f"Description:\n{issue.description}\n"
        f"Root Cause: {issue.root_cause or 'Not yet determined'}\n"
        f"Existing Remediation Notes: {issue.remediation_plan or 'None'}\n"
        f"Framework References:\n{framework_text or '  None mapped'}\n"
        f"Business Unit / Owner: {issue.business_unit or 'Not specified'} / "
        f"{issue.owner or 'Not assigned'}\n"
    )

    prompt = ANALYSIS_PROMPT_TEMPLATE.format(issue_details=issue_details)

    print(f"  [analyse] Generating analysis for {issue_id} via Claude…")
    client = anthropic.Anthropic()
    response = client.messages.create(
        model="claude-opus-4-6",
        max_tokens=4096,
        thinking={"type": "adaptive"},
        messages=[{"role": "user", "content": prompt}],
    )

    raw = next((b.text for b in response.content if b.type == "text"), "{}").strip()
    # Strip markdown fences if present
    if raw.startswith("```"):
        raw = "\n".join(raw.split("\n")[1:])
        if raw.endswith("```"):
            raw = raw[: raw.rfind("```")]

    try:
        analysis: dict = json.loads(raw)
    except json.JSONDecodeError:
        return f"Could not parse analysis JSON. Raw output:\n{raw[:600]}"

    # Store problem statement
    issue.problem_statement = analysis.get("problem_statement", "")

    # Store control impacts
    issue.control_impacts = [
        ControlImpact(
            control_id=ci.get("control_id"),
            control_name=ci.get("control_name", ""),
            gap_description=ci.get("gap_description", ""),
            risk_rating=ci.get("risk_rating", "Medium"),
            framework_refs=ci.get("framework_refs", {}),
        )
        for ci in analysis.get("control_impacts", [])
    ]

    # Store action items (sequential IDs)
    new_items: list[ActionItem] = []
    for ai_data in analysis.get("action_items", []):
        item_id = f"AI-{len(new_items) + 1:03d}"
        est_days = ai_data.get("estimated_days")
        target = (
            (date.today() + timedelta(days=est_days)).isoformat() if est_days else None
        )
        # If no explicit team, infer from control domain
        team = ai_data.get("team") or DOMAIN_TO_TEAM.get(issue.control_domain, "")
        new_items.append(
            ActionItem(
                id=item_id,
                task=ai_data.get("task", ""),
                team=team,
                priority=ai_data.get("priority", "Medium"),
                estimated_days=est_days,
                target_date=target,
                dependencies=ai_data.get("dependencies", []),
                notes=ai_data.get("notes"),
            )
        )
    issue.action_items = new_items

    # Mark analysis as generated
    issue.analysis_generated = True
    issue.analysis_generated_date = datetime.now().isoformat()
    issue.audit_trail.append(
        AuditEntry(action="analysis_generated", new_value=f"{len(new_items)} action items")
    )
    issue.updated_date = datetime.now().isoformat()
    data_store.save_issue(issue)

    # Format output for the risk analyst to review
    lines = [
        f"=== Analysis for {issue_id}: {issue.title} ===\n",
        "PROBLEM STATEMENT",
        "-" * 40,
        issue.problem_statement or "(none)",
        "",
        "CONTROL IMPACTS",
        "-" * 40,
    ]
    for ci in issue.control_impacts:
        lines += [
            f"  ▸ {ci.control_name}  [{ci.risk_rating}]",
            f"    Gap: {ci.gap_description}",
            "    Framework refs: " + ", ".join(f"{k}: {v}" for k, v in ci.framework_refs.items() if v),
            "",
        ]

    lines += ["ACTION PLAN", "-" * 40]
    for ai in issue.action_items:
        dep_text = f"  (after: {', '.join(ai.dependencies)})" if ai.dependencies else ""
        lines += [
            f"  {ai.id}  [{ai.priority}]  Team: {ai.team or 'TBD'}",
            f"    {ai.task}",
            f"    Target: {ai.target_date or 'TBD'}  |  Est. {ai.estimated_days or '?'}d{dep_text}",
        ]
        if ai.notes:
            lines.append(f"    Note: {ai.notes}")
        lines.append("")

    lines.append(
        f"Analysis stored on {issue_id}. Share with the first-line team and log the "
        f"review outcome as a checkpoint using log_checkpoint."
    )
    return "\n".join(lines)


def get_issue_analysis(issue_id: str) -> str:
    """Return the full analysis, action plan status, and checkpoint history."""
    issue = data_store.get_issue(issue_id)
    if issue is None:
        return f"Issue '{issue_id}' not found."
    if not issue.analysis_generated:
        return (
            f"No analysis has been generated for {issue_id} yet. "
            f"Call analyse_issue('{issue_id}') to generate one."
        )

    lines = [
        f"=== {issue_id}: {issue.title} ===",
        f"Severity: {issue.severity}  |  Status: {issue.status}  |  "
        f"SOX: {'Yes' if issue.is_sox_relevant else 'No'}  |  "
        f"Due: {issue.due_date or 'N/A'}",
        f"First-line team: {issue.first_line_team or 'Not assigned'}",
        "",
        "PROBLEM STATEMENT",
        "-" * 40,
        issue.problem_statement or "(not generated)",
        "",
        "CONTROL IMPACTS",
        "-" * 40,
    ]
    for ci in issue.control_impacts:
        lines += [
            f"  ▸ {ci.control_name}  [{ci.risk_rating}]",
            f"    {ci.gap_description}",
        ]
        refs = ", ".join(f"{k}: {v}" for k, v in ci.framework_refs.items() if v)
        if refs:
            lines.append(f"    {refs}")
        lines.append("")

    lines += ["ACTION PLAN", "-" * 40]
    for ai in issue.action_items:
        status_icon = {"Completed": "✓", "In Progress": "►", "Blocked": "✗"}.get(ai.status, "○")
        lines += [
            f"  {status_icon} {ai.id}  [{ai.priority}]  {ai.status}  —  Team: {ai.team or 'TBD'}",
            f"    {ai.task}",
            f"    Target: {ai.target_date or 'TBD'}",
        ]
        if ai.notes:
            lines.append(f"    Note: {ai.notes}")
        lines.append("")

    open_actions = sum(1 for a in issue.action_items if a.status != "Completed")
    lines.append(
        f"Action items: {len(issue.action_items)} total, {open_actions} open."
    )

    if issue.checkpoints:
        lines += ["", "CHECKPOINT HISTORY", "-" * 40]
        for cp in issue.checkpoints:
            lines += [
                f"  [{cp.id}] {cp.date}  |  Attendees: {', '.join(cp.attendees)}",
                f"    {cp.discussion_summary or '(no summary)'}",
            ]
            if cp.decisions:
                lines.append("    Decisions: " + "; ".join(cp.decisions))
            if cp.next_checkpoint_date:
                lines.append(f"    Next checkpoint: {cp.next_checkpoint_date}")
            lines.append("")
    else:
        lines += ["", "No checkpoints recorded yet."]

    return "\n".join(lines)


def update_action_item(
    issue_id: str,
    action_item_id: str,
    status: str | None = None,
    owner: str | None = None,
    target_date: str | None = None,
    notes: str | None = None,
) -> str:
    issue = data_store.get_issue(issue_id)
    if issue is None:
        return f"Issue '{issue_id}' not found."

    ai = next((a for a in issue.action_items if a.id == action_item_id), None)
    if ai is None:
        return f"Action item '{action_item_id}' not found on {issue_id}."

    changes: list[str] = []
    if status:
        ai.status = status
        if status == "Completed":
            ai.completed_date = datetime.now().isoformat()
        changes.append(f"status={status}")
    if owner:
        ai.owner = owner
        changes.append(f"owner={owner}")
    if target_date:
        ai.target_date = target_date
        changes.append(f"target_date={target_date}")
    if notes:
        ai.notes = (ai.notes + "\n" + notes) if ai.notes else notes
        changes.append("notes updated")

    issue.updated_date = datetime.now().isoformat()
    issue.audit_trail.append(
        AuditEntry(
            action="action_item_updated",
            field=action_item_id,
            new_value=", ".join(changes),
        )
    )
    data_store.save_issue(issue)

    open_count = sum(1 for a in issue.action_items if a.status != "Completed")
    return (
        f"Action item {action_item_id} updated on {issue_id}.\n"
        f"  Changes: {', '.join(changes)}\n"
        f"  Open actions remaining: {open_count}"
    )


def log_checkpoint(
    issue_id: str,
    date: str,
    attendees: list[str],
    discussion_summary: str,
    agenda: str | None = None,
    decisions: list[str] | None = None,
    agreed_actions: list[str] | None = None,
    next_steps: str | None = None,
    next_checkpoint_date: str | None = None,
) -> str:
    issue = data_store.get_issue(issue_id)
    if issue is None:
        return f"Issue '{issue_id}' not found."

    cp_id = issue.next_checkpoint_id()
    checkpoint = Checkpoint(
        id=cp_id,
        date=date,
        attendees=attendees,
        agenda=agenda,
        discussion_summary=discussion_summary,
        decisions=decisions or [],
        agreed_actions=agreed_actions or [],
        next_steps=next_steps,
        next_checkpoint_date=next_checkpoint_date,
    )
    issue.checkpoints.append(checkpoint)
    issue.audit_trail.append(
        AuditEntry(
            action="checkpoint_logged",
            new_value=f"{cp_id} on {date} — {len(attendees)} attendee(s)",
        )
    )
    issue.updated_date = datetime.now().isoformat()
    data_store.save_issue(issue)

    lines = [
        f"Checkpoint {cp_id} recorded for {issue_id}.",
        f"  Date: {date}  |  Attendees: {', '.join(attendees)}",
    ]
    if decisions:
        lines.append(f"  Decisions: {'; '.join(decisions)}")
    if agreed_actions:
        lines.append(f"  Agreed actions: {len(agreed_actions)}")
    if next_checkpoint_date:
        lines.append(f"  Next checkpoint: {next_checkpoint_date}")
    lines.append(f"  Total checkpoints for {issue_id}: {len(issue.checkpoints)}")
    return "\n".join(lines)


def read_pdf_from_grc(file_path: str) -> str:
    """
    Read a GRC-tool PDF export and use Claude to extract structured issue data.
    Returns a JSON string ready for review before calling import_extracted_issues.
    """
    path = Path(file_path).expanduser().resolve()
    if not path.exists():
        return f"File not found: {file_path}"
    if path.suffix.lower() != ".pdf":
        return f"File is not a PDF: {file_path}"

    with path.open("rb") as f:
        pdf_b64 = base64.standard_b64encode(f.read()).decode()

    client = anthropic.Anthropic()  # reads ANTHROPIC_API_KEY from env

    print(f"  [pdf] Extracting issues from '{path.name}' via Claude…")
    extraction = client.messages.create(
        model="claude-opus-4-6",
        max_tokens=8192,
        messages=[
            {
                "role": "user",
                "content": [
                    {
                        "type": "document",
                        "source": {
                            "type": "base64",
                            "media_type": "application/pdf",
                            "data": pdf_b64,
                        },
                    },
                    {"type": "text", "text": EXTRACTION_PROMPT},
                ],
            }
        ],
    )

    raw = next((b.text for b in extraction.content if b.type == "text"), "[]").strip()

    # Strip markdown code fences if present
    if raw.startswith("```"):
        raw = "\n".join(raw.split("\n")[1:])
        if raw.endswith("```"):
            raw = raw[: raw.rfind("```")]

    try:
        extracted: list[dict] = json.loads(raw)
    except json.JSONDecodeError:
        return f"Could not parse extracted issues. Raw output:\n{raw[:800]}"

    return json.dumps(
        {
            "source_file": path.name,
            "issues_found": len(extracted),
            "issues": extracted,
        },
        indent=2,
    )


def import_extracted_issues(issues: list[dict]) -> str:
    """
    Bulk-create issues extracted from a GRC PDF.
    Preserves GRC source ID in notes and honours GRC status/due-date.
    """
    ALLOWED_FIELDS = {
        "title", "description", "issue_type", "control_domain", "severity",
        "owner", "business_unit", "control_id", "is_sox_relevant",
        "regulatory_impact", "root_cause", "remediation_plan",
    }

    created_lines: list[str] = []
    skipped_lines: list[str] = []

    for idx, raw in enumerate(issues, 1):
        # Pull out fields that create_issue doesn't accept
        source_id = raw.get("source_id")
        status_from_grc = raw.get("status")
        due_date_from_grc = raw.get("due_date")

        create_kwargs = {k: v for k, v in raw.items() if k in ALLOWED_FIELDS and v is not None}

        required = ["title", "description", "issue_type", "control_domain", "severity"]
        missing = [f for f in required if not create_kwargs.get(f)]
        if missing:
            label = raw.get("title", f"Issue {idx}")[:50]
            skipped_lines.append(f"  - '{label}': missing {missing}")
            continue

        try:
            result = create_issue(**create_kwargs)

            # Parse the auto-assigned ID from the result string
            issue_id: str | None = None
            for line in result.split("\n"):
                if "ID:" in line:
                    issue_id = line.split("ID:")[1].strip()
                    break

            if issue_id is None:
                skipped_lines.append(f"  - Issue {idx}: could not determine assigned ID")
                continue

            # Apply GRC status and due-date overrides
            post_updates: dict[str, Any] = {}
            if status_from_grc and status_from_grc != "Open":
                try:
                    post_updates["status"] = Status(status_from_grc).value
                except ValueError:
                    pass  # unknown status — leave as Open
            if due_date_from_grc:
                post_updates["due_date"] = due_date_from_grc
            if post_updates:
                data_store.update_issue(issue_id, post_updates)

            # Record GRC provenance in the issue notes and audit trail
            if source_id:
                issue = data_store.get_issue(issue_id)
                if issue:
                    stamped = (
                        f"[{datetime.now().strftime('%Y-%m-%d %H:%M')}] "
                        f"Imported from GRC tool. Source ID: {source_id}"
                    )
                    issue.notes.append(stamped)
                    issue.audit_trail.append(
                        AuditEntry(action="grc_import", new_value=f"Source: {source_id}")
                    )
                    data_store.save_issue(issue)

            created_lines.append(
                f"  {issue_id} ← {source_id or 'no source ID'}: "
                f"{create_kwargs['title'][:65]}"
            )
        except Exception as exc:
            label = create_kwargs.get("title", f"Issue {idx}")[:50]
            skipped_lines.append(f"  - '{label}': {exc}")

    lines = [f"Import complete: {len(created_lines)} created, {len(skipped_lines)} skipped.\n"]
    if created_lines:
        lines.append("Created:")
        lines.extend(created_lines)
    if skipped_lines:
        lines.append("\nSkipped:")
        lines.extend(skipped_lines)
    return "\n".join(lines)


# ---------------------------------------------------------------------------
# Dispatcher — routes tool name → implementation
# ---------------------------------------------------------------------------

def dispatch(tool_name: str, tool_input: dict) -> str:
    try:
        if tool_name == "create_issue":
            return create_issue(**tool_input)
        elif tool_name == "get_issue":
            return get_issue(**tool_input)
        elif tool_name == "update_issue":
            return update_issue(**tool_input)
        elif tool_name == "add_note":
            return add_note(**tool_input)
        elif tool_name == "list_issues":
            return list_issues(**tool_input)
        elif tool_name == "check_overdue_issues":
            return check_overdue_issues()
        elif tool_name == "generate_report":
            return generate_report(**tool_input)
        elif tool_name == "close_issue":
            return close_issue(**tool_input)
        elif tool_name == "read_pdf_from_grc":
            return read_pdf_from_grc(**tool_input)
        elif tool_name == "import_extracted_issues":
            return import_extracted_issues(**tool_input)
        elif tool_name == "analyse_issue":
            return analyse_issue(**tool_input)
        elif tool_name == "get_issue_analysis":
            return get_issue_analysis(**tool_input)
        elif tool_name == "update_action_item":
            return update_action_item(**tool_input)
        elif tool_name == "log_checkpoint":
            return log_checkpoint(**tool_input)
        else:
            return f"Unknown tool: {tool_name}"
    except Exception as exc:
        return f"Tool error ({tool_name}): {exc}"
