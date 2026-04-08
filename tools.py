"""
Tool definitions and implementations for the IT Issue Management Agent.

Each tool has:
  - A JSON schema (for Claude's tool use API)
  - An implementation function that returns a plain string result
"""

from __future__ import annotations

import json
from datetime import date, datetime, timedelta
from typing import Any

import data_store
from config import (
    FRAMEWORK_REFERENCES,
    SLA_DAYS,
    ControlDomain,
    IssueType,
    Severity,
    Status,
)
from models import AuditEntry, Issue


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
        else:
            return f"Unknown tool: {tool_name}"
    except Exception as exc:
        return f"Tool error ({tool_name}): {exc}"
