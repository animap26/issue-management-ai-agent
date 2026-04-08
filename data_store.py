"""
JSON file-based data store for issues.
Keeps a single flat JSON file — auditable, portable, no DB dependency.
"""

from __future__ import annotations

import json
import os
from datetime import datetime
from pathlib import Path

from models import AuditEntry, Issue

DATA_FILE = Path(__file__).parent / "data" / "issues.json"


def _load_all() -> dict[str, dict]:
    DATA_FILE.parent.mkdir(parents=True, exist_ok=True)
    if not DATA_FILE.exists():
        DATA_FILE.write_text(json.dumps({}))
    with DATA_FILE.open() as f:
        return json.load(f)


def _save_all(store: dict[str, dict]) -> None:
    DATA_FILE.parent.mkdir(parents=True, exist_ok=True)
    with DATA_FILE.open("w") as f:
        json.dump(store, f, indent=2, default=str)


def save_issue(issue: Issue) -> None:
    store = _load_all()
    store[issue.id] = issue.model_dump()
    _save_all(store)


def get_issue(issue_id: str) -> Issue | None:
    store = _load_all()
    data = store.get(issue_id)
    if data is None:
        return None
    return Issue.model_validate(data)


def get_all_issues() -> list[Issue]:
    store = _load_all()
    return [Issue.model_validate(v) for v in store.values()]


def update_issue(issue_id: str, updates: dict, performed_by: str = "AI Agent") -> Issue | None:
    issue = get_issue(issue_id)
    if issue is None:
        return None

    issue.updated_date = datetime.now().isoformat()

    for field, new_value in updates.items():
        if not hasattr(issue, field):
            continue
        old_value = getattr(issue, field)
        setattr(issue, field, new_value)
        issue.audit_trail.append(
            AuditEntry(
                action="field_update",
                field=field,
                old_value=str(old_value) if old_value is not None else None,
                new_value=str(new_value) if new_value is not None else None,
                performed_by=performed_by,
            )
        )

    save_issue(issue)
    return issue


def delete_issue(issue_id: str) -> bool:
    store = _load_all()
    if issue_id not in store:
        return False
    del store[issue_id]
    _save_all(store)
    return True


def filter_issues(
    status: str | None = None,
    severity: str | None = None,
    domain: str | None = None,
    owner: str | None = None,
    issue_type: str | None = None,
    overdue_only: bool = False,
    sox_only: bool = False,
) -> list[Issue]:
    issues = get_all_issues()

    if status:
        issues = [i for i in issues if i.status.lower() == status.lower()]
    if severity:
        issues = [i for i in issues if i.severity.lower() == severity.lower()]
    if domain:
        issues = [i for i in issues if domain.lower() in i.control_domain.lower()]
    if owner:
        issues = [i for i in issues if i.owner and owner.lower() in i.owner.lower()]
    if issue_type:
        issues = [i for i in issues if issue_type.lower() in i.issue_type.lower()]
    if overdue_only:
        issues = [i for i in issues if i.is_overdue()]
    if sox_only:
        issues = [i for i in issues if i.is_sox_relevant]

    return issues


def next_issue_id() -> str:
    store = _load_all()
    if not store:
        return "IIT-0001"
    existing = [k for k in store if k.startswith("IIT-")]
    if not existing:
        return "IIT-0001"
    nums = [int(k.split("-")[1]) for k in existing]
    return f"IIT-{max(nums) + 1:04d}"
