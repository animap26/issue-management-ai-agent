"""
IT Control Deficiency & Self-Identified Issue (SII) Management Agent
First Line of Risk — AI-assisted issue tracking and remediation

Usage:
    python agent.py                          # interactive mode
    python agent.py --pdf /path/to/export.pdf  # load a GRC PDF at startup

Requires:
    ANTHROPIC_API_KEY environment variable set.
"""

from __future__ import annotations

import argparse
import base64
import os
import sys
from pathlib import Path

import anthropic

import tools as tool_lib

MODEL = "claude-opus-4-6"

SYSTEM_PROMPT = """You are an AI assistant supporting the Risk Analyst in the First Line of Risk team. \
Your primary role is to help the risk analyst analyse IT control deficiencies and self-identified \
issues (SIIs), prepare analysis work products for review with first-line technical teams, and \
track remediation through structured checkpoint reviews.

## How Issues Enter the Process

Issues come from two sources:
1. **GRC-logged issues** — raised by the second line risk oversight team, Internal Audit, \
or Third Party Risk Management in platforms such as ServiceNow or Archer. The risk analyst \
uploads the PDF export for you to analyse.
2. **Self-identified issues (SIIs)** — proactively identified and reported by the first-line \
technical teams listed below.

## First-Line Technical Teams
- **Infrastructure Services** — owns Infrastructure & Networks, IT Operations, Incident Management
- **Application Development** — owns Software Development, Change Management
- **Service Continuity & Disaster Recovery** — owns Business Continuity & DR
- **Information Security** — owns Information Security, Access Management, Data Management
- **Third Party Risk Management** — owns Vendor Management

## Your Core Workflow

### Step 1 — Intake
- For GRC PDF: read_pdf_from_grc → preview → confirm → import_extracted_issues
- For SII: gather details interactively → create_issue

### Step 2 — Analysis (for every issue)
Call analyse_issue to generate the work product the risk analyst brings to the first-line team:
- **Problem Statement** — what the issue is, why it matters, what is at risk
- **Control Impact Analysis** — which IT controls are compromised, mapped to SOX ITGC / \
COBIT / ISO 27001 / NIST CSF
- **Recommended Action Plan** — specific remediation steps, suggested first-line team \
ownership, priorities, and timelines

After generating the analysis, summarise it clearly for the risk analyst and \
suggest scheduling the first checkpoint review with the relevant first-line team.

### Step 3 — Checkpoint Reviews
The risk analyst meets with the first-line team to review the analysis and agree on actions. \
Record every review with log_checkpoint:
- Who attended (risk analyst + first-line team members)
- What was discussed and decided
- Agreed actions with owners and dates
- Next checkpoint date

After logging, update any action items that were agreed using update_action_item.

### Step 4 — Progress Tracking Between Checkpoints
- Use update_action_item to reflect progress reported by the first-line team
- Use check_overdue_issues to surface anything slipping
- Use get_issue_analysis before each checkpoint to prepare a status briefing

### Step 5 — Closure
Only close an issue (close_issue) when:
- All action items are Completed
- Documented evidence of remediation exists
- For SOX-relevant issues: validation has been performed by the risk analyst

## Behavioural Rules
1. **Analysis before action** — never just log an issue and leave it. Always offer to run \
analyse_issue immediately after an issue is created or imported.
2. **Checkpoint discipline** — remind the risk analyst to schedule the next checkpoint. \
Issues without a checkpoint within 14 days of analysis should be flagged.
3. **No autonomous closure** — always require evidence. Never close without it.
4. **Human confirmation for Critical/SOX** — for Critical severity or SOX-relevant issues, \
state the action you are about to take and wait for confirmation.
5. **Precise framework mapping** — every control impact must reference the correct SOX ITGC \
category, COBIT process, and ISO 27001 clause.
6. **Concise and professional** — output is suitable for a risk/compliance audience and \
appropriate to share in review meetings.

## Available Tools
- create_issue — log a new deficiency or SII
- get_issue — retrieve full issue details
- update_issue — update fields on an issue
- add_note — append a timestamped note
- list_issues — filter and list issues
- check_overdue_issues — scan and flag overdue items
- generate_report — summary / SOX / overdue / by-domain / full register reports
- close_issue — close with documented evidence
- read_pdf_from_grc — extract issues from a GRC tool PDF export
- import_extracted_issues — bulk-create issues from extracted PDF data
- analyse_issue — generate problem statement, control impacts, and action plan
- get_issue_analysis — view current analysis, action plan status, and checkpoint history
- update_action_item — update status/owner/date on a specific action item
- log_checkpoint — record a review meeting outcome

Begin each session by offering to run a quick status check (overdue scan + summary report) \
unless the user immediately starts with a specific request."""


def run_agent_turn(
    client: anthropic.Anthropic,
    messages: list[dict],
) -> str:
    """
    Run one full agentic turn: call Claude, execute any tool calls,
    loop until Claude produces a final text response.
    Returns the final assistant text.
    """
    while True:
        # Use streaming to handle potentially long report outputs
        with client.messages.stream(
            model=MODEL,
            max_tokens=4096,
            thinking={"type": "adaptive"},
            system=SYSTEM_PROMPT,
            tools=tool_lib.TOOL_SCHEMAS,
            messages=messages,
        ) as stream:
            response = stream.get_final_message()

        # Append assistant response to history
        messages.append({"role": "assistant", "content": response.content})

        if response.stop_reason == "end_turn":
            # Extract the final text
            text_blocks = [b.text for b in response.content if b.type == "text"]
            return "\n".join(text_blocks)

        if response.stop_reason != "tool_use":
            # Unexpected stop reason — surface as text
            text_blocks = [b.text for b in response.content if b.type == "text"]
            return "\n".join(text_blocks) or f"[Stopped: {response.stop_reason}]"

        # Execute all tool calls and collect results
        tool_results = []
        for block in response.content:
            if block.type != "tool_use":
                continue

            print(f"\n  [tool] {block.name}({_summarise_input(block.input)})")
            result = tool_lib.dispatch(block.name, block.input)
            print(f"  [result] {result[:120]}{'...' if len(result) > 120 else ''}")

            tool_results.append(
                {
                    "type": "tool_result",
                    "tool_use_id": block.id,
                    "content": result,
                }
            )

        messages.append({"role": "user", "content": tool_results})


def _summarise_input(input_dict: dict) -> str:
    """Compact single-line summary of tool input for console display."""
    pairs = []
    for k, v in list(input_dict.items())[:4]:
        val = str(v)[:40].replace("\n", " ")
        pairs.append(f"{k}={val!r}")
    suffix = ", ..." if len(input_dict) > 4 else ""
    return ", ".join(pairs) + suffix


def _build_pdf_message(pdf_path: Path, prompt: str) -> dict:
    """
    Construct a user message that embeds a PDF as a document block
    so Claude can read it natively alongside the text prompt.
    """
    with pdf_path.open("rb") as f:
        pdf_b64 = base64.standard_b64encode(f.read()).decode()

    return {
        "role": "user",
        "content": [
            {
                "type": "document",
                "source": {
                    "type": "base64",
                    "media_type": "application/pdf",
                    "data": pdf_b64,
                },
                "title": pdf_path.name,
            },
            {"type": "text", "text": prompt},
        ],
    }


def _parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="IT Issue Management Agent — First Line of Risk"
    )
    parser.add_argument(
        "--pdf",
        metavar="FILE",
        help="Path to a GRC tool PDF export to import at startup.",
    )
    return parser.parse_args()


def main() -> None:
    args = _parse_args()

    api_key = os.environ.get("ANTHROPIC_API_KEY")
    if not api_key:
        print("Error: ANTHROPIC_API_KEY environment variable is not set.")
        sys.exit(1)

    client = anthropic.Anthropic(api_key=api_key)
    messages: list[dict] = []

    print("=" * 60)
    print("  IT Issue Management Agent — First Line of Risk")
    print("=" * 60)
    print("Type your message below. Commands: 'quit' to exit.\n")

    if args.pdf:
        # PDF import mode — embed the PDF in the opening message
        pdf_path = Path(args.pdf).expanduser().resolve()
        if not pdf_path.exists():
            print(f"Error: PDF not found: {pdf_path}")
            sys.exit(1)
        if pdf_path.suffix.lower() != ".pdf":
            print(f"Error: File is not a PDF: {pdf_path}")
            sys.exit(1)

        print(f"Loading GRC export: {pdf_path.name}\n")
        opening_msg = _build_pdf_message(
            pdf_path,
            (
                "This is an IT issue export from our GRC tool. "
                "Please extract all issues from this document, present me a preview table "
                "(ID, title, severity, domain, GRC source ID), highlight any Critical or "
                "SOX-relevant items, then ask for my confirmation before importing."
            ),
        )
    else:
        # Standard mode — status check on startup
        print("Agent initialising — running status check...\n")
        opening_msg = {
            "role": "user",
            "content": "Run a quick status check: scan for overdue issues and give me a summary report.",
        }

    messages.append(opening_msg)
    response = run_agent_turn(client, messages)
    print(f"\nAgent: {response}\n")

    # Interactive loop
    while True:
        try:
            user_input = input("You: ").strip()
        except (EOFError, KeyboardInterrupt):
            print("\nExiting.")
            break

        if not user_input:
            continue
        if user_input.lower() in ("quit", "exit", "q"):
            print("Goodbye.")
            break

        messages.append({"role": "user", "content": user_input})
        response = run_agent_turn(client, messages)
        print(f"\nAgent: {response}\n")


if __name__ == "__main__":
    main()
