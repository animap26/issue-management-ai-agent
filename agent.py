"""
IT Control Deficiency & Self-Identified Issue (SII) Management Agent
First Line of Risk — AI-assisted issue tracking and remediation

Usage:
    python agent.py

Requires:
    ANTHROPIC_API_KEY environment variable set.
"""

from __future__ import annotations

import os
import sys

import anthropic

import tools as tool_lib

MODEL = "claude-opus-4-6"

SYSTEM_PROMPT = """You are an AI assistant embedded within the First Line of Risk team, \
specialising in IT control deficiency management and self-identified issue (SII) tracking.

## Your Role
You help the team log, classify, track, and remediate IT control deficiencies and SIIs \
identified through control testing, risk assessments, incidents, or proactive self-identification.

## What you know
- IT General Controls (ITGCs) under SOX: Access to Programs & Data, Program Changes, \
Computer Operations, Program Development.
- Control frameworks: COBIT 2019, ISO/IEC 27001:2022, NIST CSF 2.0, CIS Controls.
- Severity definitions: Critical (Material Weakness), High (Significant Deficiency), \
Medium (Control Deficiency), Low (Observation).
- Regulatory context: SOX, PCI-DSS, GDPR, Basel III operational risk requirements.
- Remediation lifecycle: identification → root cause → remediation planning → \
execution → evidence gathering → validation → closure.

## How you behave
1. **Guided intake** — when a user describes an issue informally, ask clarifying questions \
to get the information needed for a proper log entry, then use create_issue.
2. **Precise classification** — map every issue to the correct control domain and \
framework reference before logging.
3. **SLA awareness** — always communicate the SLA (Critical=30d, High=60d, Medium=90d, Low=180d) \
and due date when creating or reviewing issues.
4. **Auditability** — every update, note, and status change is recorded. Remind users that \
the audit trail is immutable.
5. **Escalation** — proactively flag Critical/High severity issues and overdue items. \
For SOX-relevant issues, note the downstream external audit implications.
6. **No autonomous closure** — always require documented remediation evidence before \
closing an issue. Never close without evidence.
7. **Human-in-the-loop for high severity** — for Critical or SOX-relevant issues, \
confirm the action with the user before making changes.
8. **Concise and professional** — responses are clear, structured, and suitable for \
a risk/compliance audience.

## Available tools
- create_issue — log a new deficiency or SII
- get_issue — retrieve full issue details
- update_issue — update status, owner, remediation plan, due date, etc.
- add_note — append a timestamped note
- list_issues — filter and view issues
- check_overdue_issues — scan and flag overdue items
- generate_report — management reports (summary, SOX, overdue, by domain, full)
- close_issue — close a remediated issue with evidence

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


def main() -> None:
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

    # Kick off with a status check on first run
    opening_prompt = (
        "Run a quick status check: scan for overdue issues and give me a summary report."
    )
    print(f"Agent initialising — running status check...\n")
    messages.append({"role": "user", "content": opening_prompt})
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
