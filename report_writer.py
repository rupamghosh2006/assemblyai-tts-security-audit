"""
report_writer.py — Append findings to the live pentest report after each test.

Usage (at the end of every test script):
    from report_writer import append_to_report
    append_to_report(FINDINGS, section="§1 Authentication & Authorization")

The report file is: pentest_report.md (same folder as this script).
It is created on first run and appended to on every subsequent run.
"""
import os
import json
import datetime

REPORT_PATH = os.path.join(os.path.dirname(os.path.abspath(__file__)), "PENTEST_REPORT.md")

SEVERITY_ORDER = ["Critical", "High", "Medium", "Low", "Informational"]
SEVERITY_EMOJI = {
    "Critical":      "🔴",
    "High":          "🟠",
    "Medium":        "🟡",
    "Low":           "🔵",
    "Informational": "⚪",
}


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _now() -> str:
    return datetime.datetime.utcnow().strftime("%Y-%m-%d %H:%M UTC")


def _severity_badge(sev: str) -> str:
    return f"{SEVERITY_EMOJI.get(sev, '❓')} **{sev}**"


def _load_all_findings() -> list:
    """Read every findings_*.json in the script directory and return merged list."""
    script_dir = os.path.dirname(os.path.abspath(__file__))
    all_findings = []
    for fname in sorted(os.listdir(script_dir)):
        if fname.startswith("findings_") and fname.endswith(".json"):
            fpath = os.path.join(script_dir, fname)
            try:
                with open(fpath, encoding="utf-8") as f:
                    data = json.load(f)
                    if isinstance(data, list):
                        all_findings.extend(data)
            except Exception:
                pass
    # Deduplicate by title
    seen = set()
    deduped = []
    for f in all_findings:
        key = f.get("title", "")
        if key not in seen:
            seen.add(key)
            deduped.append(f)
    # Sort by severity
    deduped.sort(key=lambda x: SEVERITY_ORDER.index(x.get("severity", "Informational"))
                 if x.get("severity", "Informational") in SEVERITY_ORDER else 99)
    return deduped


def _build_summary_table(findings: list) -> str:
    counts = {s: 0 for s in SEVERITY_ORDER}
    for f in findings:
        sev = f.get("severity", "Informational")
        if sev in counts:
            counts[sev] += 1
    total = sum(counts.values())

    lines = [
        "| Severity | Count |",
        "|---|---|",
    ]
    for sev in SEVERITY_ORDER:
        if counts[sev]:
            lines.append(f"| {SEVERITY_EMOJI[sev]} {sev} | {counts[sev]} |")
    lines.append(f"| **Total** | **{total}** |")
    return "\n".join(lines)


def _finding_to_md(finding: dict, idx: int) -> str:
    sev   = finding.get("severity", "?")
    title = finding.get("title", "Untitled")
    ep    = finding.get("endpoint", "")
    repro = finding.get("steps_to_reproduce", "")
    impact = finding.get("impact", "")
    fix   = finding.get("remediation", "")
    ev    = finding.get("evidence", {})

    lines = [
        f"### F-{idx:02d} &nbsp; {SEVERITY_EMOJI.get(sev,'❓')} {title}",
        f"- **Severity:** {sev}",
        f"- **Endpoint:** `{ep}`",
        "",
        "**Steps to reproduce:**",
        f"```\n{repro}\n```" if repro else "_See evidence_",
        "",
        f"**Impact:** {impact}",
        "",
        f"**Remediation:** {fix}",
    ]
    if ev:
        lines += ["", "**Evidence:**", "```json", json.dumps(ev, indent=2), "```"]
    lines.append("\n---")
    return "\n".join(lines)


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------

def append_to_report(new_findings: list, section: str):
    """
    Append new_findings from `section` to the live report.
    Regenerates the full findings list + summary from all findings_*.json files.
    """
    # Merge new findings into the right JSON file first (caller already did this via save_findings)
    # Then rebuild the full report
    regenerate_report(section_just_completed=section)
    print(f"\n[REPORT] Report updated -> {REPORT_PATH}")


def regenerate_report(section_just_completed: str = ""):
    """Rebuild the entire pentest_report.md from all findings_*.json files."""
    all_findings = _load_all_findings()
    now = _now()

    lines = [
        "# AssemblyAI TTS — Penetration Test Report",
        "",
        f"> **Status:** In progress &nbsp;|&nbsp; **Last updated:** {now}",
        f"> **Scope:** `tts.us.assemblyai.com` / `tts.eu.assemblyai.com` &nbsp;|&nbsp; "
        f"**Classification:** Internal / Confidential",
        "",
        "---",
        "",
        "## Executive Summary",
        "",
        _build_summary_table(all_findings),
        "",
        "---",
        "",
        "## Sections Completed",
        "",
    ]

    # Track which sections have findings
    section_map = {}
    for f in all_findings:
        sec = f.get("section", "Uncategorised")
        section_map.setdefault(sec, []).append(f)

    completed_sections = [
        ("§1a", "Authentication & Authorization — Header Fuzzing",   "findings_01_auth.json"),
        ("§1b", "Authentication & Authorization — Temporary Tokens", "findings_02_tokens.json"),
        ("§3",  "Input Validation & Injection",                      "findings_03_input.json"),
        ("§4",  "WebSocket Protocol",                                "findings_04_websocket.json"),
        ("§5",  "Rate Limiting, Billing & Resource Abuse",           "findings_05_billing.json"),
        ("§7",  "Infrastructure, TLS & Privacy",                     "findings_06_infra.json"),
        ("§8",  "Cross-Tenant Voice Authorization (IDOR)",           "findings_07_idor.json"),
    ]
    script_dir = os.path.dirname(os.path.abspath(__file__))
    for code, name, fname in completed_sections:
        exists = os.path.exists(os.path.join(script_dir, fname))
        status = "✅ Complete" if exists else "⏳ Pending"
        lines.append(f"- {status} — **{code}** {name}")

    lines += [
        "",
        "---",
        "",
        "## All Findings",
        "",
        "_Sorted by severity. Appended automatically after each test script._",
        "",
    ]

    if not all_findings:
        lines.append("_No findings yet._")
    else:
        for idx, finding in enumerate(all_findings, 1):
            lines.append(_finding_to_md(finding, idx))
            lines.append("")

    lines += [
        "---",
        "",
        "## Raw Evidence",
        "",
        "Full request/response logs are stored in the individual `findings_NN_*.json` files "
        "in the same directory. API keys are redacted in all logs.",
        "",
        "---",
        f"_Report auto-generated by `report_writer.py` · Last run: {now}_",
    ]

    with open(REPORT_PATH, "w", encoding="utf-8") as f:
        f.write("\n".join(lines))


# ---------------------------------------------------------------------------
# CLI usage: python report_writer.py  → rebuild from existing JSON files
# ---------------------------------------------------------------------------
if __name__ == "__main__":
    regenerate_report()
    print(f"[+] Report written to {REPORT_PATH}")
    findings = _load_all_findings()
    print(f"[+] Total findings: {len(findings)}")
