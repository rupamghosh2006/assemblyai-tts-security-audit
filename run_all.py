"""
Master runner — runs all pentest scripts in sequence.
AssemblyAI TTS Pentest | Run with: python run_all.py

Requires:  pip install requests websockets
Key must be in environment:  $env:ASSEMBLYAI_API_KEY = "your_key"
"""
import os
import sys
import json
import subprocess
import datetime

SCRIPTS = [
    ("01_auth_fuzzing.py",   "§1 Auth & Authorization"),
    ("02_temp_tokens.py",    "§1 Temporary Token Tests"),
    ("03_input_fuzzing.py",  "§3 Input Validation & Injection"),
    ("04_websocket.py",      "§4 WebSocket Protocol"),
    ("05_billing.py",        "§5 Billing & Rate Limits"),
    ("06_infrastructure.py", "§7 Infrastructure & Privacy"),
    ("07_voice_idor.py",     "§8 Cross-Tenant Voice Authorization"),
]

FINDING_FILES = [
    "findings_01_auth.json",
    "findings_02_tokens.json",
    "findings_03_input.json",
    "findings_04_websocket.json",
    "findings_05_billing.json",
    "findings_06_infra.json",
    "findings_07_idor.json",
]


def merge_findings():
    all_findings = []
    for f in FINDING_FILES:
        if os.path.exists(f):
            with open(f) as fh:
                try:
                    all_findings.extend(json.load(fh))
                except Exception:
                    pass

    # Sort by severity
    order = {"Critical": 0, "High": 1, "Medium": 2, "Low": 3, "Informational": 4}
    all_findings.sort(key=lambda x: order.get(x.get("severity", "Informational"), 99))

    out = "findings_MASTER.json"
    with open(out, "w") as f:
        json.dump(all_findings, f, indent=2)

    print(f"\n{'='*70}")
    print(f"MASTER FINDINGS REPORT — {datetime.datetime.utcnow().isoformat()}Z")
    print(f"{'='*70}")
    counts = {}
    for finding in all_findings:
        s = finding.get("severity", "?")
        counts[s] = counts.get(s, 0) + 1
        print(f"\n[{s.upper()}] {finding['title']}")
        print(f"  Endpoint : {finding.get('endpoint','')}")
        print(f"  Impact   : {finding.get('impact','')}")
        print(f"  Fix      : {finding.get('remediation','')}")

    print(f"\n{'='*70}")
    print("Summary:")
    for severity in ["Critical", "High", "Medium", "Low", "Informational"]:
        n = counts.get(severity, 0)
        if n:
            print(f"  {severity:<15}: {n}")
    print(f"\nTotal findings : {len(all_findings)}")
    print(f"Written to     : {out}")


if __name__ == "__main__":
    if "--merge-only" in sys.argv:
        merge_findings()
        sys.exit(0)

    from utils import get_api_key
    get_api_key()  # Auto-loads from .env if present or checks environment

    script_dir = os.path.dirname(os.path.abspath(__file__))

    for script, section in SCRIPTS:
        print(f"\n{'#'*70}")
        print(f"# Running {section}: {script}")
        print(f"{'#'*70}")

        # 04_websocket.py is interactive (asks about timeout probe) — run it last manually if preferred
        if script == "04_websocket.py":
            print("[i] WebSocket tests are interactive. Run separately:")
            print(f"    python {script}")
            continue

        result = subprocess.run(
            [sys.executable, os.path.join(script_dir, script)],
            env=os.environ.copy(),
            timeout=300,
        )
        if result.returncode != 0:
            print(f"[!] {script} exited with code {result.returncode}")

    merge_findings()
