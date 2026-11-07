"""
Shared utilities for AssemblyAI TTS pentest scripts.
API key is NEVER stored here — always read from environment.
"""
import os
import sys
import json
import hashlib
import datetime
import re

BASE_US = "https://tts.us.assemblyai.com/v1"
BASE_EU = "https://tts.eu.assemblyai.com/v1"
WS_US   = "wss://tts.us.assemblyai.com/v1/ws"
WS_EU   = "wss://tts.eu.assemblyai.com/v1/ws"

FINDINGS = []


def get_api_key() -> str:
    key = os.environ.get("ASSEMBLYAI_API_KEY", "")
    if not key:
        env_file = os.path.join(os.path.dirname(os.path.abspath(__file__)), ".env")
        if os.path.exists(env_file):
            try:
                with open(env_file) as f:
                    for line in f:
                        line = line.strip()
                        if line.startswith("ASSEMBLYAI_API_KEY="):
                            key = line.split("=", 1)[1].strip().strip('"').strip("'")
                            os.environ["ASSEMBLYAI_API_KEY"] = key
                            break
            except Exception:
                pass
    if not key:
        print("[ERROR] ASSEMBLYAI_API_KEY environment variable is not set.")
        print("        Set it with:  $env:ASSEMBLYAI_API_KEY = 'your_key'  (PowerShell)")
        sys.exit(1)
    return key


def get_api_key_b() -> str:
    key_b = os.environ.get("ASSEMBLYAI_API_KEY_B", "")
    if not key_b:
        env_file = os.path.join(os.path.dirname(os.path.abspath(__file__)), ".env")
        if os.path.exists(env_file):
            try:
                with open(env_file) as f:
                    for line in f:
                        line = line.strip()
                        if line.startswith("ASSEMBLYAI_API_KEY_B="):
                            key_b = line.split("=", 1)[1].strip().strip('"').strip("'")
                            os.environ["ASSEMBLYAI_API_KEY_B"] = key_b
                            break
            except Exception:
                pass
    return key_b


def redact(text: str) -> str:
    """
    Replace any occurrence of the real API key (or any prefix ≥8 chars of it)
    with ***redacted***, so partial key variants in fuzz cases are also hidden.
    Also redacts any standalone 32-char hex string.
    """
    key = os.environ.get("ASSEMBLYAI_API_KEY", "")
    s = str(text)
    if key:
        # Redact the full key
        s = s.replace(key, "***redacted***")
        # Redact any prefix of the key that is ≥ 8 characters
        for length in range(len(key) - 1, 7, -1):
            partial = key[:length]
            if partial in s:
                s = s.replace(partial, "***redacted***")
    # Catch any other bare 32-char hex string not already replaced
    s = re.sub(r'[0-9a-f]{32}', '***redacted***', s, flags=re.IGNORECASE)
    return s


def log_request(label: str, method: str, url: str, headers: dict,
                body, response=None, extra: str = ""):
    """Log one request/response pair to stdout and to the FINDINGS log."""
    ts = datetime.datetime.utcnow().isoformat() + "Z"
    safe_headers = {k: redact(v) for k, v in headers.items()}

    entry = {
        "timestamp": ts,
        "label": label,
        "method": method,
        "url": url,
        "request_headers": safe_headers,
        "request_body": body,
    }
    if response is not None:
        entry["response_status"] = response.status_code
        entry["response_headers"] = dict(response.headers)
        raw = response.text or ""
        entry["response_body_hash"] = hashlib.sha256(raw.encode()).hexdigest()
        entry["response_body_excerpt"] = redact(raw[:300])
    if extra:
        entry["notes"] = extra

    print(json.dumps(entry, indent=2))
    return entry


def add_finding(title: str, severity: str, endpoint: str,
                reproduce: str, impact: str, remediation: str,
                evidence=None, section: str = ""):
    finding = {
        "title": title,
        "severity": severity,
        "endpoint": endpoint,
        "section": section,
        "steps_to_reproduce": reproduce,
        "impact": impact,
        "remediation": remediation,
        "evidence": evidence or {},
    }
    FINDINGS.append(finding)
    print("\n" + "="*70)
    print(f"[FINDING] [{severity.upper()}] {title}")
    print(f"  Endpoint : {endpoint}")
    print(f"  Impact   : {impact}")
    print(f"  Fix      : {remediation}")
    print("="*70 + "\n")
    return finding


def save_findings(path: str = "findings.json", section: str = ""):
    """Save findings JSON and regenerate the live markdown report."""
    # Tag every finding with its section if not already set
    if section:
        for f in FINDINGS:
            if not f.get("section"):
                f["section"] = section

    # Write the per-script JSON (resolve relative paths to script dir)
    script_dir = os.path.dirname(os.path.abspath(__file__))
    full_path = os.path.join(script_dir, path) if not os.path.isabs(path) else path
    with open(full_path, "w") as fh:
        json.dump(FINDINGS, fh, indent=2)
    print(f"\n[+] {len(FINDINGS)} finding(s) written to {path}")

    # Regenerate the live report from all findings_*.json files
    try:
        import sys
        if script_dir not in sys.path:
            sys.path.insert(0, script_dir)
        from report_writer import regenerate_report
        regenerate_report(section_just_completed=section)
        print(f"[REPORT] Live report updated -> {os.path.join(script_dir, 'PENTEST_REPORT.md')}")
    except Exception as e:
        print(f"[!] Could not update live report: {e}")


def get_default_voice_id() -> str:
    """Return configured or discovered voice_id."""
    if os.environ.get("ASSEMBLYAI_VOICE_ID"):
        return os.environ["ASSEMBLYAI_VOICE_ID"]
    v_file = os.path.join(os.path.dirname(os.path.abspath(__file__)), "voice_id.txt")
    if os.path.exists(v_file):
        try:
            with open(v_file) as f:
                vid = f.read().strip()
                if vid:
                    return vid
        except Exception:
            pass
    return "01a1b59b-a5e9-753e-b832-29c1b8da324f"


def baseline_body(voice_id: str = None):
    """
    Minimal valid TTS HTTP request body for baseline/control requests.
    Valid containers: 'raw' or 'wav'.
    """
    if voice_id is None:
        voice_id = get_default_voice_id()
    return {
        "text": "Hello, this is an authorized security test.",
        "voice_id": voice_id,
        "container": "wav",
    }
