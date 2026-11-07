"""
§5 — Rate Limiting, Billing & Resource Abuse Tests
AssemblyAI TTS Pentest | Run with: python 05_billing.py

Requires:  pip install requests
Key must be in environment:  $env:ASSEMBLYAI_API_KEY = "your_key"
NOTE: Run only during the approved test window — these tests generate real API load.
"""
import os
import sys
import requests
import time

sys.path.insert(0, os.path.dirname(__file__))
from utils import (
    get_api_key, log_request, add_finding, save_findings,
    BASE_US, baseline_body, redact
)

ENDPOINT = f"{BASE_US}/speech"


def post_text(label: str, key: str, text: str, description: str = "") -> tuple:
    body = {**baseline_body(), "text": text}
    hdrs = {"Authorization": key, "Content-Type": "application/json"}
    try:
        r = requests.post(ENDPOINT, headers=hdrs, json=body, timeout=35)
        billed = r.headers.get("x-tts-billed-characters", "N/A")
        log_request(label, "POST", ENDPOINT, hdrs, body, r, extra=description)
        print(f"  {label:<40} status={r.status_code}  billed={billed}  sent={len(text)}")
        return r, billed
    except Exception as e:
        print(f"  {label:<40} ERROR: {e}")
        class _FakeResp:
            status_code = -1
            headers = {}
            content = b""
            text = str(e)
        return _FakeResp(), "N/A"


# ---------------------------------------------------------------------------
# B1 — Billing character count accuracy
# ---------------------------------------------------------------------------
def test_billing_accuracy(key: str):
    print("\n[*] B1 — Billing accuracy checks")
    cases = [
        ("billing_plain_ascii",   "Hello World",           "Plain ASCII — expect 11"),
        ("billing_unicode_2byte",  "café",                  "Unicode — Python len=4, bytes=5; expect 4 chars billed"),
        ("billing_emoji",          "Hello 😀 World",        "Emoji (4-byte codepoint) — expect chars not bytes"),
        ("billing_zwsp",           "Hello\u200bWorld",      "Zero-width space — should it count?"),
        ("billing_whitespace_only","   \t  ",               "Whitespace only — expect 0 or error"),
        ("billing_repeated_text",  "ha" * 500,              "1000 chars (repeated) — expect 1000"),
        ("billing_markup_in_text", "<b>Hello</b>",          "HTML-like markup — are tags billed?"),
    ]
    discrepancies = []
    for label, text, desc in cases:
        r, billed = post_text(label, key, text, desc)
        if r.status_code == 200 and billed != "N/A":
            actual_chars = len(text)
            try:
                billed_int = int(billed)
                if billed_int != actual_chars:
                    discrepancies.append((label, actual_chars, billed_int, text))
            except ValueError:
                pass

    if discrepancies:
        for label, sent, billed, text in discrepancies:
            add_finding(
                title=f"Billing discrepancy: sent {sent} chars, billed {billed} — {label}",
                severity="Medium",
                endpoint=f"POST {ENDPOINT}",
                reproduce=f'Send text: "{text[:50]}..." — x-tts-billed-characters={billed}, len(text)={sent}',
                impact="Customers may be over- or under-billed; under-billing is an abuse vector.",
                remediation="Audit billing logic against Unicode normalization, whitespace, and markup handling.",
            )


# ---------------------------------------------------------------------------
# B2 — Cancelled request still billed?
# ---------------------------------------------------------------------------
def test_cancel_billing(key: str):
    print("\n[*] B2 — Cancel billing (requires WebSocket — see 04_websocket.py for WS cancel)")
    print("  [i] For HTTP: check if a request that errors server-side is billed.")
    # Trigger a likely-to-fail request (empty text) and see if billed_chars is set
    body = {**baseline_body(), "text": ""}
    hdrs = {"Authorization": key, "Content-Type": "application/json"}
    r = requests.post(ENDPOINT, headers=hdrs, json=body, timeout=20)
    billed = r.headers.get("x-tts-billed-characters", "N/A")
    log_request("cancel_empty_text", "POST", ENDPOINT, hdrs, body, r)
    print(f"  Empty-text request: status={r.status_code}  billed={billed}")
    if r.status_code != 200 and billed not in ("N/A", "0", None):
        add_finding(
            title="Failed HTTP request returns non-zero billed_characters",
            severity="High",
            endpoint=f"POST {ENDPOINT}",
            reproduce='Send {"text": ""} — receives error status but x-tts-billed-characters is non-zero.',
            impact="Customers are charged for requests that produced no audio.",
            remediation="Set billed_characters=0 for requests that fail before audio generation begins.",
        )


# ---------------------------------------------------------------------------
# B3 — Rate limit probing (10 rapid sequential requests — not a DoS test)
# ---------------------------------------------------------------------------
def test_rate_limit_probe(key: str):
    print("\n[*] B3 — Rate limit probe (10 sequential requests — not a load test)")
    statuses = []
    for i in range(10):
        body = {**baseline_body(), "text": f"Rate limit test request number {i+1}"}
        hdrs = {"Authorization": key, "Content-Type": "application/json"}
        r = requests.post(ENDPOINT, headers=hdrs, json=body, timeout=30)
        statuses.append(r.status_code)
        print(f"  Request {i+1:>2}: status={r.status_code}  retry-after={r.headers.get('retry-after','N/A')}")
        time.sleep(0.2)  # 200ms between requests — polite probing

    if 429 in statuses:
        idx = statuses.index(429)
        print(f"[+] Rate limit hit at request #{idx+1} — rate limiting IS enforced")
    else:
        print("[i] No 429 seen in 10 sequential requests — limit may be higher or not enforced at this rate")
        add_finding(
            title="Rate limiting not observed in 10 sequential requests",
            severity="Informational",
            endpoint=f"POST {ENDPOINT}",
            reproduce="Send 10 POST /v1/speech requests sequentially with 200ms gaps; no 429 received.",
            impact="Rate limit threshold is unknown; may be absent or very high.",
            remediation="Confirm rate limits are configured and appropriate for the account tier.",
        )


# ---------------------------------------------------------------------------
# B4 — Compute amplification probe (short text → long audio)
# ---------------------------------------------------------------------------
def test_compute_amplification(key: str):
    print("\n[*] B4 — Compute amplification (pathological text)")
    amp_cases = [
        ("amp_numbers",    "one two three four five six seven eight nine ten " * 20,
                          "Number-heavy text × 20 — may be slow to synthesise"),
        ("amp_punctuation","Hello... World... " * 50,
                          "Repeated ellipses — pause-heavy"),
        ("amp_mixed_lang", "The price is $1,234.56 on 03/07/2024 at 10:00 AM. " * 20,
                          "Numbers, dates, currency — heavy normalisation load"),
    ]
    for label, text, desc in amp_cases:
        start = time.time()
        r, billed = post_text(label, key, text, desc)
        elapsed = time.time() - start
        content_len = len(r.content) if r.status_code == 200 else 0
        print(f"    elapsed={elapsed:.1f}s  audio_bytes={content_len}")

        if elapsed > 15:
            add_finding(
                title=f"Compute amplification: {label} took {elapsed:.1f}s",
                severity="Low",
                endpoint=f"POST {ENDPOINT}",
                reproduce=f"POST with text: '{text[:80]}...' — response took {elapsed:.1f}s",
                impact="Pathological inputs consume disproportionate server resources.",
                remediation="Add server-side synthesis time limits; meter complex normalisation tasks.",
            )


# ---------------------------------------------------------------------------
# MAIN
# ---------------------------------------------------------------------------
if __name__ == "__main__":
    key = get_api_key()
    print(f"[*] Target endpoint : {ENDPOINT}")
    print(f"[*] Key loaded      : ***redacted*** ({len(key)} chars)")
    print("[!] Running billing tests — these make real API calls and may consume quota")

    test_billing_accuracy(key)
    test_cancel_billing(key)
    test_rate_limit_probe(key)
    test_compute_amplification(key)
    save_findings("findings_05_billing.json", section="§5 Rate Limiting, Billing & Resource Abuse")
