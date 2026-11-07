"""
§1 — Authentication & Authorization Tests
AssemblyAI TTS Pentest | Run with: python 01_auth_fuzzing.py

Requires:  pip install requests httpx
Key must be in environment:  $env:ASSEMBLYAI_API_KEY = "your_key"
"""
import os
import sys
import requests

try:
    import httpx  # used for edge-case headers that requests rejects client-side
    HAS_HTTPX = True
except ImportError:
    HAS_HTTPX = False

sys.path.insert(0, os.path.dirname(__file__))
from utils import (
    get_api_key, log_request, add_finding, save_findings,
    BASE_US, baseline_body, redact
)

ENDPOINT = f"{BASE_US}/speech"
VOICES_ENDPOINT = f"{BASE_US}/voices"


# ---------------------------------------------------------------------------
# Step 0 — Discover a valid voice ID so the baseline body works
# ---------------------------------------------------------------------------
def discover_voice_id(key: str) -> str:
    """Call the voices listing endpoint and return the first available voice_id."""
    try:
        r = requests.get(
            VOICES_ENDPOINT,
            headers={"Authorization": key},
            timeout=10,
        )
        print(f"[*] GET {VOICES_ENDPOINT} → {r.status_code}")
        if r.status_code == 200:
            data = r.json()
            # Response is typically {"voices": [...]} or a list directly
            voices = data.get("voices", data) if isinstance(data, dict) else data
            if voices:
                first = voices[0]
                vid = first.get("voice_id") or first.get("id") or str(first)
                print(f"[+] Using voice_id: {vid}")
                return vid
        print(f"[!] Could not list voices ({r.status_code}): {redact(r.text[:200])}")
    except Exception as e:
        print(f"[!] Voice discovery error: {e}")

    # Fallback: try known AssemblyAI stock voice names from their docs
    for fallback in ["alloy", "shimmer", "nova", "echo", "fable", "onyx",
                     "en-US-Standard-A", "default"]:
        print(f"[*] Trying fallback voice_id: {fallback}")
        body = {**baseline_body(), "voice_id": fallback}
        r = requests.post(
            ENDPOINT,
            headers={"Authorization": key, "Content-Type": "application/json"},
            json=body,
            timeout=15,
        )
        if r.status_code == 200:
            print(f"[+] Valid voice_id found: {fallback}")
            return fallback
        print(f"    {fallback}: {r.status_code} — {redact(r.text[:100])}")

    print("[!] Could not find a valid voice_id automatically.")
    print("    Check https://www.assemblyai.com/docs/api-reference/tts/list-voices")
    print("    Then set ASSEMBLYAI_VOICE_ID in your environment and re-run.")
    return os.environ.get("ASSEMBLYAI_VOICE_ID", "alloy")  # best guess


def run_request(label: str, headers: dict, params: dict = None,
                body: dict = None, description: str = "",
                voice_id: str = "alloy") -> requests.Response:
    """Send one POST to the speech endpoint and log it."""
    b = body if body is not None else {**baseline_body(), "voice_id": voice_id}
    # Sanitise headers dict for logging (redact all values)
    safe_hdrs = {k: redact(v) for k, v in headers.items()}
    try:
        r = requests.post(ENDPOINT, headers=headers, params=params, json=b, timeout=20)
        log_request(label, "POST", ENDPOINT, safe_hdrs, b, r, extra=description)
        return r
    except requests.exceptions.InvalidHeader as exc:
        # requests rejects some malformed headers client-side before sending.
        # Fall back to httpx which is more permissive, or record the fact.
        print(f"  [{label}] requests rejected header client-side: {exc}")
        if HAS_HTTPX:
            return _run_httpx(label, headers, params, b, description, safe_hdrs)
        else:
            print(f"  [{label}] Install httpx to test this case server-side: pip install httpx")
            # Return a dummy response-like object so callers don't crash
            class _FakeResp:
                status_code = -1
                text = f"CLIENT_SIDE_REJECT: {exc}"
                headers = {}
                content = b""
            log_request(label, "POST", ENDPOINT, safe_hdrs, b, extra=f"CLIENT_SIDE_REJECT: {exc}")
            return _FakeResp()


def _run_httpx(label: str, headers: dict, params: dict, body: dict,
               description: str, safe_hdrs: dict):
    """Use httpx (less strict header validation) for edge-case header tests."""
    try:
        with httpx.Client(verify=True, timeout=20) as client:
            r_hx = client.post(ENDPOINT, headers=headers, params=params or {},
                               json=body)
        # Wrap httpx response to look like a requests.Response for logging
        class _Wrap:
            status_code = r_hx.status_code
            text = r_hx.text
            headers = dict(r_hx.headers)
            content = r_hx.content
        w = _Wrap()
        log_request(label, "POST", ENDPOINT, safe_hdrs, body, w,
                    extra=f"[via httpx] {description}")
        return w
    except Exception as e:
        print(f"  [{label}] httpx also failed: {e}")
        class _FakeResp:
            status_code = -1
            text = str(e)
            headers = {}
            content = b""
        return _FakeResp()


# ---------------------------------------------------------------------------
# 3a — BASELINE (confirm key works)
# ---------------------------------------------------------------------------
def test_baseline(key: str, voice_id: str):
    print("\n[*] 3a — Baseline request")
    hdrs = {"Authorization": key, "Content-Type": "application/json"}
    body = {**baseline_body(), "voice_id": voice_id}
    r = run_request("baseline", hdrs, body=body, voice_id=voice_id,
                    description="Normal valid request — should return 200 + audio")
    if r.status_code == 200:
        print("[+] Baseline PASSED — key is valid")
        for h in ["x-tts-model", "x-tts-voice-id", "x-tts-billed-characters",
                  "x-request-id", "x-tts-region", "content-type"]:
            val = r.headers.get(h, "(not present)")
            print(f"    {h}: {val}")

        # --- Analyse baseline response headers for additional findings ---

        # F-BL-1: x-tts-unknown-params — API silently ignoring request fields
        unknown = r.headers.get("x-tts-unknown-params", "")
        if unknown:
            add_finding(
                title=f"API silently ignores unrecognised request parameters (x-tts-unknown-params: {unknown})",
                severity="Low",
                endpoint=f"POST {ENDPOINT}",
                reproduce=(
                    f"POST with 'output_format' nested object in body.\n"
                    f"Response contains x-tts-unknown-params: {unknown}\n"
                    f"Server used its own defaults (pcm_s16le/24000Hz) instead of requested format."
                ),
                impact=(
                    "Silent parameter ignorance makes it impossible for clients to know "
                    "their format preferences were not applied — leading to unexpected audio "
                    "formats, potential billing confusion, and masking of future parameter "
                    "injection attempts that also go silently ignored."
                ),
                remediation=(
                    "Return a 400 error (or at minimum a warning field in the response body) "
                    "when unrecognised parameters are supplied. Never silently ignore request fields."
                ),
                evidence={"x-tts-unknown-params": unknown,
                          "requested": "container=mp3, encoding=mp3, sample_rate=22050",
                          "actual": r.headers.get("content-type", "")},
            )

        # F-BL-2: server-timing exposes internal processing breakdown
        srv_timing = r.headers.get("server-timing", "")
        if srv_timing:
            add_finding(
                title="server-timing header exposes internal processing stage durations",
                severity="Informational",
                endpoint=f"POST {ENDPOINT}",
                reproduce=(
                    f"Any successful POST. Response contains:\n"
                    f"server-timing: {srv_timing}"
                ),
                impact=(
                    "Leaks internal architecture: stage names (open, model, ttfa = time-to-first-audio) "
                    "and durations. Enables timing oracle attacks — e.g. comparing 'model' duration "
                    "across voice IDs or text inputs to infer model internals or enumerate voice existence."
                ),
                remediation=(
                    "Remove server-timing from API responses, or strip internal stage names "
                    "if aggregate timing must be exposed for diagnostics."
                ),
                evidence={"server-timing": srv_timing},
            )

        # F-BL-3: x-tts-voice-expires-at leaks voice token expiry
        voice_exp = r.headers.get("x-tts-voice-expires-at", "")
        if voice_exp:
            import datetime as _dt
            try:
                exp_dt = _dt.datetime.utcfromtimestamp(int(voice_exp)).isoformat() + "Z"
            except Exception:
                exp_dt = voice_exp
            add_finding(
                title="x-tts-voice-expires-at header leaks voice access token expiry timestamp",
                severity="Informational",
                endpoint=f"POST {ENDPOINT}",
                reproduce=(
                    f"Any successful POST with a valid voice_id returns:\n"
                    f"x-tts-voice-expires-at: {voice_exp}  (= {exp_dt})"
                ),
                impact=(
                    "Discloses the internal expiry of the voice access credential. "
                    "An attacker who can observe responses can determine the voice's "
                    "lease duration and time attacks accordingly."
                ),
                remediation="Remove x-tts-voice-expires-at from response headers, or only include it in authenticated admin/management endpoints.",
                evidence={"x-tts-voice-expires-at": voice_exp, "decoded": exp_dt},
            )
    else:
        print(f"[!] Baseline FAILED — status {r.status_code}")
        print(f"    Body: {redact(r.text[:300])}")
    return r


# ---------------------------------------------------------------------------
# 3b — AUTH FUZZING
# ---------------------------------------------------------------------------
def test_auth_fuzzing(key: str, voice_id: str):
    print("\n[*] 3b — Auth header fuzzing")

    # Build truncated key variants
    trunc_half = key[:len(key)//2]
    trunc_one  = key[:-1]

    cases = [
        # (label, headers, params, expected_note)
        ("auth_missing_header",
         {"Content-Type": "application/json"},
         None,
         "No Authorization header at all"),

        ("auth_empty_value",
         {"Authorization": "", "Content-Type": "application/json"},
         None,
         "Authorization header present but empty"),

        ("auth_truncated_half",
         {"Authorization": trunc_half, "Content-Type": "application/json"},
         None,
         "Key truncated to half length"),

        ("auth_truncated_one_char",
         {"Authorization": trunc_one, "Content-Type": "application/json"},
         None,
         "Key missing final character"),

        ("auth_leading_whitespace",
         {"Authorization": f" {key}", "Content-Type": "application/json"},
         None,
         "Leading space before key — should 401"),

        ("auth_trailing_whitespace",
         {"Authorization": f"{key} ", "Content-Type": "application/json"},
         None,
         "Trailing space after key"),

        ("auth_bearer_prefix",
         {"Authorization": f"Bearer {key}", "Content-Type": "application/json"},
         None,
         "Bearer prefix — docs say raw key; check if Bearer is silently accepted"),

        ("auth_bearer_lowercase",
         {"Authorization": f"bearer {key}", "Content-Type": "application/json"},
         None,
         "Lowercase bearer prefix"),

        ("auth_wrong_case_key",
         {"Authorization": key.upper(), "Content-Type": "application/json"},
         None,
         "Key uppercased — API keys are usually case-sensitive"),

        ("auth_double_header",
         {"Authorization": key, "Content-Type": "application/json"},
         None,
         "Duplicate Authorization header (sent via manual method below)"),

        ("auth_query_param",
         {"Content-Type": "application/json"},
         {"api_key": key},
         "Key in query string — logging-leak risk if accepted"),

        ("auth_query_param_authorization",
         {"Content-Type": "application/json"},
         {"authorization": key},
         "Key as 'authorization' query param"),

        ("auth_completely_wrong",
         {"Authorization": "thisisnotavalidkeyatall", "Content-Type": "application/json"},
         None,
         "Completely invalid key — note error message wording for oracle"),

        ("auth_all_zeros",
         {"Authorization": "0" * len(key), "Content-Type": "application/json"},
         None,
         "Same-length all-zeros key — different error from truncated?"),
    ]

    results = {}
    for label, headers, params, description in cases:
        r = run_request(label, headers, params, description=description, voice_id=voice_id)
        results[label] = (r.status_code, r.text[:200])

    # --- Analysis ---
    print("\n[*] Auth fuzzing summary:")
    print(f"  {'Label':<35} {'Status':>6}  Auth?  Excerpt")
    print(f"  {'-'*35} {'-'*6}  {'-'*5}  {'-'*40}")
    for label, (status, excerpt) in results.items():
        safe = redact(excerpt).replace('\n', ' ')[:55]
        # 200/422 = auth passed; 401/403 = auth failed; -1 = client-side reject
        if status in (200, 422):
            auth_ok = "PASS"
        elif status in (401, 403):
            auth_ok = "FAIL"
        elif status == -1:
            auth_ok = "N/A"
        else:
            auth_ok = f"?{status}"
        print(f"  {label:<35} {status:>6}  {auth_ok:<5}  {safe}")

    # -----------------------------------------------------------------------
    # Finding: Bearer prefix (and lowercase bearer) silently accepted
    # Auth passed = status 200 (valid voice) OR 422 (voice not found, but auth OK)
    # -----------------------------------------------------------------------
    for label, scheme in [("auth_bearer_prefix", "Bearer"),
                           ("auth_bearer_lowercase", "bearer")]:
        if results.get(label, (999,))[0] in (200, 422):
            add_finding(
                title=f"Authorization: {scheme} <key> accepted (undocumented auth scheme)",
                severity="Medium",
                endpoint=f"POST {ENDPOINT}",
                reproduce=(
                    f"Send: Authorization: {scheme} ***redacted***\n"
                    "Result: 422 voice_not_found (not 401) — auth layer passed."
                ),
                impact=(
                    "Undocumented auth variant accepted server-side. "
                    "If a client mistakenly sends 'Bearer <key>', it still authenticates — "
                    "masking misconfigurations. Also means auth parsing is more permissive "
                    "than documented, increasing the attack surface for auth bypass variants."
                ),
                remediation=(
                    "Explicitly reject keys prefixed with 'Bearer ' if the documented format "
                    "is raw key only, or formally document and test both schemes."
                ),
                evidence={"status": results[label][0],
                          "note": "422=auth passed; 401=auth failed"},
            )

    # -----------------------------------------------------------------------
    # Finding: Trailing whitespace accepted (key silently stripped)
    # -----------------------------------------------------------------------
    if results.get("auth_trailing_whitespace", (999,))[0] in (200, 422):
        add_finding(
            title="Authorization header with trailing whitespace accepted (key silently trimmed)",
            severity="Low",
            endpoint=f"POST {ENDPOINT}",
            reproduce=(
                "Send: Authorization: ***redacted***<SPACE>\n"
                "Result: 422 (auth passed — space was silently stripped server-side)."
            ),
            impact=(
                "Overly-permissive header parsing. Could mask malformed credentials "
                "in client implementations; makes auth behaviour harder to reason about."
            ),
            remediation="Reject keys with surrounding whitespace rather than silently trimming.",
            evidence={"status": results["auth_trailing_whitespace"][0]},
        )

    # -----------------------------------------------------------------------
    # Finding: Duplicate Authorization header accepted
    # -----------------------------------------------------------------------
    if results.get("auth_double_header", (999,))[0] in (200, 422):
        add_finding(
            title="Duplicate Authorization header accepted — behaviour of key selection unspecified",
            severity="Low",
            endpoint=f"POST {ENDPOINT}",
            reproduce=(
                "Send two Authorization headers with the same valid key.\n"
                "Result: 422 (auth passed). It is unclear which header value is selected "
                "when the two headers carry different values."
            ),
            impact=(
                "If the server selects the second (attacker-controlled) header in a "
                "request-smuggling or proxy-forwarding scenario, auth could be bypassed. "
                "Needs further testing with header 1 = valid, header 2 = invalid."
            ),
            remediation="Reject requests that contain more than one Authorization header.",
            evidence={"status": results["auth_double_header"][0]},
        )

    # -----------------------------------------------------------------------
    # Finding: Query-param auth accepted
    # -----------------------------------------------------------------------
    if results.get("auth_query_param", (999,))[0] not in (401, 403, -1):
        add_finding(
            title="API key accepted via query parameter",
            severity="High",
            endpoint=f"POST {ENDPOINT}",
            reproduce=(
                f"Send POST {ENDPOINT}?api_key=***redacted*** without an "
                "Authorization header. Response is not 401."
            ),
            impact=(
                "Keys in URLs are written to web-server access logs, proxy logs, "
                "browser history, and Referer headers — leading to inadvertent credential exposure."
            ),
            remediation="Reject authentication via query parameters; require the Authorization header only.",
            evidence={"status": results["auth_query_param"][0]},
        )

    # -----------------------------------------------------------------------
    # Finding: Oracle — 'missing_authorization' vs 'unauthorized' error codes
    # These ARE different codes (not just different request IDs), which is a real oracle.
    # -----------------------------------------------------------------------
    code_missing = '"code":"missing_authorization"'
    code_unauth  = '"code":"unauthorized"'
    excerpt_missing = results.get("auth_missing_header", (999, ""))[1]
    excerpt_wrong   = results.get("auth_completely_wrong", (999, ""))[1]
    if code_missing in excerpt_missing and code_unauth in excerpt_wrong:
        add_finding(
            title="Auth error codes reveal whether header is absent vs key is wrong (oracle)",
            severity="Informational",
            endpoint=f"POST {ENDPOINT}",
            reproduce=(
                "No Authorization header → code: 'missing_authorization'\n"
                "Wrong/truncated key     → code: 'unauthorized'\n"
                "These distinct codes let an attacker distinguish 'sent no key' "
                "from 'sent a key that was checked and rejected'."
            ),
            impact=(
                "Minor enumeration aid — attacker knows their request reached the auth "
                "check vs being rejected pre-check. Low practical impact on its own."
            ),
            remediation=(
                "Consider returning a single generic error code (e.g. 'unauthorized') "
                "for all auth failures regardless of whether the header was absent or invalid."
            ),
            evidence={
                "missing_header_code": "missing_authorization",
                "wrong_key_code": "unauthorized",
            },
        )

    # -----------------------------------------------------------------------
    # Finding: Backend region leaked in all responses including auth failures
    # -----------------------------------------------------------------------
    # Check if x-tts-region appears in a 401 response
    for label, (status, excerpt) in results.items():
        if status == 401:
            # We logged the full response in the JSON above; note it as informational
            add_finding(
                title="x-tts-region header leaks backend region in all responses (incl. 401)",
                severity="Informational",
                endpoint=f"POST {ENDPOINT}",
                reproduce=(
                    "Any request (even unauthenticated) returns x-tts-region: us-east-1. "
                    "Visible in 401, 422, and 200 responses alike."
                ),
                impact=(
                    "Discloses backend cloud region to unauthenticated callers. "
                    "Useful for targeted infrastructure attacks or latency fingerprinting."
                ),
                remediation=(
                    "Only return x-tts-region in authenticated, successful responses, "
                    "or remove it entirely and convey region through the endpoint URL only."
                ),
                evidence={"header": "x-tts-region: us-east-1"},
            )
            break  # one finding is enough

    return results


# ---------------------------------------------------------------------------
# MAIN
# ---------------------------------------------------------------------------
if __name__ == "__main__":
    key = get_api_key()
    print(f"[*] Target endpoint : {ENDPOINT}")
    print(f"[*] Key loaded      : ***redacted*** ({len(key)} chars)")
    if not HAS_HTTPX:
        print("[!] httpx not installed — edge-case header tests will be noted but not sent.")
        print("    Install with:  pip install httpx")

    # Step 0: discover a valid voice ID before anything else
    voice_id = discover_voice_id(key)

    test_baseline(key, voice_id)
    test_auth_fuzzing(key, voice_id)
    save_findings("findings_01_auth.json")
