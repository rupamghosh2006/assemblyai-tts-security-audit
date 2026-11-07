"""
§1 (continued) — Temporary Token Tests
AssemblyAI TTS Pentest | Run with: python 02_temp_tokens.py

Requires:  pip install requests
Key must be in environment:  $env:ASSEMBLYAI_API_KEY = "your_key"
"""
import os
import sys
import time
import requests

sys.path.insert(0, os.path.dirname(__file__))
from utils import (
    get_api_key, log_request, add_finding, save_findings,
    BASE_US, BASE_EU, baseline_body, redact
)

# Real AssemblyAI Token Endpoints
TOKEN_US = "https://token.us.assemblyai.com/v1/token"
TOKEN_EU = "https://token.eu.assemblyai.com/v1/token"
SPEECH_US = f"{BASE_US}/speech"
SPEECH_EU = f"{BASE_EU}/speech"


def safe_json(resp: requests.Response) -> dict:
    try:
        return resp.json()
    except Exception:
        return {"raw_text": resp.text[:300] if resp.text else ""}


def issue_token(key: str, endpoint: str = TOKEN_US, product: str = "tts",
                expires_in_seconds: int = 60, extra_body: dict = None) -> dict:
    """Request a temporary token using master key or another token."""
    body = {
        "product": product,
        "expires_in_seconds": expires_in_seconds
    }
    if extra_body:
        body.update(extra_body)
    try:
        r = requests.post(
            endpoint,
            headers={"Authorization": key, "Content-Type": "application/json"},
            json=body,
            timeout=20,
        )
        parsed = safe_json(r)
        label = f"issue_token_{product}_{endpoint.split('.')[1]}"
        log_request(label, "POST", endpoint,
                    {"Authorization": "***redacted***", "Content-Type": "application/json"},
                    body, r)
        return {"status": r.status_code, "body": parsed, "raw": r}
    except Exception as e:
        print(f"  [!] Request to {endpoint} failed: {e}")
        return {"status": -1, "body": {"error": str(e)}, "raw": None}


# ---------------------------------------------------------------------------
# T1 — Baseline Token Issuance & Synthesis
# ---------------------------------------------------------------------------
def test_token_baseline(key: str):
    print("\n[*] T1 — Baseline temporary token issuance (TTS product)")
    res = issue_token(key, endpoint=TOKEN_US, product="tts", expires_in_seconds=300)
    st = res["status"]
    body = res["body"]

    if st == 200 and body.get("token"):
        tok = body["token"]
        exp = body.get("expires_in_seconds", 300)
        print(f"  [+] Token successfully minted from {TOKEN_US} (TTL: {exp}s)")

        # Verify this token works on the TTS speech endpoint
        r = requests.post(
            SPEECH_US,
            headers={"Authorization": tok, "Content-Type": "application/json"},
            json=baseline_body(),
            timeout=20,
        )
        print(f"  POST {SPEECH_US} with temporary token -> status: {r.status_code}")
        if r.status_code == 200:
            print("  [+] Speech successfully synthesized using temporary token!")
            # Note fingerprinting from token endpoint headers
            srv = res["raw"].headers.get("server", "")
            if srv:
                add_finding(
                    title=f"Token endpoint exposes server implementation ({srv})",
                    severity="Informational",
                    endpoint=f"POST {TOKEN_US}",
                    reproduce=f"Send POST {TOKEN_US} — response header 'server: {srv}'",
                    impact="Discloses internal application server technology stack (uvicorn/ASGI).",
                    remediation="Strip or genericise server response headers at the edge reverse-proxy.",
                    evidence={"server": srv},
                    section="§1b Temporary Tokens",
                )
            return tok
        else:
            print(f"  [!] Speech synthesis returned {r.status_code}: {r.text[:200]}")
            return tok
    else:
        print(f"  [!] Token issuance failed (status {st}): {body}")
        return None


# ---------------------------------------------------------------------------
# T2 — Expiry Enforcement (1-second token)
# ---------------------------------------------------------------------------
def test_expiry(key: str):
    print("\n[*] T2 — Expiry enforcement (1-second token)")
    res = issue_token(key, endpoint=TOKEN_US, product="tts", expires_in_seconds=1)
    if res["status"] != 200 or not res["body"].get("token"):
        print(f"  [!] Could not issue 1-second token (status {res['status']}), skipping")
        return

    token = res["body"]["token"]
    print("  [*] Waiting 4 seconds for 1-second token to expire...")
    time.sleep(4)

    r = requests.post(
        SPEECH_US,
        headers={"Authorization": token, "Content-Type": "application/json"},
        json=baseline_body(),
        timeout=20,
    )
    log_request("expired_token_use", "POST", SPEECH_US,
                {"Authorization": "***redacted***", "Content-Type": "application/json"},
                baseline_body(), r,
                extra="Using token 4s after 1s expiry — should be 401")

    print(f"  Expired token request status: {r.status_code}")
    # 200 or 422 indicates authentication passed! Only 401 means authentication was rejected.
    if r.status_code in (200, 422):
        add_finding(
            title="Expired temporary token accepted by TTS endpoint",
            severity="High",
            endpoint=f"POST {SPEECH_US}",
            reproduce=(
                "1. Mint a temporary token with expires_in_seconds=1 at POST https://token.us.assemblyai.com/v1/token.\n"
                "2. Wait 4 seconds.\n"
                "3. Send POST https://tts.us.assemblyai.com/v1/speech with Authorization: <expired-token>.\n"
                f"Result: {r.status_code} — request authenticated with an expired token instead of 401."
            ),
            impact="Expired client-side temporary tokens remain valid, defeating time-bounded token protections.",
            remediation="Validate token expiration timestamp strictly on every synthesis request server-side.",
            evidence={"status": r.status_code, "body": r.text[:200]},
            section="§1b Temporary Tokens",
        )
    elif r.status_code == 401:
        print(f"  [+] Expired token correctly rejected with 401 Unauthorized (good: expiry enforced)")


# ---------------------------------------------------------------------------
# T3 — Cross-Product Token Reuse (Streaming STT token on TTS endpoint)
# Major test from Master Prompt §1
# ---------------------------------------------------------------------------
def test_cross_product_reuse(key: str):
    print("\n[*] T3 — Cross-product token reuse (Streaming STT token vs TTS endpoint)")
    res = issue_token(key, endpoint=TOKEN_US, product="streaming", expires_in_seconds=300)
    if res["status"] != 200 or not res["body"].get("token"):
        print(f"  [!] Could not issue streaming token (status {res['status']})")
        return

    stt_token = res["body"]["token"]
    print(f"  [+] Minted product='streaming' token. Attempting to use on TTS endpoint...")

    r = requests.post(
        SPEECH_US,
        headers={"Authorization": stt_token, "Content-Type": "application/json"},
        json=baseline_body(),
        timeout=20,
    )
    log_request("cross_product_streaming_token_on_tts", "POST", SPEECH_US,
                {"Authorization": "***redacted***", "Content-Type": "application/json"},
                baseline_body(), r,
                extra="product='streaming' token used on /v1/speech TTS endpoint")

    print(f"  Status: {r.status_code}")
    # If status is 200 or 422, auth layer permitted the STT token to execute TTS
    if r.status_code in (200, 422):
        add_finding(
            title="Cross-product token reuse: 'streaming' STT token accepted by TTS endpoint",
            severity="High",
            endpoint=f"POST {SPEECH_US}",
            reproduce=(
                "1. Mint a token with product='streaming' at POST https://token.us.assemblyai.com/v1/token.\n"
                "2. Send POST https://tts.us.assemblyai.com/v1/speech using the streaming token.\n"
                f"Result: {r.status_code} — auth check passed using an STT token."
            ),
            impact=(
                "Scope bypass: A temporary token provisioned only for Real-Time Speech-to-Text "
                "can be repurposed to synthesize speech on the TTS product, exposing unexpected billing "
                "and quota consumption from compromised client browsers."
            ),
            remediation="Enforce audience/product scope check in TTS authentication middleware; reject tokens where product != 'tts'.",
            evidence={"status": r.status_code, "body": r.text[:200]},
            section="§1b Temporary Tokens",
        )
    elif r.status_code == 401:
        print(f"  [+] Streaming token rejected with 401 Unauthorized (good: product scope enforced)")


# ---------------------------------------------------------------------------
# T4 — Cross-Region Token Reuse (US-minted token on EU endpoint)
# ---------------------------------------------------------------------------
def test_cross_region_reuse(key: str, valid_token: str):
    print("\n[*] T4 — Cross-region token reuse (US token vs EU TTS endpoint)")
    if not valid_token:
        print("  [!] Skipping — no valid US token")
        return

    r = requests.post(
        SPEECH_EU,
        headers={"Authorization": valid_token, "Content-Type": "application/json"},
        json=baseline_body(),
        timeout=20,
    )
    log_request("cross_region_token_on_eu", "POST", SPEECH_EU,
                {"Authorization": "***redacted***", "Content-Type": "application/json"},
                baseline_body(), r,
                extra="US-minted token used on EU TTS endpoint")

    print(f"  Status on EU endpoint: {r.status_code}")
    if r.status_code in (200, 422):
        add_finding(
            title="US-issued temporary token accepted by EU endpoint",
            severity="Medium",
            endpoint=f"POST {SPEECH_EU}",
            reproduce=(
                "1. Mint a token via US endpoint: https://token.us.assemblyai.com/v1/token.\n"
                "2. Call EU speech endpoint: https://tts.eu.assemblyai.com/v1/speech with this token.\n"
                f"Result: {r.status_code} — cross-region execution succeeds."
            ),
            impact="Data residency violation: Tokens minted for one geopolitical jurisdiction can execute requests in another.",
            remediation="Bind tokens to their issuing data zone and reject cross-region token redemption.",
            evidence={"status": r.status_code, "x-tts-region": r.headers.get("x-tts-region")},
            section="§1b Temporary Tokens",
        )
    elif r.status_code == 401:
        print(f"  [+] US token rejected on EU endpoint with 401 (good: regional isolation verified)")


# ---------------------------------------------------------------------------
# T5 — Token Minting Another Token (Privilege Escalation)
# ---------------------------------------------------------------------------
def test_token_mint_token(valid_token: str):
    print("\n[*] T5 — Privilege escalation: Can a temporary token mint another token?")
    if not valid_token:
        print("  [!] Skipping — no valid token")
        return

    # Test with valid duration <= 600s
    r = requests.post(
        TOKEN_US,
        headers={"Authorization": valid_token, "Content-Type": "application/json"},
        json={"product": "tts", "expires_in_seconds": 300},
        timeout=20,
    )
    parsed = safe_json(r)
    log_request("token_mints_token_valid_ttl", "POST", TOKEN_US,
                {"Authorization": "***redacted***", "Content-Type": "application/json"},
                {"product": "tts", "expires_in_seconds": 300}, r,
                extra="Using temp token to mint another token (valid TTL: 300s)")

    print(f"  Status (valid TTL 300s): {r.status_code}")
    if r.status_code == 200 and parsed.get("token"):
        add_finding(
            title="Temporary token can mint additional temporary tokens (Privilege Escalation)",
            severity="High",
            endpoint=f"POST {TOKEN_US}",
            reproduce=(
                "1. Mint a temporary token.\n"
                "2. Send POST https://token.us.assemblyai.com/v1/token with Authorization: <temporary-token> and {'product': 'tts', 'expires_in_seconds': 300}.\n"
                "Result: 200 OK — a new valid temporary token is returned."
            ),
            impact=(
                "Privilege escalation & perpetual session: A client-side browser or compromised "
                "ephemeral token can continuously re-mint fresh tokens indefinitely without the master API key, "
                "bypassing TTL limits and remaining active permanently."
            ),
            remediation="Require master API keys for token issuance; explicitly reject bearer/temporary tokens at token endpoints.",
            evidence={"status": r.status_code, "new_token_prefix": parsed.get("token", "")[:20]},
            section="§1b Temporary Tokens",
        )
    else:
        print(f"  [+] Temporary token cannot mint new tokens — status {r.status_code} (expected)")


# ---------------------------------------------------------------------------
# T6 — Token Replay (Single-use vs Multi-use)
# ---------------------------------------------------------------------------
def test_token_replay(valid_token: str):
    print("\n[*] T6 — Token replay: Test multiple synthesis calls with one token")
    if not valid_token:
        print("  [!] Skipping — no valid token")
        return

    statuses = []
    for i in range(2):
        r = requests.post(
            SPEECH_US,
            headers={"Authorization": valid_token, "Content-Type": "application/json"},
            json=baseline_body(),
            timeout=20,
        )
        statuses.append(r.status_code)
        print(f"  Synthesis attempt #{i+1} status: {r.status_code}")

    if all(s == 200 for s in statuses):
        add_finding(
            title="Temporary tokens allow multi-request replay within validity window",
            severity="Informational",
            endpoint=f"POST {SPEECH_US}",
            reproduce="Mint temporary token and send multiple POST /v1/speech requests. All succeed.",
            impact="If temporary tokens are intended to be strictly single-session or single-use, multi-use allows stolen tokens to generate arbitrary traffic until expiration.",
            remediation="If single-session semantics are intended for browser clients, invalidate token after session initialization.",
            evidence={"attempts": statuses},
            section="§1b Temporary Tokens",
        )


# ---------------------------------------------------------------------------
# MAIN
# ---------------------------------------------------------------------------
if __name__ == "__main__":
    key = get_api_key()
    print(f"[*] US Token Endpoint : {TOKEN_US}")
    print(f"[*] EU Token Endpoint : {TOKEN_EU}")
    print(f"[*] Key loaded        : ***redacted*** ({len(key)} chars)")

    token = test_token_baseline(key)
    test_expiry(key)
    test_cross_product_reuse(key)
    test_cross_region_reuse(key, token)
    test_token_mint_token(token)
    test_token_replay(token)

    save_findings("findings_02_tokens.json", section="§1b Authentication & Authorization — Temporary Tokens")
