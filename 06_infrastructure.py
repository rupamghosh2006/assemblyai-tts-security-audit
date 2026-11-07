"""
§7 — Infrastructure, TLS, CORS & Privacy Tests
AssemblyAI TTS Pentest | Run with: python 06_infrastructure.py

Requires:  pip install requests sslyze
Key must be in environment:  $env:ASSEMBLYAI_API_KEY = "your_key"
"""
import os
import sys
import requests

sys.path.insert(0, os.path.dirname(__file__))
from utils import (
    get_api_key, log_request, add_finding, save_findings,
    BASE_US, BASE_EU, baseline_body, redact
)

ENDPOINT_US = f"{BASE_US}/speech"
ENDPOINT_EU = f"{BASE_EU}/speech"


# ---------------------------------------------------------------------------
# X1 — CORS configuration
# ---------------------------------------------------------------------------
def test_cors(key: str):
    print("\n[*] X1 — CORS configuration")
    origins = [
        "https://evil.com",
        "null",
        "https://tts.us.assemblyai.com.evil.com",
        "https://assemblyai.com",
        "http://localhost:3000",
    ]
    for origin in origins:
        # Preflight
        r = requests.options(
            ENDPOINT_US,
            headers={
                "Origin": origin,
                "Access-Control-Request-Method": "POST",
                "Access-Control-Request-Headers": "authorization,content-type",
            },
            timeout=10,
        )
        acao = r.headers.get("Access-Control-Allow-Origin", "(not set)")
        acac = r.headers.get("Access-Control-Allow-Credentials", "(not set)")
        print(f"  Origin: {origin:<45} ACAO={acao}  ACAC={acac}")

        if acao == "*" and acac == "true":
            add_finding(
                title="CORS wildcard + Allow-Credentials is an invalid combination",
                severity="High",
                endpoint=f"OPTIONS {ENDPOINT_US}",
                reproduce=f"OPTIONS with Origin: {origin} — ACAO=* and ACAC=true",
                impact="Browsers reject this combination; may indicate misconfigured CORS that leaks responses to arbitrary origins.",
                remediation="Never combine ACAO: * with ACAC: true; use explicit origin allowlisting.",
            )
        elif acao == origin and origin in ("https://evil.com", "null"):
            add_finding(
                title=f"CORS reflects arbitrary Origin: {origin}",
                severity="High",
                endpoint=f"OPTIONS {ENDPOINT_US}",
                reproduce=f"OPTIONS with Origin: {origin} → ACAO: {origin}",
                impact="Any web page can make cross-origin authenticated requests; enables CSRF/data theft.",
                remediation="Validate Origin against a strict allowlist; never reflect arbitrary origins.",
            )


# ---------------------------------------------------------------------------
# X2 — Key/token in response body / error messages
# ---------------------------------------------------------------------------
def test_key_in_response(key: str):
    print("\n[*] X2 — Key/token not leaked in error responses")
    # Send a deliberately broken request and check if the key echoes back
    body = {**baseline_body(), "voice_id": f"trigger_error_{key[:8]}"}
    hdrs = {"Authorization": key, "Content-Type": "application/json"}
    r = requests.post(ENDPOINT_US, headers=hdrs, json=body, timeout=20)
    if key in r.text:
        add_finding(
            title="Raw API key reflected in error response body",
            severity="Critical",
            endpoint=f"POST {ENDPOINT_US}",
            reproduce="Send a request with an invalid voice_id. API key appears verbatim in response body.",
            impact="Any logged response body or browser network tab exposes the API key.",
            remediation="Never echo user-supplied headers or credentials back in response bodies.",
        )
        print("  [!!!] Key found in response body — CRITICAL FINDING")
    else:
        print(f"  [+] Key not found in response body (status {r.status_code})")

    # Check x-request-id for predictability
    request_ids = []
    for _ in range(5):
        r2 = requests.post(ENDPOINT_US, headers=hdrs, json=baseline_body(), timeout=20)
        rid = r2.headers.get("x-request-id", "")
        request_ids.append(rid)
    print(f"  x-request-id samples: {request_ids}")
    if len(set(request_ids)) < len(request_ids):
        add_finding(
            title="Duplicate x-request-id values across requests",
            severity="Medium",
            endpoint=f"POST {ENDPOINT_US}",
            reproduce="Send 5 requests; observe repeated x-request-id values.",
            impact="Non-unique request IDs break correlation; may enable cross-session data leakage via support lookups.",
            remediation="Use cryptographically random UUIDs for x-request-id.",
        )


# ---------------------------------------------------------------------------
# X3 — TLS downgrade / plaintext fallback
# ---------------------------------------------------------------------------
def test_tls_fallback(key: str):
    print("\n[*] X3 — TLS / plaintext fallback check")
    http_url = ENDPOINT_US.replace("https://", "http://")
    try:
        r = requests.post(http_url, headers={"Authorization": key,
                                              "Content-Type": "application/json"},
                          json=baseline_body(), timeout=10, allow_redirects=False)
        print(f"  HTTP (non-TLS) status: {r.status_code}  Location: {r.headers.get('Location','')}")
        if r.status_code == 200:
            add_finding(
                title="API accepts plaintext HTTP (no TLS required)",
                severity="Critical",
                endpoint=http_url,
                reproduce="Send POST over http:// (not https://); receives 200 OK.",
                impact="Credentials and audio transmitted in plaintext; trivial interception.",
                remediation="Redirect all HTTP to HTTPS; reject plaintext connections at the load balancer.",
            )
        elif r.status_code in (301, 302, 307, 308):
            print(f"  [+] HTTP redirected to HTTPS — good, but check for plain-HTTP credential leakage in transit")
        else:
            print(f"  [+] HTTP rejected (status {r.status_code})")
    except requests.exceptions.ConnectionError as e:
        print(f"  [+] HTTP connection refused — {e}")


# ---------------------------------------------------------------------------
# X4 — HSTS header present?
# ---------------------------------------------------------------------------
def test_hsts(key: str):
    print("\n[*] X4 — HSTS header")
    r = requests.post(ENDPOINT_US,
                      headers={"Authorization": key, "Content-Type": "application/json"},
                      json=baseline_body(), timeout=20)
    hsts = r.headers.get("Strict-Transport-Security", None)
    if hsts:
        print(f"  [+] HSTS present: {hsts}")
    else:
        add_finding(
            title="Strict-Transport-Security (HSTS) header missing",
            severity="Low",
            endpoint=f"POST {ENDPOINT_US}",
            reproduce="Check response headers — Strict-Transport-Security is absent.",
            impact="Browsers don't pin to HTTPS; SSL-strip attacks are possible on first visit.",
            remediation="Add Strict-Transport-Security: max-age=31536000; includeSubDomains",
        )
        print("  [!] HSTS header missing")


# ---------------------------------------------------------------------------
# X5 — Information disclosure via llms.txt / robots.txt / openapi
# ---------------------------------------------------------------------------
def test_info_disclosure():
    print("\n[*] X5 — Auto-discoverable information disclosure")
    targets = [
        "https://assemblyai.com/docs/llms.txt",
        "https://assemblyai.com/robots.txt",
        f"{BASE_US}/openapi.json",
        f"{BASE_US}/swagger.json",
        f"{BASE_US}/docs",
        f"{BASE_US}/../",
        f"{BASE_US}/health",
        f"{BASE_US}/metrics",
        f"{BASE_US}/debug",
        f"{BASE_US}/admin",
    ]
    for url in targets:
        try:
            r = requests.get(url, timeout=10, allow_redirects=True)
            size = len(r.content)
            print(f"  {url[-60:]:<60} status={r.status_code}  bytes={size}")
            if r.status_code == 200 and size > 100:
                ct = r.headers.get("Content-Type", "")
                excerpt = redact(r.text[:200]).replace('\n', ' ')
                print(f"    Content-Type: {ct}")
                print(f"    Excerpt: {excerpt}")
                if any(kw in r.text.lower() for kw in ["internal", "secret", "password", "token", "private", "debug"]):
                    add_finding(
                        title=f"Potential information disclosure at {url}",
                        severity="Medium",
                        endpoint=url,
                        reproduce=f"GET {url} returns 200 with sensitive-looking content.",
                        impact="Attackers gain knowledge of internal structure, endpoints, or secrets.",
                        remediation="Remove or access-control debug/admin endpoints; audit llms.txt for sensitive disclosures.",
                    )
        except Exception as e:
            print(f"  {url[-60:]:<60} ERROR: {e}")


# ---------------------------------------------------------------------------
# X6 — Response header fingerprinting
# ---------------------------------------------------------------------------
def test_fingerprinting(key: str):
    print("\n[*] X6 — Response header fingerprinting")
    r = requests.post(ENDPOINT_US,
                      headers={"Authorization": key, "Content-Type": "application/json"},
                      json=baseline_body(), timeout=20)
    interesting = ["Server", "X-Powered-By", "Via", "X-Cache", "CF-Ray",
                   "X-Amz-Request-Id", "X-Amzn-Trace-Id", "X-Goog-",
                   "x-tts-model", "x-tts-voice-id"]
    print("  Response headers:")
    for h, v in r.headers.items():
        if any(h.lower().startswith(i.lower()) for i in interesting):
            print(f"    {h}: {v}")
            if h.lower() in ("server", "x-powered-by"):
                add_finding(
                    title=f"Server fingerprinting via {h} header",
                    severity="Informational",
                    endpoint=f"POST {ENDPOINT_US}",
                    reproduce=f"Check response header {h}: {v}",
                    impact="Reveals backend technology stack; aids targeted exploit selection.",
                    remediation=f"Remove or genericise the {h} response header.",
                )


# ---------------------------------------------------------------------------
# MAIN
# ---------------------------------------------------------------------------
if __name__ == "__main__":
    key = get_api_key()
    print(f"[*] Target endpoint : {ENDPOINT_US}")
    print(f"[*] Key loaded      : ***redacted*** ({len(key)} chars)")

    test_cors(key)
    test_key_in_response(key)
    test_tls_fallback(key)
    test_hsts(key)
    test_info_disclosure()
    test_fingerprinting(key)
    save_findings("findings_06_infra.json", section="§7 Infrastructure, TLS & Privacy")
