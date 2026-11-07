"""
§8 — Cross-Tenant Voice Authorization & Object-Level Permissions (BOLA / IDOR)
AssemblyAI TTS Pentest | Run with: python 07_voice_idor.py

Tests whether Account B can inspect, synthesize, or modify private cloned voices
belonging to Account A (01a1b59b-a5e9-753e-b832-29c1b8da324f).
"""
import os
import sys
import json
import requests

sys.path.insert(0, os.path.dirname(__file__))
from utils import (
    get_api_key, get_api_key_b, log_request, add_finding, save_findings,
    BASE_US, BASE_EU, redact
)

ENDPOINT_SPEECH = f"{BASE_US}/speech"
ENDPOINT_VOICES = f"{BASE_US}/voices"
ENDPOINT_TOKEN  = "https://token.us.assemblyai.com/v1/token"

SECTION_NAME = "§8 Cross-Tenant Voice Authorization"


def run_idor_audit():
    key_a = get_api_key()
    key_b = get_api_key_b()

    if not key_b:
        print("[!] ERROR: ASSEMBLYAI_API_KEY_B not found in .env or environment.")
        sys.exit(1)

    # Resolve Account A's voice ID
    vid_file = os.path.join(os.path.dirname(__file__), "voice_id.txt")
    with open(vid_file) as f:
        voice_id_a = f.read().strip()

    slug_a = "ruponchain-da324f"

    print(f"[*] Target Endpoint : {ENDPOINT_SPEECH}")
    print(f"[*] Account A Key   : ***redacted*** ({len(key_a)} chars)")
    print(f"[*] Account B Key   : ***redacted*** ({len(key_b)} chars)")
    print(f"[*] Account A Voice : {voice_id_a} (slug: {slug_a})")

    # -----------------------------------------------------------------------
    # T1: Baseline check of Account B's voice list
    # -----------------------------------------------------------------------
    print("\n[*] T1 — Account B voice list enumeration")
    r1 = requests.get(ENDPOINT_VOICES, headers={"Authorization": key_b}, timeout=15)
    print(f"  Account B GET /voices: {r1.status_code}")
    b_voices = []
    if r1.status_code == 200:
        data = r1.json()
        b_voices = data.get("voices", [])
        print(f"  Account B voice count: {len(b_voices)}")
        a_voice_in_b = any(v.get("id") == voice_id_a for v in b_voices)
        if a_voice_in_b:
            add_finding(
                title="Account A private voice leaked in Account B voice list",
                severity="Critical",
                endpoint=f"GET {ENDPOINT_VOICES}",
                reproduce=f"Call GET /v1/voices with Account B's API key. Voice {voice_id_a} is listed.",
                impact="Global voice enumeration: Private voices are visible across tenant boundaries.",
                remediation="Filter voice lists strictly by the caller's owner_account_id unless visibility='public'.",
                evidence=r1.json(),
                section=SECTION_NAME
            )
        else:
            print("  [+] Account A's voice is NOT listed in Account B's voice catalog.")
    else:
        print(f"  Response: {r1.text[:200]}")

    # -----------------------------------------------------------------------
    # T2: Direct lookup of Account A's voice by UUID (GET /v1/voices/{id})
    # -----------------------------------------------------------------------
    print(f"\n[*] T2 — Account B direct lookup of Account A voice (UUID: {voice_id_a})")
    r2 = requests.get(f"{ENDPOINT_VOICES}/{voice_id_a}", headers={"Authorization": key_b}, timeout=15)
    print(f"  Account B GET /voices/{voice_id_a}: {r2.status_code}")
    if r2.status_code == 200:
        add_finding(
            title="Cross-Tenant Voice Metadata BOLA/IDOR (GET /v1/voices/{id})",
            severity="High",
            endpoint=f"GET {ENDPOINT_VOICES}/{voice_id_a}",
            reproduce=f"Call GET /v1/voices/{voice_id_a} using Account B's API key. Response: 200 OK with full voice metadata.",
            impact="Information disclosure: An unauthorized account can read private voice configuration, sample rate, audio duration, SHA256 hash, and internal account IDs of another tenant.",
            remediation="Enforce object-level access control on GET /v1/voices/{id}; return 404 or 403 if caller is not the owner.",
            evidence=r2.json(),
            section=SECTION_NAME
        )
        print("  [!] VULNERABILITY FOUND: Account B can read Account A's private voice metadata!")
    else:
        print(f"  [+] Access rejected: status {r2.status_code} ({r2.json().get('code', '')})")
        add_finding(
            title="Defensive Verification: Direct voice lookup rejected cross-tenant",
            severity="Informational",
            endpoint=f"GET {ENDPOINT_VOICES}/{voice_id_a}",
            reproduce=f"Call GET /v1/voices/{voice_id_a} with Account B's key. Server returns {r2.status_code} {r2.json().get('code')}.",
            impact="Verification of defensive control: Direct object reference lookup across tenants is properly blocked.",
            remediation="No remediation required; tenant isolation verified.",
            evidence={"status": r2.status_code, "response": r2.json()},
            section=SECTION_NAME
        )

    # -----------------------------------------------------------------------
    # T3: Cross-Tenant Speech Synthesis by UUID (POST /v1/speech)
    # -----------------------------------------------------------------------
    print(f"\n[*] T3 — Account B attempting speech synthesis with Account A voice UUID")
    payload_uuid = {
        "text": "Authorized multi-tenancy verification audio.",
        "voice_id": voice_id_a,
        "container": "wav"
    }
    r3 = requests.post(ENDPOINT_SPEECH, headers={"Authorization": key_b, "Content-Type": "application/json"},
                       json=payload_uuid, timeout=20)
    print(f"  Account B POST /speech (UUID): {r3.status_code}")
    if r3.status_code == 200:
        add_finding(
            title="CRITICAL: Cross-Tenant Voice Synthesis Impersonation (BOLA/IDOR)",
            severity="Critical",
            endpoint=f"POST {ENDPOINT_SPEECH}",
            reproduce=f"Account B sends POST /v1/speech with voice_id='{voice_id_a}' (owned by Account A). Server synthesizes audio (200 OK).",
            impact="Unauthorized Voice Cloning Impersonation: Any authenticated account that knows or discovers another customer's private voice ID can synthesize audio using that private voice clone without authorization.",
            remediation="Verify that the authenticated caller's account_id matches the voice's owner_account_id before initializing the synthesis pipeline.",
            evidence={"status": 200, "audio_bytes": len(r3.content)},
            section=SECTION_NAME
        )
        print("  [CRITICAL] VULNERABILITY FOUND: Account B synthesized audio using Account A's private voice clone!")
    else:
        print(f"  [+] Synthesis rejected: status {r3.status_code} ({r3.json().get('code', '')})")
        add_finding(
            title="Defensive Verification: Cross-tenant speech synthesis rejected by voice UUID",
            severity="Informational",
            endpoint=f"POST {ENDPOINT_SPEECH}",
            reproduce=f"Account B requests synthesis with voice_id='{voice_id_a}'. Server returns {r3.status_code} ({r3.json().get('code')}).",
            impact="Verification of defensive control: The synthesis pipeline strictly validates voice ownership and blocks cross-tenant synthesis.",
            remediation="No remediation required; tenant isolation verified.",
            evidence={"status": r3.status_code, "response": r3.json()},
            section=SECTION_NAME
        )

    # -----------------------------------------------------------------------
    # T4: Cross-Tenant Speech Synthesis by Slug (POST /v1/speech)
    # -----------------------------------------------------------------------
    print(f"\n[*] T4 — Account B attempting speech synthesis with Account A voice slug ({slug_a})")
    payload_slug = {
        "text": "Authorized multi-tenancy verification audio via slug.",
        "voice_id": slug_a,
        "container": "wav"
    }
    r4 = requests.post(ENDPOINT_SPEECH, headers={"Authorization": key_b, "Content-Type": "application/json"},
                       json=payload_slug, timeout=20)
    print(f"  Account B POST /speech (Slug): {r4.status_code}")
    if r4.status_code == 200:
        add_finding(
            title="CRITICAL: Cross-Tenant Voice Synthesis via Predictable Voice Slug",
            severity="Critical",
            endpoint=f"POST {ENDPOINT_SPEECH}",
            reproduce=f"Account B sends POST /v1/speech with voice_id='{slug_a}'. Server synthesizes audio (200 OK).",
            impact="Unauthorized Voice Impersonation via Slug: Account B can synthesize audio using Account A's voice slug, bypassing UUID-based access controls.",
            remediation="Validate tenant ownership regardless of whether voice is referenced by UUID or slug.",
            evidence={"status": 200, "audio_bytes": len(r4.content)},
            section=SECTION_NAME
        )
        print("  [CRITICAL] VULNERABILITY FOUND: Account B synthesized audio using Account A's voice slug!")
    else:
        print(f"  [+] Synthesis via slug rejected: status {r4.status_code} ({r4.json().get('code', '')})")

    # -----------------------------------------------------------------------
    # T5: Account B Temporary Token Cross-Tenant Synthesis
    # -----------------------------------------------------------------------
    print(f"\n[*] T5 — Account B ephemeral token cross-tenant access")
    tok_b_resp = requests.post(ENDPOINT_TOKEN, headers={"Authorization": key_b},
                               json={"product": "tts", "expires_in_seconds": 60}, timeout=15)
    if tok_b_resp.status_code == 200:
        tok_b = tok_b_resp.json().get("token")
        r5 = requests.post(ENDPOINT_SPEECH, headers={"Authorization": tok_b, "Content-Type": "application/json"},
                           json=payload_uuid, timeout=20)
        print(f"  Account B Temp Token POST /speech: {r5.status_code}")
        if r5.status_code == 200:
            add_finding(
                title="CRITICAL: Ephemeral Token Cross-Tenant Voice Synthesis Bypass",
                severity="Critical",
                endpoint=f"POST {ENDPOINT_SPEECH}",
                reproduce=f"Account B mints temporary token and calls POST /v1/speech with Account A's voice_id. Returns 200 OK.",
                impact="Temporary tokens bypass tenant isolation, allowing client-side applications to access another customer's voice clone.",
                remediation="Ensure ephemeral token tenant context is passed to and validated by the synthesizer service.",
                evidence={"status": 200},
                section=SECTION_NAME
            )
        else:
            print(f"  [+] Ephemeral token access rejected: status {r5.status_code}")
    else:
        print(f"  Account B could not mint temporary token: {tok_b_resp.status_code}")

    # -----------------------------------------------------------------------
    # T6: Cross-Tenant Deletion Attempt (DELETE /v1/voices/{id})
    # -----------------------------------------------------------------------
    print(f"\n[*] T6 — Account B attempting deletion of Account A voice")
    r6 = requests.delete(f"{ENDPOINT_VOICES}/{voice_id_a}", headers={"Authorization": key_b}, timeout=15)
    print(f"  Account B DELETE /voices/{voice_id_a}: {r6.status_code}")
    if r6.status_code in (200, 204):
        add_finding(
            title="CRITICAL: Cross-Tenant Asset Deletion via Master Key",
            severity="Critical",
            endpoint=f"DELETE {ENDPOINT_VOICES}/{voice_id_a}",
            reproduce=f"Account B issues DELETE /v1/voices/{voice_id_a} and succeeds.",
            impact="Data Destruction / Tenant Takeover: Any customer can delete another customer's custom voice models.",
            remediation="Enforce strict ownership checks on DELETE operations.",
            evidence={"status": r6.status_code},
            section=SECTION_NAME
        )
        print("  [CRITICAL] Account B was able to delete Account A's voice!")
    else:
        print(f"  [+] Deletion rejected: status {r6.status_code} ({r6.json().get('code', '')})")
        add_finding(
            title="Defensive Verification: Cross-tenant voice deletion rejected",
            severity="Informational",
            endpoint=f"DELETE {ENDPOINT_VOICES}/{voice_id_a}",
            reproduce=f"Account B issues DELETE /v1/voices/{voice_id_a}. Server returns {r6.status_code} ({r6.json().get('code')}).",
            impact="Verification of defensive control: Tenants cannot delete or modify other customers' voice assets.",
            remediation="No remediation required; tenant isolation verified.",
            evidence={"status": r6.status_code, "response": r6.json()},
            section=SECTION_NAME
        )

    # Save findings & update report
    save_findings("findings_07_idor.json", section=SECTION_NAME)


if __name__ == "__main__":
    run_idor_audit()
