"""
SSML & XXE Verification Script
Tests whether AssemblyAI TTS actually parses SSML/XML or treats markup as plain text.

Run with: python verify_ssml_xxe.py
"""
import os
import sys
import requests

sys.path.insert(0, os.path.dirname(__file__))
from utils import get_api_key, baseline_body, BASE_US, redact

ENDPOINT = f"{BASE_US}/speech"


def test_markup_interpretation():
    key = get_api_key()
    headers = {"Authorization": key, "Content-Type": "application/json"}
    base = baseline_body()

    print("[*] Probing SSML / Markup Parser Behavior...")

    # Test 1: Plain text baseline
    b_plain = {**base, "text": "Hello World"}
    r_plain = requests.post(ENDPOINT, headers=headers, json=b_plain, timeout=20)
    billed_plain = r_plain.headers.get("x-tts-billed-characters", "N/A")
    audio_plain_len = len(r_plain.content) if r_plain.status_code == 200 else 0

    # Test 2: SSML with 3-second break tag
    # If SSML is parsed: audio length will be much larger (~3s of silence) and billed chars will NOT include the tag.
    # If SSML is NOT parsed: tag characters are billed and pronounced/ignored as raw text.
    b_break = {**base, "text": "Hello <break time='3s'/> World"}
    r_break = requests.post(ENDPOINT, headers=headers, json=b_break, timeout=20)
    billed_break = r_break.headers.get("x-tts-billed-characters", "N/A")
    audio_break_len = len(r_break.content) if r_break.status_code == 200 else 0

    # Test 3: Malformed XML
    # If an XML parser runs: this should fail with 400 Bad Request (XML Syntax Error).
    # If no XML parser exists: returns 200 OK because text is processed directly by the model.
    b_malformed = {**base, "text": "<speak><unclosed_tag>Hello</speak>"}
    r_malformed = requests.post(ENDPOINT, headers=headers, json=b_malformed, timeout=20)

    # Test 4: XXE payload
    b_xxe = {**base, "text": "<?xml version='1.0'?><!DOCTYPE foo [<!ENTITY xxe SYSTEM 'file:///etc/passwd'>]><speak>&xxe;</speak>"}
    r_xxe = requests.post(ENDPOINT, headers=headers, json=b_xxe, timeout=20)
    billed_xxe = r_xxe.headers.get("x-tts-billed-characters", "N/A")

    print(f"\n1. Plain text ('Hello World'):")
    print(f"   Status: {r_plain.status_code} | Billed Chars: {billed_plain} (len={len(b_plain['text'])}) | Audio Bytes: {audio_plain_len}")

    print(f"\n2. SSML <break time='3s'/>:")
    print(f"   Status: {r_break.status_code} | Billed Chars: {billed_break} (len={len(b_break['text'])}) | Audio Bytes: {audio_break_len}")

    print(f"\n3. Malformed XML ('<speak><unclosed_tag>Hello</speak>'):")
    print(f"   Status: {r_malformed.status_code} | Response: {r_malformed.text[:120]}")

    print(f"\n4. XXE Payload:")
    print(f"   Status: {r_xxe.status_code} | Billed Chars: {billed_xxe} (len={len(b_xxe['text'])})")

    # Evaluation
    print("\n" + "="*70)
    print("ANALYSIS:")
    if billed_break == str(len(b_break["text"])) and r_malformed.status_code == 200:
        print("[!] SSML IS NOT PARSED BY AN XML ENGINE:")
        print("    - All XML/SSML tags are treated as literal text and billed character-by-character.")
        print("    - Malformed XML is NOT rejected with an XML parse error (status 200 returned).")
        print("    - Therefore, XXE and SSML Audio SSRF do NOT execute on the server backend.")
        print("    - Rather, the model processes the raw text string verbatim.")
        print("    -> Recommendation: Downgrade XXE/SSRF from Critical/High to Informational /")
        print("       'SSML Not Supported (Raw Text Fallback)' to ensure 100% audit accuracy.")
    elif r_malformed.status_code in (400, 422) or (billed_break and int(billed_break) < len(b_break["text"])):
        print("[!] SSML ENGINE DETECTED:")
        print("    - Tags are stripped or parsed by an XML engine.")
        print("    - XXE / SSRF risks are active and require out-of-band verification.")
    print("="*70)


if __name__ == "__main__":
    test_markup_interpretation()
