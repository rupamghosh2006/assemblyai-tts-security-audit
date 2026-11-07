"""
Helper: Create a minimal test voice so all other scripts have a valid voice_id.
Run ONCE before the main test scripts if your account has no voices yet.

Usage:
    python create_test_voice.py

Requires: pip install requests
Key must be in environment: $env:ASSEMBLYAI_API_KEY = "your_key"

After running, it prints and saves the voice_id to voice_id.txt for other scripts to read.
"""
import os
import sys
import json
import requests

sys.path.insert(0, os.path.dirname(__file__))
from utils import get_api_key, redact, BASE_US, BASE_EU

VOICES_US = f"{BASE_US}/voices"
VOICES_EU = f"{BASE_EU}/voices"


def probe_voice_list(key: str, base_url: str):
    """List voices and return any found."""
    r = requests.get(f"{base_url}/voices",
                     headers={"Authorization": key}, timeout=10)
    print(f"  GET {base_url}/voices → {r.status_code}")
    if r.status_code == 200:
        data = r.json()
        print(f"  Response: {json.dumps(data)[:300]}")
        voices = data.get("voices", []) if isinstance(data, dict) else data
        return voices
    return []


def create_test_voice(key: str) -> str | None:
    """
    Attempt to create a minimal test voice via the API.
    Uses a small synthetic sine-wave WAV (not a real person's voice).
    """
    import struct, math, wave, io

    # Generate a 3-second synthetic 440Hz sine wave (clearly not a real person)
    sample_rate = 22050
    duration_s  = 3
    freq_hz     = 440
    num_samples = sample_rate * duration_s
    samples = [int(32767 * math.sin(2 * math.pi * freq_hz * i / sample_rate))
               for i in range(num_samples)]

    wav_buf = io.BytesIO()
    with wave.open(wav_buf, 'wb') as wf:
        wf.setnchannels(1)
        wf.setsampwidth(2)
        wf.setframerate(sample_rate)
        wf.writeframes(struct.pack(f'<{num_samples}h', *samples))
    wav_bytes = wav_buf.getvalue()

    # Try the voice creation endpoint (adjust path if AssemblyAI uses a different one)
    for endpoint in [
        f"{BASE_US}/voices",
        "https://api.assemblyai.com/v1/realtime/token",  # probe only
    ]:
        if "token" in endpoint:
            continue
        print(f"\n[*] Attempting voice creation at {endpoint}")
        r = requests.post(
            endpoint,
            headers={"Authorization": key},
            files={"audio": ("test_voice.wav", wav_bytes, "audio/wav")},
            data={"name": "pentest-synthetic-voice"},
            timeout=30,
        )
        print(f"  Status: {r.status_code}")
        print(f"  Body:   {redact(r.text[:400])}")
        if r.status_code in (200, 201):
            data = r.json()
            vid = data.get("voice_id") or data.get("id")
            if vid:
                return str(vid)

    return None


def save_voice_id(voice_id: str):
    path = os.path.join(os.path.dirname(__file__), "voice_id.txt")
    with open(path, "w") as f:
        f.write(voice_id.strip())
    print(f"\n[+] voice_id saved to voice_id.txt: {voice_id}")
    print(f"    Set it as an env var: $env:ASSEMBLYAI_VOICE_ID = \"{voice_id}\"")


if __name__ == "__main__":
    key = get_api_key()
    print("[*] Probing US region for existing voices...")
    voices = probe_voice_list(key, BASE_US)

    if not voices:
        print("[*] Probing EU region...")
        voices = probe_voice_list(key, BASE_EU)

    if voices:
        vid = voices[0].get("voice_id") or voices[0].get("id") or str(voices[0])
        print(f"\n[+] Found existing voice: {vid}")
        save_voice_id(vid)
    else:
        print("\n[!] No voices found in either region.")
        print("[*] Attempting to create a synthetic test voice...")
        vid = create_test_voice(key)
        if vid:
            save_voice_id(vid)
        else:
            print("\n[ACTION REQUIRED] Create a voice manually:")
            print("  1. Go to: https://www.assemblyai.com/dashboard/playground/text-to-speech")
            print("  2. Create a voice (use a synthetic/consented sample)")
            print("  3. Copy the voice_id from the dashboard or API response")
            print("  4. Run: $env:ASSEMBLYAI_VOICE_ID = 'your-voice-id-here'")
            print("  5. Re-run: python 01_auth_fuzzing.py")
            sys.exit(1)
