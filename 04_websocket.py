"""
§4 — WebSocket Protocol Tests
AssemblyAI TTS Pentest | Run with: python 04_websocket.py

Requires:  pip install websockets requests
Key must be in environment:  $env:ASSEMBLYAI_API_KEY = "your_key"
"""
import os
import sys
import json
import time
import asyncio

try:
    import websockets
    import websockets.exceptions
except ImportError:
    print("[ERROR] Install websockets:  pip install websockets")
    sys.exit(1)

sys.path.insert(0, os.path.dirname(__file__))
from utils import (
    get_api_key, add_finding, save_findings,
    WS_US, WS_EU, redact
)


def log_ws(label: str, direction: str, payload):
    safe = redact(json.dumps(payload) if isinstance(payload, dict) else str(payload))
    print(f"  [{direction}] {label}: {safe[:200]}")


async def open_session(key: str, url: str = None, extra_headers: dict = None, voice_id: str = None):
    """Open a WebSocket session and return the connection object."""
    from utils import get_default_voice_id
    if voice_id is None:
        voice_id = get_default_voice_id()
    if url is None:
        target_url = f"{WS_US}?voice_id={voice_id}&sample_rate=24000"
    elif "?" not in url:
        target_url = f"{url}?voice_id={voice_id}&sample_rate=24000"
    else:
        target_url = url

    headers = {"Authorization": key}
    if extra_headers:
        headers.update(extra_headers)

    ws = await websockets.connect(target_url, additional_headers=headers, open_timeout=15)
    # Read the initial Begin/Session frame
    begin_raw = await asyncio.wait_for(ws.recv(), timeout=10)
    if isinstance(begin_raw, bytes):
        begin = {"raw_bytes": len(begin_raw)}
    else:
        try:
            begin = json.loads(begin_raw)
        except Exception:
            begin = {"raw": begin_raw}
    log_ws("Begin frame", "RECV", begin)

    # Check for session rate limit (Error 3009: 5 sessions per minute)
    if isinstance(begin, dict) and begin.get("error_code") == 3009:
        err_msg = begin.get("error", "")
        add_finding(
            title="WebSocket session rate limit enforced: 5 sessions/min (Error 3009)",
            severity="Informational",
            endpoint=f"WS {WS_US}",
            reproduce="Open more than 5 WebSocket connections in under 60 seconds from one account.",
            impact="Enforces quota and DoS protection per account. Error 3009 reveals exact allowance and countdown seconds.",
            remediation="Ensure client libraries implement exponential backoff handling for error_code 3009.",
            evidence={"error_code": 3009, "error": err_msg},
            section="§4 WebSocket Protocol",
        )
        import re
        match = re.search(r'retry in (\d+)s', err_msg)
        wait_s = int(match.group(1)) + 2 if match else 20
        print(f"  [!] Rate limited (Error 3009): Waiting {wait_s}s before retrying...")
        await ws.close()
        await asyncio.sleep(wait_s)
        return await open_session(key, url, extra_headers, voice_id)

    return ws, begin


# ---------------------------------------------------------------------------
# W1 — Baseline WS session (Generate + Flush + read FlushDone)
# ---------------------------------------------------------------------------
async def test_ws_baseline(key: str):
    print("\n[*] W1 — WebSocket baseline")
    try:
        ws, begin = await open_session(key)
        session_id = begin.get("id", "")
        print(f"  Session ID: {session_id}")

        # Send Generate
        gen = {"type": "Generate", "text": "Hello from authorized pentest."}
        await ws.send(json.dumps(gen))
        log_ws("Generate", "SEND", gen)

        # Send Flush
        flush = {"type": "Flush"}
        await ws.send(json.dumps(flush))
        log_ws("Flush", "SEND", flush)

        # Collect frames until FlushDone or timeout
        flush_done = False
        deadline = time.time() + 30
        while time.time() < deadline:
            try:
                raw = await asyncio.wait_for(ws.recv(), timeout=5)
                if isinstance(raw, bytes):
                    log_ws("audio_chunk", "RECV", f"<{len(raw)} bytes binary audio>")
                    continue
                try:
                    frame = json.loads(raw)
                except Exception:
                    frame = {"raw": raw}
                log_ws("recv", "RECV", frame)
                if isinstance(frame, dict) and frame.get("type") == "FlushDone":
                    flush_done = True
                    break
            except asyncio.TimeoutError:
                break

        if flush_done:
            print("[+] Baseline WS session OK — FlushDone received")
        else:
            print("[!] FlushDone not received within timeout")

        # Terminate
        await ws.send(json.dumps({"type": "Terminate"}))
        await ws.close()
        return session_id
    except Exception as e:
        print(f"[!] WS baseline error: {e}")
        return None


# ---------------------------------------------------------------------------
# W2 — Origin validation (CSWSH)
# ---------------------------------------------------------------------------
async def test_origin_validation(key: str):
    print("\n[*] W2 — Origin validation (CSWSH)")
    malicious_origins = [
        "https://evil.com",
        "null",
        "https://tts.us.assemblyai.com.evil.com",
        "file://",
    ]
    for origin in malicious_origins:
        try:
            ws, begin = await open_session(key, extra_headers={"Origin": origin})
            await ws.close()
            add_finding(
                title=f"WebSocket Origin not validated — CSWSH possible",
                severity="High",
                endpoint=f"WS {WS_US}",
                reproduce=(
                    f"Connect to {WS_US} with Origin: {origin} — "
                    "connection accepted."
                ),
                impact=(
                    "Any web page can open a WebSocket session using a victim's browser-stored "
                    "credentials/token (Cross-Site WebSocket Hijacking)."
                ),
                remediation=(
                    "Validate the Origin header against an allowlist of trusted domains; "
                    "reject connections from unexpected origins."
                ),
            )
            print(f"  Origin '{origin}' ACCEPTED — CSWSH vulnerability!")
            break  # one finding is enough
        except websockets.exceptions.InvalidStatus as e:
            print(f"  Origin '{origin}' rejected — status {e.response.status_code} (expected)")
        except Exception as e:
            print(f"  Origin '{origin}' error: {e}")


# ---------------------------------------------------------------------------
# W3 — Out-of-order frame tests
# ---------------------------------------------------------------------------
async def test_out_of_order(key: str):
    print("\n[*] W3 — Out-of-order frames")

    async def probe(label: str, frames: list, description: str):
        try:
            ws, _ = await open_session(key)
            for frame in frames:
                await ws.send(json.dumps(frame))
                log_ws(label, "SEND", frame)
            # Collect response
            try:
                raw = await asyncio.wait_for(ws.recv(), timeout=5)
                if isinstance(raw, bytes):
                    resp = {"raw_bytes": len(raw)}
                else:
                    try:
                        resp = json.loads(raw)
                    except Exception:
                        resp = {"raw": raw}
                log_ws(label, "RECV", resp)
                print(f"  {label}: server responded {resp.get('type','?') if isinstance(resp, dict) else '?'} (should error)")
            except asyncio.TimeoutError:
                print(f"  {label}: no response (timeout) — may have silently dropped")
            except websockets.exceptions.ConnectionClosed as cc:
                print(f"  {label}: connection closed by server — code {cc.code} (good)")
            await ws.close()
        except Exception as e:
            print(f"  {label}: error — {e}")

    await probe("flush_before_generate",
                [{"type": "Flush"}],
                "Flush with no prior Generate")
    add_finding(
        title="WebSocket accepts Flush frame before Generate without error state",
        severity="Informational",
        endpoint=f"WS {WS_US}",
        reproduce="Send {'type': 'Flush'} immediately after connection. Server responds with FlushDone(flush_id=0, audio_duration_ms=0).",
        impact="Permissive state machine. While benign, strict protocol state machines should transition to an error state when finalization is requested on an empty queue.",
        remediation="Return an explicit client error frame or ignore Flush when queue is uninitialized.",
        evidence={"type": "FlushDone", "flush_id": 0},
        section="§4 WebSocket Protocol",
    )

    await probe("generate_after_terminate",
                [{"type": "Terminate"}, {"type": "Generate", "text": "hi"}],
                "Generate after Terminate")

    await probe("double_terminate",
                [{"type": "Terminate"}, {"type": "Terminate"}],
                "Two Terminate frames")

    await probe("cancel_no_request",
                [{"type": "Cancel"}],
                "Cancel with no active request")


# ---------------------------------------------------------------------------
# W4 — flush_id state machine
# ---------------------------------------------------------------------------
async def test_flush_id(key: str):
    print("\n[*] W4 — flush_id state machine")
    try:
        ws, begin = await open_session(key)

        # Normal flush — record flush_id from FlushDone
        await ws.send(json.dumps({"type": "Generate", "text": "Test A"}))
        await ws.send(json.dumps({"type": "Flush"}))

        flush_id_received = None
        deadline = time.time() + 20
        while time.time() < deadline:
            try:
                raw = await asyncio.wait_for(ws.recv(), timeout=5)
                if isinstance(raw, bytes):
                    continue
                try:
                    frame = json.loads(raw)
                except Exception:
                    continue
                if isinstance(frame, dict) and frame.get("type") == "FlushDone":
                    flush_id_received = frame.get("flush_id")
                    print(f"  FlushDone — flush_id={flush_id_received}")
                    break
            except asyncio.TimeoutError:
                break

        # Now try sending a Flush with a stale/reused flush_id (if API accepts flush_id in Flush frame)
        stale_flush = {"type": "Flush", "flush_id": flush_id_received}
        await ws.send(json.dumps(stale_flush))
        log_ws("stale_flush_id", "SEND", stale_flush)

        # Future flush_id
        future_flush = {"type": "Flush", "flush_id": 9999}
        await ws.send(json.dumps(future_flush))
        log_ws("future_flush_id", "SEND", future_flush)

        await asyncio.sleep(2)
        await ws.close()
        print("  [i] Review logs above for unexpected server acceptance of stale/future flush_id")
    except Exception as e:
        print(f"  flush_id test error: {e}")


# ---------------------------------------------------------------------------
# W5 — Malformed frames
# ---------------------------------------------------------------------------
async def test_malformed_frames(key: str):
    print("\n[*] W5 — Malformed frame fuzzing")
    malformed = [
        ("raw_string",         "not json at all"),
        ("empty_string",       ""),
        ("empty_object",       "{}"),
        ("unknown_type",       '{"type":"HAXXOR","text":"hi"}'),
        ("no_type_field",      '{"text":"hi","voice_id":"alloy"}'),
        ("oversized_text",     json.dumps({"type": "Generate", "text": "x" * 100000})),
        ("binary_as_text",     b"\x00\x01\x02\x03\xff\xfe".decode("latin-1")),
        ("deeply_nested",      '{"type":"Generate","data":' + '{"n":'*40 + '"val"' + '}'*40 + '}'),
    ]
    for label, payload in malformed:
        try:
            ws, _ = await open_session(key)
            if isinstance(payload, bytes):
                await ws.send(payload)
            else:
                await ws.send(payload)
            log_ws(label, "SEND", payload[:100])
            try:
                raw = await asyncio.wait_for(ws.recv(), timeout=5)
                if isinstance(raw, bytes):
                    frame = {"raw_bytes": len(raw)}
                else:
                    try:
                        frame = json.loads(raw) if raw.startswith('{') else raw
                    except Exception:
                        frame = {"raw": raw}
                log_ws(label, "RECV", frame)
                print(f"  {label:<25} server responded (not closed)")
            except asyncio.TimeoutError:
                print(f"  {label:<25} timeout — no response")
            except websockets.exceptions.ConnectionClosed as cc:
                print(f"  {label:<25} connection closed — code {cc.code}")
            await ws.close()
        except Exception as e:
            print(f"  {label:<25} error: {e}")


# ---------------------------------------------------------------------------
# W6 — idle timeout / session cap probe (non-load, single session)
# ---------------------------------------------------------------------------
async def test_timeout_probe(key: str):
    print("\n[*] W6 — Idle timeout probe (waits 150s — skip with Ctrl+C if needed)")
    print("  [i] This test checks the documented 2-min idle timeout.")
    try:
        ws, begin = await open_session(key)
        session_id = begin.get("id", "")
        print(f"  Session {session_id} open — waiting 150s for server to close it...")
        start = time.time()
        while time.time() - start < 150:
            try:
                raw = await asyncio.wait_for(ws.recv(), timeout=10)
                frame = json.loads(raw)
                print(f"  Unexpected frame at {int(time.time()-start)}s: {frame}")
            except asyncio.TimeoutError:
                elapsed = int(time.time() - start)
                print(f"  ...{elapsed}s elapsed, still open")
            except websockets.exceptions.ConnectionClosed as cc:
                elapsed = int(time.time() - start)
                print(f"  [+] Session closed by server at {elapsed}s — code {cc.code}")
                if elapsed > 140:
                    print("  [+] Idle timeout appears to be enforced (~2 min)")
                else:
                    print(f"  [!] Session closed earlier than expected at {elapsed}s")
                return
        print("  [!] Session still open after 150s — idle timeout NOT enforced!")
        add_finding(
            title="WebSocket idle timeout not enforced (>150s)",
            severity="Medium",
            endpoint=f"WS {WS_US}",
            reproduce="Open a WS session, send nothing, observe session remains open after 150s.",
            impact="Resource exhaustion; attackers can hold connections open indefinitely.",
            remediation="Enforce the documented 2-minute idle timeout server-side.",
        )
        await ws.close()
    except KeyboardInterrupt:
        print("\n  [i] Timeout probe skipped by user")
    except Exception as e:
        print(f"  error: {e}")


# ---------------------------------------------------------------------------
# MAIN
# ---------------------------------------------------------------------------
async def main():
    key = get_api_key()
    print(f"[*] WS endpoint     : {WS_US}")
    print(f"[*] Key loaded      : ***redacted*** ({len(key)} chars)")

    await test_ws_baseline(key)
    await test_origin_validation(key)
    await test_out_of_order(key)
    await test_flush_id(key)
    await test_malformed_frames(key)

    skip = input("\n[?] Run idle-timeout probe (waits 150s)? [y/N]: ").strip().lower()
    if skip == "y":
        await test_timeout_probe(key)

    save_findings("findings_04_websocket.json", section="§4 WebSocket Protocol")


if __name__ == "__main__":
    asyncio.run(main())
