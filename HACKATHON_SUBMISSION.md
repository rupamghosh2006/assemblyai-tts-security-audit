# 📝 Voice Hackathon Week: Hack into Speech — Official Submission Responses

This document contains copy-paste ready answers for every single field of the **AssemblyAI Voice Hackathon Week Submission Google Form**.

---

### Field 1: What are you submitting? (select all that apply)*
- [x] **Security issue report**
- [x] **Bug Report**
- [x] **API feedback (bug or suggestion)**

---

### Field 2: Team or submitter name*
```text
Rupam Ghosh
```

---

### Field 3: Team members' names and emails (if a team)
_One line per teammate: Name, email, Discord username. Up to 4 people total including you._
```text
Rupam Ghosh, rupamgh32@gmail.com, rupamghosh
```

---

### Field 4: Twitter or Linkedin or both
```text
LinkedIn: https://www.linkedin.com/in/rupam-ghosh-
Twitter / X: https://x.com/rupamghosh2006
```

---

### Field 5: Primary contact email*
```text
rupamgh32@gmail.com
```

---

### Field 6: Discord username*
```text
rupamghosh
```

---

### Field 7: Project name
```text
AssemblyAI Streaming TTS Security Audit & Vulnerability Assessment Suite
```

---

### Field 8: One-line project tagline
```text
Comprehensive automated security testing suite and responsible disclosure audit for AssemblyAI's Streaming TTS API, uncovering 35 findings across auth, WebSockets, token scopes, and data residency.
```

---

### Field 9: Project description
_What does it do, what problem does it solve, and how does it use the AssemblyAI TTS flow? Required if you're submitting a project._

```text
An automated penetration testing, vulnerability assessment, and responsible disclosure suite engineered specifically for AssemblyAI's Streaming Text-to-Speech (TTS) infrastructure (tts.us.assemblyai.com and tts.eu.assemblyai.com).

The suite systematically evaluates the AssemblyAI TTS flow under adversarial conditions across 7 core security vectors:
1. Authentication & Authorization Header Fuzzing (RFC compliance, header injection, case tolerance)
2. Ephemeral Token Lifecycles & Scope Boundaries (cross-product token reuse, token replay, privilege escalation)
3. Input Validation & Markup Injection (SSML/XML parsing boundaries, XXE probes, Unicode normalization, CRLF)
4. WebSocket Protocol Security (Cross-Site WebSocket Hijacking / CSWSH, state machine transitions, frame limits, idle timeouts, session lease desynchronization)
5. Billing Accuracy, Rate Limiting & Compute Amplification (character counting, cancellation metering, latency amplification)
6. Infrastructure, TLS & Privacy (CORS wildcard policies, HSTS enforcement, server technology fingerprinting, timing attacks)
7. Cross-Tenant Voice Authorization / IDOR (BOLA testing verifying multi-tenant voice cloning model isolation)

Outcomes:
- Discovered 3 High-severity vulnerabilities, 4 Medium-severity issues, 6 Low-severity issues, and verified 22 robust architectural defensive benchmarks.
- Provides complete step-by-step reproduction code, technical impact analysis, and actionable remediation guidelines for AssemblyAI engineers.
- Validates the resilience of AssemblyAI's cryptographic token design (AWS KMS envelope encryption) and multi-tenant voice ownership boundaries.
```

---

### Field 10: Bugs / Feedback
```text
Key Security Findings & Actionable API Feedback:

1. [HIGH - CWE-284/CWE-863] Cross-Product Scope Bypass (STT Token Accepted on TTS Endpoint):
   - Finding: A temporary token minted with product='streaming' (intended solely for Real-Time Speech-to-Text) is successfully accepted by POST https://tts.us.assemblyai.com/v1/speech to synthesize audio.
   - Impact: Malicious actors who extract client-side microphone streaming tokens from browser apps can repurpose them to generate audio and consume the victim's TTS credit quota.
   - Fix: Enforce audience/product claim verification in the TTS authentication middleware; reject tokens where product != 'tts'.

2. [HIGH - CWE-1385] Missing WebSocket Origin Validation (CSWSH Possible):
   - Finding: wss://tts.us.assemblyai.com/v1/ws accepts arbitrary Origin headers (tested Origin: https://evil.com) during connection upgrade.
   - Impact: Malicious websites visited by an authenticated user can establish unauthorized WebSocket streams to hijack TTS capabilities.
   - Fix: Validate the Origin header against an approved domain allowlist during the initial HTTP upgrade handshake.

3. [HIGH - CWE-613/CWE-672] WebSocket Session Outlives Ephemeral Token Expiry (Lease Bypass):
   - Finding: Temporary token expiration timestamps are only evaluated during the initial HTTP upgrade handshake. Once connected, a client can synthesize audio indefinitely long after the token has expired (tested 2s TTL, stream synthesized successfully after 6s+ elapsed).
   - Impact: Clients can lease temporary credentials into perpetual synthesis channels.
   - Fix: Schedule an eviction timer matching expires_at on the WebSocket gateway worker, or validate expiration on every incoming Generate frame.

4. [MEDIUM - CWE-200/CWE-285] STT Temporary Tokens Grant Read Access to Private Voice Library:
   - Finding: Tokens minted for client-side STT can call GET https://tts.us.assemblyai.com/v1/voices, returning the full private voice library, voice names, audio clip size, SHA256 hashes, and internal organization account ID.
   - Fix: Restrict /v1/voices strictly to master API keys or administrative scopes.

5. [MEDIUM - CWE-284] US-Issued Temporary Token Accepted by EU Endpoint:
   - Finding: Tokens minted in the US data zone are accepted by POST https://tts.eu.assemblyai.com/v1/speech.
   - Fix: Cryptographically bind the target data zone to token claims and reject cross-region redemption.

6. [LOW - CWE-598] Master API Key and Token Exposure via WebSocket Query Parameter:
   - Finding: The WebSocket gateway accepts master credentials via ?token=<key>, leaking secrets to edge load balancer logs and proxy histories.
   - Fix: Enforce header-based or Sec-WebSocket-Protocol authentication.

7. [API FEEDBACK & DEVELOPER EXPERIENCE]:
   - Silent Parameter Discarding: Passing unsupported parameters (e.g. output_format) silently defaults to raw PCM with header x-tts-unknown-params. Suggest returning 400 Bad Request to prevent silent client misconfiguration.
   - SSML Markup Clarification: Tags like <break time="3s"/> are neither parsed nor rejected; they are billed character-by-character as literal text. Suggest adding an explicit note in docs or throwing 400 on unescaped markup.
   - Header Hardening: Recommend removing server-timing, server: uvicorn, and x-tts-voice-expires-at from public production responses.
```

---

### Field 11: Tech stack / frameworks used
```text
Python 3.13, Requests, WebSockets, Asyncio, JSON Schema Fuzzing, AWS KMS Packet Analysis, REST API, WebSocket Protocol Auditing
```

---

### Field 12: Demo video link
_A short screen recording (YouTube, Loom, or Drive link) showing your project working. Required if you're submitting a project._
```text
(Optional / Available upon request or insert Loom/Drive recording link of test suite execution)
```

---

### Field 13: Live demo or hosted app link (if available)
```text
https://github.com/rupamghosh2006/assemblyai-tts-security-audit
```

---

### Field 14: Source code repository link
_GitHub (or similar) link. Required if you're submitting a project._
```text
https://github.com/rupamghosh2006/assemblyai-tts-security-audit
```

---

### Field 15: Screenshots or a recording (optional)
_Upload 1 supported file. Max 10 MB._
```text
(Can attach a terminal screenshot of python run_all.py displaying the 35 findings summary or the PENTEST_REPORT.md PDF export)
```
