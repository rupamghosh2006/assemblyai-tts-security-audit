# 🛡️ AssemblyAI Streaming TTS — Security Audit & Vulnerability Assessment Suite

[![Hackathon](https://img.shields.io/badge/AssemblyAI-Voice%20Hackathon%20Week-blueviolet.svg)](https://www.assemblyai.com)
[![Category](https://img.shields.io/badge/Submission-Security%20Finding%20%26%20Bug%20Report-red.svg)](#submission-context)
[![Language](https://img.shields.io/badge/Python-3.11%20%7C%203.12%20%7C%203.13-blue.svg)](https://www.python.org/)
[![License](https://img.shields.io/badge/License-MIT-green.svg)](LICENSE)
[![Findings](https://img.shields.io/badge/Total%20Findings-35-orange.svg)](#findings-summary)

An automated penetration testing, vulnerability assessment, and responsible disclosure suite built for the **AssemblyAI Voice Hackathon Week: Hack into Speech** (Submission Category: **Security Issue Report / Bug Report / API Feedback**).

This suite systematically evaluates the security posture, authentication boundaries, token lifecycles, WebSocket implementation, rate limiting, and multi-tenant isolation of the **AssemblyAI Streaming Text-to-Speech (TTS) API** (`tts.us.assemblyai.com` and `tts.eu.assemblyai.com`).

---

## 📋 Table of Contents

- [Submission Context](#submission-context)
- [Executive Summary](#executive-summary)
- [Severity Breakdown](#severity-breakdown)
- [Key Vulnerability Highlights](#key-vulnerability-highlights)
  - [F-01: Cross-Product Scope Bypass (High)](#f-01--cross-product-token-reuse-stt-token-accepted-by-tts-endpoint)
  - [F-02: Cross-Site WebSocket Hijacking (High)](#f-02--websocket-origin-not-validated--cswsh-possible)
  - [F-03: Indefinite Synthesis on Expired Token (High)](#f-03--websocket-session-outlives-ephemeral-token-expiration)
  - [F-06: STT Token Voice Library Information Disclosure (Medium)](#f-06--stt-temporary-tokens-grant-read-access-to-private-voice-library)
  - [F-07: Cross-Region Data Residency Boundary Violation (Medium)](#f-07--us-issued-temporary-token-accepted-by-eu-endpoint)
  - [F-11: Secret Exposure via WebSocket Query Parameters (Low)](#f-11--master-api-key-and-token-exposure-via-websocket-uri-query-param)
- [Verified Defensive Controls](#verified-defensive-controls)
- [API Feedback & Developer Experience Notes](#api-feedback--developer-experience-notes)
- [Repository Structure](#repository-structure)
- [Installation & Quickstart](#installation--quickstart)
- [Running the Test Suites](#running-the-test-suites)
- [Responsible Disclosure & Safety](#responsible-disclosure--safety)

---

## 🏆 Submission Context

- **Event:** Voice Hackathon Week: Hack into Speech
- **Track:** Security Issue Report / Bug Report / API Feedback
- **Author:** Rupam Ghosh ([@rupamghosh2006](https://github.com/rupamghosh2006))
- **Form Answers:** See [HACKATHON_SUBMISSION.md](HACKATHON_SUBMISSION.md) for full question-by-question responses formatted for the submission form.

---

## 📊 Executive Summary

During the audit of AssemblyAI's Streaming TTS endpoints, a total of **35 unique findings** were identified and cataloged across 7 distinct security vectors:

| Severity | Count | Impact Summary |
|---|---|---|
| 🟠 **High** | **3** | Cross-product scope bypass, Cross-Site WebSocket Hijacking (CSWSH), and session lease desynchronization allowing unlimited synthesis on expired tokens. |
| 🟡 **Medium** | **4** | Undocumented auth parsing variations, private voice inventory disclosure via client-side tokens, and cross-region token redemption. |
| 🔵 **Low** | **6** | Permissive header trimming, duplicate auth header acceptance, silent parameter discarding, secret exposure in URL query strings, compute amplification on mixed-format text, and missing HSTS. |
| ⚪ **Informational / Defensive** | **22** | Infrastructure disclosure (`server-timing`, `uvicorn`, cloud region headers), and verification of robust defensive controls (AWS KMS token encryption, cross-tenant voice IDOR isolation, idle timeouts, frame limits, plaintext HTTP rejection). |
| **Total** | **35** | |

> **Full Detailed Report:** Read the complete 35-finding report with step-by-step reproduction code, technical impacts, and actionable remediations in [PENTEST_REPORT.md](PENTEST_REPORT.md).

---

## 🚨 Key Vulnerability Highlights

### F-01 &nbsp; 🟠 Cross-Product Token Reuse: STT Token Accepted by TTS Endpoint
- **Severity:** High | **CWE:** CWE-284 (Improper Access Control) / CWE-863 (Incorrect Authorization)
- **Endpoint:** `POST https://tts.us.assemblyai.com/v1/speech`
- **What happens:** When an ephemeral token is minted specifically for Speech-to-Text (`product="streaming"` at `https://token.us.assemblyai.com/v1/token`), the TTS endpoint accepts this token without rejecting the mismatched product scope.
- **Impact:** An attacker who extracts a client-side microphone streaming token from a browser web app can synthesize arbitrary audio and consume the organization's TTS credits and compute quotas.
- **Remediation:** Enforce audience/product claim verification in the TTS authentication gateway; reject tokens where `product != "tts"`.

---

### F-02 &nbsp; 🟠 WebSocket Origin Not Validated — CSWSH Possible
- **Severity:** High | **CWE:** CWE-1385 (Missing Origin Validation in WebSockets)
- **Endpoint:** `WS wss://tts.us.assemblyai.com/v1/ws`
- **What happens:** The WebSocket handshake accepts connections with arbitrary `Origin` headers (e.g. `Origin: https://evil.com`).
- **Impact:** If an authenticated victim visits a malicious site while having an active session or accessible token, the malicious page can initiate a cross-site WebSocket handshake to stream audio or hijack TTS capabilities under the victim's account.
- **Remediation:** Enforce origin allowlisting during the HTTP `101 Switching Protocols` handshake.

---

### F-03 &nbsp; 🟠 WebSocket Session Outlives Ephemeral Token Expiration
- **Severity:** High | **CWE:** CWE-613 (Insufficient Session Expiration)
- **Endpoint:** `WS wss://tts.us.assemblyai.com/v1/ws`
- **What happens:** Ephemeral tokens with short lifespans (e.g., `expires_in_seconds=2`) are only validated during connection establishment. Once the WebSocket connection is open, the client can continue sending `Generate` and `Flush` frames indefinitely long after the token has expired (verified: synthesis succeeded 6+ seconds after a 2-second token expired).
- **Impact:** Bypasses temporary token expiration boundaries; a temporary credential can be leased into an indefinite synthesis channel as long as keepalive or traffic continues.
- **Remediation:** WebSocket gateway workers must track `expires_at` and schedule an eviction timer or re-validate token validity before processing each `Generate` frame.

---

### F-06 &nbsp; 🟡 STT Temporary Tokens Grant Read Access to Private Voice Library
- **Severity:** Medium | **CWE:** CWE-200 (Information Disclosure)
- **Endpoint:** `GET https://tts.us.assemblyai.com/v1/voices`
- **What happens:** Ephemeral tokens provisioned for client-side STT can query the voice management endpoint `GET /v1/voices`.
- **Impact:** The response discloses private cloned voices, voice names, audio clip size, SHA256 hashes, and internal organization `owner_account_id` to public browser clients.
- **Remediation:** Restrict `/v1/voices` strictly to master API keys or administrative scopes; client-side tokens should only access voice IDs explicitly assigned to their session.

---

### F-07 &nbsp; 🟡 US-Issued Temporary Token Accepted by EU Endpoint
- **Severity:** Medium | **CWE:** CWE-284 (Improper Access Control / Data Residency)
- **Endpoint:** `POST https://tts.eu.assemblyai.com/v1/speech`
- **What happens:** A temporary token generated on the US token minting service (`token.us.assemblyai.com`) is accepted for authentication by the EU speech synthesis endpoint (`tts.eu.assemblyai.com`).
- **Impact:** Violates data sovereignty boundaries where credentials intended for US jurisdiction can authenticate in the EU infrastructure.
- **Remediation:** Cryptographically bind the regional target zone into the token ciphertext and reject cross-zone token redemption.

---

### F-11 &nbsp; 🔵 Master API Key and Token Exposure via WebSocket URI Query Param
- **Severity:** Low | **CWE:** CWE-598 (Information Exposure Through Query Strings in URI)
- **Endpoint:** `WS wss://tts.us.assemblyai.com/v1/ws?token=<credential>`
- **What happens:** While the REST API strictly rejects query parameter authentication, the WebSocket endpoint allows passing master API keys directly in `?token=...`.
- **Impact:** Query strings are logged in edge load balancer access logs (CloudFront, ALB), corporate proxy logs, and browser histories.
- **Remediation:** Deprecate `?token=` in URLs and require credentials to be passed via headers or the `Sec-WebSocket-Protocol` subprotocol mechanism.

---

## 🛡️ Verified Defensive Controls

In addition to vulnerabilities, this security audit tested and formally verified several exemplary defensive mechanisms implemented by AssemblyAI:

1. **AWS KMS Ciphertext Token Encryption (F-21):** Temporary tokens utilize AWS KMS symmetric envelope encryption (`AQICAH...` header format), completely preventing offline JWT tampering, HMAC secret brute forcing, and `alg: none` exploits.
2. **Strict Multi-Tenant Voice Isolation (F-33, F-34, F-35):** Tested against BOLA / IDOR across two distinct customer accounts. Account B is strictly forbidden from viewing, synthesizing, or deleting Account A's private cloned voice models.
3. **Geopolitical Voice Model Isolation (F-20):** Voice models created in the US data zone cannot be accessed or synthesized from the EU data zone.
4. **WebSocket Idle Inactivity Eviction (F-28):** Idle sessions are terminated after 120 seconds with Error 3006, preventing connection pool exhaustion.
5. **Frame Size Limits (F-27):** Real-time synthesis frames are bounded to 2,000 characters (Error 3006), protecting against memory exhaustion.
6. **Plaintext HTTP Rejection (F-31):** Unencrypted HTTP requests on port 80 are strictly rejected, preventing accidental credential leakage.

---

## 💡 API Feedback & Developer Experience Notes

- **Silent Parameter Discarding:** When invalid or unsupported parameters are passed (e.g. `output_format`), the API responds with `200 OK` and silently defaults to raw PCM, attaching header `x-tts-unknown-params: output_format`. In client SDKs, this leads to confusion where developers believe they requested MP3 but receive unplayable raw PCM. **Recommendation:** Return `400 Bad Request` with an explicit parameter error.
- **SSML Markup Documentation:** Standard SSML tags like `<break time="3s"/>` are neither parsed nor rejected; they are treated as literal text and billed character-by-character. **Recommendation:** Clearly state in the API docs that SSML is unsupported, or reject XML tags with `400 Bad Request`.
- **Server Header Hardening:** Remove `server-timing`, `server: uvicorn`, and `x-tts-voice-expires-at` from public responses to prevent unnecessary infrastructure fingerprinting.

---

## 📁 Repository Structure

```
├── README.md                 # Project overview, findings executive summary, setup
├── PENTEST_REPORT.md         # Comprehensive 35-finding technical report
├── HACKATHON_SUBMISSION.md   # Exact answers for the Voice Hackathon Week submission form
├── requirements.txt          # Python dependencies
├── .env.example              # Template for API keys
├── .gitignore                # Protects secrets (.env, voice_id.txt, logs)
│
├── run_all.py                # Master automated runner & merger
├── report_writer.py          # Markdown pentest report generator
├── utils.py                  # Common utilities, API redactor & HTTP helpers
│
├── 01_auth_fuzzing.py        # §1a Authentication header fuzzing
├── 02_temp_tokens.py         # §1b Ephemeral token lifecycle & scope bypass tests
├── 03_input_fuzzing.py       # §3 Unicode edge cases, SSML, CRLF, param fuzzing
├── 04_websocket.py           # §4 WebSocket protocol, CSWSH, frame parsing, idle timeouts
├── 05_billing.py             # §5 Billing validation & compute amplification
├── 06_infrastructure.py      # §7 TLS, CORS, HSTS, server timing, fingerprinting
├── 07_voice_idor.py          # §8 Cross-tenant voice authorization (IDOR / BOLA)
├── create_test_voice.py      # Synthetic audio test voice generator
├── verify_ssml_xxe.py        # Targeted SSML / XML entity verification
│
├── findings_01_auth.json      # Raw JSON evidence for §1a
├── findings_02_tokens.json    # Raw JSON evidence for §1b
├── findings_03_input.json     # Raw JSON evidence for §3
├── findings_04_websocket.json # Raw JSON evidence for §4
├── findings_05_billing.json   # Raw JSON evidence for §5
├── findings_06_infra.json     # Raw JSON evidence for §7
├── findings_07_idor.json      # Raw JSON evidence for §8
└── findings_MASTER.json       # Merged 35 findings dataset sorted by severity
```

---

## 🚀 Installation & Quickstart

### 1. Clone the repository
```bash
git clone https://github.com/rupamghosh2006/assemblyai-tts-security-audit.git
cd assemblyai-tts-security-audit
```

### 2. Install dependencies
```bash
pip install -r requirements.txt
```

### 3. Configure credentials
Copy `.env.example` to `.env` and provide your test key:
```bash
cp .env.example .env
```
Or set environment variables in your terminal:
```powershell
# Windows PowerShell
$env:ASSEMBLYAI_API_KEY = "your_assemblyai_api_key"

# Optional: Secondary account key to verify multi-tenant IDOR defense
$env:ASSEMBLYAI_API_KEY_B = "secondary_account_key"
```

---

## 🧪 Running the Test Suites

### Run the entire audit suite
```bash
python run_all.py
```

### Run individual security test suites
```bash
# 1. Auth header fuzzing
python 01_auth_fuzzing.py

# 2. Ephemeral tokens & scope bypass
python 02_temp_tokens.py

# 3. Input fuzzing & markup parsing
python 03_input_fuzzing.py

# 4. WebSocket security (CSWSH & timeouts)
python 04_websocket.py

# 5. Billing accuracy & compute amplification
python 05_billing.py

# 6. Infrastructure, TLS & CORS
python 06_infrastructure.py

# 7. Cross-tenant IDOR / BOLA verification
python 07_voice_idor.py
```

### Merge and summarize findings without re-running network tests
```bash
python run_all.py --merge-only
```

---

## 🔒 Responsible Disclosure & Safety Policy

This assessment was conducted strictly within non-destructive testing boundaries following responsible disclosure principles:
- **No production disruption:** Fuzzing was strictly bounded in concurrency and payload size.
- **Privacy preservation:** Voice cloning tests were conducted exclusively using synthetic sine-wave generated audio (`create_test_voice.py`), without using real personal voice data.
- **Secret Redaction:** Raw API keys are never written to logs, console output, or committed files; all captured JSON evidence strictly redacts secrets.
- **Tenant Isolation:** Cross-tenant tests were carried out exclusively between two test accounts owned and controlled by the researcher.

---

## 👤 Author

**Rupam Ghosh**  
- **GitHub:** [@rupamghosh2006](https://github.com/rupamghosh2006)  
- **LinkedIn:** [linkedin.com/in/rupam-ghosh-162593273/](https://www.linkedin.com/in/rupam-ghosh-162593273/)  
- **X / Twitter:** [@rupamghosh2006](https://x.com/rupamghosh2006)  
- **Email:** rupamgh32@gmail.com / rupamgh2006@gmail.com  
- **Discord:** rupamghosh2006
