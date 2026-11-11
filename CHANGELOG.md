# Changelog

All notable changes to **`lh-jsonl-logger`** will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

---

## [0.1.0] - 2026-11-11

### Added
- **Clean-Room PSR-4 Autoloader** (`Logihertz\JsonlLogger\Autoloader`): Zero-dependency autoloader for the `Logihertz\JsonlLogger` namespace.
- **Log Injection & PII Sanitizer** (`Logihertz\JsonlLogger\LogSanitizer`):
  - Strict CRLF (`\r`, `\n`), null byte (`\0`), and ANSI escape sequence (`\x1b[...]`) stripping and detection (CWE-117).
  - Recursive PII and credential redactor masking keys (`password`, `secret`, `token`, `api_key`, `authorization`, `cookie`, `cvv`, `credit_card`, `ssn`, `private_key`) as `[REDACTED]` (CWE-532).
  - Inline Bearer token regex redaction (`Bearer [REDACTED]`).
- **Tamper-Evident Cryptographic Hash Chaining** (`Logihertz\JsonlLogger\HashChainEngine`):
  - SHA-256 and HMAC-SHA256 log hash chaining linking $H_i = \text{SHA-256}(H_{i-1} \parallel \text{canonical\_json}(E_i))$.
  - 64-zero genesis hash verification ($H_0$).
  - Canonical JSON serialization with recursive key sorting (`ksort`) and unescaped Unicode/slashes.
  - Constant-time verification stream validator using `hash_equals()` with exact line mismatch pinpointing.
- **Atomic File-Locked NDJSON Writer** (`Logihertz\JsonlLogger\AtomicJsonlWriter`):
  - Exclusive advisory locking (`flock(LOCK_EX)`) guaranteeing thread-safe, process-safe append-only writes (CWE-362).
  - Restrictive file permission enforcement (`0600` / `0640`) upon creation (CWE-276).
  - Deterministic size-based rotation shifting `.jsonl` -> `.jsonl.1` -> `.jsonl.2` up to `$maxBackups` (CWE-400).
  - Seamless chain continuity recovery from previous file entries.
- **10-Rule Logging Posture Auditor** (`Logihertz\JsonlLogger\LoggerAuditor`):
  - Rules `LH-LOG-001` through `LH-LOG-010` covering credential masking, hash chaining, file permissions, injection sanitization, atomic locking, log rotation, CERT-In 180-day retention, remote TLS transport, UTC ISO-8601 formatting, and disk alerts.
  - Standardized Logihertz Security Posture Score calculation:
    $$S_{\text{posture}} = \max(0, 100 - (25\cdot c_{\text{CRIT}} + 10\cdot c_{\text{HIGH}} + 4\cdot c_{\text{MED}} + 1\cdot c_{\text{LOW}}))$$
- **Multi-Format Exporters** (`Logihertz\JsonlLogger\Exporters`):
  - ANSI colored terminal table with security score banner.
  - Machine-readable Canonical JSON report.
  - OASIS SARIF v2.1.0 output with rule metadata and CWE mappings.
- **Standalone CLI Utility** (`bin/lh-logger`):
  - Subcommands: `scan`, `verify-chain`, `write`, `redact`, `--version`, `--help`.
- **Verification Test Suite** (`tests/run_tests.php`):
  - 85+ deterministic assertions verifying hash-chain math, sanitization, atomic locking, rotation, auditor rules, and exit codes.
