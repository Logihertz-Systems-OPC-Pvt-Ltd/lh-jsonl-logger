# Logihertz JSONL Logger (`lh-jsonl-logger`)

[![Organization](https://img.shields.io/badge/Organization-Logihertz%20Systems-000000.svg)](https://logihertz.com/)
[![License: Apache-2.0](https://img.shields.io/badge/License-Apache--2.0-blue.svg)](https://opensource.org/licenses/Apache-2.0)
[![PHP: 8.2+](https://img.shields.io/badge/PHP-8.2%20%7C%208.3%20%7C%208.4-777BB4.svg?logo=php&logoColor=white)](https://www.php.net/)
[![OASIS SARIF v2.1.0](https://img.shields.io/badge/OASIS-SARIF%20v2.1.0-green.svg)](https://docs.oasis-open.org/sarif/sarif/v2.1.0/sarif-v2.1.0.html)
[![Zero Dependencies](https://img.shields.io/badge/Dependencies-0%20External-success.svg)](#architecture)
[![CI Matrix](https://github.com/Logihertz-Systems-OPC-Pvt-Ltd/lh-jsonl-logger/actions/workflows/ci.yml/badge.svg)](https://github.com/Logihertz-Systems-OPC-Pvt-Ltd/lh-jsonl-logger/actions/workflows/ci.yml)

**Enterprise-grade, zero-dependency PHP 8.2+ atomic file-locked NDJSON/JSONL telemetry logger, tamper-evident SHA-256 hash-chain verifier, recursive PII/credential redactor, and 10-rule logging posture auditor.**

---

## Executive Summary

Modern enterprise audit streams, compliance telemetry, and high-concurrency API backends face severe risks from log injection (`CWE-117`), credential leakage (`CWE-532`), race conditions and corrupt lines during concurrent writes (`CWE-362`), and post-compromise tampering of log trails (`CWE-353`).

**`lh-jsonl-logger`** (`bin/lh-logger`) provides a clean-room, zero-dependency PHP 8.2+ engine engineered to solve these challenges with mathematical precision:
- **Zero External Dependencies**: Powered strictly by native PHP 8.2+ (`ext-hash`, `ext-json`, `ext-spl`, `flock()`, `hash()`, `hash_hmac()`, and `hash_equals()`).
- **Atomic File-Locked Append**: Uses advisory POSIX exclusive locks (`flock($fp, LOCK_EX)`) to guarantee atomic, uninterleaved log lines across parallel processes without external locking daemons.
- **Cryptographic Tamper-Evidence**: Implements continuous SHA-256 and HMAC-SHA256 forward hash-chaining so any modified, injected, reordered, or deleted log line is mathematically detectable.
- **Log Injection & PII Redaction**: Strips CRLF and ANSI escape sequences while recursively masking credentials (`password`, `token`, `secret`, `api_key`, `authorization`, `Bearer ...`) as `[REDACTED]`.
- **Deterministic Posture Auditor**: 10-rule security evaluation engine producing colored terminal tables, canonical JSON, and OASIS SARIF v2.1.0 reports for CI/CD pipelines.

---

## Architecture & Mathematical Foundations

### 1. Tamper-Evident SHA-256 Hash Chain

Every log record in an audit stream is bound cryptographically to its predecessor:

$$H_i = \text{SHA-256}\left(H_{i-1} \parallel \text{canonical\_json}(E_i)\right)$$

Where:
- $H_0 = \texttt{"0000000000000000000000000000000000000000000000000000000000000000"}$ (64-character hex zero genesis hash).
- $\text{canonical\_json}(E_i)$ is the deterministic JSON representation of the event payload with keys sorted recursively (`ksort`), `JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE`, and excluding `entry_hash`.
- When an HMAC key is supplied, the chain uses keyed HMAC-SHA256:
  $$H_i = \text{HMAC-SHA256}\left(K, H_{i-1} \parallel \text{canonical\_json}(E_i)\right)$$
- Verification evaluates each link in the chain using constant-time `hash_equals()`, immediately pinpointing the exact line number where any integrity breach occurred.

### 2. Atomic Locking & Deterministic Rotation

```
┌────────────────────────────────────────────────────────┐
│ Process A ──┐                                          │
│ Process B ──┼──► flock(fp, LOCK_EX) ──► fwrite(JSONL)  │
│ Process C ──┘           ▲                     │        │
│                         │                     ▼        │
│                [Exclusive Lock]          fflush(fp)    │
│                         │                     │        │
│                         └──────── flock(fp, LOCK_UN)   │
└────────────────────────────────────────────────────────┘
```

When active file size exceeds `maxBytes`, `AtomicJsonlWriter` performs an atomic rotation:
$$\text{stream.jsonl.2} \leftarrow \text{stream.jsonl.1} \leftarrow \text{stream.jsonl}$$
maintaining chain continuity by linking the first record of the rotated file to the last hash of the previous stream.

---

## Core Detection Rules (`LH-LOG-001` .. `LH-LOG-010`)

The built-in `LoggerAuditor` evaluates logging policy configurations against 10 deterministic security rules:

| Rule ID | Severity | Weight ($W_r$) | CWE Mapping | Trigger Condition & Description |
|:---|:---:|:---:|:---:|:---|
| **LH-LOG-001** | `CRITICAL` | 25 | CWE-532 | Sensitive credential/PII redaction disabled (`redact_sensitive_fields: false`) or empty sensitive key list |
| **LH-LOG-002** | `CRITICAL` | 25 | CWE-353 | Cryptographic tamper-evident hash chaining disabled (`hash_chaining_enabled: false`) on audit logs |
| **LH-LOG-003** | `CRITICAL` | 25 | CWE-276 | World-readable or permissive file permissions (`file_permissions` not `0600`/`0640`, e.g., `0666` or `0644`) |
| **LH-LOG-004** | `HIGH` | 10 | CWE-117 | CRLF and ANSI escape sequence log injection sanitization disabled (`sanitize_control_chars: false`) |
| **LH-LOG-005** | `HIGH` | 10 | CWE-362 | Exclusive atomic file locking disabled (`atomic_flock_enabled: false`), risking interleaved corrupted lines |
| **LH-LOG-006** | `HIGH` | 10 | CWE-400 | Log rotation disabled (`rotation_enabled: false`) or excessive single-file size limit (`max_file_size_mb > 500`) |
| **LH-LOG-007** | `HIGH` | 10 | CWE-778 | Insufficient log retention period (`retention_days < 180`, violating CERT-In 180-day mandate) |
| **LH-LOG-008** | `MEDIUM` | 4 | CWE-319 | Remote syslog/SIEM forwarding configured over unencrypted transport (`remote_transport_tls: false`) |
| **LH-LOG-009** | `MEDIUM` | 4 | CWE-693 | Non-UTC or ambiguous timestamp format (`timestamp_utc_iso8601: false`), hindering forensic correlation |
| **LH-LOG-010** | `LOW` | 1 | CWE-755 | Missing disk-full / write-failure alert policy (`alert_on_write_failure: false`) |

### Standardized Security Posture Score:

$$S_{\text{posture}} = \max\left(0, 100 - \sum_{r \in \text{Violations}} W_r\right) = \max\left(0, 100 - (25 \cdot c_{\text{CRIT}} + 10 \cdot c_{\text{HIGH}} + 4 \cdot c_{\text{MED}} + 1 \cdot c_{\text{LOW}})\right)$$

- **Compliant Baseline (`hardened_log_policy.json`)**: $S_{\text{posture}} = 100/100$ (Exit code `0`).
- **Non-Compliant Policy (`vulnerable_log_policy.json`)**: $S_{\text{posture}} = \max(0, 100 - 124) = 0/100$ (Exit code `1`).

---

## Installation & CLI Usage

### Requirements
- **PHP**: `8.2`, `8.3`, or `8.4`
- **Extensions**: `ext-hash`, `ext-json`, `ext-spl`

### CLI Commands

```bash
# 1. Audit Logging Policy Configuration
php bin/lh-logger scan fixtures/hardened_log_policy.json --format table
php bin/lh-logger scan fixtures/hardened_log_policy.json --format sarif --output report.sarif

# 2. Verify Cryptographic Integrity of an Audit Stream
php bin/lh-logger verify-chain fixtures/sample_audit_stream.jsonl

# 3. Append an Audit Record with Automatic Hash-Chaining
php bin/lh-logger write \
  --file app_audit.jsonl \
  --event user.login \
  --level INFO \
  --data '{"user":"admin","ip":"192.168.1.100","session":"xyz"}'

# 4. Redact PII and Sensitive Secrets from JSON Input
php bin/lh-logger redact \
  --input '{"username":"sam","password":"supersecret","token":"Bearer 98765"}'

# 5. CLI Help & Version
php bin/lh-logger --help
php bin/lh-logger --version
```

### Programmatic Usage

```php
use Logihertz\JsonlLogger\AtomicJsonlWriter;
use Logihertz\JsonlLogger\HashChainEngine;
use Logihertz\JsonlLogger\LogSanitizer;

// Initialize components
$sanitizer = new LogSanitizer();
$chainEngine = new HashChainEngine();
$writer = new AtomicJsonlWriter('var/log/audit.jsonl', $sanitizer, $chainEngine);

// Write atomic, hash-chained, sanitized audit entry
$record = [
    'timestamp' => gmdate('Y-m-d\TH:i:s\Z'),
    'event' => 'order.checkout',
    'level' => 'INFO',
    'user_id' => 'USR-48201',
    'metadata' => [
        'cart_id' => 'CRT-9921',
        'credit_card' => '4111222233334444', // Automatically masked to [REDACTED]
    ]
];

$writer->writeRecord($record);

// Verify stream integrity
$results = $chainEngine->verifyStream(file('var/log/audit.jsonl'));
if (!$results['valid']) {
    throw new RuntimeException("Audit stream compromised at line {$results['broken_at_line']}: {$results['reason']}");
}
```

---

## Exit Codes

| Exit Code | Semantic Meaning |
|:---:|:---|
| **`0`** | Clean scan (Score: 100, zero violations) or valid hash chain verification |
| **`1`** | Policy violation detected (findings > 0) or tampered/broken hash chain |
| **`2`** | Invalid CLI arguments, missing file, or invalid JSON payload |

---

## Corporate Attribution & Governance

- **Organization**: [Logihertz Systems (OPC) Private Limited](https://logihertz.com/)
- **GitHub Organization**: [`Logihertz-Systems-OPC-Pvt-Ltd`](https://github.com/Logihertz-Systems-OPC-Pvt-Ltd)
- **Creator, Founder, Director & Sole Developer**: **Sameer Tawade** ([`ops@logihertz.com`](mailto:ops@logihertz.com) / [`security@logihertz.com`](mailto:security@logihertz.com))
- **Git Commit Author**: `logihertzsystems <ops@logihertz.com>`
- **License**: Released under the [Apache License, Version 2.0](https://www.apache.org/licenses/LICENSE-2.0).

Copyright &copy; 2026 Logihertz Systems (OPC) Private Limited. All Rights Reserved.
