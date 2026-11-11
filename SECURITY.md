# Security Policy

## Scope & Commitment

Logihertz Systems (OPC) Private Limited maintains high engineering and cryptographic
standards across all open-source utilities. **`lh-jsonl-logger`** is designed for
high-throughput telemetry, tamper-evident audit trails, and strict compliance environments.

We welcome responsible security disclosures regarding:
- Cryptographic vulnerabilities in SHA-256 or HMAC-SHA256 hash chaining.
- Race conditions or advisory lock bypasses in `AtomicJsonlWriter` (`flock`).
- Control character or CRLF injection bypasses in `LogSanitizer`.
- PII/secret redaction bypasses for nested objects or sensitive keys.
- Misclassification or bypasses in the 10-rule `LoggerAuditor`.
- Information disclosure via file permission inheritance or log rotation race conditions.

---

## Supported Versions

| Version | Status | Security Support |
|:---|:---:|:---|
| `0.1.x` | Active | Full security updates and patches |
| `< 0.1.0` | End of Life | Not supported |

---

## Reporting a Vulnerability

Please report potential security vulnerabilities privately. **Do not create public GitHub issues for undisclosed security flaws.**

### Reporting Channels:
1. **Email (Primary)**: [`security@logihertz.com`](mailto:security@logihertz.com)
2. **Operations (Escalation)**: [`ops@logihertz.com`](mailto:ops@logihertz.com)

### When submitting a report, please include:
- A clear description of the vulnerability and its potential impact.
- Exact reproduction steps, including PHP version (`8.2`, `8.3`, or `8.4`).
- Minimal proof-of-concept code, tampered JSONL streams, or custom policy files.
- Any suggested remediations or mitigations.

---

## Service Level Agreements (SLA)

| Milestone | Target Response Time |
|:---|:---:|
| **Initial Acknowledgment** | Within 48 hours |
| **Triage & Severity Classification** | Within 3 business days |
| **Fix Development & Private Verification** | Within 5 business days |
| **Public Advisory & Coordinated Release** | Within 14 calendar days |

---

## Disclosure Guidelines

- Please allow sufficient time for patch development and verification before public disclosure.
- Ensure test data does not contain real production secrets or customer PII.
- Logihertz Systems credits security researchers in our release notes and `CHANGELOG.md`.
