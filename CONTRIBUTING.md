# Contributing to Logihertz JSONL Logger (`lh-jsonl-logger`)

Thank you for your interest in contributing to **`lh-jsonl-logger`**! We adhere to
strict clean-room engineering, zero-dependency minimalism, and deterministic verification.

---

## 1. Zero External Runtime Dependencies Mandate

`lh-jsonl-logger` is designed to be embedded in mission-critical PHP infrastructure without
introducing dependency bloat or supply chain attack surface.

- **Mandatory**: All runtime code under `src/` and `bin/` must use **native PHP 8.2+ core features only**.
- **Forbidden**: Third-party Composer runtime dependencies (e.g., Monolog, Symfony components, Guzzle) are strictly forbidden.
- **Allowed Core Extensions**: `ext-hash`, `ext-json`, `ext-spl`, native stream and POSIX file locking (`flock`, `chmod`, `rename`).

---

## 2. PHP Version Compatibility Standards

- Code must pass on **PHP 8.2, 8.3, and 8.4**.
- **Do not use PHP 8.3+ typed class constants** (e.g. `public const string FOO = 'bar';` is forbidden; use untyped `public const FOO = 'bar';` to ensure clean execution on PHP 8.2).
- Always use `declare(strict_types=1);` in every PHP source file.
- Use explicit parameter and return types for all functions and methods.

---

## 3. Cryptographic & Telemetry Guidelines

- **Tamper-Evident Hash Chains**: Every log record must link cryptographically to the preceding record:
  $$H_i = \text{SHA-256}\left(H_{i-1} \parallel \text{canonical\_json}(E_i)\right)$$
- **Genesis Hash**: The stream must begin with 64 zero hex characters (`0000000000000000000000000000000000000000000000000000000000000000`).
- **Canonical Serialization**: Keys must be sorted recursively (`ksort`), with `JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE`, and `entry_hash` excluded during signature generation.
- **Constant-Time Verification**: Verification of hashes and HMAC signatures must use `hash_equals()` to avoid timing side-channels.
- **Atomic Locking**: File write operations must acquire an exclusive lock (`flock(..., LOCK_EX)`) before writing and flushing.
- **Sanitization & Redaction**: All strings from untrusted sources must be stripped of CRLF (`\r`, `\n`), null bytes (`\0`), and ANSI escape sequences. Sensitive keys must be masked recursively as `[REDACTED]`.

---

## 4. Local Development Workflow

### Syntax Lint:
```bash
find src bin tests -type f -exec php -l {} +
```

### Run Test Suite:
```bash
php tests/run_tests.php
```

### Smoke Test CLI Operations:
```bash
# Verify compliant policy
php bin/lh-logger scan fixtures/hardened_log_policy.json --format table

# Verify tamper-evident audit stream
php bin/lh-logger verify-chain fixtures/sample_audit_stream.jsonl

# Test log redaction
php bin/lh-logger redact --input '{"user":"alice","password":"supersecretpassword","token":"Bearer 12345"}'
```

---

## 5. Adding Detection Rules (`LH-LOG-001` .. `LH-LOG-010`)

When proposing changes or new detection rules in `LoggerAuditor`:
1. Assign a unique rule ID (`LH-LOG-xxx`).
2. Map the vulnerability to an official CWE (e.g., CWE-117, CWE-532, CWE-353, CWE-276).
3. Assign severity (`CRITICAL`, `HIGH`, `MEDIUM`, `LOW`) and corresponding weight.
4. Update `fixtures/vulnerable_log_policy.json` to trigger the rule and `fixtures/hardened_log_policy.json` to pass it cleanly.
5. Add deterministic assertions in `tests/run_tests.php`.

---

## 6. Commit & Attribution Standards

- Maintainer attribution: `Sameer Tawade <ops@logihertz.com>`
- Organization identity: `logihertzsystems <ops@logihertz.com>`
- Use Conventional Commits (`feat:`, `fix:`, `docs:`, `test:`, `refactor:`).
