<?php

declare(strict_types=1);

namespace Logihertz\JsonlLogger;

use JsonException;
use RuntimeException;

/**
 * Deterministic 10-rule logging and audit trail posture auditor.
 *
 * Evaluates telemetry policies against security rules LH-LOG-001 through LH-LOG-010
 * and computes the standardized Logihertz Security Posture Score (0-100).
 *
 * @author Sameer Tawade <ops@logihertz.com>
 * @license Apache-2.0
 */
final class LoggerAuditor
{
    /**
     * Complete definition of all 10 core detection rules.
     */
    public const RULE_DEFINITIONS = [
        'LH-LOG-001' => [
            'id' => 'LH-LOG-001',
            'severity' => 'CRITICAL',
            'weight' => 25,
            'cwe' => 'CWE-532',
            'title' => 'Sensitive credential/PII redaction disabled or missing key list',
            'description' => 'Audit logger does not enforce automatic recursive redaction of sensitive credentials, tokens, or PII.',
            'recommendation' => 'Enable redact_sensitive_fields: true and specify a non-empty array of sensitive_fields.',
        ],
        'LH-LOG-002' => [
            'id' => 'LH-LOG-002',
            'severity' => 'CRITICAL',
            'weight' => 25,
            'cwe' => 'CWE-353',
            'title' => 'Cryptographic tamper-evident hash chaining disabled on audit logs',
            'description' => 'Audit stream lacks cryptographic forward hash-chaining, leaving logs vulnerable to silent post-compromise tampering or deletion.',
            'recommendation' => 'Enable hash_chaining_enabled: true to bind each record cryptographically with SHA-256 / HMAC-SHA256.',
        ],
        'LH-LOG-003' => [
            'id' => 'LH-LOG-003',
            'severity' => 'CRITICAL',
            'weight' => 25,
            'cwe' => 'CWE-276',
            'title' => 'World-readable or overly permissive log file permissions',
            'description' => 'Log files are written with permissive permissions outside 0600 or 0640, exposing sensitive operational data to local unprivileged users.',
            'recommendation' => 'Enforce file_permissions: "0600" (owner read/write) or "0640" (group read restricted).',
        ],
        'LH-LOG-004' => [
            'id' => 'LH-LOG-004',
            'severity' => 'HIGH',
            'weight' => 10,
            'cwe' => 'CWE-117',
            'title' => 'CRLF and ANSI escape sequence log injection sanitization disabled',
            'description' => 'Control character filtering is disabled, allowing attackers to forge fake audit entries via CRLF injection or manipulate terminal displays.',
            'recommendation' => 'Enable sanitize_control_chars: true to strip ANSI escape codes and neutralize CRLF sequences.',
        ],
        'LH-LOG-005' => [
            'id' => 'LH-LOG-005',
            'severity' => 'HIGH',
            'weight' => 10,
            'cwe' => 'CWE-362',
            'title' => 'Exclusive atomic file locking disabled, risking interleaved corrupted lines',
            'description' => 'Concurrent multi-process writes do not acquire exclusive POSIX advisory locks (flock), risking truncated or interleaved NDJSON records.',
            'recommendation' => 'Enable atomic_flock_enabled: true to enforce flock(LOCK_EX) on append-only streams.',
        ],
        'LH-LOG-006' => [
            'id' => 'LH-LOG-006',
            'severity' => 'HIGH',
            'weight' => 10,
            'cwe' => 'CWE-400',
            'title' => 'Log rotation disabled or excessive single-file size threshold (> 500MB)',
            'description' => 'Log rotation is absent or configured with an excessive file size threshold, risking disk exhaustion and degraded forensic search performance.',
            'recommendation' => 'Enable rotation_enabled: true with max_file_size_mb <= 500 and max_backups >= 5.',
        ],
        'LH-LOG-007' => [
            'id' => 'LH-LOG-007',
            'severity' => 'HIGH',
            'weight' => 10,
            'cwe' => 'CWE-778',
            'title' => 'Insufficient audit log retention period (< 180 days)',
            'description' => 'Log retention period is less than 180 days, violating CERT-In cyber security directives and forensic investigation requirements.',
            'recommendation' => 'Set retention_days to 180 or greater to satisfy CERT-In, PCI-DSS, and ISO 27001 retention standards.',
        ],
        'LH-LOG-008' => [
            'id' => 'LH-LOG-008',
            'severity' => 'MEDIUM',
            'weight' => 4,
            'cwe' => 'CWE-319',
            'title' => 'Remote syslog/SIEM forwarding configured over unencrypted transport',
            'description' => 'Log forwarding to remote SIEM or log aggregation collector is transmitted over plaintext transport without TLS.',
            'recommendation' => 'Enforce remote_transport_tls: true using TLS 1.3 or mTLS for all network log shipping.',
        ],
        'LH-LOG-009' => [
            'id' => 'LH-LOG-009',
            'severity' => 'MEDIUM',
            'weight' => 4,
            'cwe' => 'CWE-693',
            'title' => 'Non-UTC or ambiguous timestamp format configured',
            'description' => 'Telemetry timestamps do not enforce strict UTC ISO-8601 formatting, impairing chronological multi-service forensic correlation.',
            'recommendation' => 'Enable timestamp_utc_iso8601: true to enforce Zulu-time (UTC) ISO-8601 timestamps (YYYY-MM-DDTHH:MM:SSZ).',
        ],
        'LH-LOG-010' => [
            'id' => 'LH-LOG-010',
            'severity' => 'LOW',
            'weight' => 1,
            'cwe' => 'CWE-755',
            'title' => 'Missing disk-full / write-failure alert policy or unbounded record size',
            'description' => 'No failure alerting is configured for log write errors (e.g. disk full), or maximum single-record size limit is unconstrained.',
            'recommendation' => 'Enable alert_on_write_failure: true and configure a safe max_record_size_kb limit (e.g. 64KB).',
        ],
    ];

    /**
     * Audit a logging policy manifest array or file path.
     *
     * @param array<string, mixed>|string $target Policy array or path to JSON policy file.
     * @return array{
     *     target: string,
     *     posture_score: int,
     *     summary: array{
     *         total_findings: int,
     *         critical: int,
     *         high: int,
     *         medium: int,
     *         low: int
     *     },
     *     findings: array<int, array{
     *         rule_id: string,
     *         severity: string,
     *         cwe: string,
     *         title: string,
     *         description: string,
     *         recommendation: string,
     *         evidence: string
     *     }>
     * }
     */
    public function audit(array|string $target): array
    {
        $targetName = 'in-memory-policy';
        $policy = [];

        if (is_string($target)) {
            $targetName = $target;
            if (!file_exists($target)) {
                throw new RuntimeException("Target policy file not found: {$target}");
            }
            $contents = (string) file_get_contents($target);
            try {
                /** @var mixed $decoded */
                $decoded = json_decode($contents, true, 512, JSON_THROW_ON_ERROR);
            } catch (JsonException $e) {
                throw new RuntimeException("Failed to parse policy JSON: " . $e->getMessage(), 0, $e);
            }
            if (!is_array($decoded)) {
                throw new RuntimeException("Policy file must contain a JSON object.");
            }
            $policy = $decoded;
        } else {
            $policy = $target;
        }

        $findings = [];

        // LH-LOG-001: Sensitive credential/PII redaction
        $redactEnabled = $policy['redact_sensitive_fields'] ?? false;
        $sensitiveKeys = $policy['sensitive_fields'] ?? [];
        if ($redactEnabled !== true || !is_array($sensitiveKeys) || empty($sensitiveKeys)) {
            $findings[] = $this->createFinding(
                'LH-LOG-001',
                sprintf(
                    'redact_sensitive_fields=%s, sensitive_fields_count=%d',
                    json_encode($redactEnabled),
                    is_array($sensitiveKeys) ? count($sensitiveKeys) : 0
                )
            );
        }

        // LH-LOG-002: Tamper-evident hash chaining
        $hashChaining = $policy['hash_chaining_enabled'] ?? false;
        if ($hashChaining !== true) {
            $findings[] = $this->createFinding(
                'LH-LOG-002',
                sprintf('hash_chaining_enabled=%s', json_encode($hashChaining))
            );
        }

        // LH-LOG-003: File permissions (0600 or 0640)
        $permRaw = $policy['file_permissions'] ?? null;
        $permInt = null;
        if (is_string($permRaw)) {
            $permInt = (int) octdec(ltrim($permRaw, '0') === '' ? '0' : ltrim($permRaw, '0'));
        } elseif (is_int($permRaw)) {
            $permInt = $permRaw;
        }

        if ($permInt === null || ($permInt !== 0600 && $permInt !== 0640)) {
            $findings[] = $this->createFinding(
                'LH-LOG-003',
                sprintf('file_permissions=%s (allowed: 0600, 0640)', json_encode($permRaw))
            );
        }

        // LH-LOG-004: Control character / CRLF injection sanitization
        $sanitizeControl = $policy['sanitize_control_chars'] ?? false;
        if ($sanitizeControl !== true) {
            $findings[] = $this->createFinding(
                'LH-LOG-004',
                sprintf('sanitize_control_chars=%s', json_encode($sanitizeControl))
            );
        }

        // LH-LOG-005: Exclusive atomic locking (flock)
        $atomicFlock = $policy['atomic_flock_enabled'] ?? false;
        if ($atomicFlock !== true) {
            $findings[] = $this->createFinding(
                'LH-LOG-005',
                sprintf('atomic_flock_enabled=%s', json_encode($atomicFlock))
            );
        }

        // LH-LOG-006: Log rotation enabled & size limit <= 500MB
        $rotationEnabled = $policy['rotation_enabled'] ?? false;
        $maxSizeMb = isset($policy['max_file_size_mb']) ? (float) $policy['max_file_size_mb'] : 0.0;
        if ($rotationEnabled !== true || $maxSizeMb > 500.0 || $maxSizeMb <= 0.0) {
            $findings[] = $this->createFinding(
                'LH-LOG-006',
                sprintf('rotation_enabled=%s, max_file_size_mb=%s (max allowed: 500)', json_encode($rotationEnabled), json_encode($maxSizeMb))
            );
        }

        // LH-LOG-007: Retention period >= 180 days (CERT-In mandate)
        $retentionDays = isset($policy['retention_days']) ? (int) $policy['retention_days'] : 0;
        if ($retentionDays < 180) {
            $findings[] = $this->createFinding(
                'LH-LOG-007',
                sprintf('retention_days=%d (minimum required: 180)', $retentionDays)
            );
        }

        // LH-LOG-008: Remote SIEM transport encryption (TLS)
        $remoteForwarding = $policy['remote_forwarding_enabled'] ?? true;
        $remoteTls = $policy['remote_transport_tls'] ?? false;
        if ($remoteForwarding === true && $remoteTls !== true) {
            $findings[] = $this->createFinding(
                'LH-LOG-008',
                sprintf('remote_forwarding_enabled=true, remote_transport_tls=%s', json_encode($remoteTls))
            );
        }

        // LH-LOG-009: UTC ISO-8601 timestamp format
        $utcTimestamp = $policy['timestamp_utc_iso8601'] ?? false;
        if ($utcTimestamp !== true) {
            $findings[] = $this->createFinding(
                'LH-LOG-009',
                sprintf('timestamp_utc_iso8601=%s', json_encode($utcTimestamp))
            );
        }

        // LH-LOG-010: Failure alerting policy & bounded record size
        $alertOnFailure = $policy['alert_on_write_failure'] ?? false;
        $maxRecordKb = isset($policy['max_record_size_kb']) ? (int) $policy['max_record_size_kb'] : 0;
        if ($alertOnFailure !== true || $maxRecordKb <= 0 || $maxRecordKb > 1024) {
            $findings[] = $this->createFinding(
                'LH-LOG-010',
                sprintf('alert_on_write_failure=%s, max_record_size_kb=%s', json_encode($alertOnFailure), json_encode($maxRecordKb))
            );
        }

        $counts = [
            'total_findings' => count($findings),
            'critical' => 0,
            'high' => 0,
            'medium' => 0,
            'low' => 0,
        ];

        $deductions = 0;
        foreach ($findings as $f) {
            match ($f['severity']) {
                'CRITICAL' => $counts['critical']++,
                'HIGH' => $counts['high']++,
                'MEDIUM' => $counts['medium']++,
                'LOW' => $counts['low']++,
                default => null,
            };
            $ruleDef = self::RULE_DEFINITIONS[$f['rule_id']];
            $deductions += (int) $ruleDef['weight'];
        }

        $postureScore = max(0, 100 - $deductions);

        return [
            'target' => $targetName,
            'posture_score' => $postureScore,
            'summary' => $counts,
            'findings' => $findings,
        ];
    }

    /**
     * Helper to construct finding record from rule definition.
     *
     * @param string $ruleId Rule identifier.
     * @param string $evidence Specific offending configuration fragment.
     * @return array{rule_id: string, severity: string, cwe: string, title: string, description: string, recommendation: string, evidence: string}
     */
    private function createFinding(string $ruleId, string $evidence): array
    {
        $def = self::RULE_DEFINITIONS[$ruleId];
        return [
            'rule_id' => $ruleId,
            'severity' => (string) $def['severity'],
            'cwe' => (string) $def['cwe'],
            'title' => (string) $def['title'],
            'description' => (string) $def['description'],
            'recommendation' => (string) $def['recommendation'],
            'evidence' => $evidence,
        ];
    }
}
