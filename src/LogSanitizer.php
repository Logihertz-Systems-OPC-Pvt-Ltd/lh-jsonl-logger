<?php

declare(strict_types=1);

namespace Logihertz\JsonlLogger;

/**
 * Log sanitization and recursive PII/credential redaction engine.
 *
 * Mitigates Log Injection (CWE-117) and Information Exposure Through Log Files (CWE-532)
 * by neutralizing CRLF, null bytes, and ANSI escape sequences, and masking sensitive
 * credentials and authentication tokens.
 *
 * @author Sameer Tawade <ops@logihertz.com>
 * @license Apache-2.0
 */
final class LogSanitizer
{
    /**
     * Default list of sensitive keys targeted for redaction.
     */
    public const DEFAULT_SENSITIVE_KEYS = [
        'password',
        'passwd',
        'secret',
        'token',
        'api_key',
        'apikey',
        'authorization',
        'auth_token',
        'access_token',
        'refresh_token',
        'client_secret',
        'cookie',
        'cvv',
        'credit_card',
        'card_number',
        'ssn',
        'private_key',
        'id_token',
    ];

    /**
     * Check if a string contains log injection control characters (CRLF, null bytes, ANSI escapes).
     *
     * @param string $value The string to evaluate.
     * @return bool True if injection characters are detected.
     */
    public function containsInjectionChars(string $value): bool
    {
        if (strpbrk($value, "\r\n\0") !== false) {
            return true;
        }

        return (bool) preg_match('/\x1b\[[0-9;]*[a-zA-Z]/', $value);
    }

    /**
     * Sanitize a string by stripping ANSI escape sequences, null bytes, and neutralizing CRLF.
     *
     * @param string $value Raw untrusted string.
     * @return string Sanitized string safe for single-line NDJSON logs.
     */
    public function sanitizeString(string $value): string
    {
        // Strip ANSI terminal escape sequences
        $cleaned = preg_replace('/\x1b\[[0-9;]*[a-zA-Z]/', '', $value) ?? $value;

        // Remove null bytes
        $cleaned = str_replace("\0", '', $cleaned);

        // Neutralize carriage returns and line feeds to prevent NDJSON line splitting
        return str_replace(["\r\n", "\r", "\n"], ['\\n', '\\n', '\\n'], $cleaned);
    }

    /**
     * Recursively redact sensitive keys and inline credentials across structured log arrays.
     *
     * @param array<string, mixed> $record The structured log record.
     * @param array<int, string> $sensitiveKeys Custom sensitive key list, or defaults if empty.
     * @param bool $sanitizeStrings Whether to sanitize control characters in string values.
     * @return array<string, mixed> Sanitized and redacted log record.
     */
    public function redactPayload(
        array $record,
        array $sensitiveKeys = [],
        bool $sanitizeStrings = true
    ): array {
        $keys = !empty($sensitiveKeys) ? $sensitiveKeys : self::DEFAULT_SENSITIVE_KEYS;
        $normalizedKeys = array_map('strtolower', $keys);

        $redacted = [];
        foreach ($record as $key => $value) {
            $keyStr = (string) $key;
            $lowerKey = strtolower($keyStr);

            // Determine if the key itself matches or contains a sensitive marker
            $isSensitive = false;
            foreach ($normalizedKeys as $target) {
                if ($lowerKey === $target || str_contains($lowerKey, $target)) {
                    $isSensitive = true;
                    break;
                }
            }

            if ($isSensitive) {
                $redacted[$key] = '[REDACTED]';
                continue;
            }

            if (is_array($value)) {
                $redacted[$key] = $this->redactPayload($value, $sensitiveKeys, $sanitizeStrings);
            } elseif (is_string($value)) {
                $processed = $value;

                // Mask inline Bearer authentication tokens
                if (stripos($processed, 'Bearer ') !== false) {
                    $processed = (string) preg_replace(
                        '/Bearer\s+[A-Za-z0-9\-._~+\/]+=*/i',
                        'Bearer [REDACTED]',
                        $processed
                    );
                }

                // Mask inline Basic authentication credentials
                if (stripos($processed, 'Basic ') !== false) {
                    $processed = (string) preg_replace(
                        '/Basic\s+[A-Za-z0-9+\/]+=*/i',
                        'Basic [REDACTED]',
                        $processed
                    );
                }

                if ($sanitizeStrings) {
                    $processed = $this->sanitizeString($processed);
                }

                $redacted[$key] = $processed;
            } else {
                $redacted[$key] = $value;
            }
        }

        return $redacted;
    }
}
