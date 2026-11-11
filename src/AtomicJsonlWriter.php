<?php

declare(strict_types=1);

namespace Logihertz\JsonlLogger;

use RuntimeException;

/**
 * Atomic, advisory-locked append-only NDJSON log writer with automatic size rotation
 * and restrictive file permission enforcement.
 *
 * Implements POSIX advisory exclusive locking (flock) to prevent race conditions and
 * interleaved/corrupted lines during concurrent multi-process writes (CWE-362),
 * enforces secure permissions (CWE-276), and manages log rotation (CWE-400).
 *
 * @author Sameer Tawade <ops@logihertz.com>
 * @license Apache-2.0
 */
final class AtomicJsonlWriter
{
    private string $filePath;
    private LogSanitizer $sanitizer;
    private HashChainEngine $chainEngine;
    private int $fileMode;
    private string $lastHash;

    /**
     * @param string $filePath Destination path for NDJSON log stream.
     * @param LogSanitizer|null $sanitizer Sanitizer & redaction instance.
     * @param HashChainEngine|null $chainEngine Hash chain signer/verifier.
     * @param int $fileMode Restrictive octal permissions (default 0600).
     */
    public function __construct(
        string $filePath,
        ?LogSanitizer $sanitizer = null,
        ?HashChainEngine $chainEngine = null,
        int $fileMode = 0600
    ) {
        $this->filePath = $filePath;
        $this->sanitizer = $sanitizer ?? new LogSanitizer();
        $this->chainEngine = $chainEngine ?? new HashChainEngine();
        $this->fileMode = $fileMode;
        $this->lastHash = $this->getLastEntryHash();
    }

    /**
     * Retrieve the last recorded entry_hash from the current file, or genesis hash if empty/missing.
     *
     * @return string 64-character hex hash.
     */
    public function getLastEntryHash(): string
    {
        if (!file_exists($this->filePath) || filesize($this->filePath) === 0) {
            return HashChainEngine::GENESIS_HASH;
        }

        $fp = fopen($this->filePath, 'rb');
        if ($fp === false) {
            return HashChainEngine::GENESIS_HASH;
        }

        $pos = -1;
        $line = '';
        $fsize = filesize($this->filePath);

        while (fseek($fp, $pos, SEEK_END) !== -1) {
            $char = fgetc($fp);
            if ($char === "\n" && $line !== '') {
                break;
            }
            if ($char !== "\n" && $char !== "\r") {
                $line = $char . $line;
            }
            $pos--;
            if (abs($pos) > $fsize) {
                break;
            }
        }
        fclose($fp);

        $line = trim($line);
        if ($line === '') {
            return HashChainEngine::GENESIS_HASH;
        }

        $data = json_decode($line, true);
        if (is_array($data) && isset($data['entry_hash']) && is_string($data['entry_hash'])) {
            return $data['entry_hash'];
        }

        return HashChainEngine::GENESIS_HASH;
    }

    /**
     * Perform deterministic size-based log rotation when file size reaches threshold.
     *
     * @param int $maxBytes Maximum file size in bytes before triggering rotation.
     * @param int $maxBackups Number of rotated archive files to retain.
     * @return bool True if rotation was executed, false otherwise.
     */
    public function rotateIfNeeded(int $maxBytes, int $maxBackups = 5): bool
    {
        if (!file_exists($this->filePath) || filesize($this->filePath) < $maxBytes) {
            return false;
        }

        // Shift existing rotated files: file.jsonl.4 -> file.jsonl.5, etc.
        for ($i = $maxBackups - 1; $i >= 1; $i--) {
            $old = $this->filePath . '.' . $i;
            $new = $this->filePath . '.' . ($i + 1);
            if (file_exists($old)) {
                if ($i === $maxBackups - 1) {
                    unlink($old);
                } else {
                    rename($old, $new);
                }
            }
        }

        // Rotate active file to .1
        rename($this->filePath, $this->filePath . '.1');
        return true;
    }

    /**
     * Write an atomic, sanitized, tamper-evident hash-chained record to the NDJSON stream.
     *
     * @param array<string, mixed> $record The structured log record.
     * @param string|null $hmacSecret Optional HMAC secret key.
     * @param int|null $maxBytes Optional rotation size threshold in bytes.
     * @param int $maxBackups Number of rotated backups to keep.
     * @return array<string, mixed> The signed, written record.
     * @throws RuntimeException On I/O or locking errors.
     */
    public function writeRecord(
        array $record,
        ?string $hmacSecret = null,
        ?int $maxBytes = null,
        int $maxBackups = 5
    ): array {
        if ($maxBytes !== null && $maxBytes > 0) {
            $this->rotateIfNeeded($maxBytes, $maxBackups);
        }

        // Ensure mandatory UTC ISO-8601 timestamp is present
        if (!isset($record['timestamp']) || !is_string($record['timestamp'])) {
            $record['timestamp'] = gmdate('Y-m-d\TH:i:s\Z');
        }

        // Neutralize CRLF / control chars and redact sensitive fields
        $sanitized = $this->sanitizer->redactPayload($record);

        // Sign record with continuous forward hash chain
        $signed = $this->chainEngine->signRecord($sanitized, $this->lastHash, $hmacSecret);

        $jsonLine = json_encode($signed, JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE) . "\n";

        $dir = dirname($this->filePath);
        if (!is_dir($dir)) {
            mkdir($dir, 0750, true);
        }

        $isNewFile = !file_exists($this->filePath) || filesize($this->filePath) === 0;

        $fp = fopen($this->filePath, 'ab');
        if ($fp === false) {
            throw new RuntimeException("Failed to open log file for append: {$this->filePath}");
        }

        // Acquire exclusive advisory lock before writing
        if (!flock($fp, LOCK_EX)) {
            fclose($fp);
            throw new RuntimeException("Failed to acquire exclusive lock on: {$this->filePath}");
        }

        if ($isNewFile) {
            chmod($this->filePath, $this->fileMode);
        }

        $written = fwrite($fp, $jsonLine);
        fflush($fp);
        flock($fp, LOCK_UN);
        fclose($fp);

        if ($written === false || $written < strlen($jsonLine)) {
            throw new RuntimeException("Incomplete write occurred on: {$this->filePath}");
        }

        // Advance in-memory chain state
        $this->lastHash = (string) $signed['entry_hash'];
        return $signed;
    }

    /**
     * Get the active log file path.
     */
    public function getFilePath(): string
    {
        return $this->filePath;
    }
}
