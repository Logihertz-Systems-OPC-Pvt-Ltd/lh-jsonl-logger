<?php

declare(strict_types=1);

namespace Logihertz\JsonlLogger;

use JsonException;

/**
 * Tamper-evident cryptographic hash-chain engine for NDJSON audit trails.
 *
 * Implements continuous SHA-256 and HMAC-SHA256 forward hash-chaining:
 * H_i = SHA-256(H_{i-1} || canonical_json(E_i))
 * with constant-time verification to detect log tampering, injection, reordering,
 * or line deletion (CWE-353).
 *
 * @author Sameer Tawade <ops@logihertz.com>
 * @license Apache-2.0
 */
final class HashChainEngine
{
    /**
     * Standard 64-character hexadecimal zero string representing genesis previous-hash H_0.
     */
    public const GENESIS_HASH = '0000000000000000000000000000000000000000000000000000000000000000';

    /**
     * Compute a canonical JSON string with recursively sorted keys.
     *
     * @param array<string, mixed> $data The record data to canonicalize.
     * @return string Deterministic, unescaped JSON string.
     */
    public function canonicalJson(array $data): string
    {
        $sorted = $this->recursiveKsort($data);
        return json_encode($sorted, JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE | JSON_THROW_ON_ERROR);
    }

    /**
     * Recursively sort array keys to guarantee deterministic serialization.
     *
     * @param array<string|int, mixed> $array Target array.
     * @return array<string|int, mixed> Sorted array.
     */
    private function recursiveKsort(array $array): array
    {
        ksort($array);
        foreach ($array as $key => $value) {
            if (is_array($value)) {
                $array[$key] = $this->recursiveKsort($value);
            }
        }
        return $array;
    }

    /**
     * Sign an audit record and attach `prev_hash` and `entry_hash`.
     *
     * @param array<string, mixed> $record The structured log entry.
     * @param string $prevHash Previous entry's hash (or GENESIS_HASH for first entry).
     * @param string|null $hmacSecret Optional secret key for HMAC-SHA256 signing.
     * @return array<string, mixed> The signed record containing prev_hash and entry_hash.
     */
    public function signRecord(array $record, string $prevHash, ?string $hmacSecret = null): array
    {
        $signed = $record;
        $signed['prev_hash'] = $prevHash;

        // Ensure entry_hash is not included in the payload being hashed
        unset($signed['entry_hash']);

        $canonical = $this->canonicalJson($signed);
        $payload = $prevHash . $canonical;

        $entryHash = $hmacSecret !== null && $hmacSecret !== ''
            ? hash_hmac('sha256', $payload, $hmacSecret)
            : hash('sha256', $payload);

        $signed['entry_hash'] = $entryHash;
        return $signed;
    }

    /**
     * Verify the cryptographic integrity of a JSONL / NDJSON audit stream.
     *
     * @param array<int, string> $jsonlLines Array of NDJSON line strings.
     * @param string|null $hmacSecret Optional HMAC secret key used during signing.
     * @return array{valid: bool, total_entries: int, broken_at_line: int|null, reason: string|null}
     */
    public function verifyStream(array $jsonlLines, ?string $hmacSecret = null): array
    {
        $expectedPrev = self::GENESIS_HASH;
        $validCount = 0;
        $lineNumber = 0;

        foreach ($jsonlLines as $rawLine) {
            $lineNumber++;
            $trimmed = trim($rawLine);
            if ($trimmed === '') {
                continue;
            }

            try {
                /** @var mixed $record */
                $record = json_decode($trimmed, true, 512, JSON_THROW_ON_ERROR);
            } catch (JsonException $e) {
                return [
                    'valid' => false,
                    'total_entries' => $validCount,
                    'broken_at_line' => $lineNumber,
                    'reason' => "JSON syntax error on line {$lineNumber}: " . $e->getMessage(),
                ];
            }

            if (!is_array($record)) {
                return [
                    'valid' => false,
                    'total_entries' => $validCount,
                    'broken_at_line' => $lineNumber,
                    'reason' => "Line {$lineNumber} does not contain a JSON object.",
                ];
            }

            if (!isset($record['prev_hash']) || !is_string($record['prev_hash'])) {
                return [
                    'valid' => false,
                    'total_entries' => $validCount,
                    'broken_at_line' => $lineNumber,
                    'reason' => "Missing or invalid 'prev_hash' on line {$lineNumber}.",
                ];
            }

            if (!isset($record['entry_hash']) || !is_string($record['entry_hash'])) {
                return [
                    'valid' => false,
                    'total_entries' => $validCount,
                    'broken_at_line' => $lineNumber,
                    'reason' => "Missing or invalid 'entry_hash' on line {$lineNumber}.",
                ];
            }

            // Verify that prev_hash matches the previous record's entry_hash
            if (!hash_equals($expectedPrev, $record['prev_hash'])) {
                return [
                    'valid' => false,
                    'total_entries' => $validCount,
                    'broken_at_line' => $lineNumber,
                    'reason' => "Chain break on line {$lineNumber}: expected prev_hash '{$expectedPrev}', found '{$record['prev_hash']}'.",
                ];
            }

            $recordedHash = $record['entry_hash'];
            $recordWithoutHash = $record;
            unset($recordWithoutHash['entry_hash']);

            $canonical = $this->canonicalJson($recordWithoutHash);
            $payload = $record['prev_hash'] . $canonical;

            $computedHash = $hmacSecret !== null && $hmacSecret !== ''
                ? hash_hmac('sha256', $payload, $hmacSecret)
                : hash('sha256', $payload);

            // Constant-time verification of computed hash against recorded entry_hash
            if (!hash_equals($computedHash, $recordedHash)) {
                return [
                    'valid' => false,
                    'total_entries' => $validCount,
                    'broken_at_line' => $lineNumber,
                    'reason' => "Cryptographic hash mismatch on line {$lineNumber}: computed '{$computedHash}', recorded '{$recordedHash}'.",
                ];
            }

            $expectedPrev = $recordedHash;
            $validCount++;
        }

        return [
            'valid' => true,
            'total_entries' => $validCount,
            'broken_at_line' => null,
            'reason' => null,
        ];
    }
}
