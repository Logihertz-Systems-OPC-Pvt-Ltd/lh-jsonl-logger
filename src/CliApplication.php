<?php

declare(strict_types=1);

namespace Logihertz\JsonlLogger;

use JsonException;
use Throwable;

/**
 * Command-Line Interface router for lh-jsonl-logger (lh-logger).
 *
 * Implements subcommands: scan, verify-chain, write, redact, --version, --help.
 *
 * @author Sameer Tawade <ops@logihertz.com>
 * @license Apache-2.0
 */
final class CliApplication
{
    public const VERSION = '0.1.0';

    public const EXIT_OK = 0;
    public const EXIT_POLICY_VIOLATION = 1;
    public const EXIT_USAGE_ERROR = 2;

    /**
     * Run the CLI application with given arguments.
     *
     * @param array<int, string> $argv Command line arguments ($argv[0] is script path).
     * @return int Deterministic exit code.
     */
    public function run(array $argv): int
    {
        array_shift($argv); // Remove script name

        if (empty($argv) || in_array('--help', $argv, true) || in_array('-h', $argv, true)) {
            $this->printHelp();
            return empty($argv) ? self::EXIT_USAGE_ERROR : self::EXIT_OK;
        }

        if (in_array('--version', $argv, true) || in_array('-v', $argv, true)) {
            $this->printVersion();
            return self::EXIT_OK;
        }

        $command = array_shift($argv);

        return match ($command) {
            'scan' => $this->handleScan($argv),
            'verify-chain' => $this->handleVerifyChain($argv),
            'write' => $this->handleWrite($argv),
            'redact' => $this->handleRedact($argv),
            default => $this->handleUnknownCommand((string) $command),
        };
    }

    /**
     * Handle the `scan` subcommand.
     *
     * @param array<int, string> $args
     * @return int Exit code.
     */
    private function handleScan(array $args): int
    {
        $target = null;
        $format = 'table';
        $output = null;

        for ($i = 0; $i < count($args); $i++) {
            $arg = $args[$i];
            if ($arg === '--format' || $arg === '-f') {
                $format = $args[++$i] ?? 'table';
            } elseif (str_starts_with($arg, '--format=')) {
                $format = substr($arg, 9);
            } elseif ($arg === '--output' || $arg === '-o') {
                $output = $args[++$i] ?? null;
            } elseif (str_starts_with($arg, '--output=')) {
                $output = substr($arg, 9);
            } elseif ($target === null && !str_starts_with($arg, '-')) {
                $target = $arg;
            } else {
                fwrite(STDERR, "Error: Unrecognized option '{$arg}'.\n");
                return self::EXIT_USAGE_ERROR;
            }
        }

        if ($target === null) {
            fwrite(STDERR, "Error: Missing target policy JSON file path.\n");
            fwrite(STDERR, "Usage: lh-logger scan <path-to-policy.json> [--format table|json|sarif] [--output <file>]\n");
            return self::EXIT_USAGE_ERROR;
        }

        if (!file_exists($target)) {
            fwrite(STDERR, "Error: Policy file not found: {$target}\n");
            return self::EXIT_USAGE_ERROR;
        }

        try {
            $auditor = new LoggerAuditor();
            $result = $auditor->audit($target);
            $exporters = new Exporters();

            $rendered = match (strtolower($format)) {
                'json' => $exporters->renderJson($result),
                'sarif' => $exporters->renderSarif($result),
                default => $exporters->renderTable($result),
            };

            if ($output !== null && $output !== '') {
                if (file_put_contents($output, $rendered) === false) {
                    fwrite(STDERR, "Error: Failed to write output to: {$output}\n");
                    return self::EXIT_USAGE_ERROR;
                }
                echo "Report successfully written to {$output}\n";
            } else {
                echo $rendered;
            }

            return $result['summary']['total_findings'] > 0 ? self::EXIT_POLICY_VIOLATION : self::EXIT_OK;
        } catch (Throwable $e) {
            fwrite(STDERR, "Audit Error: " . $e->getMessage() . "\n");
            return self::EXIT_USAGE_ERROR;
        }
    }

    /**
     * Handle the `verify-chain` subcommand.
     *
     * @param array<int, string> $args
     * @return int Exit code.
     */
    private function handleVerifyChain(array $args): int
    {
        $streamFile = null;
        $hmacKey = null;

        for ($i = 0; $i < count($args); $i++) {
            $arg = $args[$i];
            if ($arg === '--hmac-key' || $arg === '-k') {
                $hmacKey = $args[++$i] ?? null;
            } elseif (str_starts_with($arg, '--hmac-key=')) {
                $hmacKey = substr($arg, 11);
            } elseif ($streamFile === null && !str_starts_with($arg, '-')) {
                $streamFile = $arg;
            } else {
                fwrite(STDERR, "Error: Unrecognized option '{$arg}'.\n");
                return self::EXIT_USAGE_ERROR;
            }
        }

        if ($streamFile === null) {
            fwrite(STDERR, "Error: Missing stream JSONL file path.\n");
            fwrite(STDERR, "Usage: lh-logger verify-chain <stream.jsonl> [--hmac-key <secret>]\n");
            return self::EXIT_USAGE_ERROR;
        }

        if (!file_exists($streamFile)) {
            fwrite(STDERR, "Error: Stream file not found: {$streamFile}\n");
            return self::EXIT_USAGE_ERROR;
        }

        $lines = file($streamFile, FILE_IGNORE_NEW_LINES);
        if ($lines === false) {
            fwrite(STDERR, "Error: Unable to read stream file: {$streamFile}\n");
            return self::EXIT_USAGE_ERROR;
        }

        $chainEngine = new HashChainEngine();
        $res = $chainEngine->verifyStream($lines, $hmacKey);

        if ($res['valid']) {
            echo "\033[32m[✓] Cryptographic Hash-Chain Integrity: VERIFIED INTACT\033[0m\n";
            echo sprintf("    Verified %d records without tampering or chain breakage.\n", $res['total_entries']);
            return self::EXIT_OK;
        }

        fwrite(STDERR, "\033[1;31m[✗] Cryptographic Hash-Chain Integrity: COMPROMISED\033[0m\n");
        fwrite(STDERR, sprintf("    Broken at line: %s\n", (string) $res['broken_at_line']));
        fwrite(STDERR, sprintf("    Reason:         %s\n", (string) $res['reason']));
        return self::EXIT_POLICY_VIOLATION;
    }

    /**
     * Handle the `write` subcommand.
     *
     * @param array<int, string> $args
     * @return int Exit code.
     */
    private function handleWrite(array $args): int
    {
        $filePath = null;
        $event = null;
        $level = 'INFO';
        $dataRaw = null;
        $hmacKey = null;

        for ($i = 0; $i < count($args); $i++) {
            $arg = $args[$i];
            if ($arg === '--file' || $arg === '-f') {
                $filePath = $args[++$i] ?? null;
            } elseif (str_starts_with($arg, '--file=')) {
                $filePath = substr($arg, 7);
            } elseif ($arg === '--event' || $arg === '-e') {
                $event = $args[++$i] ?? null;
            } elseif (str_starts_with($arg, '--event=')) {
                $event = substr($arg, 8);
            } elseif ($arg === '--level' || $arg === '-l') {
                $level = strtoupper($args[++$i] ?? 'INFO');
            } elseif (str_starts_with($arg, '--level=')) {
                $level = strtoupper(substr($arg, 8));
            } elseif ($arg === '--data' || $arg === '-d') {
                $dataRaw = $args[++$i] ?? null;
            } elseif (str_starts_with($arg, '--data=')) {
                $dataRaw = substr($arg, 7);
            } elseif ($arg === '--hmac-key' || $arg === '-k') {
                $hmacKey = $args[++$i] ?? null;
            } elseif (str_starts_with($arg, '--hmac-key=')) {
                $hmacKey = substr($arg, 11);
            } else {
                fwrite(STDERR, "Error: Unrecognized option '{$arg}'.\n");
                return self::EXIT_USAGE_ERROR;
            }
        }

        if ($filePath === null || $event === null) {
            fwrite(STDERR, "Error: --file and --event are mandatory for write.\n");
            fwrite(STDERR, "Usage: lh-logger write --file <stream.jsonl> --event <event_name> [--level <INFO>] [--data <json>]\n");
            return self::EXIT_USAGE_ERROR;
        }

        $payloadData = [];
        if ($dataRaw !== null && trim($dataRaw) !== '') {
            try {
                /** @var mixed $decoded */
                $decoded = json_decode($dataRaw, true, 512, JSON_THROW_ON_ERROR);
                if (is_array($decoded)) {
                    $payloadData = $decoded;
                }
            } catch (JsonException $e) {
                fwrite(STDERR, "Error: Invalid JSON payload in --data: " . $e->getMessage() . "\n");
                return self::EXIT_USAGE_ERROR;
            }
        }

        try {
            $writer = new AtomicJsonlWriter($filePath);
            $record = [
                'timestamp' => gmdate('Y-m-d\TH:i:s\Z'),
                'event' => $event,
                'level' => $level,
                'payload' => $payloadData,
            ];

            $signed = $writer->writeRecord($record, $hmacKey);
            echo "Successfully written and hash-chained record:\n";
            echo sprintf("  Event:      %s\n", $signed['event']);
            echo sprintf("  Level:      %s\n", $signed['level']);
            echo sprintf("  Prev Hash:  %s\n", $signed['prev_hash']);
            echo sprintf("  Entry Hash: %s\n", $signed['entry_hash']);
            return self::EXIT_OK;
        } catch (Throwable $e) {
            fwrite(STDERR, "Write Error: " . $e->getMessage() . "\n");
            return self::EXIT_USAGE_ERROR;
        }
    }

    /**
     * Handle the `redact` subcommand.
     *
     * @param array<int, string> $args
     * @return int Exit code.
     */
    private function handleRedact(array $args): int
    {
        $input = null;

        for ($i = 0; $i < count($args); $i++) {
            $arg = $args[$i];
            if ($arg === '--input' || $arg === '-i') {
                $input = $args[++$i] ?? null;
            } elseif (str_starts_with($arg, '--input=')) {
                $input = substr($arg, 8);
            } else {
                fwrite(STDERR, "Error: Unrecognized option '{$arg}'.\n");
                return self::EXIT_USAGE_ERROR;
            }
        }

        if ($input === null || trim($input) === '') {
            fwrite(STDERR, "Error: Missing --input JSON string.\n");
            fwrite(STDERR, "Usage: lh-logger redact --input '{\"password\":\"secret\"}'\n");
            return self::EXIT_USAGE_ERROR;
        }

        try {
            /** @var mixed $decoded */
            $decoded = json_decode($input, true, 512, JSON_THROW_ON_ERROR);
            if (!is_array($decoded)) {
                fwrite(STDERR, "Error: Input must be a valid JSON object.\n");
                return self::EXIT_USAGE_ERROR;
            }

            $sanitizer = new LogSanitizer();
            $redacted = $sanitizer->redactPayload($decoded);

            echo json_encode($redacted, JSON_PRETTY_PRINT | JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE) . "\n";
            return self::EXIT_OK;
        } catch (JsonException $e) {
            fwrite(STDERR, "Error: Failed to parse input JSON: " . $e->getMessage() . "\n");
            return self::EXIT_USAGE_ERROR;
        }
    }

    /**
     * Handle unrecognized command.
     */
    private function handleUnknownCommand(string $command): int
    {
        fwrite(STDERR, "Error: Unrecognized command '{$command}'.\n");
        $this->printHelp();
        return self::EXIT_USAGE_ERROR;
    }

    /**
     * Print help information.
     */
    public function printHelp(): void
    {
        echo <<<HELP
lh-logger: Enterprise Zero-Dependency Atomic JSONL Logger & Hash-Chain Verifier
Version: 0.1.0 | Logihertz Systems (OPC) Private Limited

USAGE:
  lh-logger scan <path-to-policy.json> [options]
  lh-logger verify-chain <path-to-stream.jsonl> [options]
  lh-logger write --file <stream.jsonl> --event <event_name> [options]
  lh-logger redact --input <json_string>
  lh-logger --version
  lh-logger --help

COMMANDS:
  scan          Audit logging policy configuration against rules LH-LOG-001..010
  verify-chain  Verify cryptographic forward hash chain integrity of an NDJSON stream
  write         Atomically append a sanitized, tamper-evident hash-chained record
  redact        Redact credentials, tokens, and PII from a JSON object

SCAN OPTIONS:
  --format, -f <table|json|sarif>   Report output format (default: table)
  --output, -o <path>               Optional destination file path for report

VERIFY-CHAIN OPTIONS:
  --hmac-key, -k <secret>           Optional HMAC key used during signing

WRITE OPTIONS:
  --file, -f <path>                 Target .jsonl file path (required)
  --event, -e <name>                Audit event name (required, e.g. auth.login)
  --level, -l <INFO|WARN|ERROR>     Log level (default: INFO)
  --data, -d <json>                 Optional JSON payload string
  --hmac-key, -k <secret>           Optional HMAC secret key

REDACT OPTIONS:
  --input, -i <json>                Raw JSON payload string to redact
HELP;
        echo "\n";
    }

    /**
     * Print version information.
     */
    public function printVersion(): void
    {
        echo sprintf(
            "lh-logger v%s (Clean-room PHP 8.2+)\nLogihertz Systems (OPC) Private Limited\nhttps://logihertz.com/\n",
            self::VERSION
        );
    }
}
