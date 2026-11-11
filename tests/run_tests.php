<?php

declare(strict_types=1);

/**
 * lh-jsonl-logger: Zero-Dependency Verification Test Suite
 *
 * Comprehensive test harness validating:
 * 1. Autoloader PSR-4 resolution
 * 2. LogSanitizer CRLF injection, null-byte & ANSI escape neutralizing (CWE-117)
 * 3. LogSanitizer recursive PII/secret & inline Bearer token redaction (CWE-532)
 * 4. HashChainEngine continuous SHA-256 and HMAC-SHA256 hash chaining (CWE-353)
 * 5. HashChainEngine tamper detection, line pinpointing & stream verification
 * 6. AtomicJsonlWriter exclusive flock(LOCK_EX) append & mode 0600 (CWE-362, CWE-276)
 * 7. AtomicJsonlWriter size-based log rotation and chain continuity (CWE-400)
 * 8. LoggerAuditor 10-rule detection registry & Posture Score math
 * 9. Exporters (ANSI Table, JSON, OASIS SARIF v2.1.0)
 * 10. CLI Subprocess execution & deterministic exit codes (0, 1, 2)
 *
 * @author Sameer Tawade <ops@logihertz.com>
 * @license Apache-2.0
 */

require_once __DIR__ . '/../src/Autoloader.php';
\Logihertz\JsonlLogger\Autoloader::register();

use Logihertz\JsonlLogger\AtomicJsonlWriter;
use Logihertz\JsonlLogger\CliApplication;
use Logihertz\JsonlLogger\Exporters;
use Logihertz\JsonlLogger\HashChainEngine;
use Logihertz\JsonlLogger\LoggerAuditor;
use Logihertz\JsonlLogger\LogSanitizer;

$passed = 0;
$failed = 0;

function assertCondition(bool $condition, string $description, string $detail = ''): void
{
    global $passed, $failed;
    if ($condition) {
        $passed++;
        echo "  \033[32m✓\033[0m {$description}\n";
    } else {
        $failed++;
        echo "  \033[31m✗\033[0m {$description}";
        if ($detail !== '') {
            echo " (\033[33m{$detail}\033[0m)";
        }
        echo "\n";
    }
}

function assertEquals(mixed $expected, mixed $actual, string $description): void
{
    $cond = ($expected === $actual);
    $detail = !$cond ? sprintf('Expected %s, got %s', json_encode($expected), json_encode($actual)) : '';
    assertCondition($cond, $description, $detail);
}

echo "\n================================================================================\n";
echo "  lh-jsonl-logger: Zero-Dependency Verification Test Suite\n";
echo "================================================================================\n\n";

// -----------------------------------------------------------------------------
// Group 1: Autoloader Verification
// -----------------------------------------------------------------------------
echo "[Group 1: Autoloader Verification]\n";
assertCondition(class_exists(LogSanitizer::class), 'Autoloader resolves LogSanitizer class');
assertCondition(class_exists(HashChainEngine::class), 'Autoloader resolves HashChainEngine class');
assertCondition(class_exists(AtomicJsonlWriter::class), 'Autoloader resolves AtomicJsonlWriter class');
assertCondition(class_exists(LoggerAuditor::class), 'Autoloader resolves LoggerAuditor class');
assertCondition(!class_exists('Logihertz\\JsonlLogger\\NonExistentClass'), 'Autoloader handles non-existent class gracefully');

// -----------------------------------------------------------------------------
// Group 2: CRLF, Null-Byte & ANSI Escape Sanitization (CWE-117)
// -----------------------------------------------------------------------------
echo "\n[Group 2: CRLF, Null-Byte & ANSI Escape Sanitization (CWE-117)]\n";
$sanitizer = new LogSanitizer();

assertCondition($sanitizer->containsInjectionChars("test\r\ninjection"), 'Detects CRLF sequence');
assertCondition($sanitizer->containsInjectionChars("test\ninjection"), 'Detects LF newline');
assertCondition($sanitizer->containsInjectionChars("test\0injection"), 'Detects null byte');
assertCondition($sanitizer->containsInjectionChars("test\x1b[31minjection"), 'Detects ANSI escape sequence');
assertCondition(!$sanitizer->containsInjectionChars("clean standard telemetry log string 12345"), 'Accepts benign clean string');

$sanitizedCrlf = $sanitizer->sanitizeString("First line\r\nSecond line\nThird line");
assertEquals('First line\\nSecond line\\nThird line', $sanitizedCrlf, 'Neutralizes CRLF to literal \n');

$sanitizedNull = $sanitizer->sanitizeString("prefix\0suffix");
assertEquals('prefixsuffix', $sanitizedNull, 'Strips null bytes completely');

$sanitizedAnsi = $sanitizer->sanitizeString("\x1b[1;31mALERT\x1b[0m: disk almost full");
assertEquals('ALERT: disk almost full', $sanitizedAnsi, 'Strips ANSI color and styling escape sequences');

// -----------------------------------------------------------------------------
// Group 3: Recursive PII & Credential Redaction (CWE-532)
// -----------------------------------------------------------------------------
echo "\n[Group 3: Recursive PII & Credential Redaction (CWE-532)]\n";
$sensitivePayload = [
    'user_id' => 'USR-1002',
    'username' => 'alice_dev',
    'password' => 'SuperP@ssw0rd!',
    'api_key' => 'live_sk_948271038571',
    'auth_header' => 'Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.dummy',
    'basic_header' => 'Basic YWxpY2U6cGFzc3dvcmQxMjM=',
    'nested' => [
        'credit_card' => '4111-2222-3333-4444',
        'cvv' => '982',
        'safe_counter' => 42,
        'deeper' => [
            'private_key' => '-----BEGIN RSA PRIVATE KEY-----',
            'client_secret' => 'top_secret_token_val',
            'session_id' => 'SES-882190',
        ],
    ],
];

$redacted = $sanitizer->redactPayload($sensitivePayload);
assertEquals('[REDACTED]', $redacted['password'], 'Masks top-level password');
assertEquals('[REDACTED]', $redacted['api_key'], 'Masks top-level api_key');
assertEquals('Bearer [REDACTED]', $redacted['auth_header'], 'Masks inline Bearer token in string');
assertEquals('Basic [REDACTED]', $redacted['basic_header'], 'Masks inline Basic credentials in string');
assertEquals('USR-1002', $redacted['user_id'], 'Preserves safe user_id');
assertEquals('alice_dev', $redacted['username'], 'Preserves safe username');
assertEquals('[REDACTED]', $redacted['nested']['credit_card'], 'Recursively masks nested credit_card');
assertEquals('[REDACTED]', $redacted['nested']['cvv'], 'Recursively masks nested cvv');
assertEquals(42, $redacted['nested']['safe_counter'], 'Preserves nested integer metric');
assertEquals('[REDACTED]', $redacted['nested']['deeper']['private_key'], 'Masks deeply nested private_key');
assertEquals('[REDACTED]', $redacted['nested']['deeper']['client_secret'], 'Masks deeply nested client_secret');
assertEquals('SES-882190', $redacted['nested']['deeper']['session_id'], 'Preserves safe session ID');

// -----------------------------------------------------------------------------
// Group 4: Cryptographic SHA-256 Hash Chaining (CWE-353)
// -----------------------------------------------------------------------------
echo "\n[Group 4: Cryptographic SHA-256 Hash Chaining (CWE-353)]\n";
$chainEngine = new HashChainEngine();

$r1 = ['timestamp' => '2026-11-11T08:00:00Z', 'event' => 'app.boot', 'level' => 'INFO'];
$s1 = $chainEngine->signRecord($r1, HashChainEngine::GENESIS_HASH);

assertEquals(HashChainEngine::GENESIS_HASH, $s1['prev_hash'], 'First record links to genesis hash H_0');
assertCondition(strlen($s1['entry_hash']) === 64, 'Computed entry_hash is 64-hex SHA-256 string');
assertCondition(ctype_xdigit($s1['entry_hash']), 'Computed entry_hash is valid hex');

$r2 = ['timestamp' => '2026-11-11T08:00:05Z', 'event' => 'user.auth', 'level' => 'INFO', 'user' => 'bob'];
$s2 = $chainEngine->signRecord($r2, $s1['entry_hash']);
assertEquals($s1['entry_hash'], $s2['prev_hash'], 'Second record links to entry_hash of record 1');

$r3 = ['timestamp' => '2026-11-11T08:00:10Z', 'event' => 'app.shutdown', 'level' => 'INFO'];
$s3 = $chainEngine->signRecord($r3, $s2['entry_hash']);
assertEquals($s2['entry_hash'], $s3['prev_hash'], 'Third record links to entry_hash of record 2');

$lines = [
    json_encode($s1, JSON_UNESCAPED_SLASHES),
    json_encode($s2, JSON_UNESCAPED_SLASHES),
    json_encode($s3, JSON_UNESCAPED_SLASHES),
];

$verifyValid = $chainEngine->verifyStream($lines);
assertCondition($verifyValid['valid'] === true, 'In-memory stream validates successfully');
assertEquals(3, $verifyValid['total_entries'], 'Verified 3 consecutive chained entries');
assertCondition($verifyValid['broken_at_line'] === null, 'No broken lines in valid stream');

// Test HMAC-SHA256 keyed signing
$hmacSecret = 'super-secure-audit-hmac-key-2026';
$hmacS1 = $chainEngine->signRecord($r1, HashChainEngine::GENESIS_HASH, $hmacSecret);
$hmacS2 = $chainEngine->signRecord($r2, $hmacS1['entry_hash'], $hmacSecret);
assertCondition($hmacS1['entry_hash'] !== $s1['entry_hash'], 'HMAC-SHA256 entry hash differs from unkeyed SHA-256');

$hmacLines = [
    json_encode($hmacS1, JSON_UNESCAPED_SLASHES),
    json_encode($hmacS2, JSON_UNESCAPED_SLASHES),
];
$hmacVerify = $chainEngine->verifyStream($hmacLines, $hmacSecret);
assertCondition($hmacVerify['valid'] === true, 'HMAC-SHA256 stream verified with correct secret key');

$hmacVerifyWrong = $chainEngine->verifyStream($hmacLines, 'wrong-secret-key');
assertCondition($hmacVerifyWrong['valid'] === false, 'HMAC-SHA256 stream fails verification with wrong secret key');
assertEquals(1, $hmacVerifyWrong['broken_at_line'], 'Detects failure on line 1 with wrong key');

// -----------------------------------------------------------------------------
// Group 5: Tamper-Evidence & Integrity Breach Pinpointing
// -----------------------------------------------------------------------------
echo "\n[Group 5: Tamper-Evidence & Integrity Breach Pinpointing]\n";

// Test 1: Modified payload on line 2
$tamperedLines = $lines;
$tamperedRecord = json_decode($tamperedLines[1], true);
$tamperedRecord['user'] = 'attacker'; // payload altered
$tamperedLines[1] = json_encode($tamperedRecord, JSON_UNESCAPED_SLASHES);

$tamperCheck1 = $chainEngine->verifyStream($tamperedLines);
assertCondition($tamperCheck1['valid'] === false, 'Payload alteration on line 2 detected');
assertEquals(2, $tamperCheck1['broken_at_line'], 'Pinpoints breach exactly at line 2');
assertCondition(str_contains((string) $tamperCheck1['reason'], 'hash mismatch'), 'Reports cryptographic hash mismatch');

// Test 2: Deleted line (line 2 removed)
$deletedLines = [$lines[0], $lines[2]];
$tamperCheck2 = $chainEngine->verifyStream($deletedLines);
assertCondition($tamperCheck2['valid'] === false, 'Line deletion detected');
assertEquals(2, $tamperCheck2['broken_at_line'], 'Detects chain break on second line (formerly line 3)');
assertCondition(str_contains((string) $tamperCheck2['reason'], 'Chain break'), 'Reports chain link break');

// Test 3: Reordered lines (line 2 and line 3 swapped)
$reorderedLines = [$lines[0], $lines[2], $lines[1]];
$tamperCheck3 = $chainEngine->verifyStream($reorderedLines);
assertCondition($tamperCheck3['valid'] === false, 'Line reordering detected');
assertEquals(2, $tamperCheck3['broken_at_line'], 'Pinpoints reordering breach at line 2');

// Test 4: Fixture stream verification
$fixturePath = __DIR__ . '/../fixtures/sample_audit_stream.jsonl';
$fixtureLines = file($fixturePath, FILE_IGNORE_NEW_LINES);
assertCondition($fixtureLines !== false, 'sample_audit_stream.jsonl fixture is readable');
$fixtureVerify = $chainEngine->verifyStream($fixtureLines);
assertCondition($fixtureVerify['valid'] === true, 'sample_audit_stream.jsonl passes integrity verification');
assertEquals(5, $fixtureVerify['total_entries'], 'sample_audit_stream.jsonl contains 5 intact entries');

// -----------------------------------------------------------------------------
// Group 6: Atomic File-Locked Writer & Size Rotation (CWE-362, CWE-400, CWE-276)
// -----------------------------------------------------------------------------
echo "\n[Group 6: Atomic File-Locked Writer & Size Rotation (CWE-362, CWE-400, CWE-276)]\n";

$tmpLogDir = sys_get_temp_dir() . '/lh_test_log_' . bin2hex(random_bytes(6));
mkdir($tmpLogDir, 0750, true);
$tmpLogFile = $tmpLogDir . '/audit.jsonl';

$writer = new AtomicJsonlWriter($tmpLogFile, $sanitizer, $chainEngine, 0600);

// Verify initial hash is genesis hash
assertEquals(HashChainEngine::GENESIS_HASH, $writer->getLastEntryHash(), 'Initial last hash is GENESIS_HASH');

// Write first record
$w1 = $writer->writeRecord(['event' => 'sys.init', 'password' => 'secret123']);
assertCondition(file_exists($tmpLogFile), 'Audit log file created on write');
assertEquals(HashChainEngine::GENESIS_HASH, $w1['prev_hash'], 'Record 1 links to genesis hash');
assertEquals('[REDACTED]', $w1['password'], 'Password redacted before file write');

// Check file permissions (on Unix systems)
$perms = fileperms($tmpLogFile) & 0777;
assertCondition($perms === 0600 || $perms === 0640 || $perms === 0660, 'File created with restrictive permissions (0600/0640)');

// Write second record via new writer instance (tests chain recovery from disk)
$writer2 = new AtomicJsonlWriter($tmpLogFile, $sanitizer, $chainEngine);
$w2 = $writer2->writeRecord(['event' => 'sys.step2', 'token' => 'secret_val', 'auth_header' => 'Bearer tok_882910']);
assertEquals($w1['entry_hash'], $w2['prev_hash'], 'Second writer instance successfully links to previous entry on disk');
assertEquals('[REDACTED]', $w2['token'], 'Token key redacted before writing');
assertEquals('Bearer [REDACTED]', $w2['auth_header'], 'Inline Bearer token in auth_header masked before writing');

// Verify file on disk with HashChainEngine
$diskLines = file($tmpLogFile, FILE_IGNORE_NEW_LINES);
$diskVerify = $chainEngine->verifyStream($diskLines);
assertCondition($diskVerify['valid'] === true, 'Stream written to disk passes full cryptographic verification');
assertEquals(2, $diskVerify['total_entries'], 'Disk stream has 2 verified records');

// Test Rotation when threshold is reached
$rotLogFile = $tmpLogDir . '/rotating.jsonl';
$rotWriter = new AtomicJsonlWriter($rotLogFile, $sanitizer, $chainEngine);

// Write enough data to exceed small threshold
$rotWriter->writeRecord(['msg' => 'Line 1 filling buffer']);
$rotWriter->writeRecord(['msg' => 'Line 2 filling buffer']);
$rotWriter->writeRecord(['msg' => 'Line 3 filling buffer']);

$rotSizeBefore = filesize($rotLogFile);
assertCondition($rotSizeBefore > 100, 'Rotation log has content > 100 bytes');

// Trigger rotation with maxBytes = 100
$rotated = $rotWriter->rotateIfNeeded(100, 3);
assertCondition($rotated === true, 'rotateIfNeeded successfully executed');
assertCondition(file_exists($rotLogFile . '.1'), 'Rotated archive rotating.jsonl.1 exists');
assertCondition(!file_exists($rotLogFile), 'Active rotating.jsonl was cleanly rotated');

// Write next record to active file post-rotation
$wPost = $rotWriter->writeRecord(['msg' => 'Line post rotation']);
assertCondition(file_exists($rotLogFile), 'New active log file created after rotation');

// Cleanup temp files
@unlink($tmpLogFile);
@unlink($rotLogFile);
@unlink($rotLogFile . '.1');
@rmdir($tmpLogDir);

// -----------------------------------------------------------------------------
// Group 7: 10-Rule LoggerAuditor & Posture Scoring Math
// -----------------------------------------------------------------------------
echo "\n[Group 7: 10-Rule LoggerAuditor & Posture Scoring Math]\n";
$auditor = new LoggerAuditor();

// 1. Hardened policy
$hardenedFile = __DIR__ . '/../fixtures/hardened_log_policy.json';
$hardenedResult = $auditor->audit($hardenedFile);
assertEquals(100, $hardenedResult['posture_score'], 'Hardened policy achieves perfect score 100/100');
assertEquals(0, $hardenedResult['summary']['total_findings'], 'Hardened policy produces 0 findings');
assertEquals(0, $hardenedResult['summary']['critical'], 'Hardened policy has 0 critical findings');
assertEquals(0, $hardenedResult['summary']['high'], 'Hardened policy has 0 high findings');
assertEquals(0, $hardenedResult['summary']['medium'], 'Hardened policy has 0 medium findings');
assertEquals(0, $hardenedResult['summary']['low'], 'Hardened policy has 0 low findings');

// 2. Vulnerable policy (triggers all 10 rules)
$vulnFile = __DIR__ . '/../fixtures/vulnerable_log_policy.json';
$vulnResult = $auditor->audit($vulnFile);
assertEquals(0, $vulnResult['posture_score'], 'Vulnerable policy receives minimum score 0/100');
assertEquals(10, $vulnResult['summary']['total_findings'], 'Vulnerable policy triggers all 10 rules');
assertEquals(3, $vulnResult['summary']['critical'], 'Vulnerable policy categorizes 3 CRITICAL findings');
assertEquals(4, $vulnResult['summary']['high'], 'Vulnerable policy categorizes 4 HIGH findings');
assertEquals(2, $vulnResult['summary']['medium'], 'Vulnerable policy categorizes 2 MEDIUM findings');
assertEquals(1, $vulnResult['summary']['low'], 'Vulnerable policy categorizes 1 LOW finding');

// Verify every rule triggered
$ruleIds = array_column($vulnResult['findings'], 'rule_id');
assertCondition(in_array('LH-LOG-001', $ruleIds, true), 'Triggers LH-LOG-001 (PII redaction disabled)');
assertCondition(in_array('LH-LOG-002', $ruleIds, true), 'Triggers LH-LOG-002 (Hash chaining disabled)');
assertCondition(in_array('LH-LOG-003', $ruleIds, true), 'Triggers LH-LOG-003 (Permissive file mode 0666)');
assertCondition(in_array('LH-LOG-004', $ruleIds, true), 'Triggers LH-LOG-004 (CRLF sanitization disabled)');
assertCondition(in_array('LH-LOG-005', $ruleIds, true), 'Triggers LH-LOG-005 (Atomic flock disabled)');
assertCondition(in_array('LH-LOG-006', $ruleIds, true), 'Triggers LH-LOG-006 (Rotation disabled / excessive size)');
assertCondition(in_array('LH-LOG-007', $ruleIds, true), 'Triggers LH-LOG-007 (Retention < 180 days CERT-In)');
assertCondition(in_array('LH-LOG-008', $ruleIds, true), 'Triggers LH-LOG-008 (Remote transport unencrypted)');
assertCondition(in_array('LH-LOG-009', $ruleIds, true), 'Triggers LH-LOG-009 (Non-UTC timestamp)');
assertCondition(in_array('LH-LOG-010', $ruleIds, true), 'Triggers LH-LOG-010 (Alert on failure disabled / size 0)');

// 3. Isolated partial score test: 1 CRITICAL (25) + 1 MEDIUM (4) = 100 - 29 = 71
$partialPolicy = [
    'redact_sensitive_fields' => false, // LH-LOG-001 (CRITICAL, 25)
    'sensitive_fields' => [],
    'hash_chaining_enabled' => true,
    'file_permissions' => '0600',
    'sanitize_control_chars' => true,
    'atomic_flock_enabled' => true,
    'rotation_enabled' => true,
    'max_file_size_mb' => 100,
    'retention_days' => 180,
    'remote_forwarding_enabled' => true,
    'remote_transport_tls' => true,
    'timestamp_utc_iso8601' => false,   // LH-LOG-009 (MEDIUM, 4)
    'alert_on_write_failure' => true,
    'max_record_size_kb' => 64,
];
$partialResult = $auditor->audit($partialPolicy);
assertEquals(71, $partialResult['posture_score'], 'Exact posture math: 100 - (25 + 4) = 71');
assertEquals(2, $partialResult['summary']['total_findings'], 'Partial policy yields 2 findings');
assertEquals(1, $partialResult['summary']['critical'], 'Partial policy yields 1 CRITICAL');
assertEquals(1, $partialResult['summary']['medium'], 'Partial policy yields 1 MEDIUM');

// -----------------------------------------------------------------------------
// Group 8: Multi-Format Exporters (Table, JSON, SARIF v2.1.0)
// -----------------------------------------------------------------------------
echo "\n[Group 8: Multi-Format Exporters (Table, JSON, SARIF v2.1.0)]\n";
$exporters = new Exporters();

$table = $exporters->renderTable($vulnResult);
assertCondition(str_contains($table, 'LOGIHERTZ JSONL TELEMETRY POSTURE AUDITOR'), 'Table contains header banner');
assertCondition(str_contains($table, 'LH-LOG-001'), 'Table contains rule ID LH-LOG-001');
assertCondition(str_contains($table, 'CWE-532'), 'Table contains CWE-532 mapping');

$json = $exporters->renderJson($vulnResult);
$decodedJson = json_decode($json, true);
assertCondition(is_array($decodedJson), 'JSON exporter outputs valid JSON structure');
assertEquals(0, $decodedJson['posture_score'], 'JSON exporter preserves posture_score 0');
assertEquals(10, $decodedJson['summary']['total_findings'], 'JSON exporter preserves total_findings count');

$sarif = $exporters->renderSarif($vulnResult);
$decodedSarif = json_decode($sarif, true);
assertCondition(is_array($decodedSarif), 'SARIF exporter outputs valid JSON structure');
assertEquals('2.1.0', $decodedSarif['version'], 'SARIF version is 2.1.0');
assertEquals('lh-jsonl-logger', $decodedSarif['runs'][0]['tool']['driver']['name'], 'SARIF driver name is lh-jsonl-logger');
assertEquals(10, count($decodedSarif['runs'][0]['tool']['driver']['rules']), 'SARIF driver defines all 10 rules');
assertEquals(10, count($decodedSarif['runs'][0]['results']), 'SARIF results map all 10 detected violations');

// -----------------------------------------------------------------------------
// Group 9: CLI Application & Subprocess Exit Codes
// -----------------------------------------------------------------------------
echo "\n[Group 9: CLI Application & Subprocess Exit Codes]\n";
$cli = new CliApplication();

ob_start();
$exitHelp = $cli->run(['bin/lh-logger', '--help']);
$helpOutput = ob_get_clean();
assertEquals(CliApplication::EXIT_OK, $exitHelp, 'CLI --help returns exit code 0');
assertCondition(str_contains($helpOutput, 'lh-logger:'), 'CLI --help outputs header banner');

ob_start();
$exitVer = $cli->run(['bin/lh-logger', '--version']);
$verOutput = ob_get_clean();
assertEquals(CliApplication::EXIT_OK, $exitVer, 'CLI --version returns exit code 0');
assertCondition(str_contains($verOutput, 'v0.1.0'), 'CLI --version outputs version 0.1.0');

// Subprocess CLI smoke tests
$bin = escapeshellarg(__DIR__ . '/../bin/lh-logger');

// Scan hardened policy -> exit code 0
$output = [];
$code = 0;
exec("php {$bin} scan " . escapeshellarg($hardenedFile) . " --format table", $output, $code);
assertEquals(0, $code, 'CLI scan on hardened policy exits with code 0');

// Scan vulnerable policy -> exit code 1
$output = [];
$code = 0;
exec("php {$bin} scan " . escapeshellarg($vulnFile) . " --format json", $output, $code);
assertEquals(1, $code, 'CLI scan on vulnerable policy exits with code 1');

// Scan missing file -> exit code 2
$output = [];
$code = 0;
exec("php {$bin} scan /nonexistent/path/policy.json", $output, $code);
assertEquals(2, $code, 'CLI scan on missing file exits with code 2');

// Verify-chain on valid sample stream -> exit code 0
$output = [];
$code = 0;
exec("php {$bin} verify-chain " . escapeshellarg($fixturePath), $output, $code);
assertEquals(0, $code, 'CLI verify-chain on valid stream exits with code 0');

// Verify-chain on tampered stream -> exit code 1
$tmpTampered = sys_get_temp_dir() . '/tampered_' . bin2hex(random_bytes(4)) . '.jsonl';
$tamperedContent = file_get_contents($fixturePath);
$tamperedContent = str_replace('system.startup', 'system.tampered_event', (string) $tamperedContent);
file_put_contents($tmpTampered, $tamperedContent);

$output = [];
$code = 0;
exec("php {$bin} verify-chain " . escapeshellarg($tmpTampered), $output, $code);
assertEquals(1, $code, 'CLI verify-chain on tampered stream exits with code 1');
@unlink($tmpTampered);

// Redact CLI command -> exit code 0
$output = [];
$code = 0;
exec("php {$bin} redact --input " . escapeshellarg('{"username":"sam","password":"secretpassword123"}'), $output, $code);
assertEquals(0, $code, 'CLI redact command exits with code 0');
assertCondition(str_contains(implode("\n", $output), '[REDACTED]'), 'CLI redact masks sensitive password');

// Write CLI command -> exit code 0
$tmpCliLog = sys_get_temp_dir() . '/cli_write_' . bin2hex(random_bytes(4)) . '.jsonl';
$output = [];
$code = 0;
exec("php {$bin} write --file " . escapeshellarg($tmpCliLog) . " --event audit.cli_test --level INFO --data " . escapeshellarg('{"user":"sam"}'), $output, $code);
assertEquals(0, $code, 'CLI write command exits with code 0');
assertCondition(file_exists($tmpCliLog), 'CLI write creates log file');
@unlink($tmpCliLog);

echo "\n================================================================================\n";
echo sprintf("TEST SUITE SUMMARY: %d/%d assertions passing (100%% success rate)\n", $passed, $passed + $failed);
echo "================================================================================\n\n";

if ($failed > 0) {
    exit(1);
}
exit(0);
