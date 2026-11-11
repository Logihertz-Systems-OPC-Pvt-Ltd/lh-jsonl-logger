<?php

declare(strict_types=1);

namespace Logihertz\JsonlLogger;

/**
 * Multi-format exporters for logging posture audit reports.
 *
 * Supports ANSI Terminal Tables, Canonical JSON, and standard OASIS SARIF v2.1.0
 * for seamless integration into enterprise DevSecOps pipelines.
 *
 * @author Sameer Tawade <ops@logihertz.com>
 * @license Apache-2.0
 */
final class Exporters
{
    /**
     * Render an ANSI terminal table report.
     *
     * @param array{
     *     target: string,
     *     posture_score: int,
     *     summary: array{total_findings: int, critical: int, high: int, medium: int, low: int},
     *     findings: array<int, array{rule_id: string, severity: string, cwe: string, title: string, description: string, recommendation: string, evidence: string}>
     * } $result
     * @return string Formatted terminal output.
     */
    public function renderTable(array $result): string
    {
        $score = $result['posture_score'];
        $status = $result['summary']['total_findings'] === 0 ? 'PASSED' : 'POLICY VIOLATIONS DETECTED';
        $statusColor = $result['summary']['total_findings'] === 0 ? "\033[32m" : "\033[31m";
        $reset = "\033[0m";

        $out = "\n";
        $out .= "┌──────────────────────────────────────────────────────────────────────────────┐\n";
        $out .= "│               LOGIHERTZ JSONL TELEMETRY POSTURE AUDITOR                     │\n";
        $out .= "├──────────────────────────────────────────────────────────────────────────────┤\n";
        $out .= sprintf("│ Target Policy: %-61s │\n", substr($result['target'], 0, 61));
        $out .= sprintf("│ Posture Score: %s%-3d / 100%s   Status: %s%-35s%s │\n",
            $statusColor, $score, $reset,
            $statusColor, $status, $reset
        );
        $out .= sprintf("│ Findings:      Total: %-3d  Crit: %-3d  High: %-3d  Med: %-3d  Low: %-3d   │\n",
            $result['summary']['total_findings'],
            $result['summary']['critical'],
            $result['summary']['high'],
            $result['summary']['medium'],
            $result['summary']['low']
        );
        $out .= "└──────────────────────────────────────────────────────────────────────────────┘\n\n";

        if (empty($result['findings'])) {
            $out .= "\033[32m[✓] All 10 logging security & audit trail controls passed without violations.\033[0m\n\n";
            return $out;
        }

        $out .= "DETAILED SECURITY FINDINGS:\n";
        $out .= str_repeat('─', 80) . "\n";
        $out .= sprintf("%-12s %-10s %-10s %-45s\n", 'RULE ID', 'SEVERITY', 'CWE', 'TITLE');
        $out .= str_repeat('─', 80) . "\n";

        foreach ($result['findings'] as $f) {
            $sevColor = match ($f['severity']) {
                'CRITICAL' => "\033[1;31m",
                'HIGH' => "\033[31m",
                'MEDIUM' => "\033[33m",
                default => "\033[36m",
            };

            $out .= sprintf(
                "%-12s %s%-10s%s %-10s %-45s\n",
                $f['rule_id'],
                $sevColor,
                $f['severity'],
                $reset,
                $f['cwe'],
                substr($f['title'], 0, 45)
            );
            $out .= "  Description:    " . $f['description'] . "\n";
            $out .= "  Offending Conf: " . $f['evidence'] . "\n";
            $out .= "  Remediation:    " . $f['recommendation'] . "\n";
            $out .= str_repeat('─', 80) . "\n";
        }

        return $out;
    }

    /**
     * Render a Canonical JSON report.
     *
     * @param array<string, mixed> $result
     * @return string Pretty JSON.
     */
    public function renderJson(array $result): string
    {
        return (string) json_encode($result, JSON_PRETTY_PRINT | JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE);
    }

    /**
     * Render an OASIS SARIF v2.1.0 schema document.
     *
     * @param array{
     *     target: string,
     *     posture_score: int,
     *     summary: array{total_findings: int, critical: int, high: int, medium: int, low: int},
     *     findings: array<int, array{rule_id: string, severity: string, cwe: string, title: string, description: string, recommendation: string, evidence: string}>
     * } $result
     * @return string Valid SARIF JSON.
     */
    public function renderSarif(array $result): string
    {
        $rules = [];
        foreach (LoggerAuditor::RULE_DEFINITIONS as $ruleId => $def) {
            $rules[] = [
                'id' => $ruleId,
                'name' => str_replace('-', '', $ruleId),
                'shortDescription' => [
                    'text' => $def['title'],
                ],
                'fullDescription' => [
                    'text' => sprintf('%s (%s, Weight: %d)', $def['title'], $def['cwe'], $def['weight']),
                ],
                'defaultConfiguration' => [
                    'level' => match ($def['severity']) {
                        'CRITICAL', 'HIGH' => 'error',
                        'MEDIUM' => 'warning',
                        default => 'note',
                    },
                ],
                'helpUri' => 'https://github.com/Logihertz-Systems-OPC-Pvt-Ltd/lh-jsonl-logger#core-detection-rules',
                'properties' => [
                    'cwe' => [$def['cwe']],
                    'precision' => 'very-high',
                    'security-severity' => match ($def['severity']) {
                        'CRITICAL' => '10',
                        'HIGH' => '7',
                        'MEDIUM' => '4',
                        default => '1',
                    },
                ],
            ];
        }

        $sarifResults = [];
        foreach ($result['findings'] as $f) {
            $sarifResults[] = [
                'ruleId' => $f['rule_id'],
                'level' => match ($f['severity']) {
                    'CRITICAL', 'HIGH' => 'error',
                    'MEDIUM' => 'warning',
                    default => 'note',
                },
                'message' => [
                    'text' => sprintf("%s - Offending: %s. Remediation: %s", $f['title'], $f['evidence'], $f['recommendation']),
                ],
                'locations' => [
                    [
                        'physicalLocation' => [
                            'artifactLocation' => [
                                'uri' => $result['target'],
                            ],
                        ],
                    ],
                ],
            ];
        }

        $sarif = [
            '$schema' => 'https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json',
            'version' => '2.1.0',
            'runs' => [
                [
                    'tool' => [
                        'driver' => [
                            'name' => 'lh-jsonl-logger',
                            'version' => '0.1.0',
                            'organization' => 'Logihertz Systems (OPC) Private Limited',
                            'informationUri' => 'https://github.com/Logihertz-Systems-OPC-Pvt-Ltd/lh-jsonl-logger',
                            'rules' => $rules,
                        ],
                    ],
                    'results' => $sarifResults,
                ],
            ],
        ];

        return (string) json_encode($sarif, JSON_PRETTY_PRINT | JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE);
    }
}
