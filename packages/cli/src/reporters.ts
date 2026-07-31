import type { Decision } from "@aiguard/sdk";

export type ScanRecord = {
  source: string;
  decision: Decision;
  elapsedMs: number;
};

export function humanReport(records: ScanRecord[]): string {
  if (records.length === 0) {
    return "No inputs were scanned.\n";
  }
  const lines: string[] = [];
  for (const record of records) {
    lines.push(`${record.decision.action.toUpperCase()} ${record.source}`);
    lines.push(
      `  coverage: ${record.decision.coverage.status}; findings: ${record.decision.findings.length}; ${record.elapsedMs.toFixed(2)} ms`,
    );
    if (record.decision.coverage.degradedDetectors.length > 0) {
      lines.push(`  degraded: ${record.decision.coverage.degradedDetectors.join(", ")}`);
    }
    for (const finding of record.decision.findings) {
      lines.push(
        `  - [${finding.severity}/${finding.confidence}] ${finding.ruleId} (${finding.category}) ${finding.maskedPreview}`,
      );
      lines.push(`    ${finding.explanation}`);
      lines.push(`    Fix: ${finding.remediation}`);
    }
  }
  return `${lines.join("\n")}\n`;
}

export function jsonReport(records: ScanRecord[]): string {
  // Serialize an explicit allowlist. Scanner hosts may keep raw/transformed
  // content in memory, but reports must never inherit those private fields.
  const safeRecords = records.map(({ source, decision, elapsedMs }) => ({
    source,
    decision,
    elapsedMs,
  }));
  return `${JSON.stringify({ schemaVersion: 1, records: safeRecords }, null, 2)}\n`;
}

export function sarifReport(records: ScanRecord[]): string {
  const rules = new Map<string, { id: string; explanation: string; remediation: string }>();
  const results: unknown[] = [];
  for (const record of records) {
    for (const finding of record.decision.findings) {
      rules.set(finding.ruleId, {
        id: finding.ruleId,
        explanation: finding.explanation,
        remediation: finding.remediation,
      });
      results.push({
        ruleId: finding.ruleId,
        level: finding.severity === "critical" || finding.severity === "high" ? "error" : "warning",
        message: { text: `${finding.category}: ${finding.explanation} ${finding.remediation}` },
        locations: [
          {
            physicalLocation: {
              artifactLocation: { uri: record.source },
              region: {
                charOffset: finding.location.start,
                charLength: finding.location.end - finding.location.start,
              },
            },
          },
        ],
        properties: {
          confidence: finding.confidence,
          maskedPreview: finding.maskedPreview,
          fingerprint: finding.fingerprint,
        },
      });
    }
  }
  return `${JSON.stringify(
    {
      version: "2.1.0",
      $schema: "https://json.schemastore.org/sarif-2.1.0.json",
      runs: [
        {
          tool: {
            driver: {
              name: "AI Data Boundary",
              semanticVersion: "0.1.0-alpha.0",
              rules: [...rules.values()].map((rule) => ({
                id: rule.id,
                shortDescription: { text: rule.explanation },
                help: { text: rule.remediation },
              })),
            },
          },
          results,
        },
      ],
    },
    null,
    2,
  )}\n`;
}
