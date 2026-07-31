import { randomBytes } from "node:crypto";

import { scanJson, validateRulePacks } from "@aiguard/core-wasm";

import type { Envelope, RulePack } from "./types.js";

export type RuleTestFailure = {
  ruleId: string;
  fixtureType: "positive" | "negative";
  fixtureIndex: number;
  message: string;
};

export type RuleTestReport = {
  passed: number;
  failed: number;
  failures: RuleTestFailure[];
};

export function testRulePacks(packs: RulePack[]): RuleTestReport {
  validateRulePacks(packs);
  const report: RuleTestReport = { passed: 0, failed: 0, failures: [] };
  const key = randomBytes(32).toString("hex");

  for (const pack of packs) {
    for (const rule of pack.rules) {
      const oneRulePack: RulePack = { ...pack, rules: [rule] };
      for (const fixtureType of ["positive", "negative"] as const) {
        const fixtures = rule.fixtures?.[fixtureType] ?? [];
        for (const [fixtureIndex, fixture] of fixtures.entries()) {
          const envelope: Envelope = {
            direction: "to_model",
            source: { kind: "rule-test", name: fixture, trust: "trusted" },
            mediaType: "text/plain",
            segments: [{ id: "fixture", text: fixture }],
          };
          const decision = scanJson(
            envelope,
            { version: 1, mode: "audit", actions: {}, suppressions: [], redact: false },
            [oneRulePack],
            key,
          ) as { findings: Array<{ ruleId: string }> };
          const detected = decision.findings.some((finding) => finding.ruleId === rule.id);
          const success = fixtureType === "positive" ? detected : !detected;
          if (success) {
            report.passed += 1;
          } else {
            report.failed += 1;
            report.failures.push({
              ruleId: rule.id,
              fixtureType,
              fixtureIndex,
              message:
                fixtureType === "positive"
                  ? "expected the rule to detect the synthetic fixture"
                  : "expected the rule to ignore the hard-negative fixture",
            });
          }
        }
      }
    }
  }
  return report;
}
