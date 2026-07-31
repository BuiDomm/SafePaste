import { performance } from "node:perf_hooks";

import { createGuard } from "@aiguard/sdk";

const guard = createGuard({ hmacKey: "0123456789abcdef0123456789abcdef" });
const base = "export function sum(a, b) { return a + b; }\n";
const input = base.repeat(Math.ceil(32_768 / base.length)).slice(0, 32_768);
const warmup = 50;
const iterations = 500;

for (let index = 0; index < warmup; index += 1) {
  guard.scanText(input);
}

const samples = [];
for (let index = 0; index < iterations; index += 1) {
  const started = performance.now();
  guard.scanText(input);
  samples.push(performance.now() - started);
}
samples.sort((left, right) => left - right);
const percentile = (value) => samples[Math.min(samples.length - 1, Math.floor(samples.length * value))];
const report = {
  schemaVersion: 1,
  bytes: Buffer.byteLength(input),
  iterations,
  p50Ms: percentile(0.5),
  p95Ms: percentile(0.95),
  targetP95Ms: 50,
  passed: percentile(0.95) < 50,
  runtime: { node: process.version, platform: process.platform, arch: process.arch },
};

process.stdout.write(`${JSON.stringify(report, null, 2)}\n`);
if (!report.passed) {
  process.exitCode = 1;
}
