#!/usr/bin/env node

import { existsSync, readFileSync, writeFileSync } from "node:fs";
import { resolve } from "node:path";

import { validateRulePacks } from "@aiguard/core-wasm";
import { baseRulePack } from "@aiguard/rules-base";
import { vietnameseRulePack } from "@aiguard/rules-vi";
import {
  loadConfig,
  testRulePacks,
  type GuardConfig,
  type Mode,
  type RulePack,
} from "@aiguard/sdk";

import { hasFlag, option, positionals } from "./args.js";
import { doctorHuman, runDoctor } from "./doctor.js";
import { startProxy } from "./proxy.js";
import { humanReport, jsonReport, sarifReport, type ScanRecord } from "./reporters.js";
import { collectFiles, createCliGuard, scanFile, scanTextInput } from "./scanner.js";
import { loadOrCreateHmacKey } from "./state.js";

const VERSION = "0.1.0-alpha.0";
const HELP = `AI Data Boundary ${VERSION}

Usage:
  aiguard init
  aiguard scan [paths...] [--stdin] [--format human|json|sarif] [--mode audit|interactive|enforce]
  aiguard sanitize [path] [--stdin]
  aiguard doctor [--format human|json]
  aiguard proxy --upstream URL [--host 127.0.0.1] [--port 4242]
  aiguard rules validate [--format human|json]
  aiguard rules test [--format human|json]

The CLI only protects content explicitly passed through it. It does not intercept system-wide traffic.
`;

function modeOverride(args: string[]): Partial<GuardConfig> | undefined {
  const value = option(args, "--mode");
  if (!value) return undefined;
  if (!["audit", "interactive", "enforce"].includes(value)) {
    throw new Error("--mode must be audit, interactive, or enforce");
  }
  return { mode: value as Mode };
}

function configFor(args: string[]): GuardConfig {
  return loadConfig({
    explicitPath: option(args, "--config"),
    overrides: modeOverride(args),
  });
}

async function stdinText(): Promise<string> {
  const chunks: Buffer[] = [];
  for await (const chunk of process.stdin) {
    chunks.push(Buffer.isBuffer(chunk) ? chunk : Buffer.from(chunk));
  }
  return Buffer.concat(chunks).toString("utf8");
}

function output(records: ScanRecord[], format: string): void {
  if (format === "json") {
    process.stdout.write(jsonReport(records));
  } else if (format === "sarif") {
    process.stdout.write(sarifReport(records));
  } else if (format === "human") {
    process.stdout.write(humanReport(records));
  } else {
    throw new Error("--format must be human, json, or sarif");
  }
}

async function scanCommand(args: string[]): Promise<number> {
  const config = configFor(args);
  const guard = createCliGuard(config, loadOrCreateHmacKey());
  const paths = positionals(args);
  const useStdin = hasFlag(args, "--stdin") || (paths.length === 0 && !process.stdin.isTTY);
  if (paths.length === 0 && !useStdin) {
    throw new Error("scan requires a path or --stdin");
  }
  const records: ScanRecord[] = [];
  if (useStdin) {
    records.push(scanTextInput(guard, await stdinText()));
  }
  for (const file of collectFiles(paths, config.exclude.paths)) {
    records.push(scanFile(guard, file));
  }
  output(records, option(args, "--format") ?? "human");
  return records.some((record) => record.decision.action !== "allow") ? 1 : 0;
}

async function sanitizeCommand(args: string[]): Promise<number> {
  const config = configFor(args);
  const guard = createCliGuard(config, loadOrCreateHmacKey());
  const paths = positionals(args);
  const useStdin = hasFlag(args, "--stdin") || (paths.length === 0 && !process.stdin.isTTY);
  if ((paths.length === 0 && !useStdin) || paths.length > 1 || (paths.length === 1 && useStdin)) {
    throw new Error("sanitize accepts exactly one path or --stdin");
  }
  const record = useStdin
    ? scanTextInput(guard, await stdinText(), { redact: true })
    : scanFile(guard, resolve(paths[0]!), true);
  if (record.decision.coverage.status !== "complete") {
    process.stderr.write(humanReport([record]));
    return 1;
  }
  process.stdout.write(record.transformed ?? record.original ?? "");
  if (record.decision.findings.length > 0) {
    process.stderr.write(
      `[aiguard] sanitized ${record.decision.findings.length} finding(s); raw values were not logged\n`,
    );
  }
  return record.decision.action === "block" ? 1 : 0;
}

function initCommand(): number {
  const path = resolve(".aiguard.yml");
  if (existsSync(path)) {
    throw new Error(`${path} already exists`);
  }
  writeFileSync(
    path,
    `version: 1
mode: interactive
profiles:
  - recommended
  - developer
  - vi-VN
actions:
  credential: block
  secret: ask
  financial: ask
  pii: warn
  sensitive_file: ask
exclude:
  paths:
    - "**/.git/**"
    - "**/node_modules/**"
requiredDetectors:
  - deterministic
suppressions: []
customRules: []
maxFileBytes: 1048576
`,
    { encoding: "utf8", flag: "wx" },
  );
  process.stdout.write(`Created ${path}\n`);
  return 0;
}

function rulesCommand(args: string[]): number {
  const subcommand = args[0];
  const format = option(args, "--format") ?? "human";
  const packs = [baseRulePack, vietnameseRulePack] as RulePack[];
  if (subcommand === "validate") {
    const report = validateRulePacks(packs);
    process.stdout.write(
      format === "json"
        ? `${JSON.stringify(report, null, 2)}\n`
        : `Valid rule packs: ${report.packs}; executable plugins: 0\n`,
    );
    return 0;
  }
  if (subcommand === "test") {
    const report = testRulePacks(packs);
    process.stdout.write(
      format === "json"
        ? `${JSON.stringify(report, null, 2)}\n`
        : `Rule fixtures: ${report.passed} passed, ${report.failed} failed\n${report.failures
            .map((failure) => `- ${failure.ruleId} ${failure.fixtureType}[${failure.fixtureIndex}]: ${failure.message}`)
            .join("\n")}\n`,
    );
    return report.failed > 0 ? 1 : 0;
  }
  throw new Error("rules requires validate or test");
}

async function main(): Promise<number> {
  const [command, ...args] = process.argv.slice(2);
  if (!command || command === "--help" || command === "-h" || command === "help") {
    process.stdout.write(HELP);
    return 0;
  }
  if (command === "--version" || command === "-v") {
    process.stdout.write(`${VERSION}\n`);
    return 0;
  }
  switch (command) {
    case "init":
      return initCommand();
    case "scan":
      return scanCommand(args);
    case "sanitize":
      return sanitizeCommand(args);
    case "doctor": {
      const report = runDoctor(configFor(args));
      process.stdout.write(
        option(args, "--format") === "json"
          ? `${JSON.stringify(report, null, 2)}\n`
          : doctorHuman(report),
      );
      return report.healthy ? 0 : 1;
    }
    case "rules":
      return rulesCommand(args);
    case "proxy": {
      const upstream = option(args, "--upstream") ?? process.env.AIGUARD_UPSTREAM_URL;
      if (!upstream) {
        throw new Error("proxy requires --upstream URL or AIGUARD_UPSTREAM_URL");
      }
      const port = Number(option(args, "--port") ?? "4242");
      if (!Number.isInteger(port) || port < 1 || port > 65535) {
        throw new Error("--port must be an integer from 1 to 65535");
      }
      const guard = createCliGuard(configFor(args), loadOrCreateHmacKey());
      await startProxy({
        guard,
        upstream,
        host: option(args, "--host") ?? "127.0.0.1",
        port,
      });
      return 0;
    }
    default:
      throw new Error(`unknown command: ${command}`);
  }
}

main()
  .then((code) => {
    process.exitCode = code;
  })
  .catch((error: unknown) => {
    const message = error instanceof Error ? error.message : "unexpected error";
    process.stderr.write(`[aiguard] ${message}\n`);
    process.exitCode = 2;
  });
