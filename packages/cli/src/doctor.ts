import { existsSync, statSync } from "node:fs";

import { engineVersion } from "@aiguard/core-wasm";
import type { GuardConfig } from "@aiguard/sdk";

import { keyPath } from "./state.js";

export type CoverageCheck = {
  surface: string;
  status: "protected" | "bypassable" | "unsupported";
  detail: string;
};

function localBaseUrl(value: string | undefined): boolean {
  if (!value) return false;
  try {
    const url = new URL(value);
    return ["127.0.0.1", "localhost", "::1"].includes(url.hostname);
  } catch {
    return false;
  }
}

export function runDoctor(config: GuardConfig): { healthy: boolean; engine: string; checks: CoverageCheck[] } {
  const nodeSupported = Number(process.versions.node.split(".")[0]) >= 22;
  const key = keyPath();
  const keyProtected =
    !existsSync(key) || process.platform === "win32" || (statSync(key).mode & 0o077) === 0;
  const checks: CoverageCheck[] = [
    {
      surface: "cli",
      status: "protected",
      detail: "Content passed to scan/sanitize is inspected locally.",
    },
    {
      surface: "node-sdk",
      status: "bypassable",
      detail: "Only requests passed through createGuard/guardedFetch are protected.",
    },
    {
      surface: "openai-proxy",
      status: localBaseUrl(process.env.OPENAI_BASE_URL) ? "protected" : "bypassable",
      detail: localBaseUrl(process.env.OPENAI_BASE_URL)
        ? "OPENAI_BASE_URL points to a local host. Confirm the port matches the running proxy."
        : "OPENAI_BASE_URL does not point to a local guard proxy.",
    },
    {
      surface: "anthropic-proxy",
      status: localBaseUrl(process.env.ANTHROPIC_BASE_URL) ? "protected" : "bypassable",
      detail: localBaseUrl(process.env.ANTHROPIC_BASE_URL)
        ? "ANTHROPIC_BASE_URL points to a local host. Confirm the port matches the running proxy."
        : "ANTHROPIC_BASE_URL does not point to a local guard proxy.",
    },
    {
      surface: "mcp-gateway",
      status: "unsupported",
      detail: "MCP gateway enforcement is planned for v0.3 and is not active.",
    },
    {
      surface: "desktop-browser",
      status: "unsupported",
      detail: "The current desktop is a scaffold; no browser interception is active.",
    },
  ];
  return {
    healthy: nodeSupported && keyProtected && config.requiredDetectors.includes("deterministic"),
    engine: engineVersion(),
    checks,
  };
}

export function doctorHuman(report: ReturnType<typeof runDoctor>): string {
  const lines = [`AI Data Boundary doctor`, `engine: ${report.engine}`, `healthy: ${report.healthy}`];
  for (const check of report.checks) {
    lines.push(`${check.status.toUpperCase()} ${check.surface}`);
    lines.push(`  ${check.detail}`);
  }
  return `${lines.join("\n")}\n`;
}
