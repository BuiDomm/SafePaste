import { lstatSync, readFileSync, readdirSync, realpathSync, statSync } from "node:fs";
import { extname, relative, resolve } from "node:path";
import { performance } from "node:perf_hooks";

import { createGuard, unscannedDecision, type Decision, type Guard, type GuardConfig } from "@aiguard/sdk";

import type { ScanRecord } from "./reporters.js";

const excludedDirectories = new Set([".git", "node_modules", "dist", "build", "target"]);
const binaryExtensions = new Set([
  ".7z",
  ".avi",
  ".dmg",
  ".exe",
  ".gif",
  ".gz",
  ".ico",
  ".jpeg",
  ".jpg",
  ".mov",
  ".mp3",
  ".mp4",
  ".pdf",
  ".png",
  ".wasm",
  ".webp",
  ".zip",
]);

export type ScannedInput = ScanRecord & {
  original?: string;
  transformed?: string;
};

export function createCliGuard(config: GuardConfig, hmacKey: string): Guard {
  return createGuard({ config, hmacKey });
}

function globMatches(pattern: string, path: string): boolean {
  const normalizedPattern = pattern.replaceAll("\\", "/");
  const normalizedPath = path.replaceAll("\\", "/");
  const escaped = normalizedPattern.replace(/[.+^${}()|[\]\\]/g, "\\$&");
  const expression = escaped
    .replaceAll("**/", "__AIGUARD_GLOBSTAR_DIR__")
    .replaceAll("**", "__AIGUARD_GLOBSTAR__")
    .replaceAll("*", "[^/]*")
    .replaceAll("__AIGUARD_GLOBSTAR_DIR__", "(?:.*/)?")
    .replaceAll("__AIGUARD_GLOBSTAR__", ".*");
  return new RegExp(`^${expression}$`).test(normalizedPath);
}

export function collectFiles(paths: string[], excludePatterns: string[] = []): string[] {
  const files: string[] = [];
  const seen = new Set<string>();
  const visit = (input: string): void => {
    const absolute = resolve(input);
    const relativePath = relative(process.cwd(), absolute);
    if (excludePatterns.some((pattern) => globMatches(pattern, relativePath))) {
      return;
    }
    const entry = lstatSync(absolute);
    if (entry.isSymbolicLink()) {
      return;
    }
    if (entry.isDirectory()) {
      for (const child of readdirSync(absolute, { withFileTypes: true })) {
        if (child.isDirectory() && excludedDirectories.has(child.name)) {
          continue;
        }
        visit(resolve(absolute, child.name));
      }
      return;
    }
    if (entry.isFile()) {
      const canonical = realpathSync(absolute);
      if (!seen.has(canonical)) {
        seen.add(canonical);
        files.push(absolute);
      }
    }
  };
  for (const path of paths) {
    visit(path);
  }
  return files.sort();
}

function mediaType(path: string): string {
  switch (extname(path).toLowerCase()) {
    case ".json":
      return "application/json";
    case ".yaml":
    case ".yml":
      return "application/yaml";
    case ".env":
      return "application/x-env";
    case ".diff":
    case ".patch":
      return "text/x-diff";
    default:
      return "text/plain";
  }
}

function isBinary(buffer: Buffer, path: string): boolean {
  return binaryExtensions.has(extname(path).toLowerCase()) || buffer.subarray(0, 8_192).includes(0);
}

function mergeUnscanned(pathDecision: Decision, mode: GuardConfig["mode"], reason: string): Decision {
  const fallback = unscannedDecision(mode, reason);
  const rank = { allow: 0, warn: 1, ask: 2, redact: 3, block: 4 } as const;
  return {
    ...pathDecision,
    action: rank[pathDecision.action] >= rank[fallback.action] ? pathDecision.action : fallback.action,
    coverage: fallback.coverage,
  };
}

export function scanFile(guard: Guard, path: string, redact = false): ScannedInput {
  const started = performance.now();
  const size = statSync(path).size;
  const pathOnly = guard.scanText("", { sourceKind: "file", sourceName: path });
  if (size > guard.config.maxFileBytes) {
    return {
      source: relative(process.cwd(), path) || path,
      decision: mergeUnscanned(pathOnly, guard.config.mode, "file_too_large"),
      elapsedMs: performance.now() - started,
    };
  }
  const buffer = readFileSync(path);
  if (isBinary(buffer, path)) {
    return {
      source: relative(process.cwd(), path) || path,
      decision: mergeUnscanned(pathOnly, guard.config.mode, "binary_or_unsupported_media"),
      elapsedMs: performance.now() - started,
    };
  }
  const original = buffer.toString("utf8");
  const decision = guard.scanText(original, {
    sourceKind: "file",
    sourceName: path,
    mediaType: mediaType(path),
    redact,
  });
  return {
    source: relative(process.cwd(), path) || path,
    decision,
    elapsedMs: performance.now() - started,
    original,
    transformed: decision.transformed?.segments[0]?.text,
  };
}

export function scanTextInput(
  guard: Guard,
  text: string,
  options: { source?: string; mediaType?: string; redact?: boolean } = {},
): ScannedInput {
  const started = performance.now();
  const decision = guard.scanText(text, {
    sourceKind: "stdin",
    sourceName: options.source ?? "stdin",
    mediaType: options.mediaType,
    redact: options.redact,
  });
  return {
    source: options.source ?? "stdin",
    decision,
    elapsedMs: performance.now() - started,
    original: text,
    transformed: decision.transformed?.segments[0]?.text,
  };
}
