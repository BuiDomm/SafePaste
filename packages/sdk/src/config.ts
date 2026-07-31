import { existsSync, readFileSync } from "node:fs";
import { homedir } from "node:os";
import { dirname, join, parse, resolve } from "node:path";
import { parse as parseYaml } from "yaml";

import type { Action, GuardConfig, Mode, Rule, Suppression } from "./types.js";

const knownKeys = new Set([
  "version",
  "mode",
  "profiles",
  "actions",
  "exclude",
  "requiredDetectors",
  "suppressions",
  "customRules",
  "maxFileBytes",
]);
const modes = new Set<Mode>(["audit", "interactive", "enforce"]);
const actions = new Set<Action>(["allow", "warn", "ask", "redact", "block"]);

export const defaultConfig: GuardConfig = {
  version: 1,
  mode: "interactive",
  profiles: ["recommended", "developer", "vi-VN"],
  actions: {
    credential: "block",
    secret: "ask",
    financial: "ask",
    pii: "warn",
    sensitive_file: "ask",
    proprietary: "ask",
  },
  exclude: {
    paths: ["**/.git/**", "**/node_modules/**", "**/dist/**", "**/build/**", "**/target/**"],
  },
  requiredDetectors: ["deterministic"],
  suppressions: [],
  customRules: [],
  maxFileBytes: 1_048_576,
};

type PartialConfig = Partial<Omit<GuardConfig, "exclude">> & {
  exclude?: { paths?: string[] };
};

function assertRecord(value: unknown, label: string): asserts value is Record<string, unknown> {
  if (!value || typeof value !== "object" || Array.isArray(value)) {
    throw new Error(`${label} must be an object`);
  }
}

export function validateConfig(value: unknown, source = "config"): PartialConfig {
  assertRecord(value, source);
  for (const key of Object.keys(value)) {
    if (!knownKeys.has(key)) {
      throw new Error(`${source} contains unknown key: ${key}`);
    }
  }
  if (value.version !== undefined && value.version !== 1) {
    throw new Error(`${source}.version must be 1`);
  }
  if (value.mode !== undefined && !modes.has(value.mode as Mode)) {
    throw new Error(`${source}.mode must be audit, interactive, or enforce`);
  }
  if (value.actions !== undefined) {
    assertRecord(value.actions, `${source}.actions`);
    for (const [category, action] of Object.entries(value.actions)) {
      if (!actions.has(action as Action)) {
        throw new Error(`${source}.actions.${category} has invalid action`);
      }
    }
  }
  for (const key of ["profiles", "requiredDetectors", "suppressions", "customRules"] as const) {
    if (value[key] !== undefined && !Array.isArray(value[key])) {
      throw new Error(`${source}.${key} must be an array`);
    }
  }
  if (value.maxFileBytes !== undefined) {
    if (typeof value.maxFileBytes !== "number" || !Number.isInteger(value.maxFileBytes) || value.maxFileBytes < 1) {
      throw new Error(`${source}.maxFileBytes must be a positive integer`);
    }
  }
  if (value.exclude !== undefined) {
    assertRecord(value.exclude, `${source}.exclude`);
    const unknownExclude = Object.keys(value.exclude).filter((key) => key !== "paths");
    if (unknownExclude.length > 0) {
      throw new Error(`${source}.exclude contains unknown key: ${unknownExclude[0]}`);
    }
    if (value.exclude.paths !== undefined && !Array.isArray(value.exclude.paths)) {
      throw new Error(`${source}.exclude.paths must be an array`);
    }
  }
  return value as PartialConfig;
}

function merge(base: GuardConfig, override: PartialConfig): GuardConfig {
  return {
    ...base,
    ...override,
    version: 1,
    profiles: override.profiles ? [...override.profiles] : [...base.profiles],
    actions: { ...base.actions, ...override.actions },
    exclude: { paths: override.exclude?.paths ? [...override.exclude.paths] : [...base.exclude.paths] },
    requiredDetectors: override.requiredDetectors
      ? [...override.requiredDetectors]
      : [...base.requiredDetectors],
    suppressions: override.suppressions
      ? ([...override.suppressions] as Suppression[])
      : [...base.suppressions],
    customRules: override.customRules ? ([...override.customRules] as Rule[]) : [...base.customRules],
  };
}

function readYaml(path: string): PartialConfig {
  const parsed = parseYaml(readFileSync(path, "utf8")) as unknown;
  return validateConfig(parsed, path);
}

export function userConfigPath(): string {
  if (process.platform === "win32") {
    return join(process.env.APPDATA ?? join(homedir(), "AppData", "Roaming"), "aiguard", "config.yml");
  }
  return join(process.env.XDG_CONFIG_HOME ?? join(homedir(), ".config"), "aiguard", "config.yml");
}

export function findProjectConfig(cwd = process.cwd()): string | undefined {
  let current = resolve(cwd);
  const root = parse(current).root;
  while (true) {
    const candidate = join(current, ".aiguard.yml");
    if (existsSync(candidate)) {
      return candidate;
    }
    if (current === root) {
      return undefined;
    }
    current = dirname(current);
  }
}

export function loadConfig(options: {
  cwd?: string;
  explicitPath?: string;
  overrides?: PartialConfig;
} = {}): GuardConfig {
  let result = structuredClone(defaultConfig);
  const userPath = userConfigPath();
  if (existsSync(userPath)) {
    result = merge(result, readYaml(userPath));
  }
  const projectPath = options.explicitPath ?? findProjectConfig(options.cwd);
  if (projectPath) {
    if (!existsSync(projectPath)) {
      throw new Error(`config file not found: ${projectPath}`);
    }
    result = merge(result, readYaml(projectPath));
  }
  if (options.overrides) {
    result = merge(result, validateConfig(options.overrides, "CLI overrides"));
  }
  return result;
}
