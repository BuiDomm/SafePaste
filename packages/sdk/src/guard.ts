import { createHmac, randomBytes } from "node:crypto";

import { scanJson, validateRulePacks } from "@aiguard/core-wasm";
import { baseRulePack } from "@aiguard/rules-base";
import { vietnameseRulePack } from "@aiguard/rules-vi";

import { defaultConfig, validateConfig } from "./config.js";
import type {
  Action,
  Decision,
  Envelope,
  Guard,
  GuardConfig,
  RulePack,
  ScanTextOptions,
} from "./types.js";

export type CreateGuardOptions = {
  config?: Partial<GuardConfig>;
  rulePacks?: RulePack[];
  hmacKey?: string;
};

function mergedConfig(override?: Partial<GuardConfig>): GuardConfig {
  if (!override) {
    return structuredClone(defaultConfig);
  }
  const validated = validateConfig(override, "guard config");
  return {
    ...structuredClone(defaultConfig),
    ...validated,
    version: 1,
    profiles: validated.profiles ?? [...defaultConfig.profiles],
    actions: { ...defaultConfig.actions, ...validated.actions },
    exclude: { paths: validated.exclude?.paths ?? [...defaultConfig.exclude.paths] },
    requiredDetectors: validated.requiredDetectors ?? [...defaultConfig.requiredDetectors],
    suppressions: validated.suppressions ?? [],
    customRules: validated.customRules ?? [],
  };
}

function customRulePack(config: GuardConfig): RulePack | undefined {
  if (config.customRules.length === 0) {
    return undefined;
  }
  return {
    manifest: {
      apiVersion: 1,
      id: "aiguard.custom",
      version: "1",
      minEngineVersion: "0.1.0-alpha.0",
      license: "LicenseRef-User-Configuration",
      locales: ["custom"],
    },
    rules: config.customRules,
  };
}

function policy(config: GuardConfig, redact: boolean): Record<string, unknown> {
  return {
    version: config.version,
    mode: config.mode,
    actions: config.actions,
    suppressions: config.suppressions,
    now: new Date().toISOString(),
    redact,
  };
}

export function createGuard(options: CreateGuardOptions = {}): Guard {
  const config = mergedConfig(options.config);
  const packs = [...(options.rulePacks ?? [baseRulePack, vietnameseRulePack])] as RulePack[];
  const custom = customRulePack(config);
  if (custom) {
    packs.push(custom);
  }
  validateRulePacks(packs);
  const hmacKey = options.hmacKey ?? randomBytes(32).toString("hex");

  const scan = (envelope: Envelope, scanOptions: { redact?: boolean } = {}): Decision => {
    assertEnvelope(envelope);
    return scanJson(envelope, policy(config, scanOptions.redact ?? false), packs, hmacKey) as Decision;
  };

  return {
    config,
    rulePacks: packs,
    scan,
    sanitize(envelope: Envelope): Decision {
      return scan(envelope, { redact: true });
    },
    scanText(text: string, scanOptions: ScanTextOptions = {}): Decision {
      return scan(
        {
          direction: scanOptions.direction ?? "to_model",
          source: {
            kind: scanOptions.sourceKind ?? "text",
            ...(scanOptions.sourceName ? { name: scanOptions.sourceName } : {}),
            trust: scanOptions.trust ?? "trusted",
          },
          ...(scanOptions.destination ? { destination: scanOptions.destination } : {}),
          mediaType: scanOptions.mediaType ?? "text/plain",
          segments: [{ id: "content", text }],
        },
        { redact: scanOptions.redact },
      );
    },
  };
}

function assertEnvelope(envelope: Envelope): void {
  if (!envelope || typeof envelope !== "object") {
    throw new Error("envelope must be an object");
  }
  if (!Array.isArray(envelope.segments) || envelope.segments.length === 0) {
    throw new Error("envelope.segments must contain at least one segment");
  }
  const ids = new Set<string>();
  for (const segment of envelope.segments) {
    if (!segment.id || typeof segment.text !== "string") {
      throw new Error("every segment needs a non-empty id and text string");
    }
    if (ids.has(segment.id)) {
      throw new Error(`duplicate segment id: ${segment.id}`);
    }
    ids.add(segment.id);
  }
}

export function unscannedDecision(mode: GuardConfig["mode"], reason: string): Decision {
  const action: Action = mode === "enforce" ? "block" : mode === "interactive" ? "ask" : "warn";
  return {
    action,
    findings: [],
    coverage: { status: "unscanned", degradedDetectors: [reason] },
    versions: { engine: "host", policy: "1", rulePacks: {} },
  };
}

export function keyedFingerprint(key: string, value: string): string {
  return createHmac("sha256", key).update(value).digest("hex");
}
