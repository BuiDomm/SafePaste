import { createRequire } from "node:module";

type WasmExports = {
  engine_version(): string;
  scan_json(envelope: string, policy: string, rulePacks: string, hmacKey: string): string;
  validate_rules_json(rulePacks: string): string;
};

const require = createRequire(import.meta.url);
let loaded: WasmExports | undefined;

function wasm(): WasmExports {
  if (!loaded) {
    try {
      loaded = require("../generated/aiguard_core.js") as WasmExports;
    } catch (error) {
      const detail = error instanceof Error ? error.message : String(error);
      throw new Error(
        `AI Data Boundary WebAssembly core is not built. Run \"npm run build:wasm\" first. ${detail}`,
      );
    }
  }
  return loaded;
}

export function engineVersion(): string {
  return wasm().engine_version();
}

export function scanJson(
  envelope: unknown,
  policy: unknown,
  rulePacks: unknown,
  hmacKey: string,
): unknown {
  return JSON.parse(
    wasm().scan_json(
      JSON.stringify(envelope),
      JSON.stringify(policy),
      JSON.stringify(rulePacks),
      hmacKey,
    ),
  ) as unknown;
}

export function validateRulePacks(rulePacks: unknown): { valid: boolean; packs: number } {
  return JSON.parse(wasm().validate_rules_json(JSON.stringify(rulePacks))) as {
    valid: boolean;
    packs: number;
  };
}
